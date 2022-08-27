use std::{
    collections::HashMap,
    ffi::{CStr, CString, OsStr},
    os::unix::prelude::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OsStrExt, OsStringExt, OwnedFd},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, UNIX_EPOCH},
};

use anyhow::{bail, Context};
use atoi::atoi;
use bstr::{BStr, BString, ByteSlice, ByteVec};
use fuser::{FileAttr, FileType, MountOption, FUSE_ROOT_ID};
use libc::{EINVAL, ENOENT, EPERM};
use log::warn;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[allow(unused)]
struct PathOrigin {
    pub attr: String,
    pub output: String,
    pub toplevel: bool,
}

#[derive(Debug, Deserialize)]
#[allow(unused)]
struct Package {
    pub store_dir: String,
    pub hash: String,
    pub name: String,
    pub origin: PathOrigin,
}

type LeakStr = &'static BStr;

#[derive(Debug)]
enum EntryMeta {
    Package,
    RegularFile { size: u64, executable: bool },
    Directory { size: u64 },
    Symlink { target: LeakStr },
}

fn parse_entry<'a>(cur: &mut &'a [u8]) -> anyhow::Result<(EntryMeta, i32, &'a [u8])> {
    let meta_len = memchr::memchr(0, cur).context("NUL expected")?;
    let meta = &cur[..meta_len];
    *cur = &cur[meta_len + 1..];

    let (prefix_len_delta, ptr_add) = if cur[0] != 0x80 {
        (i32::from(cur[0] as i8), 1)
    } else {
        (i32::from(i16::from_be_bytes([cur[1], cur[2]])), 3)
    };

    *cur = &cur[ptr_add..];

    let rest_len = memchr::memchr(b'\n', cur).context("newline expected")?;
    let rest = &cur[..rest_len];
    *cur = &cur[rest_len + 1..];

    let (&kind, meta) = meta.split_last().context("empty metadata")?;
    let meta = if kind == b'r' || kind == b'x' {
        let size = atoi(meta).context("cannot parse file size")?;
        let executable = kind == b'x';
        EntryMeta::RegularFile { size, executable }
    } else if kind == b'd' {
        let size = atoi(meta).context("cannot parse directory size")?;
        EntryMeta::Directory { size }
    } else if kind == b's' {
        EntryMeta::Symlink {
            target: meta.to_owned().leak().as_bstr(),
        }
    } else if kind == b'p' {
        EntryMeta::Package
    } else {
        bail!("Unexpected entry kind {}", kind);
    };

    Ok((meta, prefix_len_delta, rest))
}

#[derive(Debug)]
enum Node {
    Dummy,
    RegularFile {
        size: u64,
        executable: bool,
    },
    Directory {
        size: u64,
        children: Box<[(LeakStr, usize)]>,
    },
    Symlink {
        target: LeakStr,
    },
}

#[derive(Debug)]
struct DirectoryBuilder {
    name: LeakStr,
    size: u64,
    children: Vec<(LeakStr, usize)>,
}

impl DirectoryBuilder {
    fn new(name: LeakStr, size: u64) -> Self {
        Self {
            name,
            size,
            children: Vec::new(),
        }
    }

    fn finish(self) -> (&'static BStr, Node) {
        (
            self.name,
            Node::Directory {
                size: self.size,
                children: self.children.into_boxed_slice(),
            },
        )
    }
}

fn parse_package(cur: &mut &[u8], nodes: &mut Vec<Node>) -> anyhow::Result<(Package, usize)> {
    let mut last_suffix = &b""[..];
    let mut dir_stack: Vec<DirectoryBuilder> = vec![];
    let mut top_dir = DirectoryBuilder::new(b"".as_bstr(), 0);
    let mut last_node: Node = Node::Dummy;
    let mut last_name: BString = BString::default();

    loop {
        let (meta, prefix_delta, suffix) = parse_entry(&mut *cur)?;

        if let Some(rest) = suffix.strip_prefix(b"/") {
            let new_top_dir = match last_node {
                Node::Directory { size, .. } => {
                    let last_name = <Vec<u8>>::from(last_name.clone()).leak().as_bstr();
                    DirectoryBuilder::new(last_name, size)
                }
                _ => bail!("directory expected"),
            };
            dir_stack.push(top_dir);
            top_dir = new_top_dir;
            last_name = BString::from(rest);
        } else if !matches!(last_node, Node::Dummy) {
            let mut last_len = last_name.len();
            {
                let index = nodes.len();
                nodes.push(last_node);
                let last_name = <Vec<u8>>::from(last_name.clone()).leak().as_bstr();
                top_dir.children.push((last_name, index));
            }

            let mut remove_len = usize::try_from(last_suffix.len() as i32 - prefix_delta)?;
            while remove_len > last_len {
                remove_len -= 1 + last_len;

                last_len = top_dir.name.len();

                let mut new_top_dir = dir_stack.pop().context("malformed file tree")?;
                let (name, node) = top_dir.finish();
                let index = nodes.len();
                nodes.push(node);
                new_top_dir.children.push((name, index));
                top_dir = new_top_dir;
            }

            last_name = BString::from(&top_dir.children.last().unwrap().0[..last_len - remove_len]);
            last_name.push_str(suffix);
        } else {
            last_name.push_str(suffix);
        }

        last_suffix = suffix;
        last_node = match meta {
            EntryMeta::RegularFile { size, executable } => Node::RegularFile { size, executable },
            EntryMeta::Symlink { target } => Node::Symlink { target },
            EntryMeta::Directory { size } => Node::Directory {
                size,
                children: Box::new([]),
            },
            EntryMeta::Package => {
                break;
            }
        };
    }

    if top_dir.children.len() != 1 {
        bail!("malformed file tree");
    }
    let root = top_dir.children[0].1;
    let package = serde_json::from_slice(last_suffix)?;
    Ok((package, root))
}

const TTL: Duration = Duration::from_secs(1);
const FILE_PERM: u16 = 0o444;
const EXEC_FILE_PERM: u16 = 0o555;
const DIR_PERM: u16 = 0o555;
const SYMLINK_PERM: u16 = 0o444;
const ROOT_ID: usize = FUSE_ROOT_ID as usize;

fn create_attr(ino: u64, size: u64, kind: FileType, perm: u16) -> FileAttr {
    let blksize: u32 = 512;
    let blocks = if size == 0 {
        0
    } else {
        (size - 1) / u64::from(blksize) + 1
    };
    FileAttr {
        ino,
        size,
        blocks,
        atime: UNIX_EPOCH,
        mtime: UNIX_EPOCH,
        ctime: UNIX_EPOCH,
        crtime: UNIX_EPOCH,
        kind,
        perm,
        nlink: 1,
        uid: 0,
        gid: 0,
        rdev: 0,
        blksize,
        flags: 0,
    }
}

struct Fs {
    nodes: Vec<Node>,
    packages: Vec<(Package, usize)>,
    lookup_index: HashMap<(u64, LeakStr), usize>,
    parent_node: Vec<Option<(LeakStr, usize)>>,
    root_to_package: HashMap<usize, usize>,

    local_store: OwnedFd,
    open_nodes: HashMap<usize, OwnedFd>,
}

fn open_dir(dir: PathBuf) -> std::io::Result<OwnedFd> {
    let dir = CString::new(dir.into_os_string().into_vec())?;
    let fd = unsafe { libc::open(dir.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    if fd >= 0 {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn open_at(dir: BorrowedFd, path: &CStr) -> std::io::Result<OwnedFd> {
    let fd = unsafe { libc::openat(dir.as_raw_fd(), path.as_ptr(), libc::O_RDONLY) };
    if fd >= 0 {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn read_file(fd: BorrowedFd, offset: i64, size: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; size];
    let n = unsafe {
        libc::lseek(fd.as_raw_fd(), offset as i64, libc::SEEK_SET);
        libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), size)
    };
    if n >= 0 {
        buf.truncate((n as usize).min(buf.len()));
        Ok(buf)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn run_nix_copy(store_path: &Path) -> std::io::Result<()> {
    let status = Command::new("nix")
        .args(["copy", "--from", "https://cache.nixos.org/"])
        .arg(store_path)
        .spawn()?
        .wait()?;

    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("nix copy failed for {}", store_path.display()),
        ))
    }
}

impl Fs {
    pub fn new(nodes: Vec<Node>, packages: Vec<(Package, usize)>) -> anyhow::Result<Self> {
        let mut lookup_index = HashMap::new();
        let mut parent_node = vec![None; nodes.len()];
        let mut root_to_package = HashMap::new();

        for (i, &(ref package, root)) in packages.iter().enumerate() {
            let name = format!("{}-{}", package.hash, package.name)
                .into_bytes()
                .leak()
                .as_bstr();
            lookup_index.insert((FUSE_ROOT_ID, name), root);
            parent_node[root] = Some((name, ROOT_ID));
            root_to_package.insert(root, i);
        }

        for (i, node) in nodes.iter().enumerate() {
            if let Node::Directory { children, .. } = node {
                for &(name, child) in children.iter() {
                    lookup_index.insert((i as u64, name), child);
                    assert!(parent_node[child].is_none());
                    parent_node[child] = Some((name, i));
                }
            }
        }
        Ok(Self {
            nodes,
            packages,
            lookup_index,
            parent_node,
            root_to_package,

            local_store: open_dir(PathBuf::from("/nix/store"))?,
            open_nodes: HashMap::new(),
        })
    }

    fn is_node(&self, ino: u64) -> bool {
        ino < self.nodes.len() as u64 && !matches!(self.nodes[ino as usize], Node::Dummy)
    }

    fn attr_root(&self) -> FileAttr {
        let size = self.nodes.len() as u64 * std::mem::size_of::<Node>() as u64;
        create_attr(FUSE_ROOT_ID, size, FileType::Directory, DIR_PERM)
    }

    fn attr_node(&self, i: usize) -> FileAttr {
        match &self.nodes[i] {
            &Node::RegularFile { size, executable } => {
                let perm = if executable {
                    EXEC_FILE_PERM
                } else {
                    FILE_PERM
                };
                create_attr(i as u64, size, FileType::RegularFile, perm)
            }
            Node::Directory { size, children: _ } => {
                create_attr(i as u64, *size, FileType::Directory, DIR_PERM)
            }
            Node::Symlink { target } => create_attr(
                i as u64,
                target.len() as u64,
                FileType::Symlink,
                SYMLINK_PERM,
            ),
            Node::Dummy => {
                warn!("attr dummy node {}", i);
                self.attr_root()
            }
        }
    }

    fn file_type_node(&self, i: usize) -> FileType {
        match &self.nodes[i] {
            Node::RegularFile { .. } => FileType::RegularFile,
            Node::Directory { .. } => FileType::Directory,
            Node::Symlink { .. } => FileType::Symlink,
            Node::Dummy => {
                warn!("file type dummy node {}", i);
                FileType::RegularFile
            }
        }
    }

    fn readdir_root(&mut self, offset: usize, mut reply: fuser::ReplyDirectory) {
        if offset == 0 && reply.add(FUSE_ROOT_ID, 1, FileType::Directory, ".") {
            return reply.ok();
        }
        if offset <= 1 && reply.add(FUSE_ROOT_ID, 2, FileType::Directory, "..") {
            return reply.ok();
        }

        for (i, &(_, root)) in self
            .packages
            .iter()
            .enumerate()
            .skip(offset.saturating_sub(2))
        {
            let next_offset = 2 + i as i64 + 1;
            let kind = self.file_type_node(root);
            if let Some((name, _)) = self.parent_node[root] {
                if reply.add(root as u64, next_offset, kind, OsStr::from_bytes(name)) {
                    return reply.ok();
                }
            }
        }

        reply.ok()
    }

    fn readdir_node(&mut self, node: usize, offset: usize, mut reply: fuser::ReplyDirectory) {
        let children = if let Node::Directory { children, .. } = &self.nodes[node] {
            &children[..]
        } else {
            return reply.error(ENOENT);
        };

        if offset == 0 && reply.add(node as u64, 1, FileType::Directory, ".") {
            return reply.ok();
        }
        let parent = self.parent_node[node]
            .as_ref()
            .map_or(FUSE_ROOT_ID, |x| x.1 as u64);
        if offset <= 1 && reply.add(parent, 2, FileType::Directory, "..") {
            return reply.ok();
        }

        for (i, &(name, child)) in children.iter().enumerate().skip(offset.saturating_sub(2)) {
            let next_offset = 2 + i as i64 + 1;
            let kind = self.file_type_node(child);
            if reply.add(child as u64, next_offset, kind, OsStr::from_bytes(name)) {
                return reply.ok();
            }
        }

        reply.ok()
    }

    fn get_node_link(&self, node: usize) -> Option<&BStr> {
        if let Node::Symlink { target } = &self.nodes[node] {
            Some(target.as_bstr())
        } else {
            None
        }
    }

    fn get_package_and_path(&self, mut node: usize) -> Option<(&Package, PathBuf)> {
        let mut parts = Vec::new();
        loop {
            let (part, parent) = self.parent_node[node]?;
            if parent == 0 || parent == node {
                return None;
            }
            parts.push(part);
            if parent == ROOT_ID {
                let package_id = *self.root_to_package.get(&node)?;
                let package = &self.packages[package_id].0;
                let mut buf = PathBuf::new();
                for &part in parts.iter().rev() {
                    buf.push(OsStr::from_bytes(part));
                }
                return Some((package, buf));
            }
            node = parent;
        }
    }

    fn try_open_node(&mut self, node: usize, path: &CString) -> bool {
        if let Ok(fd) = open_at(self.local_store.as_fd(), path.as_ref()) {
            log::info!(
                "Opened {} {} as FD {}",
                node,
                path.as_bytes().as_bstr(),
                fd.as_raw_fd()
            );
            self.open_nodes.insert(node, fd);
            true
        } else {
            false
        }
    }

    fn open_node(&mut self, node: usize, reply: fuser::ReplyOpen) {
        if let Some(fd) = self.open_nodes.get(&node) {
            log::info!("Node {} is already opened as FD {}", node, fd.as_raw_fd());
            return reply.opened(0, 0);
        }

        let (_package, path) = match self.get_package_and_path(node) {
            Some(ok) => ok,
            None => {
                log::error!("get_package_and_path failed for node {}", node);
                return reply.error(ENOENT);
            }
        };

        let path = if let Ok(ok) = CString::new(path.into_os_string().into_vec()) {
            ok
        } else {
            return reply.error(EINVAL);
        };

        if self.try_open_node(node, &path) {
            return reply.opened(0, 0);
        }

        let mut store_path = PathBuf::from("/nix/store");
        store_path.push(OsStr::from_bytes(path.as_bytes()));

        if let Err(err) = run_nix_copy(&store_path) {
            log::error!(
                "Failed to copy {} from binary cache: {}",
                store_path.display(),
                err
            );
            return reply.error(err.raw_os_error().unwrap_or(ENOENT));
        }
        log::info!(
            "Copied {} {} from binary cache",
            node,
            path.as_bytes().as_bstr()
        );

        if self.try_open_node(node, &path) {
            return reply.opened(0, 0);
        }

        reply.error(ENOENT)
    }

    fn release_node(&mut self, node: usize, reply: fuser::ReplyEmpty) {
        if let Some(fd) = self.open_nodes.remove(&node) {
            log::info!("Closing FD {} of node {}", fd.as_raw_fd(), node);
            drop(fd);
            return reply.ok();
        }

        log::warn!("release({}) but no FD is associated", node);
        reply.ok()
    }

    fn read_node(&mut self, node: usize, offset: i64, size: usize, reply: fuser::ReplyData) {
        let fd = if let Some(fd) = self.open_nodes.get(&node) {
            fd.as_fd()
        } else {
            return reply.error(EPERM);
        };

        match read_file(fd, offset, size) {
            Ok(buf) => {
                log::info!(
                    "Read {}/{} bytes from FD {}",
                    buf.len(),
                    size,
                    fd.as_raw_fd()
                );
                reply.data(&buf)
            }
            Err(err) => reply.error(err.raw_os_error().unwrap_or(EINVAL)),
        }
    }
}

impl fuser::Filesystem for Fs {
    fn lookup(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        reply: fuser::ReplyEntry,
    ) {
        if let Some(&i) = self.lookup_index.get(&(parent, name.as_bytes().as_bstr())) {
            let attr = self.attr_node(i);
            return reply.entry(&TTL, &attr, 0);
        }

        reply.error(ENOENT)
    }

    fn getattr(&mut self, _req: &fuser::Request<'_>, ino: u64, reply: fuser::ReplyAttr) {
        if ino == FUSE_ROOT_ID {
            let attr = self.attr_root();
            return reply.attr(&TTL, &attr);
        }

        if self.is_node(ino) {
            let attr = self.attr_node(ino as usize);
            return reply.attr(&TTL, &attr);
        }

        reply.error(ENOENT)
    }

    fn readdir(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        reply: fuser::ReplyDirectory,
    ) {
        assert!(offset >= 0);
        let offset = offset.min(isize::MAX as i64) as usize;

        if ino == FUSE_ROOT_ID {
            return self.readdir_root(offset, reply);
        }

        if self.is_node(ino) {
            return self.readdir_node(ino as usize, offset, reply);
        }

        reply.error(ENOENT)
    }

    fn readlink(&mut self, _req: &fuser::Request<'_>, ino: u64, reply: fuser::ReplyData) {
        if self.is_node(ino) {
            if let Some(target) = self.get_node_link(ino as usize) {
                return reply.data(target);
            }
        }

        reply.error(ENOENT)
    }

    fn open(&mut self, _req: &fuser::Request<'_>, ino: u64, _flags: i32, reply: fuser::ReplyOpen) {
        if self.is_node(ino) {
            return self.open_node(ino as usize, reply);
        }

        reply.error(ENOENT)
    }

    fn release(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        _fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        if self.is_node(ino) {
            return self.release_node(ino as usize, reply);
        }

        reply.ok()
    }

    fn read(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: fuser::ReplyData,
    ) {
        assert!(offset >= 0);
        let size = size as usize;
        log::info!("read({}, {}, {})", ino, offset, size);

        if self.is_node(ino) {
            return self.read_node(ino as usize, offset, size, reply);
        }

        reply.error(EPERM)
    }
}

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let db = std::fs::read("/nix/store/7mlb139kmqxkdy5l880jr8p6jcagra10-index-x86_64-linux")?;
    if db.len() < 12 || &db[..12] != b"NIXI\x01\0\0\0\0\0\0\0" {
        bail!("unexpected database file format");
    }

    let db_raw = {
        let mut reader = &db[12..];
        let decompressed = zstd::decode_all(&mut reader)?;
        drop(db);
        decompressed
    };

    // Could make multi-threaded by finding b"p\0" (not a 2-byte prefix length diff because path cannot be that long)
    let mut cur = &db_raw[..];

    let mut nodes = vec![Node::Dummy, Node::Dummy];
    let mut packages = Vec::new();
    while !cur.is_empty() {
        packages.push(parse_package(&mut cur, &mut nodes).context("failed to parse database")?);
        #[cfg(debug_assertions)]
        if packages.len() > 100 {
            break;
        }
    }
    println!("{} packages parsed ({} nodes)", packages.len(), nodes.len());

    let fs = Fs::new(nodes, packages)?;
    let mountpoint = PathBuf::from("/run/user/1000/fs");

    fuser::mount2(
        fs,
        &mountpoint,
        &[
            MountOption::FSName("testfs".to_owned()),
            MountOption::DefaultPermissions,
        ],
    )?;
    Ok(())
}
