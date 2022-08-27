use std::{
    collections::{btree_map, BTreeMap, HashMap},
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

#[derive(Debug, Clone, Copy)]
enum Node {
    EmptySpace,
    RegularFile {
        size: u64,
        executable: bool,
    },
    Directory {
        /// Sorted by name
        children: &'static [(LeakStr, usize)],
    },
    Symlink {
        target: LeakStr,
    },
}

impl Node {
    pub fn directory(mut children: Vec<(LeakStr, usize)>) -> Self {
        children.sort_by(|x, y| x.0.cmp(y.0));
        Node::Directory {
            children: children.leak(),
        }
    }
}

#[derive(Debug)]
struct DirectoryBuilder {
    name: LeakStr,
    children: Vec<(LeakStr, usize)>,
}

impl DirectoryBuilder {
    fn new(name: LeakStr) -> Self {
        Self {
            name,
            children: Vec::new(),
        }
    }

    fn finish(self) -> (&'static BStr, Node) {
        (self.name, Node::directory(self.children))
    }
}

fn alloc_node(nodes: &mut Vec<Node>, node: Node) -> usize {
    let i = nodes.len();
    nodes.push(node);
    i
}

fn parse_package(cur: &mut &[u8], nodes: &mut Vec<Node>) -> anyhow::Result<(Package, usize)> {
    let mut last_suffix = &b""[..];
    let mut dir_stack: Vec<DirectoryBuilder> = vec![];
    let mut top_dir = DirectoryBuilder::new(b"".as_bstr());
    let mut last_node: Node = Node::EmptySpace;
    let mut last_name: BString = BString::default();

    loop {
        let (meta, prefix_delta, suffix) = parse_entry(&mut *cur)?;

        if let Some(rest) = suffix.strip_prefix(b"/") {
            let new_top_dir = match last_node {
                Node::Directory { .. } => {
                    let last_name = <Vec<u8>>::from(last_name.clone()).leak().as_bstr();
                    DirectoryBuilder::new(last_name)
                }
                _ => bail!("directory expected"),
            };
            dir_stack.push(top_dir);
            top_dir = new_top_dir;
            last_name = BString::from(rest);
        } else if !matches!(last_node, Node::EmptySpace) {
            let mut last_len = last_name.len();
            {
                let index = alloc_node(&mut *nodes, last_node);
                let last_name = <Vec<u8>>::from(last_name.clone()).leak().as_bstr();
                top_dir.children.push((last_name, index));
            }

            let mut remove_len = usize::try_from(last_suffix.len() as i32 - prefix_delta)?;
            while remove_len > last_len {
                remove_len -= 1 + last_len;

                last_len = top_dir.name.len();

                let mut new_top_dir = dir_stack.pop().context("malformed file tree")?;
                let (name, node) = top_dir.finish();
                let index = alloc_node(&mut *nodes, node);
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
            EntryMeta::Directory { size: _size } => Node::Directory { children: &[] },
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

fn follow_path(mut node: usize, path: &[&[u8]], nodes: &[Node]) -> Option<usize> {
    for &part in path {
        if let Node::Directory { children, .. } = &nodes[node] {
            node = children.iter().find(|x| x.0 == part)?.1;
        } else {
            return None;
        }
    }
    Some(node)
}

fn make_env(roots: &[(LeakStr, usize)], path: &[&[u8]], nodes: &mut Vec<Node>) -> usize {
    let mut links = BTreeMap::new();
    for &(name, root) in roots {
        let mut common_prefix = PathBuf::from("..");
        common_prefix.push(OsStr::from_bytes(name));
        for part in path {
            common_prefix.push(OsStr::from_bytes(part));
        }
        if let Some(node) = follow_path(root, path, nodes) {
            if let Node::Directory { children, .. } = &nodes[node] {
                for &(name, _) in children.iter() {
                    if let btree_map::Entry::Vacant(entry) = links.entry(name) {
                        let target = common_prefix.join(OsStr::from_bytes(name));
                        let target = target.into_os_string().into_vec().leak().as_bstr();
                        entry.insert(alloc_node(&mut *nodes, Node::Symlink { target }));
                    }
                }
            }
        }
    }
    let children = links.into_iter().collect::<Vec<_>>();
    alloc_node(
        &mut *nodes,
        Node::Directory {
            children: children.leak(),
        },
    )
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
    parent_node_lazy: Vec<(LeakStr, usize)>,

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
    pub fn new(nodes: Vec<Node>) -> anyhow::Result<Self> {
        let mut parent_node_lazy = vec![(b"".as_bstr(), 0); nodes.len()];
        parent_node_lazy[ROOT_ID].1 = ROOT_ID;

        Ok(Self {
            nodes,
            parent_node_lazy, // lazily filled at parent's lookup

            local_store: open_dir(PathBuf::from("/nix/store"))?,
            open_nodes: HashMap::new(),
        })
    }

    fn lookup_child_only(&self, node: usize, name: &[u8]) -> Option<(LeakStr, usize)> {
        match self.nodes[node] {
            Node::Directory { children } => {
                let pos = children
                    .binary_search_by_key(&name, |(name, _)| *name)
                    .ok()?;
                Some(children[pos])
            }
            _ => None,
        }
    }

    fn set_parent(&mut self, node: usize, name: LeakStr, parent: usize) {
        self.parent_node_lazy[node] = (name, parent);
    }

    fn is_node(&self, ino: u64) -> bool {
        ino < self.nodes.len() as u64 && !matches!(self.nodes[ino as usize], Node::EmptySpace)
    }

    fn file_type_node(&self, i: usize) -> FileType {
        match self.nodes[i] {
            Node::RegularFile { .. } => FileType::RegularFile,
            Node::Directory { .. } => FileType::Directory,
            Node::Symlink { .. } => FileType::Symlink,
            Node::EmptySpace => {
                warn!("file type dummy node {}", i);
                FileType::RegularFile
            }
        }
    }

    fn attr_node(&self, node: usize) -> FileAttr {
        match self.nodes[node] {
            Node::RegularFile { size, executable } => {
                let perm = if executable {
                    EXEC_FILE_PERM
                } else {
                    FILE_PERM
                };
                create_attr(node as u64, size, FileType::RegularFile, perm)
            }
            Node::Directory { children } => create_attr(
                node as u64,
                children.len() as u64,
                FileType::Directory,
                DIR_PERM,
            ),
            Node::Symlink { target } => create_attr(
                node as u64,
                target.len() as u64,
                FileType::Symlink,
                SYMLINK_PERM,
            ),
            Node::EmptySpace => unreachable!(),
        }
    }

    fn lookup_attr_node(&mut self, parent: usize, name: &[u8]) -> Option<FileAttr> {
        let (name, child) = self.lookup_child_only(parent, name)?;
        self.set_parent(child, name, parent);

        Some(self.attr_node(child))
    }

    fn read_dir_node(&mut self, node: usize, offset: usize, mut reply: fuser::ReplyDirectory) {
        let children = if let Node::Directory { children, .. } = self.nodes[node] {
            children
        } else {
            return reply.error(ENOENT);
        };

        if offset == 0 && reply.add(node as u64, 1, FileType::Directory, ".") {
            return reply.ok();
        }

        let mut parent = self.parent_node_lazy[node].1;
        if parent == 0 {
            log::warn!("parent node not set for {}", node);
            parent = ROOT_ID;
        }
        if offset <= 1 && reply.add(parent as u64, 2, FileType::Directory, "..") {
            return reply.ok();
        }

        for (i, &(name, child)) in children.iter().enumerate().skip(offset.saturating_sub(2)) {
            self.set_parent(child, name, node);

            let next_offset = 2 + i as i64 + 1;
            let kind = self.file_type_node(child);
            if reply.add(child as u64, next_offset, kind, OsStr::from_bytes(name)) {
                return reply.ok();
            }
        }

        reply.ok()
    }

    fn read_link_node(&self, node: usize) -> Option<&BStr> {
        if let Node::Symlink { target } = self.nodes[node] {
            Some(target.as_bstr())
        } else {
            None
        }
    }

    fn get_path(&self, mut node: usize) -> Option<PathBuf> {
        let mut parts = Vec::new();
        loop {
            let (part, parent) = self.parent_node_lazy[node];
            if parent == 0 || parent == node {
                return None;
            }
            parts.push(part);
            if parent == ROOT_ID {
                let mut buf = PathBuf::new();
                for &part in parts.iter().rev() {
                    buf.push(OsStr::from_bytes(part));
                }
                return Some(buf);
            }
            node = parent;
        }
    }

    fn try_open_node(&mut self, node: usize, path: &CString) -> Result<(), i32> {
        if let Ok(fd) = open_at(self.local_store.as_fd(), path.as_ref()) {
            log::info!(
                "Opened {} {} as FD {}",
                node,
                path.as_bytes().as_bstr(),
                fd.as_raw_fd()
            );
            self.open_nodes.insert(node, fd);
            Ok(())
        } else {
            Err(EINVAL)
        }
    }

    fn open_node(&mut self, node: usize) -> Result<(), i32> {
        if let Some(fd) = self.open_nodes.get(&node) {
            log::info!("Node {} is already opened as FD {}", node, fd.as_raw_fd());
            return Ok(());
        }

        let path = self.get_path(node).ok_or(ENOENT)?;
        let path = CString::new(path.into_os_string().into_vec()).map_err(|_| EINVAL)?;

        if let Ok(ok) = self.try_open_node(node, &path) {
            return Ok(ok);
        }

        let mut store_path = PathBuf::from("/nix/store");
        store_path.push(OsStr::from_bytes(path.as_bytes()));

        if let Err(err) = run_nix_copy(&store_path) {
            log::error!(
                "Failed to copy {} from binary cache: {}",
                store_path.display(),
                err
            );
            return Err(err.raw_os_error().unwrap_or(ENOENT));
        }
        log::info!(
            "Copied {} {} from binary cache",
            node,
            path.as_bytes().as_bstr()
        );

        self.try_open_node(node, &path)
    }

    fn release_node(&mut self, node: usize) {
        if let Some(fd) = self.open_nodes.remove(&node) {
            log::info!("Closing FD {} of node {}", fd.as_raw_fd(), node);
            drop(fd);
            return;
        }

        log::warn!("release({}) but no FD is associated", node);
    }

    fn read_node(&mut self, node: usize, offset: i64, size: usize) -> Result<Vec<u8>, i32> {
        let fd = if let Some(fd) = self.open_nodes.get(&node) {
            fd.as_fd()
        } else {
            return Err(EPERM);
        };

        let buf = read_file(fd, offset, size).map_err(|e| e.raw_os_error().unwrap_or(EINVAL))?;

        log::info!(
            "Read {}/{} bytes from FD {}",
            buf.len(),
            size,
            fd.as_raw_fd()
        );
        Ok(buf)
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
        let name = name.as_bytes().as_bstr();

        if self.is_node(parent) {
            if let Some(attr) = self.lookup_attr_node(parent as usize, name) {
                return reply.entry(&TTL, &attr, 0);
            }
        }

        reply.error(ENOENT)
    }

    fn getattr(&mut self, _req: &fuser::Request<'_>, ino: u64, reply: fuser::ReplyAttr) {
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

        if self.is_node(ino) {
            return self.read_dir_node(ino as usize, offset, reply);
        }

        reply.error(ENOENT)
    }

    fn readlink(&mut self, _req: &fuser::Request<'_>, ino: u64, reply: fuser::ReplyData) {
        if self.is_node(ino) {
            if let Some(target) = self.read_link_node(ino as usize) {
                return reply.data(target);
            }
        }

        reply.error(ENOENT)
    }

    fn open(&mut self, _req: &fuser::Request<'_>, ino: u64, _flags: i32, reply: fuser::ReplyOpen) {
        if self.is_node(ino) {
            match self.open_node(ino as usize) {
                Ok(()) => return reply.opened(0, 0),
                Err(e) => return reply.error(e),
            }
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
            self.release_node(ino as usize);
            return reply.ok();
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
            match self.read_node(ino as usize, offset, size) {
                Ok(buf) => return reply.data(&buf),
                Err(e) => return reply.error(e),
            };
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

    let mut nodes = vec![Node::EmptySpace, Node::EmptySpace];
    let mut root_children = Vec::new();

    while !cur.is_empty() {
        let (package, node) =
            parse_package(&mut cur, &mut nodes).context("failed to parse database")?;

        let name = format!("{}-{}", package.hash, package.name)
            .into_bytes()
            .leak()
            .as_bstr();
        root_children.push((name, node));

        #[cfg(debug_assertions)]
        if root_children.len() > 100 {
            break;
        }
    }

    println!(
        "{} packages parsed ({} nodes)",
        root_children.len(),
        nodes.len()
    );

    let bin_env = make_env(&root_children, &[b"bin"], &mut nodes);
    let lib_env = make_env(&root_children, &[b"lib"], &mut nodes);
    root_children.push((b"bin".as_bstr(), bin_env));
    root_children.push((b"lib".as_bstr(), lib_env));

    nodes[ROOT_ID] = Node::directory(root_children);

    let fs = Fs::new(nodes)?;
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
