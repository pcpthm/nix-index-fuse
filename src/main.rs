use anyhow::bail;
use clap::Parser;
use nixindexfs::{
    db::{self, EntryMeta, TreeDecoder},
    tree::{ChildMeta, ChildRef, DirId, Tree},
};
mod libc_utils;

use std::{
    collections::HashMap,
    ffi::OsStr,
    io::ErrorKind,
    os::unix::prelude::{AsFd, OsStrExt, OwnedFd},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant, UNIX_EPOCH},
};

use fuser::{
    FileAttr, FileType, MountOption, ReplyAttr, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry,
    ReplyOpen, Request, FUSE_ROOT_ID,
};
use libc::ENOENT;

use libc_utils::{open_at, open_dir, read_file, umount_ignore_errors};

fn run_nix_copy(store_path: &Path) -> std::io::Result<()> {
    log::info!("Running nix copy command for {}", store_path.display());

    let status = Command::new("nix")
        .args(["--extra-experimental-features", "nix-command"])
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

fn file_attr(inode: u64, size: u64, kind: FileType, perm: u16) -> FileAttr {
    let block_size: u32 = 512;
    let blocks = if size == 0 {
        0
    } else {
        (size - 1) / u64::from(block_size) + 1
    };
    FileAttr {
        ino: inode,
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
        blksize: block_size,
        flags: 0,
    }
}

fn child_attr(child: ChildRef, inode: u64) -> FileAttr {
    let (size, kind, perm) = match child.metadata() {
        ChildMeta::Dir(size) => (size, FileType::Directory, 0o555),
        ChildMeta::File(size, executable) => {
            let perm = if executable { 0o555 } else { 0o444 };
            (size, FileType::RegularFile, perm)
        }
        ChildMeta::Symlink(size) => (size, FileType::Symlink, 0o444),
    };
    file_attr(inode, size, kind, perm)
}

const TTL: Duration = Duration::from_secs(1);

struct Fs {
    tree: Tree,

    /// Sorted list of (inode start, parent dir)
    inode_ranges: Vec<(u64, DirId)>,

    inode_end: u64,

    prepared_dirs: HashMap<u64, (DirId, u64, usize)>,
    prepared_dir_inode: HashMap<DirId, u64>,

    /// Open files in the local store.
    open_files: HashMap<u64, OwnedFd>,

    /// Handle of the /nix/store directory (in the outer FS)
    local_store: OwnedFd,
}

impl Fs {
    pub fn new(tree: Tree, local_store: OwnedFd) -> Self {
        Self {
            tree,
            inode_ranges: Vec::new(),
            inode_end: FUSE_ROOT_ID + 1,
            prepared_dir_inode: HashMap::new(),
            prepared_dirs: HashMap::new(),
            open_files: HashMap::new(),
            local_store,
        }
    }

    fn get_tree_node(&self, ino: u64) -> Option<(DirId, ChildRef)> {
        if ino == FUSE_ROOT_ID {
            let (root_dir, root_child) = self.tree.get_root();
            return Some((root_dir, root_child));
        }
        if FUSE_ROOT_ID < ino && ino < self.inode_end {
            let i = self.inode_ranges.partition_point(|x| x.0 <= ino);
            let (range_start, parent) = self.inode_ranges[i - 1];
            let child = self.tree.get_child(parent, (ino - range_start) as usize);
            return Some((parent, child));
        }
        None
    }

    pub fn prepare_as_dir(&mut self, inode: u64) -> Option<(DirId, u64, usize)> {
        if let Some(&(dir, start, len)) = self.prepared_dirs.get(&inode) {
            return Some((dir, start, len));
        }
        let (_, child) = self.get_tree_node(inode)?;
        let dir = child.as_dir()?;
        let len = self.tree.prepare(dir);

        let start = self.inode_end;
        self.inode_ranges.push((start, dir));
        self.inode_end = start + len as u64;

        self.prepared_dirs.insert(inode, (dir, start, len));
        self.prepared_dir_inode.insert(dir, inode);

        Some((dir, start, len))
    }

    fn get_dot_dot(&self, dir: DirId) -> u64 {
        if let Some((parent, _)) = self.tree.get_parent(dir) {
            *self.prepared_dir_inode.get(&parent).unwrap()
        } else {
            FUSE_ROOT_ID
        }
    }

    fn get_path(&self, parent: DirId, child: ChildRef) -> PathBuf {
        let mut path_parts = vec![child.name()];
        let mut dir = parent;
        while let Some((parent, child_ref)) = self.tree.get_parent(dir) {
            path_parts.push(child_ref.name());
            dir = parent;
        }
        let mut path = PathBuf::from("/nix/store/");
        for &part in path_parts.iter().rev() {
            path.push(OsStr::from_bytes(part));
        }
        path
    }

    fn open_file(&mut self, abs_path: &Path) -> std::io::Result<OwnedFd> {
        if let Ok(rel_path) = abs_path.strip_prefix("/nix/store") {
            log::debug!("try open {}", rel_path.display());
            if let Ok(fd) = open_at(self.local_store.as_fd(), rel_path) {
                return Ok(fd);
            }
            run_nix_copy(abs_path)?;
            return open_at(self.local_store.as_fd(), rel_path);
        }
        log::warn!("Tried to open file outside /nix/store",);
        Err(std::io::Error::new(ErrorKind::Other, ""))
    }
}

impl fuser::Filesystem for Fs {
    fn lookup(&mut self, _: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if let Some((parent, start, _)) = self.prepare_as_dir(parent) {
            if let Some((index, child)) = self.tree.find_child(parent, name.as_bytes()) {
                let inode = start + index as u64;
                let attr = child_attr(child, inode);
                return reply.entry(&TTL, &attr, 0);
            }
        }
        reply.error(ENOENT)
    }

    fn getattr(&mut self, _: &Request, ino: u64, reply: ReplyAttr) {
        if let Some((_, child)) = self.get_tree_node(ino) {
            let attr = child_attr(child, ino);
            return reply.attr(&TTL, &attr);
        }
        reply.error(ENOENT)
    }

    fn readdir(&mut self, _: &Request, ino: u64, _fh: u64, offset: i64, mut reply: ReplyDirectory) {
        assert!(offset >= 0);
        if let Some((dir, start, len)) = self.prepare_as_dir(ino) {
            let mut offset = offset;
            if offset == 0 {
                offset += 1;
                if reply.add(ino, offset, FileType::Directory, ".") {
                    return reply.ok();
                }
            }
            if offset == 1 {
                offset += 1;
                if reply.add(self.get_dot_dot(dir), offset, FileType::Directory, "..") {
                    return reply.ok();
                }
            }
            for index in offset.saturating_sub(2).min(len as i64) as usize..len {
                offset += 1;
                let inode = start + index as u64;
                let child = self.tree.get_child(dir, index);
                let kind = child_attr(child, inode).kind;
                let name = OsStr::from_bytes(child.name());
                if reply.add(inode, offset, kind, name) {
                    return reply.ok();
                }
            }
            return reply.ok();
        }
        reply.error(ENOENT)
    }

    fn readlink(&mut self, _: &Request, ino: u64, reply: ReplyData) {
        if let Some((_, child)) = self.get_tree_node(ino) {
            if let Some(target) = child.as_symlink() {
                return reply.data(target);
            }
        }
        reply.error(ENOENT)
    }

    fn open(&mut self, _: &Request, ino: u64, _flags: i32, reply: ReplyOpen) {
        if self.open_files.contains_key(&ino) {
            return reply.opened(0, 0);
        }
        if let Some((parent, child)) = self.get_tree_node(ino) {
            let path = self.get_path(parent, child);
            match self.open_file(&path) {
                Ok(fd) => {
                    assert!(self.open_files.insert(ino, fd).is_none());
                    return reply.opened(0, 0);
                }
                Err(err) => return reply.error(err.raw_os_error().unwrap_or(ENOENT)),
            }
        }
        reply.error(ENOENT)
    }

    fn release(
        &mut self,
        _: &Request,
        ino: u64,
        _fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        if let Some(fd) = self.open_files.remove(&ino) {
            drop(fd);
            return reply.ok();
        }
        reply.ok()
    }

    fn read(
        &mut self,
        _: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        assert!(offset >= 0);
        if let Some(fd) = self.open_files.get(&ino) {
            match read_file(fd.as_fd(), offset, size as usize) {
                Ok(buf) => return reply.data(&buf),
                Err(err) => return reply.error(err.raw_os_error().unwrap_or(ENOENT)),
            }
        }
        reply.error(ENOENT)
    }

    fn destroy(&mut self) {
        nixindexfs::tree::print_stats(&self.tree);
    }
}

fn add_package_tree(
    tree: &mut Tree,
    root_name: &[u8],
    stack: &mut Vec<DirId>,
    mut cur: TreeDecoder,
) -> anyhow::Result<()> {
    while let Some(meta) = cur.next_entry()? {
        while cur.depth() + 1 < stack.len() {
            stack.pop();
        }
        let parent = *stack.last().unwrap();
        let name = if cur.path().is_empty() {
            root_name
        } else {
            cur.file_name()
        };
        match meta {
            EntryMeta::RegularFile { size, executable } => {
                tree.add_file(parent, name, size, executable);
            }
            EntryMeta::Dir { child_count } => {
                let dir = tree.add_dir(parent, name, child_count);
                stack.push(dir);
            }
            EntryMeta::Symlink { target } => {
                tree.add_symlink(parent, name, target);
            }
        }
    }

    Ok(())
}

fn prepare_mount_point(path: &Path) -> anyhow::Result<()> {
    umount_ignore_errors(path)?;
    if let Err(e) = std::fs::create_dir(path) {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            bail!("Cannot create mount point {}: {}", path.display(), e);
        }
    } else {
        log::info!("Created mount point {}", path.display());
    }
    Ok(())
}

#[derive(Parser)]
#[clap(version)]
struct Args {
    #[clap(
        long = "db",
        env = "NIX_INDEX_DB",
        help = "Location of nix-index database file."
    )]
    db_path: PathBuf,

    #[clap(help = "Mountpoint to use.")]
    mount_point: PathBuf,

    #[clap(
        long = "limit",
        help = "Limit number of packages to load. Used for debugging."
    )]
    limit_num_packages: Option<usize>,

    #[clap(
        long = "merge-all",
        help = "Merge all packages.",
        default_value_t = true
    )]
    merge_all: bool,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let args = Args::parse();

    prepare_mount_point(&args.mount_point)?;

    let mut tree = Tree::new();
    {
        println!("Loading database {}...", args.db_path.display());

        let instant = Instant::now();
        let (root, _) = tree.get_root();

        let mut num_packages = 0;
        {
            let mut decoder = db::Decoder::new(&args.db_path)?;
            let mut decoder_buf = db::DecoderBuf::new();
            let mut stack = Vec::new();
            while let Some((decoder, package_meta)) = decoder.next_package(&mut decoder_buf)? {
                let root_name = package_meta.hash_name();

                stack.clear();
                stack.push(root);

                add_package_tree(&mut tree, root_name.as_bytes(), &mut stack, decoder)?;

                num_packages += 1;

                if let Some(limit) = args.limit_num_packages {
                    if num_packages >= limit {
                        break;
                    }
                }
            }
        }

        log::info!(
            "Loaded {} packages in {}ms",
            num_packages,
            instant.elapsed().as_millis()
        );

        let instant = Instant::now();
        {
            let mut stack = vec![root];
            while let Some(parent) = stack.pop() {
                let len = tree.ensure_sorted(parent);
                for index in 0..len {
                    if let Some(dir) = tree.get_child(parent, index).as_dir() {
                        stack.push(dir);
                    }
                }
            }
        }
        log::info!("Sorted nodes in {}ms", instant.elapsed().as_millis());

        if args.merge_all {
            for index in 0..num_packages {
                if let Some(dir) = tree.get_child(root, index).as_dir() {
                    tree.add_overlay(root, 0, 1, dir);
                }
            }
        }

        nixindexfs::tree::print_stats(&tree);
    }

    let local_store = open_dir("/nix/store".as_ref())?;

    let mut fs = Fs::new(tree, local_store);
    fs.prepare_as_dir(FUSE_ROOT_ID);

    println!("Mounting to {}...", args.mount_point.display());
    fuser::mount2(
        fs,
        &args.mount_point,
        &[
            MountOption::FSName("nixindexfs".to_owned()),
            MountOption::DefaultPermissions,
        ],
    )?;
    Ok(())
}
