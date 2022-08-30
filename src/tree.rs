//! Abstract file system tree operations

use std::{
    collections::HashMap,
    ffi::OsStr,
    mem::size_of,
    num::NonZeroUsize,
    os::unix::prelude::{OsStrExt, OsStringExt},
    path::PathBuf,
};

struct Child {
    name: Box<[u8]>,
    data: u64,
}

const _: () = {
    assert!(size_of::<Child>() <= 24);
};

impl Child {
    const DIR: u64 = 1 << 63;
    const FILE: u64 = 1 << 62;
    const EXECUTABLE: u64 = 1 << 61;
    const SYMLINK: u64 = 1 << 60;
    const MASK: u64 = (1 << 56) - 1;

    fn new(name: Box<[u8]>, data: u64) -> Self {
        Self { name, data }
    }

    fn as_file(&self) -> Option<u64> {
        if self.data & Self::FILE != 0 {
            return Some(self.data & Child::MASK);
        }
        None
    }

    fn as_symlink(&self) -> Option<usize> {
        if self.data & Self::SYMLINK != 0 {
            return Some((self.data & Child::MASK) as usize);
        }
        None
    }

    fn as_dir(&self) -> Option<DirId> {
        if self.data & Self::DIR != 0 {
            let dir = DirId(NonZeroUsize::new((self.data & Self::MASK) as usize).unwrap());
            return Some(dir);
        }
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DirId(NonZeroUsize);

impl DirId {
    fn get(&self) -> usize {
        self.0.get()
    }
}

#[derive(Default)]
struct Directory {
    parent: Option<(DirId, usize)>,
    children: Vec<Child>,
    overlays: Vec<DirLink>,
    sorted: bool,
}

#[derive(Debug)]
struct DirLink {
    up: u32,
    down: u32,
    target: DirId,
}

#[derive(Debug)]
struct ChildLink {
    parent: DirLink,
    index: usize,
}

#[derive(Clone, Copy)]
pub struct ChildRef<'a> {
    tree: &'a Tree,
    child: &'a Child,
}

pub enum ChildMeta {
    Dir(u64),
    File(u64, bool),
    Symlink(u64),
}

impl<'a> ChildRef<'a> {
    fn new(tree: &'a Tree, child: &'a Child) -> Self {
        Self { tree, child }
    }

    fn from_child(tree: &'a Tree, parent: &'a Directory, index: usize) -> Self {
        Self::new(tree, &parent.children[index])
    }

    pub fn name(&self) -> &'a [u8] {
        &self.child.name
    }

    pub fn as_dir(&self) -> Option<DirId> {
        self.child.as_dir()
    }

    pub fn as_symlink(&self) -> Option<&'a [u8]> {
        let index = self.child.as_symlink()?;
        Some(&self.tree.symlinks[index])
    }

    pub fn metadata(&self) -> ChildMeta {
        if let Some(dir) = self.as_dir() {
            let dir = &self.tree.dirs[dir.get()];
            ChildMeta::Dir((dir.children.len() + dir.overlays.len()) as u64)
        } else if let Some(size) = self.child.as_file() {
            ChildMeta::File(size, self.child.data & Child::EXECUTABLE != 0)
        } else if let Some(target) = self.as_symlink() {
            ChildMeta::Symlink(target.len() as u64)
        } else {
            panic!("unexpected child type");
        }
    }
}

pub struct Tree {
    dirs: Vec<Directory>,
    symlinks: Vec<Box<[u8]>>,
    root: Child,
}

impl Tree {
    pub fn new() -> Self {
        Self {
            dirs: vec![Directory::default(), Directory::default()],
            symlinks: Vec::new(),
            root: Child::new(Default::default(), Child::DIR | 1),
        }
    }

    pub fn get_root(&self) -> (DirId, ChildRef<'_>) {
        let dir = DirId(NonZeroUsize::new(1).unwrap());
        (dir, ChildRef::new(self, &self.root))
    }

    pub fn get_child(&self, parent: DirId, index: usize) -> ChildRef<'_> {
        ChildRef::from_child(self, &self.dirs[parent.get()], index)
    }

    pub fn find_child(&self, parent: DirId, name: &[u8]) -> Option<(usize, ChildRef<'_>)> {
        let parent = &self.dirs[parent.get()];
        assert!(parent.sorted, "directory not sorted");
        let index = parent
            .children
            .binary_search_by(|c| c.name.as_ref().cmp(name))
            .ok()?;
        Some((index, ChildRef::from_child(self, parent, index)))
    }

    pub fn get_parent(&self, child: DirId) -> Option<(DirId, ChildRef<'_>)> {
        let (parent, index) = self.dirs[child.get()].parent?;
        Some((parent, self.get_child(parent, index as usize)))
    }

    fn link_to_path(&self, link: &DirLink, last: Option<usize>) -> Box<[u8]> {
        let mut path_parts = Vec::new();
        for _ in 0..link.up {
            path_parts.push(&b".."[..]);
        }
        let mut dir = link.target;
        if let Some(index) = last {
            path_parts.push(&self.dirs[dir.get()].children[index].name);
        }
        for _ in (0..link.down).rev() {
            let (parent, index) = self.dirs[dir.get()].parent.unwrap();
            path_parts.push(&self.dirs[parent.get()].children[index].name);
            dir = parent;
        }
        path_parts[link.up as usize..].reverse();
        let path = path_parts.iter().fold(PathBuf::new(), |buf, part| {
            buf.join(OsStr::from_bytes(part))
        });
        path.into_os_string().into_vec().into_boxed_slice()
    }

    fn realize_dir_link(&mut self, name: Box<[u8]>, link: &DirLink, children: &mut Vec<Child>) {
        let data = Child::SYMLINK | self.symlinks.len() as u64;
        let path = self.link_to_path(link, None);
        self.symlinks.push(path);
        children.push(Child::new(name, data));
    }

    fn realize_child_link(&mut self, name: Box<[u8]>, link: &ChildLink, children: &mut Vec<Child>) {
        let data = Child::SYMLINK | self.symlinks.len() as u64;
        let path = self.link_to_path(&link.parent, Some(link.index));
        self.symlinks.push(path);
        children.push(Child::new(name, data));
    }

    fn try_resolve_symlink(&self, parent: DirId, path: &[u8]) -> Option<(DirLink, Option<usize>)> {
        let (mut up, mut down) = (0, 0);
        let mut target = parent;
        let path = if let Some(path) = path.strip_prefix(b"/nix/store/") {
            while let Some((parent, _)) = self.get_parent(target) {
                target = parent;
                up += 1;
            }
            path
        } else {
            path
        };
        let mut iter = path.split(|&b| b == b'/');
        while let Some(name) = iter.next() {
            if name.is_empty() || name == b"." {
                continue;
            }
            if name == b".." {
                let (parent, _) = self.get_parent(target)?;
                target = parent;
                if down == 0 {
                    up += 1;
                } else {
                    down -= 1;
                }
                continue;
            }
            if !self.dirs[target.get()].sorted {
                log::warn!("resolve symlink failed due to unsorted children");
                return None;
            }
            let (index, child) = self.find_child(target, name)?;
            if let Some(dir) = child.as_dir() {
                target = dir;
                down += 1;
            } else if iter.next().is_some() {
                return None;
            } else {
                return Some((DirLink { up, down, target }, Some(index)));
            }
        }
        // Causes infinite loop
        if down == 0 {
            return None;
        }
        Some((DirLink { up, down, target }, None))
    }

    fn apply_overlays(&mut self, dir: DirId, overlays: Vec<DirLink>, children: &mut Vec<Child>) {
        let mut map = HashMap::<Box<[u8]>, (Vec<DirLink>, Vec<ChildLink>)>::new();
        for link in overlays {
            let target = &self.dirs[link.target.get()];
            assert!(target.overlays.is_empty(), "recursive overlay");
            for (index, child) in target.children.iter().enumerate() {
                let links = if let Some(some) = map.get_mut(&child.name) {
                    some
                } else {
                    map.entry(child.name.clone()).or_default()
                };
                // Try resolve directory symlinks so it can be merged with other dirs
                // Also size inspection of files
                if let Some(symlink_index) = child.as_symlink() {
                    let target = self.symlinks[symlink_index].as_ref();
                    if let Some((link, last)) = self.try_resolve_symlink(link.target, target) {
                        if let Some(index) = last {
                            links.1.push(ChildLink {
                                parent: link,
                                index,
                            });
                        } else {
                            links.0.push(link);
                        }
                        continue;
                    }
                }
                if let Some(child) = child.as_dir() {
                    links.0.push(DirLink {
                        up: link.up,
                        down: link.down + 1,
                        target: child,
                    });
                } else {
                    links.1.push(ChildLink {
                        parent: DirLink {
                            up: link.up,
                            down: link.down,
                            target: link.target,
                        },
                        index,
                    });
                }
            }
        }
        for (name, (mut dir_links, child_links)) in map {
            if !dir_links.is_empty() {
                if dir_links.len() == 1 {
                    self.realize_dir_link(name, &dir_links[0], children);
                    continue;
                }
                for link in &mut dir_links {
                    link.up += 1;
                }
                // recursively create a new dir with overlays
                let data = Child::DIR | self.dirs.len() as u64;
                self.dirs.push(Directory {
                    parent: Some((dir, 0)), // index will be filled after sorted
                    children: Vec::new(),
                    overlays: dir_links,
                    sorted: true,
                });
                children.push(Child::new(name, data));
                continue;
            }

            // Non-directories cannot be merged so some choice has to be made.
            // As a heuristic, use the biggest file.
            let link = child_links
                .iter()
                .max_by_key(|link| {
                    self.dirs[link.parent.target.get()].children[link.index].as_file()
                })
                .unwrap();
            self.realize_child_link(name, link, children);
        }
    }

    pub fn ensure_sorted(&mut self, dir: DirId) -> usize {
        let parent = &mut self.dirs[dir.get()];
        if parent.sorted {
            return parent.children.len();
        }

        let mut children = std::mem::take(&mut parent.children);
        children.sort_by(|a, b| a.name.cmp(&b.name));
        children.dedup_by(|a, b| a.name == b.name);

        for (index, child) in children.iter().enumerate() {
            if let Some(child) = child.as_dir() {
                self.dirs[child.get()].parent = Some((dir, index));
            }
        }
        let parent = &mut self.dirs[dir.get()];
        parent.children = children;
        parent.sorted = true;
        parent.children.len()
    }

    // Lazy operation support
    pub fn prepare(&mut self, dir: DirId) -> usize {
        let overlays = std::mem::take(&mut self.dirs[dir.get()].overlays);
        if !overlays.is_empty() {
            let mut children = Vec::new();
            self.apply_overlays(dir, overlays, &mut children);
            let dir = &mut self.dirs[dir.get()];
            dir.children.extend(children);
            dir.sorted = false;
        }
        self.ensure_sorted(dir)
    }

    // Tree building operations
    fn add_child(&mut self, parent: DirId, name: &[u8], data: u64) -> usize {
        let parent = &mut self.dirs[parent.get()];
        let index = parent.children.len();
        parent.sorted = false;
        parent.children.push(Child::new(name.into(), data));
        index
    }

    pub fn add_dir(&mut self, parent: DirId, name: &[u8], capacity: usize) -> DirId {
        let dir = self.dirs.len();
        let data = Child::DIR | dir as u64;
        let index = self.add_child(parent, name, data);
        self.dirs.push(Directory {
            parent: Some((parent, index)),
            children: Vec::with_capacity(capacity),
            overlays: Vec::new(),
            sorted: true,
        });
        DirId(NonZeroUsize::new(dir).unwrap())
    }

    pub fn add_file(&mut self, parent: DirId, name: &[u8], size: u64, executable: bool) -> usize {
        assert!(size <= Child::MASK);
        let data = Child::FILE | if executable { Child::EXECUTABLE } else { 0 } | size;
        self.add_child(parent, name, data)
    }

    pub fn add_symlink(&mut self, parent: DirId, name: &[u8], target: &[u8]) -> usize {
        let data = Child::SYMLINK | self.symlinks.len() as u64;
        self.symlinks.push(target.into());
        self.add_child(parent, name, data)
    }

    /// target and symlink targets should be sorted before.
    pub fn add_overlay(&mut self, parent: DirId, up: u32, down: u32, target: DirId) {
        let link = DirLink { up, down, target };
        self.dirs[parent.get()].overlays.push(link);
    }
}

pub fn print_stats(tree: &Tree) {
    const MB: usize = 1_000_000;

    let Tree {
        dirs,
        symlinks,
        root: _,
    } = tree;

    println!("dirs: {} ({}MB)", dirs.len(), get_mem(dirs) / MB);

    let mut nodes = 0;
    let mut children_mem = 0;
    let mut names = 0;
    for dir in dirs {
        nodes += dir.children.len();
        children_mem += get_mem(&dir.children);
        for child in &dir.children {
            names += child.name.len();
        }
    }

    println!(
        "nodes: {}, (children: {}MB, names: {}MB)",
        nodes,
        children_mem / MB,
        names / MB
    );

    let mut symlink_mem = get_mem(symlinks);
    for target in symlinks {
        symlink_mem += target.len();
    }
    println!("symlinks: {} ({:.0}MB)", symlinks.len(), symlink_mem / MB);

    fn get_mem<T>(vec: &Vec<T>) -> usize {
        vec.capacity() * size_of::<T>()
    }
}
