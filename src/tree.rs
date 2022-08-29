//! Abstract file system tree operations

use std::{mem::size_of, num::NonZeroUsize};

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

    fn new(name: &[u8], data: u64) -> Self {
        let name = name.into();
        Self { name, data }
    }

    fn as_dir(&self) -> Option<DirId> {
        if self.data & Child::DIR != 0 {
            let dir = DirId(NonZeroUsize::new((self.data & Self::MASK) as usize).unwrap());
            return Some(dir);
        }
        None
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
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
}

#[derive(Clone, Copy)]
pub struct ChildRef<'a> {
    tree: &'a Tree,
    child: &'a Child,
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

    pub fn as_dir(&self) -> Option<(DirId, usize)> {
        let dir = self.child.as_dir()?;
        Some((dir, self.tree.get_num_children(dir)))
    }

    pub fn as_file(&self) -> Option<(u64, bool)> {
        let data = self.child.data;
        if data & Child::FILE != 0 {
            return Some((data & Child::MASK, data & Child::EXECUTABLE != 0));
        }
        None
    }

    pub fn as_symlink(&self) -> Option<&'a [u8]> {
        if self.child.data & Child::SYMLINK != 0 {
            let index = (self.child.data & Child::MASK) as usize;
            return Some(&self.tree.symlinks[index]);
        }
        None
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
            root: Child::new(b"", Child::DIR | 1),
        }
    }

    pub fn get_root(&self) -> (DirId, ChildRef<'_>) {
        let dir = DirId(NonZeroUsize::new(1).unwrap());
        (dir, ChildRef::new(self, &self.root))
    }

    pub fn get_num_children(&self, dir: DirId) -> usize {
        self.dirs[dir.get()].children.len()
    }

    pub fn get_child(&self, parent: DirId, index: usize) -> ChildRef<'_> {
        ChildRef::from_child(self, &self.dirs[parent.get()], index)
    }

    pub fn find_child(&self, parent: DirId, name: &[u8]) -> Option<(usize, ChildRef<'_>)> {
        let parent = &self.dirs[parent.get()];
        let index = parent
            .children
            .binary_search_by(|c| c.name.as_ref().cmp(name))
            .ok()?;
        Some((index, ChildRef::from_child(self, parent, index)))
    }

    pub fn get_parent(&self, child: DirId) -> Option<(DirId, usize, ChildRef<'_>)> {
        let (parent, index) = self.dirs[child.get()].parent?;
        let index = index as usize;
        Some((parent, index, self.get_child(parent, index)))
    }

    // Lazy operation support
    pub fn prepare(&mut self, parent: DirId) {
        let mut children = std::mem::take(&mut self.dirs[parent.get()].children);
        children.sort_by(|a, b| a.name.cmp(&b.name));
        for (index, child) in children.iter().enumerate() {
            if let Some(child) = child.as_dir() {
                self.dirs[child.get()].parent = Some((parent, index));
            }
        }
        self.dirs[parent.get()].children = children;
    }

    // Tree building operations
    fn add_child(&mut self, parent: DirId, name: &[u8], data: u64) -> usize {
        let parent = &mut self.dirs[parent.get()];
        let index = parent.children.len();
        parent.children.push(Child::new(name, data));
        index
    }

    pub fn add_dir(&mut self, parent: DirId, name: &[u8], capacity: usize) -> (usize, DirId) {
        let dir = self.dirs.len();
        let data = Child::DIR | dir as u64;
        let index = self.add_child(parent, name, data);

        self.dirs.push(Directory {
            parent: Some((parent, index)),
            children: Vec::with_capacity(capacity),
        });
        (index, DirId(NonZeroUsize::new(dir).unwrap()))
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
