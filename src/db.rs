//! nix-index DB format parser

use std::{
    fs::File,
    io::{BufReader, Read},
    path::Path,
};

use anyhow::{bail, Context};
use memchr::{memchr, memmem};
use serde::Deserialize;

pub struct DecoderBuf {
    buf: Vec<u8>,
    start: usize,
    end: usize,
}

impl DecoderBuf {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            start: 0,
            end: 0,
        }
    }

    fn make_space(&mut self, min_len: usize) -> &mut [u8] {
        if self.buf.len() - self.end < min_len {
            if self.len() * 2 + min_len <= self.buf.len() {
                self.buf.copy_within(self.start..self.end, 0);
                self.end -= self.start;
                self.start = 0;
            } else {
                self.buf.resize(self.end + min_len, 0);
            }
        }
        &mut self.buf[self.end..]
    }

    pub fn read_from<R: Read>(&mut self, reader: &mut R, buf_len: usize) -> std::io::Result<usize> {
        let buf = self.make_space(buf_len);
        let read_len = reader.read(buf)?;
        assert!(read_len <= buf.len());
        self.end += read_len;
        Ok(read_len)
    }

    pub fn consume(&mut self, len: usize) -> &mut [u8] {
        assert!(len <= self.len());
        let res = &mut self.buf[self.start..][..len];
        self.start += len;
        res
    }
}

impl std::ops::Deref for DecoderBuf {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.buf[self.start..self.end]
    }
}

fn parse_prefix_delta(buf: &[u8]) -> Option<(i32, usize)> {
    let first = *buf.first()?;
    if first != 0x80 {
        Some((i32::from(first as i8), 1))
    } else if buf.len() < 3 {
        None
    } else {
        let bytes = [buf[1], buf[2]];
        Some((i32::from(i16::from_be_bytes(bytes)), 3))
    }
}
pub struct Decoder {
    reader: zstd::Decoder<'static, BufReader<File>>,
    read_buf_len: usize,
}

impl Decoder {
    pub fn new(path: &Path) -> anyhow::Result<Self> {
        let mut file = File::open(path).context("failed to open DB file")?;
        let mut signature = [0u8; 12];
        file.read_exact(&mut signature)?;
        if &signature[..] != b"NIXI\x01\0\0\0\0\0\0\0" {
            bail!("signature expected");
        }

        let reader = zstd::Decoder::new(file)?;
        Ok(Self {
            reader,
            read_buf_len: zstd::Decoder::<BufReader<File>>::recommended_output_size(),
        })
    }

    fn next_package_inner(
        &mut self,
        buf: &mut DecoderBuf,
    ) -> anyhow::Result<Option<(usize, usize)>> {
        let mut search_start = 0;
        loop {
            if let Some(i) = memmem::find(&buf[search_start..], b"\np\0") {
                let tree_end = search_start + i + 1;
                let (_, i) = parse_prefix_delta(&buf[tree_end + 2..]).context("unexpected EOF")?;
                return Ok(Some((tree_end, tree_end + 2 + i)));
            }
            search_start = buf.len().saturating_sub(3);

            let read_len = buf.read_from(&mut self.reader, self.read_buf_len)?;
            if read_len == 0 {
                if search_start == 0 {
                    return Ok(None);
                }
                bail!("Unexpected EOF");
            }
        }
    }

    pub fn next_package<'a>(
        &mut self,
        buf: &'a mut DecoderBuf,
    ) -> anyhow::Result<Option<(TreeDecoder<'a>, PackageMeta)>> {
        let (tree_end, meta_start) = match self.next_package_inner(buf)? {
            Some(some) => some,
            None => return Ok(None),
        };

        let mut search_start = meta_start;
        loop {
            if let Some(i) = memchr(b'\n', &buf[search_start..]) {
                let meta_end = search_start + i;
                let buf = buf.consume(meta_end + 1);
                let package_meta = serde_json::from_slice(&buf[meta_start..meta_end])
                    .context("failed to parse package metadata")?;
                return Ok(Some((TreeDecoder::new(&buf[..tree_end]), package_meta)));
            }
            search_start = buf.len();

            let read_len = buf.read_from(&mut self.reader, self.read_buf_len)?;
            if read_len == 0 {
                bail!("Unexpected EOF");
            }
        }
    }
}

#[derive(Debug)]
pub enum EntryMeta<'a> {
    RegularFile { size: u64, executable: bool },
    Dir { child_count: usize },
    Symlink { target: &'a [u8] },
}

fn parse_entry<'a>(cur: &mut &'a [u8]) -> Option<(&'a [u8], i32, &'a [u8])> {
    let i = memchr(b'\0', cur)?;
    let meta = &cur[..i];
    *cur = &cur[i + 1..];

    let (delta, i) = parse_prefix_delta(cur)?;
    *cur = &cur[i..];

    let i = memchr(b'\n', cur)?;
    let suffix = &cur[..i];
    *cur = &cur[i + 1..];

    Some((meta, delta, suffix))
}

fn parse_entry_meta(meta: &[u8]) -> anyhow::Result<EntryMeta<'_>> {
    let (&kind, meta) = meta.split_last().context("empty metadata")?;
    let meta = if kind == b'r' || kind == b'x' {
        let size = atoi::atoi(meta).context("size expected")?;
        let executable = kind == b'x';
        EntryMeta::RegularFile { size, executable }
    } else if kind == b'd' {
        let child_count = atoi::atoi(meta).context("child count expected")?;
        EntryMeta::Dir { child_count }
    } else if kind == b's' {
        EntryMeta::Symlink { target: meta }
    } else {
        bail!("unexpected metadata kind");
    };
    Ok(meta)
}

pub struct TreeDecoder<'a> {
    cur: &'a [u8],
    current_path: Vec<u8>,
    dir_stack: Vec<usize>,
    prefix_len: usize,
}

impl<'a> TreeDecoder<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self {
            cur: buf,
            current_path: vec![],
            dir_stack: vec![0],
            prefix_len: 0,
        }
    }

    pub fn next_entry(&mut self) -> anyhow::Result<Option<EntryMeta<'a>>> {
        if self.cur.is_empty() {
            return Ok(None);
        }

        let (meta, delta, suffix) = parse_entry(&mut self.cur).context("failed to parse entry")?;

        self.prefix_len = (self.prefix_len as i32 + delta) as usize;
        if self.current_path.len() < self.prefix_len {
            bail!("invalid prefix length");
        }

        self.current_path.truncate(self.prefix_len);
        self.current_path.extend_from_slice(suffix);

        while self.prefix_len < *self.dir_stack.last().unwrap() {
            self.dir_stack.pop();
        }

        if suffix.starts_with(b"/") {
            self.dir_stack.push(self.prefix_len + 1);
        }

        debug_assert_eq!(
            self.current_path.iter().filter(|b| **b == b'/').count(),
            self.depth()
        );

        Ok(Some(parse_entry_meta(meta)?))
    }

    pub fn path(&self) -> &[u8] {
        &self.current_path
    }

    pub fn file_name(&self) -> &[u8] {
        let dir_path_len = *self.dir_stack.last().unwrap();
        &self.current_path[dir_path_len..]
    }

    pub fn depth(&self) -> usize {
        self.dir_stack.len() - 1
    }
}

#[derive(Debug, Deserialize)]
pub struct PathOrigin {
    pub attr: String,
    pub output: String,
    pub toplevel: bool,
}

#[derive(Debug, Deserialize)]
pub struct PackageMeta {
    pub store_dir: String,
    pub hash: String,
    pub name: String,
    pub origin: PathOrigin,
}

impl PackageMeta {
    pub fn hash_name(&self) -> String {
        format!("{}-{}", self.hash, self.name)
    }
}
