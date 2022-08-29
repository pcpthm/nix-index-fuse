use std::{
    ffi::CString,
    os::unix::prelude::{AsRawFd, BorrowedFd, FromRawFd, OsStrExt, OwnedFd},
    path::Path,
    process::{Command, Stdio},
};

pub(crate) fn open_dir(dir: &Path) -> std::io::Result<OwnedFd> {
    let dir = CString::new(dir.as_os_str().as_bytes())?;
    let fd = unsafe { libc::open(dir.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    if fd >= 0 {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    } else {
        Err(std::io::Error::last_os_error())
    }
}

pub(crate) fn open_at(dir: BorrowedFd, path: &Path) -> std::io::Result<OwnedFd> {
    let path = CString::new(path.as_os_str().as_bytes())?;
    let fd = unsafe { libc::openat(dir.as_raw_fd(), path.as_ptr(), libc::O_RDONLY) };
    if fd >= 0 {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    } else {
        Err(std::io::Error::last_os_error())
    }
}

pub(crate) fn read_file(fd: BorrowedFd, offset: i64, size: usize) -> std::io::Result<Vec<u8>> {
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

pub(crate) fn umount_ignore_errors(path: &Path) -> std::io::Result<()> {
    Command::new("umount")
        .arg(path)
        .stderr(Stdio::null())
        .spawn()?
        .wait()?;
    Ok(())
}
