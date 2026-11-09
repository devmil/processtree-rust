//! Per-FD detail strings (paths, socket summary) via libproc.

use super::proc::{
    fd_type_name, proc_pidfdinfo_buffer, ProcFdInfo, PROC_PIDFDSOCKETINFO, PROC_PIDFDVNODEPATHINFO,
    PROX_FDTYPE_PIPE, PROX_FDTYPE_SOCKET, PROX_FDTYPE_VNODE,
};
use super::socket_parse;

/// `vip_path` offset inside `struct vnode_fdinfowithpath` (macOS 26 arm64).
const VNODE_PATH_OFFSET: usize = 176;

#[cfg(target_os = "macos")]
pub fn fd_detail_label(pid: i32, fdinfo: &ProcFdInfo) -> String {
    match fdinfo.proc_fdtype {
        PROX_FDTYPE_VNODE => vnode_path(pid, fdinfo.proc_fd),
        PROX_FDTYPE_SOCKET => socket_summary(pid, fdinfo.proc_fd),
        PROX_FDTYPE_PIPE => "pipe".into(),
        other => fd_type_name(other).into(),
    }
}

#[cfg(target_os = "macos")]
pub fn vnode_path(pid: i32, fd: i32) -> String {
    let mut buf = vec![0u8; 4096];
    let ret = match proc_pidfdinfo_buffer(pid, fd, PROC_PIDFDVNODEPATHINFO, &mut buf) {
        Ok(n) => n,
        Err(_) => return String::new(),
    };
    if ret > VNODE_PATH_OFFSET {
        let path = cstr_from_buf(&buf[VNODE_PATH_OFFSET..ret]);
        if !path.is_empty() {
            return path;
        }
    }
    cstr_from_buf(&buf[..ret])
}

#[cfg(target_os = "macos")]
pub fn socket_summary(pid: i32, fd: i32) -> String {
    let mut buf = vec![0u8; 8192];
    let ret = match proc_pidfdinfo_buffer(pid, fd, PROC_PIDFDSOCKETINFO, &mut buf) {
        Ok(n) => n,
        Err(_) => return String::new(),
    };
    socket_parse::socket_summary_from_buf(&buf[..ret])
}

#[cfg(target_os = "macos")]
pub fn cstr_from_buf(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}
