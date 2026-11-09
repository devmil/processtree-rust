//! Shared libproc helpers and `proc_info` layout constants (macOS).

use super::capability::CapabilityState;

pub const PROC_PIDLISTFDS: i32 = 1;
pub const PROC_PIDFDVNODEPATHINFO: i32 = 2;
pub const PROC_PIDFDSOCKETINFO: i32 = 3;
pub const PROC_PIDFDPIPEINFO: i32 = 6;
pub const PROC_PIDLISTTHREADS: i32 = 6;
pub const PROC_PIDTHREADINFO: i32 = 7;

pub const PROX_FDTYPE_VNODE: u32 = 1;
pub const PROX_FDTYPE_SOCKET: u32 = 2;
pub const PROX_FDTYPE_PSHM: u32 = 3;
pub const PROX_FDTYPE_PSEM: u32 = 4;
pub const PROX_FDTYPE_KQUEUE: u32 = 5;
pub const PROX_FDTYPE_PIPE: u32 = 6;

pub const SOCKINFO_IN: i32 = 1;
pub const SOCKINFO_TCP: i32 = 2;
pub const SOCKINFO_UN: i32 = 3;

/// Matches `struct proc_fdinfo` in `sys/proc_info.h` (macOS 14+: 8 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcFdInfo {
    pub proc_fd: i32,
    pub proc_fdtype: u32,
}

pub const PROC_FDINFO_SIZE: usize = std::mem::size_of::<ProcFdInfo>();

/// Matches `struct proc_threadinfo` in `sys/proc_info.h`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ProcThreadInfo {
    pub pth_user_time: u64,
    pub pth_system_time: u64,
    pub pth_faults: i32,
    pub pth_flags: i32,
    pub pth_run_state: u32,
    pub pth_sleep_time: u32,
    pub pth_curpri: i32,
    pub pth_priority: i32,
    pub pth_maxpri: i32,
}

pub fn executable_path(pid: i32) -> String {
    let mut buf = [0u8; 4096];
    let len = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut _, buf.len() as u32) };
    if len <= 0 {
        return String::new();
    }
    String::from_utf8_lossy(&buf[..len as usize]).into_owned()
}

pub fn map_proc_errno(err: i32, pid: i32) -> CapabilityState {
    let errno = unsafe { *libc::__error() };
    match errno {
        libc::ESRCH => CapabilityState::Terminated,
        libc::EPERM | libc::EACCES => {
            if pid > 0 && pid < 100 && pid != unsafe { libc::getpid() } {
                CapabilityState::Restricted {
                    reason: "protected system process".into(),
                }
            } else {
                CapabilityState::Restricted {
                    reason: format!("permission denied (errno {errno})"),
                }
            }
        }
        _ => CapabilityState::Error {
            code: errno as u32,
            message: format!("proc_pidinfo failed ({err})"),
        },
    }
}

pub fn proc_pidinfo<T>(
    pid: i32,
    flavor: i32,
    arg: u64,
    info: &mut T,
) -> Result<(), CapabilityState> {
    let size = std::mem::size_of::<T>() as i32;
    let ret = unsafe { libc::proc_pidinfo(pid, flavor, arg, info as *mut T as *mut _, size) };
    if ret <= 0 {
        Err(map_proc_errno(ret, pid))
    } else {
        Ok(())
    }
}

pub fn proc_pidinfo_buffer(
    pid: i32,
    flavor: i32,
    arg: u64,
    buf: &mut [u8],
) -> Result<usize, CapabilityState> {
    let ret = unsafe {
        libc::proc_pidinfo(
            pid,
            flavor,
            arg,
            buf.as_mut_ptr() as *mut _,
            buf.len() as i32,
        )
    };
    if ret <= 0 {
        Err(map_proc_errno(ret, pid))
    } else {
        Ok(ret as usize)
    }
}

pub fn proc_pidfdinfo_buffer(
    pid: i32,
    fd: i32,
    flavor: i32,
    buf: &mut [u8],
) -> Result<usize, CapabilityState> {
    let ret = unsafe {
        libc::proc_pidfdinfo(
            pid,
            fd,
            flavor,
            buf.as_mut_ptr() as *mut _,
            buf.len() as i32,
        )
    };
    if ret <= 0 {
        Err(map_proc_errno(ret, pid))
    } else {
        Ok(ret as usize)
    }
}

pub fn fd_type_name(fdtype: u32) -> &'static str {
    match fdtype {
        PROX_FDTYPE_VNODE => "vnode",
        PROX_FDTYPE_SOCKET => "socket",
        PROX_FDTYPE_PSHM => "pshm",
        PROX_FDTYPE_PSEM => "psem",
        PROX_FDTYPE_KQUEUE => "kqueue",
        PROX_FDTYPE_PIPE => "pipe",
        _ => "other",
    }
}

pub fn is_socket_fd(fdinfo: &ProcFdInfo) -> bool {
    fdinfo.proc_fdtype == PROX_FDTYPE_SOCKET
}

pub fn thread_run_state_name(state: u32) -> &'static str {
    match state {
        1 => "running",
        2 => "stopped",
        3 => "waiting",
        4 => "uninterruptible",
        5 => "halted",
        _ => "unknown",
    }
}

pub fn tcp_state_name(state: i32) -> &'static str {
    match state {
        0 => "closed",
        1 => "listen",
        2 => "syn_sent",
        3 => "syn_received",
        4 => "established",
        5 => "close_wait",
        6 => "fin_wait_1",
        7 => "closing",
        8 => "last_ack",
        9 => "fin_wait_2",
        10 => "time_wait",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_fdinfo_size_matches_platform() {
        assert_eq!(
            PROC_FDINFO_SIZE, 8,
            "update ProcFdInfo if SDK layout changed"
        );
    }
}
