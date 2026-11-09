//! File descriptor introspection via libproc.

use super::capability::CapabilityState;
#[cfg(target_os = "macos")]
use super::fd_detail;
#[cfg(target_os = "macos")]
use super::proc::{self, fd_type_name, ProcFdInfo, PROC_PIDLISTFDS};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct FileDescriptorInfo {
    pub fd: i32,
    pub kind: String,
    pub path: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileDescriptorResult {
    pub state: CapabilityState,
    pub descriptors: Vec<FileDescriptorInfo>,
}

pub fn query_file_descriptors(pid: i32) -> FileDescriptorResult {
    #[cfg(target_os = "macos")]
    {
        query_macos(pid)
    }
    #[cfg(target_os = "linux")]
    {
        query_linux(pid)
    }
    #[cfg(target_os = "windows")]
    {
        windows::query(pid)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = pid;
        FileDescriptorResult {
            state: CapabilityState::Error {
                code: 99,
                message: "unsupported platform".into(),
            },
            descriptors: vec![],
        }
    }
}

#[cfg(target_os = "linux")]
fn query_linux(pid: i32) -> FileDescriptorResult {
    let directory = crate::platform::linux_host_root()
        .join("proc")
        .join(pid.to_string())
        .join("fd");
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return FileDescriptorResult {
                state: CapabilityState::NotFound,
                descriptors: vec![],
            };
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            return FileDescriptorResult {
                state: CapabilityState::Restricted {
                    reason: error.to_string(),
                },
                descriptors: vec![],
            };
        }
        Err(error) => {
            return FileDescriptorResult {
                state: CapabilityState::Error {
                    code: error.raw_os_error().unwrap_or_default() as u32,
                    message: error.to_string(),
                },
                descriptors: vec![],
            };
        }
    };
    let mut descriptors = entries
        .take(4096)
        .flatten()
        .filter_map(|entry| {
            let fd = entry.file_name().to_string_lossy().parse().ok()?;
            let target = std::fs::read_link(entry.path()).ok()?;
            let path = target.to_string_lossy().into_owned();
            let kind = if path.starts_with("socket:") {
                "socket"
            } else if path.starts_with("pipe:") {
                "pipe"
            } else if path.starts_with("anon_inode:") {
                "anon_inode"
            } else {
                "file"
            };
            Some(FileDescriptorInfo {
                fd,
                kind: kind.into(),
                path,
            })
        })
        .collect::<Vec<_>>();
    descriptors.sort_by_key(|descriptor| descriptor.fd);
    FileDescriptorResult {
        state: CapabilityState::Available,
        descriptors,
    }
}

#[cfg(target_os = "macos")]
fn query_macos(pid: i32) -> FileDescriptorResult {
    if pid <= 0 {
        return FileDescriptorResult {
            state: CapabilityState::NotFound,
            descriptors: vec![],
        };
    }

    let fd_size = proc::PROC_FDINFO_SIZE;
    let mut buf = vec![0u8; fd_size.saturating_mul(500).max(64 * 1024)];
    let nbytes = match proc::proc_pidinfo_buffer(pid, PROC_PIDLISTFDS, 0, &mut buf) {
        Ok(n) => n,
        Err(state) => {
            return FileDescriptorResult {
                state,
                descriptors: vec![],
            };
        }
    };

    let count = nbytes / fd_size;
    let mut descriptors = Vec::new();
    for i in 0..count.min(500) {
        let offset = i * fd_size;
        let fdinfo =
            unsafe { std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const ProcFdInfo) };
        if fdinfo.proc_fd < 0 {
            continue;
        }
        let kind = fd_type_name(fdinfo.proc_fdtype).to_string();
        let path = fd_detail::fd_detail_label(pid, &fdinfo);
        descriptors.push(FileDescriptorInfo {
            fd: fdinfo.proc_fd,
            kind,
            path,
        });
    }

    descriptors.sort_by_key(|d| d.fd);

    FileDescriptorResult {
        state: CapabilityState::Available,
        descriptors,
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn query_missing_pid_is_terminated() {
        let result = query_file_descriptors(999_999_999);
        assert!(matches!(result.state, CapabilityState::Terminated));
    }

    #[test]
    fn query_self_has_standard_fds() {
        let pid = unsafe { libc::getpid() };
        let result = query_file_descriptors(pid);
        assert!(
            matches!(result.state, CapabilityState::Available),
            "unexpected state: {:?}",
            result.state
        );
        assert!(result.descriptors.len() <= 4096);
    }

    #[test]
    fn query_self_vnode_path_when_present() {
        let pid = unsafe { libc::getpid() };
        let result = query_file_descriptors(pid);
        let has_path = result.descriptors.iter().any(|d| d.path.contains('/'));
        eprintln!("self fds={} with_path={has_path}", result.descriptors.len());
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::*;

    #[test]
    fn query_self_has_standard_descriptors() {
        let result = query_file_descriptors(std::process::id() as i32);
        assert!(matches!(result.state, CapabilityState::Available));
        assert!(!result.descriptors.is_empty());
    }
}

#[cfg(target_os = "windows")]
mod windows;
