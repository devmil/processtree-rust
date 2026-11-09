//! Task-level libproc summary (thread count, Mach syscall count, Rosetta).

#[cfg(target_os = "macos")]
use super::capability::CapabilityState;
#[cfg(target_os = "macos")]
use super::proc::proc_pidinfo;
use serde::{Deserialize, Serialize};

#[cfg(target_os = "macos")]
pub const PROC_PIDTBSDINFO: i32 = 3;
#[cfg(target_os = "macos")]
pub const PROC_PIDTASKINFO: i32 = 4;

/// `struct proc_bsdinfo` (subset).
#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ProcBsdInfo {
    pub pbi_flags: u32,
    pub pbi_status: u32,
    pub pbi_xstatus: u32,
    pub pbi_pid: u32,
    pub pbi_ppid: u32,
    pub pbi_uid: u32,
    pub pbi_gid: u32,
    pub pbi_ruid: u32,
    pub pbi_rgid: u32,
    pub pbi_svuid: u32,
    pub pbi_svgid: u32,
    pub rfu_1: u32,
    pub pbi_comm: [i8; 16],
    pub pbi_name: [i8; 32],
    pub pbi_nfiles: u32,
    pub pbi_pgid: u32,
    pub pbi_pjobc: u32,
    pub e_tdev: u32,
    pub e_tpgid: u32,
    pub pbi_nice: i32,
    pub pbi_start_tvsec: u64,
    pub pbi_start_tvusec: u64,
}

/// `struct proc_taskinfo` (matches ingest/metrics).
#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ProcTaskInfo {
    pub pti_virtual_size: u64,
    pub pti_resident_size: u64,
    pub pti_total_user: u64,
    pub pti_total_system: u64,
    pub pti_threads_user: u64,
    pub pti_threads_system: u64,
    pub pti_policy: i32,
    pub pti_faults: i32,
    pub pti_pageins: i32,
    pub pti_cow_faults: i32,
    pub pti_messages_sent: i32,
    pub pti_messages_received: i32,
    pub pti_syscalls_mach: i32,
    pub pti_syscalls_unix: i32,
    pub pti_csw: i32,
    pub pti_threadnum: i32,
    pub pti_numrunning: i32,
    pub pti_priority: i32,
}

/// Rosetta / translation flag in `pbi_flags` (macOS 11+).
#[cfg(target_os = "macos")]
const P_TRANSLATED: u32 = 0x0008_0000;

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Serialize)]
pub struct TaskSummary {
    pub thread_count: i32,
    pub mach_syscall_count: i32,
    pub rosetta_translated: bool,
}

#[cfg(target_os = "macos")]
pub fn query_task_summary(pid: i32) -> Result<TaskSummary, CapabilityState> {
    let mut bsd = ProcBsdInfo::default();
    proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &mut bsd)?;
    let mut task = ProcTaskInfo::default();
    proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &mut task)?;
    Ok(TaskSummary {
        thread_count: task.pti_threadnum,
        mach_syscall_count: task.pti_syscalls_mach,
        rosetta_translated: bsd.pbi_flags & P_TRANSLATED != 0,
    })
}

/// Task-level counts; Mach syscall total is not Mach port count — prefix `~` marks approximation.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn mach_port_summary_label(summary: &TaskSummary) -> String {
    if summary.thread_count <= 0 && summary.mach_syscall_count <= 0 {
        return "—".into();
    }
    format!(
        "~{} threads · ~{} mach syscalls",
        summary.thread_count.max(0),
        summary.mach_syscall_count.max(0)
    )
}
