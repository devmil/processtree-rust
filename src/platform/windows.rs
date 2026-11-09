use std::collections::HashMap;
use std::mem;
use std::ptr;
use std::time::Instant;

use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::{
    GetLengthSid, GetTokenInformation, LookupAccountSidW, SidTypeUnknown, TokenUser, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, Thread32First, Thread32Next,
    PROCESSENTRY32W, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows_sys::Win32::System::ProcessStatus::{
    K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX,
};
use windows_sys::Win32::System::Threading::{
    GetProcessHandleCount, GetProcessIoCounters, GetProcessTimes, OpenProcess, OpenProcessToken,
    OpenThread, QueryFullProcessImageNameW, ResumeThread, SuspendThread, TerminateProcess,
    IO_COUNTERS, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, THREAD_SUSPEND_RESUME,
};

use crate::action::ProcessSignal;
use crate::error::ProcessTreeError;
use crate::model::{ProcessIdentity, ProcessRecord, ProcessStatus};
use crate::platform::ProcessMetadata;

const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn new(handle: HANDLE) -> Option<Self> {
        (!handle.is_null() && handle != INVALID_HANDLE_VALUE).then_some(Self(handle))
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

pub fn enumerate_processes() -> Result<Vec<ProcessRecord>, ProcessTreeError> {
    enumerate_processes_reusing_metadata(&HashMap::new(), true)
}

pub(crate) fn enumerate_processes_reusing_metadata(
    metadata: &HashMap<(i32, u64), ProcessMetadata>,
    refresh_metadata: bool,
) -> Result<Vec<ProcessRecord>, ProcessTreeError> {
    let snapshot = OwnedHandle::new(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) })
        .ok_or_else(last_enumeration_error)?;
    let mut entry = PROCESSENTRY32W {
        dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
        ..PROCESSENTRY32W::default()
    };
    if unsafe { Process32FirstW(snapshot.0, &mut entry) } == 0 {
        return Err(last_enumeration_error());
    }

    let mut records = Vec::new();
    loop {
        if let Some(record) = read_process(&entry, metadata, refresh_metadata) {
            records.push(record);
        }
        if unsafe { Process32NextW(snapshot.0, &mut entry) } == 0 {
            break;
        }
    }
    records.sort_by_key(ProcessRecord::pid);
    Ok(records)
}

fn read_process(
    entry: &PROCESSENTRY32W,
    metadata: &HashMap<(i32, u64), ProcessMetadata>,
    refresh_metadata: bool,
) -> Option<ProcessRecord> {
    let pid = i32::try_from(entry.th32ProcessID).ok()?;
    let process = OwnedHandle::new(unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, entry.th32ProcessID)
    })?;
    let (start_time_unix_ms, cpu_time_nanos) = process_times(process.0)?;
    let identity_key = (pid, start_time_unix_ms);
    let cached = (!refresh_metadata)
        .then(|| metadata.get(&identity_key))
        .flatten();
    let name = wide_string(&entry.szExeFile);
    let executable_path = cached
        .map(|value| value.executable_path.clone())
        .unwrap_or_else(|| executable_path(process.0));
    let (uid, user) = cached
        .map(|value| (value.uid, value.user.clone()))
        .unwrap_or_else(|| process_user(process.0));
    let (rss_bytes, virtual_memory_bytes) = process_memory(process.0);
    let storage_io = process_storage_io(process.0);
    let mut handle_count = 0;
    unsafe {
        GetProcessHandleCount(process.0, &mut handle_count);
    }

    Some(ProcessRecord {
        identity: ProcessIdentity {
            pid,
            start_time_unix_ms,
        },
        ppid: i32::try_from(entry.th32ParentProcessID).unwrap_or_default(),
        uid,
        user,
        status: ProcessStatus::Running,
        flags: entry.dwFlags,
        rss_bytes,
        virtual_memory_bytes,
        cpu_time_nanos,
        thread_count: entry.cntThreads,
        open_file_count: handle_count,
        local_ports: None,
        listening_ports: None,
        nice: 0,
        priority: entry.pcPriClassBase,
        cpu_percent: 0.0,
        gpu_percent: 0.0,
        network_in_bytes_per_second: 0.0,
        network_out_bytes_per_second: 0.0,
        total_network_in_bytes: 0,
        total_network_out_bytes: 0,
        storage_read_bytes_per_second: 0.0,
        storage_write_bytes_per_second: 0.0,
        total_storage_read_bytes: storage_io.map_or(0, |value| value.0),
        total_storage_write_bytes: storage_io.map_or(0, |value| value.1),
        storage_io_available: storage_io.is_some(),
        tree_cpu_percent: 0.0,
        tree_gpu_percent: 0.0,
        tree_rss_bytes: 0,
        tree_network_in_bytes_per_second: 0.0,
        tree_network_out_bytes_per_second: 0.0,
        tree_storage_read_bytes_per_second: 0.0,
        tree_storage_write_bytes_per_second: 0.0,
        tree_storage_io_available: false,
        descendant_count: 0,
        children: Vec::new(),
        name,
        command_line: cached
            .map(|value| value.command_line.clone())
            .unwrap_or_else(|| executable_path.clone()),
        app_bundle_path: cached
            .map(|value| value.app_bundle_path.clone())
            .unwrap_or_else(|| executable_path.clone()),
        executable_path,
        application_id: cached
            .map(|value| value.application_id.clone())
            .unwrap_or_default(),
        icon_uri: None,
    })
}

fn process_storage_io(handle: HANDLE) -> Option<(u64, u64)> {
    let mut counters = IO_COUNTERS::default();
    (unsafe { GetProcessIoCounters(handle, &mut counters) } != 0)
        .then_some((counters.ReadTransferCount, counters.WriteTransferCount))
}

fn process_times(handle: HANDLE) -> Option<(u64, u64)> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    if unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) } == 0 {
        return None;
    }
    let creation_100ns = filetime_ticks(creation);
    let start_time_unix_ms = creation_100ns.saturating_sub(WINDOWS_TO_UNIX_EPOCH_100NS) / 10_000;
    let cpu_time_nanos = filetime_ticks(kernel)
        .saturating_add(filetime_ticks(user))
        .saturating_mul(100);
    Some((start_time_unix_ms, cpu_time_nanos))
}

fn filetime_ticks(value: FILETIME) -> u64 {
    (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime)
}

fn executable_path(handle: HANDLE) -> String {
    let mut buffer = vec![0u16; 32_768];
    let mut len = buffer.len() as u32;
    if unsafe { QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut len) } == 0 {
        return String::new();
    }
    String::from_utf16_lossy(&buffer[..len as usize])
}

fn process_memory(handle: HANDLE) -> (u64, u64) {
    let mut counters = PROCESS_MEMORY_COUNTERS_EX {
        cb: mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
        ..PROCESS_MEMORY_COUNTERS_EX::default()
    };
    let ok = unsafe {
        K32GetProcessMemoryInfo(
            handle,
            (&mut counters as *mut PROCESS_MEMORY_COUNTERS_EX).cast(),
            counters.cb,
        )
    };
    if ok == 0 {
        return (0, 0);
    }
    (counters.WorkingSetSize as u64, counters.PrivateUsage as u64)
}

fn process_user(handle: HANDLE) -> (u32, String) {
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(handle, TOKEN_QUERY, &mut token) } == 0 {
        return (0, String::new());
    }
    let Some(token) = OwnedHandle::new(token) else {
        return (0, String::new());
    };
    let mut required = 0;
    unsafe {
        GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut required);
    }
    if required < mem::size_of::<TOKEN_USER>() as u32 {
        return (0, String::new());
    }
    let mut buffer = vec![0u8; required as usize];
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return (0, String::new());
    }
    let token_user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
    let sid = token_user.User.Sid;
    let sid_len = unsafe { GetLengthSid(sid) } as usize;
    let uid = if sid_len == 0 {
        0
    } else {
        let bytes = unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), sid_len) };
        bytes.iter().fold(2_166_136_261u32, |hash, byte| {
            hash.wrapping_mul(16_777_619) ^ u32::from(*byte)
        })
    };

    let mut name_len = 0;
    let mut domain_len = 0;
    let mut use_kind = SidTypeUnknown;
    unsafe {
        LookupAccountSidW(
            ptr::null(),
            sid,
            ptr::null_mut(),
            &mut name_len,
            ptr::null_mut(),
            &mut domain_len,
            &mut use_kind,
        );
    }
    if name_len == 0 {
        return (uid, String::new());
    }
    let mut name = vec![0u16; name_len as usize];
    let mut domain = vec![0u16; domain_len as usize];
    if unsafe {
        LookupAccountSidW(
            ptr::null(),
            sid,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut use_kind,
        )
    } == 0
    {
        return (uid, String::new());
    }
    let name = wide_string(&name[..name_len as usize]);
    let domain = wide_string(&domain[..domain_len as usize]);
    let user = if domain.is_empty() {
        name
    } else {
        format!("{domain}\\{name}")
    };
    (uid, user)
}

fn wide_string(value: &[u16]) -> String {
    let len = value
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(value.len());
    String::from_utf16_lossy(&value[..len])
}

fn last_enumeration_error() -> ProcessTreeError {
    ProcessTreeError::Enumeration(std::io::Error::last_os_error().to_string())
}

pub(crate) fn send_process_signal(
    identity: ProcessIdentity,
    signal: ProcessSignal,
) -> Result<(), ProcessTreeError> {
    match signal {
        ProcessSignal::Terminate | ProcessSignal::Kill => {
            let process = OwnedHandle::new(unsafe {
                OpenProcess(
                    PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                    0,
                    identity.pid as u32,
                )
            })
            .ok_or_else(last_action_error)?;
            verify_identity(process.0, identity)?;
            if unsafe { TerminateProcess(process.0, 1) } == 0 {
                return Err(last_action_error());
            }
            Ok(())
        }
        ProcessSignal::Suspend => apply_to_threads(identity, SuspendThread),
        ProcessSignal::Resume => apply_to_threads(identity, ResumeThread),
    }
}

fn verify_identity(handle: HANDLE, identity: ProcessIdentity) -> Result<(), ProcessTreeError> {
    let Some((start_time_unix_ms, _)) = process_times(handle) else {
        return Err(last_action_error());
    };
    if start_time_unix_ms != identity.start_time_unix_ms {
        return Err(ProcessTreeError::ProcessIdentityChanged);
    }
    Ok(())
}

fn apply_to_threads(
    identity: ProcessIdentity,
    operation: unsafe extern "system" fn(HANDLE) -> u32,
) -> Result<(), ProcessTreeError> {
    let process = OwnedHandle::new(unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, identity.pid as u32)
    })
    .ok_or_else(last_action_error)?;
    verify_identity(process.0, identity)?;
    let snapshot = OwnedHandle::new(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) })
        .ok_or_else(last_action_error)?;
    let mut entry = THREADENTRY32 {
        dwSize: mem::size_of::<THREADENTRY32>() as u32,
        ..THREADENTRY32::default()
    };
    if unsafe { Thread32First(snapshot.0, &mut entry) } == 0 {
        return Err(last_action_error());
    }
    let mut matched = false;
    loop {
        if entry.th32OwnerProcessID == identity.pid as u32 {
            matched = true;
            let thread = OwnedHandle::new(unsafe {
                OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID)
            })
            .ok_or_else(last_action_error)?;
            if unsafe { operation(thread.0) } == u32::MAX {
                return Err(last_action_error());
            }
        }
        if unsafe { Thread32Next(snapshot.0, &mut entry) } == 0 {
            break;
        }
    }
    matched
        .then_some(())
        .ok_or(ProcessTreeError::ProcessNotFound)
}

fn last_action_error() -> ProcessTreeError {
    ProcessTreeError::ProcessAction(std::io::Error::last_os_error().to_string())
}

pub(crate) struct CpuSampler {
    sampled_at: Option<Instant>,
    nanos_by_identity: HashMap<(i32, u64), u64>,
}

impl CpuSampler {
    pub fn new() -> Self {
        Self {
            sampled_at: None,
            nanos_by_identity: HashMap::new(),
        }
    }

    pub fn apply(&mut self, records: &mut [ProcessRecord]) {
        let now = Instant::now();
        let elapsed_nanos = self
            .sampled_at
            .map(|sampled_at| now.duration_since(sampled_at).as_nanos() as u64);
        let mut next = HashMap::with_capacity(records.len());
        for record in records {
            let identity = record.identity_key();
            if let (Some(elapsed), Some(previous)) =
                (elapsed_nanos, self.nanos_by_identity.get(&identity))
            {
                if elapsed > 0 {
                    record.cpu_percent = record.cpu_time_nanos.saturating_sub(*previous) as f64
                        / elapsed as f64
                        * 100.0;
                }
            }
            next.insert(identity, record.cpu_time_nanos);
        }
        self.sampled_at = Some(now);
        self.nanos_by_identity = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_conversion_uses_unix_epoch() {
        let ticks = WINDOWS_TO_UNIX_EPOCH_100NS + 12_345_670;
        let time = FILETIME {
            dwLowDateTime: ticks as u32,
            dwHighDateTime: (ticks >> 32) as u32,
        };
        assert_eq!(filetime_ticks(time), ticks);
        assert_eq!(
            filetime_ticks(time).saturating_sub(WINDOWS_TO_UNIX_EPOCH_100NS) / 10_000,
            1_234
        );
    }

    #[test]
    fn enumeration_includes_current_process_with_stable_identity() {
        let records = enumerate_processes().expect("enumerate Windows processes");
        let current = records
            .iter()
            .find(|record| record.pid() == std::process::id() as i32)
            .expect("current process");
        assert!(current.start_time_unix_ms() > 0);
        assert!(!current.name.is_empty());
        assert!(!current.executable_path.is_empty());
    }
}
