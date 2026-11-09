use std::collections::HashMap;

use crate::action::ProcessSignal;
use crate::error::ProcessTreeError;
use crate::model::{ProcessIdentity, ProcessRecord};

pub fn enumerate_processes() -> Result<Vec<ProcessRecord>, ProcessTreeError> {
    #[cfg(target_os = "macos")]
    {
        macos::enumerate_processes()
    }
    #[cfg(target_os = "linux")]
    {
        linux::enumerate_processes()
    }
    #[cfg(target_os = "windows")]
    {
        windows::enumerate_processes()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err(ProcessTreeError::UnsupportedPlatform)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ProcessMetadata {
    pub uid: u32,
    pub user: String,
    pub executable_path: String,
    pub command_line: String,
    pub app_bundle_path: String,
    pub application_id: String,
}

impl From<&ProcessRecord> for ProcessMetadata {
    fn from(record: &ProcessRecord) -> Self {
        Self {
            uid: record.uid,
            user: record.user.clone(),
            executable_path: record.executable_path.clone(),
            command_line: record.command_line.clone(),
            app_bundle_path: record.app_bundle_path.clone(),
            application_id: record.application_id.clone(),
        }
    }
}

pub(crate) fn enumerate_processes_reusing_metadata(
    metadata: &HashMap<(i32, u64), ProcessMetadata>,
    refresh_metadata: bool,
) -> Result<Vec<ProcessRecord>, ProcessTreeError> {
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        #[cfg(target_os = "linux")]
        return linux::enumerate_processes_reusing_metadata(metadata, refresh_metadata);
        #[cfg(target_os = "windows")]
        return windows::enumerate_processes_reusing_metadata(metadata, refresh_metadata);
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = (metadata, refresh_metadata);
        enumerate_processes()
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_host_root() -> std::path::PathBuf {
    linux::host_root()
}

pub(crate) fn application_display_name(record: &ProcessRecord, application_name: &str) -> String {
    #[cfg(target_os = "linux")]
    {
        linux::system_special_cases::display_name(
            &record.name,
            &record.executable_path,
            application_name,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = record;
        application_name.to_owned()
    }
}

pub fn gpu_metrics_available() -> bool {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        apple_gpu::probe_available()
    }
    #[cfg(target_os = "linux")]
    {
        linux::gpu_metrics_available()
    }
    #[cfg(not(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))))]
    {
        false
    }
}

pub fn send_process_signal(
    identity: ProcessIdentity,
    signal: ProcessSignal,
) -> Result<(), ProcessTreeError> {
    let Some(current) = enumerate_processes()?
        .into_iter()
        .find(|record| record.pid() == identity.pid)
    else {
        return Err(ProcessTreeError::ProcessNotFound);
    };
    if current.start_time_unix_ms() != identity.start_time_unix_ms {
        return Err(ProcessTreeError::ProcessIdentityChanged);
    }

    // Host PIDs are not valid signal targets from Flatpak's child PID
    // namespace. Never risk signalling a numerically matching sandbox PID.
    #[cfg(target_os = "linux")]
    if linux::uses_flatpak_host_root() {
        return Err(ProcessTreeError::ProcessAction(
            "process actions are unavailable from the Flatpak sandbox".into(),
        ));
    }

    #[cfg(unix)]
    {
        let result = unsafe { libc::kill(identity.pid, signal.unix_signal()) };
        if result == 0 {
            Ok(())
        } else {
            Err(ProcessTreeError::ProcessAction(
                std::io::Error::last_os_error().to_string(),
            ))
        }
    }

    #[cfg(not(unix))]
    {
        #[cfg(target_os = "windows")]
        {
            windows::send_process_signal(identity, signal)
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = signal;
            Err(ProcessTreeError::UnsupportedPlatform)
        }
    }
}

pub(crate) struct CpuSampler {
    #[cfg(target_os = "macos")]
    inner: macos::CpuSampler,
    #[cfg(target_os = "linux")]
    inner: linux::CpuSampler,
    #[cfg(target_os = "windows")]
    inner: windows::CpuSampler,
}

impl CpuSampler {
    pub fn new() -> Self {
        Self {
            #[cfg(target_os = "macos")]
            inner: macos::CpuSampler::new(),
            #[cfg(target_os = "linux")]
            inner: linux::CpuSampler::new(),
            #[cfg(target_os = "windows")]
            inner: windows::CpuSampler::new(),
        }
    }

    pub fn apply(&mut self, records: &mut [ProcessRecord]) {
        #[cfg(target_os = "macos")]
        self.inner.apply(records);
        #[cfg(target_os = "linux")]
        self.inner.apply(records);
        #[cfg(target_os = "windows")]
        self.inner.apply(records);
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        let _ = records;
    }
}

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "windows")]
mod windows;

pub(crate) struct GpuSampler {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    inner: apple_gpu::GpuSampler,
    #[cfg(target_os = "linux")]
    inner: linux::GpuSampler,
}

impl GpuSampler {
    pub fn new() -> Self {
        Self {
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            inner: apple_gpu::GpuSampler::new(),
            #[cfg(target_os = "linux")]
            inner: linux::GpuSampler::new(),
        }
    }

    pub fn apply_throttled(&mut self, records: &mut [ProcessRecord], full_scan: bool) {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            if full_scan {
                self.inner.apply(records);
            } else {
                self.inner.apply_cached(records);
            }
        }
        #[cfg(target_os = "linux")]
        {
            if full_scan {
                self.inner.apply(records);
            } else {
                self.inner.apply_cached(records);
            }
        }
        #[cfg(not(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))))]
        {
            let _ = full_scan;
            for record in records {
                record.gpu_percent = 0.0;
            }
        }
    }
}

#[cfg(any(target_os = "macos", test))]
mod sysctl_buffer;

#[cfg(target_os = "macos")]
mod macos {
    use std::collections::HashMap;
    use std::ffi::CStr;
    use std::mem;
    use std::sync::OnceLock;
    use std::time::Instant;

    use crate::error::ProcessTreeError;
    use crate::model::{ProcessIdentity, ProcessRecord, ProcessStatus};

    const MAXCOMLEN: usize = 16;
    const KINFO_PROC_SIZE: usize = 648;
    const KINFO_PID_OFFSET: usize = 40;
    const KINFO_COMM_OFFSET: usize = 243;
    const KINFO_PPID_OFFSET: usize = 560;
    const PROC_PIDTBSDINFO: i32 = 3;
    const PROC_PIDTASKINFO: i32 = 4;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct MachTimebaseInfo {
        numer: u32,
        denom: u32,
    }

    #[derive(Clone, Copy)]
    struct MachTimebase {
        numer: u32,
        denom: u32,
    }

    unsafe extern "C" {
        fn mach_timebase_info(info: *mut MachTimebaseInfo) -> libc::c_int;
    }

    #[repr(C)]
    struct ProcBsdInfo {
        pbi_flags: u32,
        pbi_status: u32,
        pbi_xstatus: u32,
        pbi_pid: u32,
        pbi_ppid: u32,
        pbi_uid: u32,
        pbi_gid: u32,
        pbi_ruid: u32,
        pbi_rgid: u32,
        pbi_svuid: u32,
        pbi_svgid: u32,
        rfu_1: u32,
        pbi_comm: [i8; MAXCOMLEN],
        pbi_name: [i8; MAXCOMLEN * 2],
        pbi_nfiles: u32,
        pbi_pgid: u32,
        pbi_pjobc: u32,
        e_tdev: u32,
        e_tpgid: u32,
        pbi_nice: i32,
        pbi_start_tvsec: u64,
        pbi_start_tvusec: u64,
    }

    #[repr(C)]
    struct ProcTaskInfo {
        pti_virtual_size: u64,
        pti_resident_size: u64,
        pti_total_user: u64,
        pti_total_system: u64,
        pti_threads_user: u64,
        pti_threads_system: u64,
        pti_policy: i32,
        pti_faults: i32,
        pti_pageins: i32,
        pti_cow_faults: i32,
        pti_messages_sent: i32,
        pti_messages_received: i32,
        pti_syscalls_mach: i32,
        pti_syscalls_unix: i32,
        pti_csw: i32,
        pti_threadnum: i32,
        pti_numrunning: i32,
        pti_priority: i32,
    }

    struct KinfoSnapshot {
        pid: i32,
        ppid: i32,
        name: String,
    }

    #[derive(Clone)]
    struct StaticProcessMetadata {
        user: String,
        name: String,
        executable_path: String,
        command_line: String,
        app_bundle_path: String,
    }

    #[derive(Default)]
    struct ProcessMetadataCache {
        by_identity: HashMap<(i32, u64), StaticProcessMetadata>,
        user_names: HashMap<u32, String>,
    }

    pub fn enumerate_processes() -> Result<Vec<ProcessRecord>, ProcessTreeError> {
        let raw = sysctl_kern_proc_all()?;
        static METADATA_CACHE: OnceLock<std::sync::Mutex<ProcessMetadataCache>> = OnceLock::new();
        let cache =
            METADATA_CACHE.get_or_init(|| std::sync::Mutex::new(ProcessMetadataCache::default()));
        let mut cache = cache.lock().map_err(|_| ProcessTreeError::LockPoisoned)?;
        let mut seen = HashMap::new();
        let processes = parse_kinfo_entries(&raw)
            .into_iter()
            .map(|entry| enrich_from_libproc(entry.pid, &entry, &mut cache, &mut seen))
            .collect();
        cache.by_identity.retain(|key, _| seen.contains_key(key));
        Ok(processes)
    }

    fn sysctl_kern_proc_all() -> Result<Vec<u8>, ProcessTreeError> {
        let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_ALL, 0];
        super::sysctl_buffer::read_process_table(KINFO_PROC_SIZE, |buffer| {
            let (ptr, mut len) = match buffer {
                Some(buffer) => (buffer.as_mut_ptr().cast(), buffer.len()),
                None => (std::ptr::null_mut(), 0),
            };
            // The buffer is initialized and writable for `len` bytes. Capture
            // errno immediately; ENOMEM may mean the process list grew.
            let ret = unsafe {
                libc::sysctl(mib.as_mut_ptr(), 3, ptr, &mut len, std::ptr::null_mut(), 0)
            };
            if ret == 0 {
                Ok(len)
            } else {
                Err(std::io::Error::last_os_error())
            }
        })
        .map_err(|error| {
            ProcessTreeError::Enumeration(format!("sysctl(KERN_PROC_ALL) failed: {error}"))
        })
    }

    fn parse_kinfo_entries(buf: &[u8]) -> Vec<KinfoSnapshot> {
        let mut out = Vec::new();
        for chunk in buf.chunks_exact(KINFO_PROC_SIZE) {
            let pid = i32::from_ne_bytes(
                chunk[KINFO_PID_OFFSET..KINFO_PID_OFFSET + 4]
                    .try_into()
                    .unwrap(),
            );
            if pid <= 0 {
                continue;
            }
            let ppid = i32::from_ne_bytes(
                chunk[KINFO_PPID_OFFSET..KINFO_PPID_OFFSET + 4]
                    .try_into()
                    .unwrap(),
            );
            let name =
                cstr_from_bytes(&chunk[KINFO_COMM_OFFSET..KINFO_COMM_OFFSET + MAXCOMLEN + 1]);
            out.push(KinfoSnapshot {
                pid,
                ppid,
                name: if name.is_empty() {
                    format!("pid-{pid}")
                } else {
                    name
                },
            });
        }
        out
    }

    fn enrich_from_libproc(
        pid: i32,
        snapshot: &KinfoSnapshot,
        cache: &mut ProcessMetadataCache,
        seen: &mut HashMap<(i32, u64), ()>,
    ) -> ProcessRecord {
        let mut bsd = mem::MaybeUninit::<ProcBsdInfo>::uninit();
        let bsd_size = mem::size_of::<ProcBsdInfo>() as i32;
        let bsd_ret = unsafe {
            libc::proc_pidinfo(
                pid,
                PROC_PIDTBSDINFO,
                0,
                bsd.as_mut_ptr() as *mut _,
                bsd_size,
            )
        };

        if bsd_ret > 0 {
            let bsd = unsafe { bsd.assume_init() };
            let task = task_metrics(pid);
            let uid = bsd.pbi_uid;
            let start_time_unix_ms =
                bsd.pbi_start_tvsec.saturating_mul(1000) + (bsd.pbi_start_tvusec / 1000);
            let identity_key = (pid, start_time_unix_ms);
            seen.insert(identity_key, ());
            let metadata = if let Some(metadata) = cache.by_identity.get(&identity_key) {
                metadata.clone()
            } else {
                let executable_path = pid_executable_path(pid);
                let command_line = pid_command_line(pid);
                let pbi_comm = cstr_to_string(&bsd.pbi_comm);
                let pbi_name = cstr_to_string(&bsd.pbi_name);
                let app_bundle_path = app_bundle_path(&executable_path);
                let user = cache
                    .user_names
                    .entry(uid)
                    .or_insert_with(|| user_name_for_uid(uid))
                    .clone();
                let metadata = StaticProcessMetadata {
                    user,
                    name: best_process_name(&pbi_name, &pbi_comm, &executable_path, &snapshot.name),
                    executable_path,
                    command_line,
                    app_bundle_path,
                };
                cache.by_identity.insert(identity_key, metadata.clone());
                metadata
            };

            return ProcessRecord {
                identity: ProcessIdentity {
                    pid,
                    start_time_unix_ms,
                },
                ppid: bsd.pbi_ppid as i32,
                uid,
                user: metadata.user,
                status: status_from_pbi(bsd.pbi_status),
                flags: bsd.pbi_flags,
                rss_bytes: task.resident_size,
                virtual_memory_bytes: task.virtual_size,
                cpu_time_nanos: task.cpu_time_nanos,
                thread_count: task.thread_count,
                open_file_count: bsd.pbi_nfiles,
                local_ports: None,
                listening_ports: None,
                nice: bsd.pbi_nice,
                priority: task.priority,
                cpu_percent: 0.0,
                gpu_percent: 0.0,
                network_in_bytes_per_second: 0.0,
                network_out_bytes_per_second: 0.0,
                total_network_in_bytes: 0,
                total_network_out_bytes: 0,
                storage_read_bytes_per_second: 0.0,
                storage_write_bytes_per_second: 0.0,
                total_storage_read_bytes: task.storage_read_bytes,
                total_storage_write_bytes: task.storage_write_bytes,
                storage_io_available: task.storage_io_available,
                tree_cpu_percent: 0.0,
                tree_gpu_percent: 0.0,
                tree_rss_bytes: task.resident_size,
                tree_network_in_bytes_per_second: 0.0,
                tree_network_out_bytes_per_second: 0.0,
                tree_storage_read_bytes_per_second: 0.0,
                tree_storage_write_bytes_per_second: 0.0,
                tree_storage_io_available: false,
                descendant_count: 0,
                children: Vec::new(),
                name: metadata.name,
                app_bundle_path: metadata.app_bundle_path,
                executable_path: metadata.executable_path,
                command_line: metadata.command_line,
                application_id: String::new(),
                icon_uri: None,
            };
        }

        let executable_path = pid_executable_path(pid);
        let command_line = pid_command_line(pid);
        ProcessRecord {
            identity: ProcessIdentity {
                pid,
                start_time_unix_ms: 0,
            },
            ppid: snapshot.ppid,
            uid: 0,
            user: "0".to_string(),
            status: ProcessStatus::Unknown,
            flags: 0,
            rss_bytes: 0,
            virtual_memory_bytes: 0,
            cpu_time_nanos: 0,
            thread_count: 0,
            open_file_count: 0,
            local_ports: None,
            listening_ports: None,
            nice: 0,
            priority: 0,
            cpu_percent: 0.0,
            gpu_percent: 0.0,
            network_in_bytes_per_second: 0.0,
            network_out_bytes_per_second: 0.0,
            total_network_in_bytes: 0,
            total_network_out_bytes: 0,
            storage_read_bytes_per_second: 0.0,
            storage_write_bytes_per_second: 0.0,
            total_storage_read_bytes: 0,
            total_storage_write_bytes: 0,
            storage_io_available: false,
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
            name: best_process_name("", &snapshot.name, &executable_path, &snapshot.name),
            app_bundle_path: app_bundle_path(&executable_path),
            executable_path,
            command_line,
            application_id: String::new(),
            icon_uri: None,
        }
    }

    struct TaskMetrics {
        resident_size: u64,
        virtual_size: u64,
        cpu_time_nanos: u64,
        thread_count: u32,
        priority: i32,
        storage_read_bytes: u64,
        storage_write_bytes: u64,
        storage_io_available: bool,
    }

    fn task_metrics(pid: i32) -> TaskMetrics {
        let mut task = mem::MaybeUninit::<ProcTaskInfo>::uninit();
        let task_size = mem::size_of::<ProcTaskInfo>() as i32;
        let ret = unsafe {
            libc::proc_pidinfo(
                pid,
                PROC_PIDTASKINFO,
                0,
                task.as_mut_ptr() as *mut _,
                task_size,
            )
        };
        if ret <= 0 {
            return TaskMetrics {
                resident_size: 0,
                virtual_size: 0,
                cpu_time_nanos: 0,
                thread_count: 0,
                priority: 0,
                storage_read_bytes: 0,
                storage_write_bytes: 0,
                storage_io_available: false,
            };
        }
        let task = unsafe { task.assume_init() };
        let storage_io = storage_io_metrics(pid);
        let total_ticks = task.pti_total_user.saturating_add(task.pti_total_system);
        TaskMetrics {
            resident_size: task.pti_resident_size,
            virtual_size: task.pti_virtual_size,
            cpu_time_nanos: mach_ticks_to_ns(total_ticks),
            thread_count: task.pti_threadnum.max(0) as u32,
            priority: task.pti_priority,
            storage_read_bytes: storage_io.map_or(0, |value| value.0),
            storage_write_bytes: storage_io.map_or(0, |value| value.1),
            storage_io_available: storage_io.is_some(),
        }
    }

    fn storage_io_metrics(pid: i32) -> Option<(u64, u64)> {
        let mut usage = mem::MaybeUninit::<libc::rusage_info_v3>::uninit();
        let result = unsafe {
            libc::proc_pid_rusage(
                pid,
                libc::RUSAGE_INFO_V3,
                usage.as_mut_ptr().cast::<libc::rusage_info_t>(),
            )
        };
        if result != 0 {
            return None;
        }
        let usage = unsafe { usage.assume_init() };
        Some((usage.ri_diskio_bytesread, usage.ri_diskio_byteswritten))
    }

    #[derive(Clone, Copy)]
    struct CpuSample {
        total_nanos: u64,
    }

    pub struct CpuSampler {
        last_wall: Option<Instant>,
        samples: HashMap<(i32, u64), CpuSample>,
    }

    impl CpuSampler {
        pub fn new() -> Self {
            Self {
                last_wall: None,
                samples: HashMap::new(),
            }
        }

        pub fn apply(&mut self, records: &mut [ProcessRecord]) {
            let now = Instant::now();
            let wall_nanos = match self.last_wall {
                Some(previous) => now.duration_since(previous).as_nanos() as u64,
                None => {
                    self.seed_samples(records);
                    self.last_wall = Some(now);
                    return;
                }
            };
            self.last_wall = Some(now);
            if wall_nanos == 0 {
                return;
            }

            let mut seen = HashMap::with_capacity(records.len());
            for record in records.iter_mut() {
                let key = record.identity_key();
                seen.insert(key, ());
                let total_nanos = record.cpu_time_nanos;
                let cpu_percent = if let Some(previous) = self.samples.get(&key) {
                    let delta_nanos = total_nanos.saturating_sub(previous.total_nanos);
                    (delta_nanos as f64 / wall_nanos as f64) * 100.0
                } else {
                    0.0
                };
                record.cpu_percent = cpu_percent.clamp(0.0, max_process_cpu_percent());
                self.samples.insert(key, CpuSample { total_nanos });
            }

            self.samples.retain(|key, _| seen.contains_key(key));
        }

        fn seed_samples(&mut self, records: &mut [ProcessRecord]) {
            for record in records {
                record.cpu_percent = 0.0;
                self.samples.insert(
                    record.identity_key(),
                    CpuSample {
                        total_nanos: record.cpu_time_nanos,
                    },
                );
            }
        }
    }

    fn mach_ticks_to_ns(ticks: u64) -> u64 {
        mach_ticks_to_ns_with_timebase(ticks, mach_timebase())
    }

    fn mach_ticks_to_ns_with_timebase(ticks: u64, timebase: MachTimebase) -> u64 {
        if timebase.denom == 0 {
            return ticks;
        }
        let nanos = (ticks as u128).saturating_mul(timebase.numer as u128) / timebase.denom as u128;
        nanos.min(u64::MAX as u128) as u64
    }

    fn mach_timebase() -> MachTimebase {
        static TIMEBASE: OnceLock<MachTimebase> = OnceLock::new();
        *TIMEBASE.get_or_init(|| {
            let mut info = MachTimebaseInfo { numer: 1, denom: 1 };
            let ret = unsafe { mach_timebase_info(&mut info) };
            if ret == 0 && info.numer != 0 && info.denom != 0 {
                MachTimebase {
                    numer: info.numer,
                    denom: info.denom,
                }
            } else {
                MachTimebase { numer: 1, denom: 1 }
            }
        })
    }

    fn max_process_cpu_percent() -> f64 {
        static MAX_CPU_PERCENT: OnceLock<f64> = OnceLock::new();
        *MAX_CPU_PERCENT.get_or_init(|| {
            std::thread::available_parallelism()
                .map(|count| count.get() as f64 * 100.0)
                .unwrap_or(100.0)
        })
    }

    fn pid_executable_path(pid: i32) -> String {
        let mut buf = [0u8; 4096];
        let len = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut _, buf.len() as u32) };
        if len <= 0 {
            return String::new();
        }
        String::from_utf8_lossy(&buf[..len as usize]).into_owned()
    }

    fn pid_command_line(pid: i32) -> String {
        const KERN_PROCARGS2: i32 = 49;
        let mut mib = [libc::CTL_KERN, KERN_PROCARGS2, pid];
        let mut len = 0usize;
        let size_probe = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                3,
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if size_probe != 0 || len < mem::size_of::<i32>() {
            return String::new();
        }

        let mut buf = vec![0u8; len];
        let ret = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                3,
                buf.as_mut_ptr() as *mut _,
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if ret != 0 || len < mem::size_of::<i32>() {
            return String::new();
        }
        buf.truncate(len);

        let argc = i32::from_ne_bytes(buf[..4].try_into().unwrap_or_default()).max(0) as usize;
        let mut cursor = 4;
        while cursor < buf.len() && buf[cursor] != 0 {
            cursor += 1;
        }
        while cursor < buf.len() && buf[cursor] == 0 {
            cursor += 1;
        }

        let mut args = Vec::new();
        for _ in 0..argc {
            if cursor >= buf.len() {
                break;
            }
            let end = buf[cursor..]
                .iter()
                .position(|&byte| byte == 0)
                .map(|offset| cursor + offset)
                .unwrap_or(buf.len());
            if end > cursor {
                args.push(String::from_utf8_lossy(&buf[cursor..end]).into_owned());
            }
            cursor = end.saturating_add(1);
        }
        args.join(" ")
    }

    fn user_name_for_uid(uid: u32) -> String {
        let mut passwd = mem::MaybeUninit::<libc::passwd>::uninit();
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let mut buffer = vec![0i8; 16_384];
        let ret = unsafe {
            libc::getpwuid_r(
                uid,
                passwd.as_mut_ptr(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
            )
        };
        if ret == 0 && !result.is_null() {
            let name = unsafe { CStr::from_ptr((*result).pw_name) };
            return name.to_string_lossy().into_owned();
        }
        uid.to_string()
    }

    fn cstr_to_string(buf: &[i8]) -> String {
        let bytes: Vec<u8> = buf
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn cstr_from_bytes(buf: &[u8]) -> String {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..end]).into_owned()
    }

    fn best_process_name(
        pbi_name: &str,
        pbi_comm: &str,
        executable_path: &str,
        fallback: &str,
    ) -> String {
        let path_base = executable_path
            .rsplit('/')
            .next()
            .filter(|name| !name.is_empty())
            .unwrap_or("");
        let bundle_display_name = bundle_display_name_from_path(executable_path);
        let candidates = [
            bundle_display_name.as_deref().unwrap_or(""),
            pbi_name,
            path_base,
            pbi_comm,
            fallback,
        ];
        let selected = candidates
            .into_iter()
            .filter(|name| !name.is_empty() && !name.starts_with("pid-"))
            .find(|name| is_useful_process_name(name))
            .unwrap_or(fallback);
        selected.to_string()
    }

    fn is_useful_process_name(value: &str) -> bool {
        let trimmed = value.trim();
        trimmed.len() > 2 && trimmed != "." && trimmed != ".."
    }

    fn app_bundle_path(executable_path: &str) -> String {
        let marker = ".app/Contents/";
        let Some(index) = executable_path.rfind(marker) else {
            return String::new();
        };
        executable_path[..index + ".app".len()].to_string()
    }

    fn bundle_display_name_from_path(executable_path: &str) -> Option<String> {
        let bundle_path = app_bundle_path(executable_path);
        let bundle_name = bundle_path.rsplit('/').next()?.strip_suffix(".app")?.trim();
        is_useful_process_name(bundle_name).then(|| bundle_name.to_string())
    }

    fn status_from_pbi(status: u32) -> ProcessStatus {
        match status {
            1 | 2 => ProcessStatus::Running,
            3 => ProcessStatus::Sleeping,
            4 => ProcessStatus::Stopped,
            5 => ProcessStatus::Zombie,
            _ => ProcessStatus::Unknown,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn derives_display_name_from_app_bundle_with_spaces() {
            let path = "/Applications/Visual Studio Code.app/Contents/MacOS/Electron";
            assert_eq!(
                bundle_display_name_from_path(path).as_deref(),
                Some("Visual Studio Code")
            );
            assert_eq!(
                best_process_name("", "Visual", path, "Visual"),
                "Visual Studio Code"
            );
        }

        #[test]
        fn uses_nearest_nested_app_bundle_name() {
            let path = "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Renderer).app/Contents/MacOS/Code Helper (Renderer)";
            assert_eq!(
                app_bundle_path(path),
                "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Renderer).app"
            );
            assert_eq!(
                bundle_display_name_from_path(path).as_deref(),
                Some("Code Helper (Renderer)")
            );
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod apple_gpu {
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::sync::OnceLock;
    use std::time::Instant;

    use core_foundation::base::{CFRelease, TCFType};
    use core_foundation::string::CFString;

    use crate::model::ProcessRecord;

    type KernReturn = i32;
    type MachPort = u32;
    type IoObject = u32;
    type IoIterator = u32;
    type IoRegistryEntry = u32;
    type CfTypeRef = *const c_void;
    type CfDictionaryRef = *const c_void;
    type CfArrayRef = *const c_void;

    const KERN_SUCCESS: KernReturn = 0;
    const K_CF_NUMBER_SINT64_TYPE: u8 = 4;

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFGetTypeID(cf: CfTypeRef) -> usize;
        fn CFArrayGetTypeID() -> usize;
        fn CFStringGetTypeID() -> usize;
        fn CFDictionaryGetTypeID() -> usize;
        fn CFNumberGetTypeID() -> usize;
        fn CFArrayGetCount(array: CfArrayRef) -> isize;
        fn CFArrayGetValueAtIndex(array: CfArrayRef, idx: isize) -> CfTypeRef;
        fn CFDictionaryGetValue(dict: CfDictionaryRef, key: CfTypeRef) -> CfTypeRef;
        fn CFNumberGetValue(number: CfTypeRef, ty: u8, value_out: *mut i64) -> u8;
    }

    #[link(name = "IOKit", kind = "framework")]
    unsafe extern "C" {
        fn IOServiceGetMatchingServices(
            master_port: MachPort,
            matching: CfTypeRef,
            existing: *mut IoIterator,
        ) -> KernReturn;
        fn IOServiceMatching(name: *const u8) -> CfTypeRef;
        fn IOIteratorNext(iterator: IoIterator) -> IoObject;
        fn IOObjectRelease(object: IoObject) -> KernReturn;
        fn IORegistryEntryGetChildIterator(
            entry: IoRegistryEntry,
            plane: *const u8,
            iterator: *mut IoIterator,
        ) -> KernReturn;
        fn IORegistryEntryCreateCFProperty(
            entry: IoRegistryEntry,
            key: CfTypeRef,
            allocator: CfTypeRef,
            options: u32,
        ) -> CfTypeRef;
    }

    #[derive(Clone, Copy)]
    struct GpuSample {
        total_nanos: u64,
    }

    pub struct GpuSampler {
        last_wall: Option<Instant>,
        samples: HashMap<i32, GpuSample>,
        last_percent: HashMap<i32, f64>,
    }

    impl GpuSampler {
        pub fn new() -> Self {
            Self {
                last_wall: None,
                samples: HashMap::new(),
                last_percent: HashMap::new(),
            }
        }

        pub fn apply_cached(&mut self, records: &mut [ProcessRecord]) {
            let mut seen = HashMap::with_capacity(records.len());
            for record in records {
                seen.insert(record.pid(), ());
                record.gpu_percent = self
                    .last_percent
                    .get(&record.pid())
                    .copied()
                    .unwrap_or(0.0)
                    .clamp(0.0, 100.0);
            }
            self.last_percent.retain(|pid, _| seen.contains_key(pid));
        }

        pub fn apply(&mut self, records: &mut [ProcessRecord]) {
            let now = Instant::now();
            let wall_nanos = match self.last_wall {
                Some(previous) => now.duration_since(previous).as_nanos() as u64,
                None => {
                    self.seed_samples(records);
                    self.last_wall = Some(now);
                    return;
                }
            };
            self.last_wall = Some(now);
            if wall_nanos == 0 {
                return;
            }

            let Some(current) = scan_gpu_nanos_by_pid() else {
                return;
            };

            let mut seen = HashMap::with_capacity(records.len());
            for record in records {
                seen.insert(record.pid(), ());
                let total_nanos = current.get(&record.pid()).copied().unwrap_or(0);
                let gpu_percent = if let Some(previous) = self.samples.get(&record.pid()) {
                    let delta_nanos = total_nanos.saturating_sub(previous.total_nanos);
                    (delta_nanos as f64 / wall_nanos as f64) * 100.0
                } else {
                    0.0
                };
                let clamped = gpu_percent.clamp(0.0, 100.0);
                record.gpu_percent = clamped;
                self.last_percent.insert(record.pid(), clamped);
                self.samples.insert(record.pid(), GpuSample { total_nanos });
            }

            self.samples.retain(|pid, _| seen.contains_key(pid));
            self.last_percent.retain(|pid, _| seen.contains_key(pid));
        }

        fn seed_samples(&mut self, records: &mut [ProcessRecord]) {
            let current = scan_gpu_nanos_by_pid().unwrap_or_default();
            for record in records {
                let total_nanos = current.get(&record.pid()).copied().unwrap_or(0);
                record.gpu_percent = 0.0;
                self.samples.insert(record.pid(), GpuSample { total_nanos });
            }
        }
    }

    pub fn probe_available() -> bool {
        static AVAILABLE: OnceLock<bool> = OnceLock::new();
        *AVAILABLE.get_or_init(|| scan_gpu_nanos_by_pid().is_some())
    }

    fn scan_gpu_nanos_by_pid() -> Option<HashMap<i32, u64>> {
        unsafe {
            let matching = IOServiceMatching(b"AGXAccelerator\0".as_ptr());
            if matching.is_null() {
                return None;
            }
            let mut accelerator_iterator: IoIterator = 0;
            let result = IOServiceGetMatchingServices(0, matching, &mut accelerator_iterator);
            if result != KERN_SUCCESS || accelerator_iterator == 0 {
                if accelerator_iterator != 0 {
                    IOObjectRelease(accelerator_iterator);
                }
                return None;
            }

            let mut totals = HashMap::new();
            let key_creator = CFString::new("IOUserClientCreator");
            let key_usage = CFString::new("AppUsage");
            loop {
                let accelerator = IOIteratorNext(accelerator_iterator);
                if accelerator == 0 {
                    break;
                }
                collect_gpu_clients_under(accelerator, &key_creator, &key_usage, &mut totals);
                IOObjectRelease(accelerator);
            }
            IOObjectRelease(accelerator_iterator);
            Some(totals)
        }
    }

    unsafe fn collect_gpu_clients_under(
        entry: IoRegistryEntry,
        key_creator: &CFString,
        key_usage: &CFString,
        totals: &mut HashMap<i32, u64>,
    ) {
        let mut child_iterator: IoIterator = 0;
        let result =
            IORegistryEntryGetChildIterator(entry, b"IOService\0".as_ptr(), &mut child_iterator);
        if result != KERN_SUCCESS || child_iterator == 0 {
            return;
        }
        loop {
            let child = IOIteratorNext(child_iterator);
            if child == 0 {
                break;
            }
            if let Some(pid) = read_creator_pid(child, key_creator) {
                let nanos = read_app_usage_nanos(child, key_usage);
                totals
                    .entry(pid)
                    .and_modify(|total| *total = total.saturating_add(nanos))
                    .or_insert(nanos);
            }
            IOObjectRelease(child);
        }
        IOObjectRelease(child_iterator);
    }

    unsafe fn read_creator_pid(entry: IoRegistryEntry, key: &CFString) -> Option<i32> {
        let value = IORegistryEntryCreateCFProperty(
            entry,
            key.as_concrete_TypeRef() as CfTypeRef,
            std::ptr::null(),
            0,
        );
        if value.is_null() {
            return None;
        }
        if CFGetTypeID(value) != CFStringGetTypeID() {
            CFRelease(value);
            return None;
        }
        let creator = CFString::wrap_under_create_rule(value as _).to_string();
        parse_creator_pid(&creator)
    }

    unsafe fn read_app_usage_nanos(entry: IoRegistryEntry, key: &CFString) -> u64 {
        let value = IORegistryEntryCreateCFProperty(
            entry,
            key.as_concrete_TypeRef() as CfTypeRef,
            std::ptr::null(),
            0,
        );
        if value.is_null() {
            return 0;
        }
        if CFGetTypeID(value) != CFArrayGetTypeID() {
            CFRelease(value);
            return 0;
        }

        let array_ref = value as CfArrayRef;
        let count = CFArrayGetCount(array_ref);
        let key_time = CFString::new("accumulatedGPUTime");
        let mut total = 0u64;
        for index in 0..count {
            let dictionary_ref = CFArrayGetValueAtIndex(array_ref, index);
            if dictionary_ref.is_null() || CFGetTypeID(dictionary_ref) != CFDictionaryGetTypeID() {
                continue;
            }
            let time_ref = CFDictionaryGetValue(
                dictionary_ref as CfDictionaryRef,
                key_time.as_concrete_TypeRef() as CfTypeRef,
            );
            if time_ref.is_null() || CFGetTypeID(time_ref) != CFNumberGetTypeID() {
                continue;
            }
            let mut raw = 0i64;
            if CFNumberGetValue(time_ref, K_CF_NUMBER_SINT64_TYPE, &mut raw) != 0 {
                total = total.saturating_add(raw.max(0) as u64);
            }
        }
        CFRelease(value);
        total
    }

    fn parse_creator_pid(creator: &str) -> Option<i32> {
        let rest = creator.strip_prefix("pid ")?;
        let pid_part = rest.split(',').next()?.trim();
        pid_part.parse().ok()
    }
}
