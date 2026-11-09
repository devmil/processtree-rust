use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::error::ProcessTreeError;
use crate::model::{ProcessIdentity, ProcessRecord, ProcessStatus};
use crate::platform::ProcessMetadata;

pub(super) mod system_special_cases;

const MAX_GPU_FDINFO_FILES_PER_PROCESS: usize = 256;
const GPU_DESCRIPTOR_REDISCOVERY_SCANS: u64 = 5;

pub fn enumerate_processes() -> Result<Vec<ProcessRecord>, ProcessTreeError> {
    enumerate_processes_reusing_metadata(&HashMap::new(), true)
}

pub(crate) fn enumerate_processes_reusing_metadata(
    metadata: &HashMap<(i32, u64), ProcessMetadata>,
    refresh_metadata: bool,
) -> Result<Vec<ProcessRecord>, ProcessTreeError> {
    let root = host_root();
    let proc_root = root.join("proc");
    let users = load_users(&root);
    let system = LinuxSystemInfo {
        boot_time_unix_ms: boot_time_unix_ms(&proc_root),
        clock_ticks_per_second: clock_ticks_per_second(),
        page_size: page_size(),
    };
    let entries = fs::read_dir(&proc_root)
        .map_err(|error| ProcessTreeError::Enumeration(error.to_string()))?;
    let mut records = entries
        .flatten()
        .filter_map(|entry| entry.file_name().to_string_lossy().parse::<i32>().ok())
        .filter_map(|pid| {
            read_process(&proc_root, pid, &users, system, metadata, refresh_metadata).ok()
        })
        .collect::<Vec<_>>();
    records.sort_by_key(ProcessRecord::pid);
    Ok(records)
}

pub(crate) struct CpuSampler {
    sampled_at: Option<Instant>,
    ticks_by_identity: HashMap<(i32, u64), u64>,
}

pub(crate) struct GpuSampler {
    sampled_at: Option<Instant>,
    nanos_by_identity: HashMap<(i32, u64), u64>,
    last_percent_by_identity: HashMap<(i32, u64), f64>,
    drm_descriptors_by_identity: HashMap<(i32, u64), Vec<OsString>>,
    full_scan_count: u64,
}

impl GpuSampler {
    pub fn new() -> Self {
        Self {
            sampled_at: None,
            nanos_by_identity: HashMap::new(),
            last_percent_by_identity: HashMap::new(),
            drm_descriptors_by_identity: HashMap::new(),
            full_scan_count: 0,
        }
    }

    pub fn apply_cached(&mut self, records: &mut [ProcessRecord]) {
        let mut seen = HashMap::with_capacity(records.len());
        for record in records {
            let identity = record.identity_key();
            seen.insert(identity, ());
            record.gpu_percent = self
                .last_percent_by_identity
                .get(&identity)
                .copied()
                .unwrap_or(0.0);
        }
        self.last_percent_by_identity
            .retain(|identity, _| seen.contains_key(identity));
    }

    pub fn apply(&mut self, records: &mut [ProcessRecord]) {
        let now = Instant::now();
        self.full_scan_count = self.full_scan_count.saturating_add(1);
        let rediscover_descriptors = self.full_scan_count == 1
            || self
                .full_scan_count
                .is_multiple_of(GPU_DESCRIPTOR_REDISCOVERY_SCANS);
        let elapsed_nanos = self
            .sampled_at
            .map(|sampled_at| now.duration_since(sampled_at).as_nanos() as u64);
        let proc_root = host_root().join("proc");
        let effective_uid = unsafe { libc::geteuid() };
        let mut next = HashMap::new();
        let mut seen = HashMap::with_capacity(records.len());

        for record in records {
            let identity = record.identity_key();
            seen.insert(identity, ());
            if effective_uid != 0 && record.uid != effective_uid {
                record.gpu_percent = 0.0;
                self.last_percent_by_identity.insert(identity, 0.0);
                continue;
            }
            let discover =
                rediscover_descriptors || !self.drm_descriptors_by_identity.contains_key(&identity);
            if discover {
                let descriptors =
                    discover_drm_descriptors(&proc_root, record.pid()).unwrap_or_default();
                self.drm_descriptors_by_identity
                    .insert(identity, descriptors);
            }
            let mut descriptors = self
                .drm_descriptors_by_identity
                .get(&identity)
                .cloned()
                .unwrap_or_default();
            let mut current =
                process_gpu_nanos_from_descriptors(&proc_root, record.pid(), &descriptors);
            if current.is_none() && !discover && !descriptors.is_empty() {
                descriptors =
                    discover_drm_descriptors(&proc_root, record.pid()).unwrap_or_default();
                current =
                    process_gpu_nanos_from_descriptors(&proc_root, record.pid(), &descriptors);
                self.drm_descriptors_by_identity
                    .insert(identity, descriptors);
            }
            record.gpu_percent = match (
                elapsed_nanos,
                current,
                self.nanos_by_identity.get(&identity),
            ) {
                (Some(wall), Some(current), Some(previous)) if wall > 0 => {
                    let percent = current.saturating_sub(*previous) as f64 / wall as f64 * 100.0;
                    percent.clamp(0.0, 100.0)
                }
                _ => 0.0,
            };
            if let Some(current) = current {
                next.insert(identity, current);
            }
            self.last_percent_by_identity
                .insert(identity, record.gpu_percent);
        }

        self.sampled_at = Some(now);
        self.nanos_by_identity = next;
        self.last_percent_by_identity
            .retain(|identity, _| seen.contains_key(identity));
        self.drm_descriptors_by_identity
            .retain(|identity, _| seen.contains_key(identity));
    }
}

#[cfg(test)]
fn process_gpu_nanos(proc_root: &Path, pid: i32) -> Option<u64> {
    let descriptors = discover_drm_descriptors(proc_root, pid)?;
    process_gpu_nanos_from_descriptors(proc_root, pid, &descriptors)
}

fn discover_drm_descriptors(proc_root: &Path, pid: i32) -> Option<Vec<OsString>> {
    let process_root = proc_root.join(pid.to_string());
    let entries = fs::read_dir(process_root.join("fd")).ok()?;
    let mut descriptors = Vec::new();
    for entry in entries.flatten() {
        let Ok(target) = fs::read_link(entry.path()) else {
            continue;
        };
        if is_drm_fd_target(&target) {
            descriptors.push(entry.file_name());
            if descriptors.len() >= MAX_GPU_FDINFO_FILES_PER_PROCESS {
                break;
            }
        }
    }
    Some(descriptors)
}

fn process_gpu_nanos_from_descriptors(
    proc_root: &Path,
    pid: i32,
    descriptors: &[OsString],
) -> Option<u64> {
    let fdinfo_root = proc_root.join(pid.to_string()).join("fdinfo");
    let mut clients = HashMap::<String, u64>::new();
    let mut anonymous_total = 0u64;
    let mut found = false;

    for descriptor in descriptors {
        let Ok(contents) = fs::read_to_string(fdinfo_root.join(descriptor)) else {
            continue;
        };
        let Some(sample) = parse_drm_fdinfo(&contents) else {
            continue;
        };
        found = true;
        if let Some(client_key) = sample.client_key {
            clients
                .entry(client_key)
                .and_modify(|current| *current = (*current).max(sample.engine_nanos))
                .or_insert(sample.engine_nanos);
        } else {
            anonymous_total = anonymous_total.saturating_add(sample.engine_nanos);
        }
    }

    found.then(|| {
        clients
            .into_values()
            .fold(anonymous_total, u64::saturating_add)
    })
}

fn is_drm_fd_target(target: &Path) -> bool {
    let Some(name) = target.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let under_dri = target
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|directory| directory == "dri");
    under_dri && (name.starts_with("card") || name.starts_with("renderD"))
}

struct DrmFdinfoSample {
    client_key: Option<String>,
    engine_nanos: u64,
}

fn parse_drm_fdinfo(contents: &str) -> Option<DrmFdinfoSample> {
    let mut client_id = None;
    let mut device = None;
    let mut engine_nanos = 0u64;
    let mut has_engine_counter = false;

    for line in contents.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            "drm-client-id" => client_id = value.split_whitespace().next().map(str::to_owned),
            "drm-pdev" | "drm-device" => {
                device = value.split_whitespace().next().map(str::to_owned);
            }
            _ if key.starts_with("drm-engine-") && !key.starts_with("drm-engine-capacity-") => {
                if let Some(nanos) = value
                    .split_whitespace()
                    .next()
                    .and_then(|number| number.parse::<u64>().ok())
                {
                    engine_nanos = engine_nanos.saturating_add(nanos);
                    has_engine_counter = true;
                }
            }
            _ => {}
        }
    }

    has_engine_counter.then(|| DrmFdinfoSample {
        client_key: client_id.map(|client| format!("{}:{client}", device.unwrap_or_default())),
        engine_nanos,
    })
}

pub(crate) fn gpu_metrics_available() -> bool {
    fs::read_dir(host_root().join("sys/class/drm"))
        .map(|entries| {
            entries.flatten().any(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.starts_with("card") || name.starts_with("renderD")
            })
        })
        .unwrap_or(false)
}

impl CpuSampler {
    pub fn new() -> Self {
        Self {
            sampled_at: None,
            ticks_by_identity: HashMap::new(),
        }
    }

    pub fn apply(&mut self, records: &mut [ProcessRecord]) {
        let now = Instant::now();
        let elapsed = self
            .sampled_at
            .map(|sampled_at| now.duration_since(sampled_at).as_secs_f64());
        let ticks_per_second = clock_ticks_per_second() as f64;
        let mut next = HashMap::new();
        for record in records {
            let identity = record.identity_key();
            let current = nanos_to_ticks(record.cpu_time_nanos);
            if let (Some(seconds), Some(previous)) =
                (elapsed, self.ticks_by_identity.get(&identity))
            {
                if seconds > 0.0 {
                    record.cpu_percent =
                        current.saturating_sub(*previous) as f64 / ticks_per_second / seconds
                            * 100.0;
                }
            }
            next.insert(identity, current);
        }
        self.sampled_at = Some(now);
        self.ticks_by_identity = next;
    }
}

struct ProcStat {
    name: String,
    status: char,
    ppid: i32,
    flags: u32,
    cpu_ticks: u64,
    priority: i32,
    nice: i32,
    thread_count: u32,
    start_ticks: u64,
    virtual_memory_bytes: u64,
    rss_pages: i64,
}

#[derive(Clone, Copy)]
struct LinuxSystemInfo {
    boot_time_unix_ms: u64,
    clock_ticks_per_second: u64,
    page_size: u64,
}

fn read_process(
    proc_root: &Path,
    pid: i32,
    users: &HashMap<u32, String>,
    system: LinuxSystemInfo,
    metadata_cache: &HashMap<(i32, u64), ProcessMetadata>,
    refresh_metadata: bool,
) -> Result<ProcessRecord, ProcessTreeError> {
    let directory = proc_root.join(pid.to_string());
    let raw_stat = fs::read_to_string(directory.join("stat"))
        .map_err(|error| ProcessTreeError::Enumeration(error.to_string()))?;
    let stat = parse_stat(&raw_stat)
        .ok_or_else(|| ProcessTreeError::Enumeration(format!("invalid /proc/{pid}/stat")))?;
    // Walking every /proc/<pid>/fd directory on every metrics poll is costly
    // and duplicates the on-demand file inspection path. Linux callers get
    // the selected process count from ProcessDetail instead.
    let open_file_count = 0;
    let start_time_unix_ms = system
        .boot_time_unix_ms
        .saturating_add(stat.start_ticks.saturating_mul(1000) / system.clock_ticks_per_second);
    let identity_key = (pid, start_time_unix_ms);
    let metadata = (!refresh_metadata)
        .then(|| metadata_cache.get(&identity_key))
        .flatten()
        .cloned()
        .unwrap_or_else(|| read_process_metadata(&directory, users));
    let storage_io = read_storage_io(&directory);
    Ok(ProcessRecord {
        identity: ProcessIdentity {
            pid,
            start_time_unix_ms,
        },
        ppid: stat.ppid,
        uid: metadata.uid,
        user: metadata.user,
        status: map_status(stat.status),
        flags: stat.flags,
        rss_bytes: stat.rss_pages.max(0) as u64 * system.page_size,
        virtual_memory_bytes: stat.virtual_memory_bytes,
        cpu_time_nanos: stat.cpu_ticks.saturating_mul(1_000_000_000)
            / system.clock_ticks_per_second,
        thread_count: stat.thread_count,
        open_file_count,
        local_ports: None,
        listening_ports: None,
        nice: stat.nice,
        priority: stat.priority,
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
        name: stat.name,
        executable_path: metadata.executable_path,
        command_line: metadata.command_line,
        app_bundle_path: metadata.app_bundle_path,
        application_id: metadata.application_id,
        icon_uri: None,
    })
}

fn read_storage_io(directory: &Path) -> Option<(u64, u64)> {
    let contents = fs::read_to_string(directory.join("io")).ok()?;
    parse_storage_io(&contents)
}

fn parse_storage_io(contents: &str) -> Option<(u64, u64)> {
    let mut read_bytes = None;
    let mut write_bytes = None;
    for line in contents.lines() {
        let (name, value) = line.split_once(':')?;
        let value = value.trim().parse::<u64>().ok()?;
        match name {
            "read_bytes" => read_bytes = Some(value),
            "write_bytes" => write_bytes = Some(value),
            _ => {}
        }
    }
    Some((read_bytes?, write_bytes?))
}

fn read_process_metadata(directory: &Path, users: &HashMap<u32, String>) -> ProcessMetadata {
    let status_text = fs::read_to_string(directory.join("status")).unwrap_or_default();
    let uid = status_text
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let command_line_bytes = fs::read(directory.join("cmdline")).unwrap_or_default();
    let command_arguments = command_line_bytes
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .map(|argument| String::from_utf8_lossy(argument).into_owned())
        .collect::<Vec<_>>();
    let command_line = String::from_utf8_lossy(&command_line_bytes)
        .trim_end_matches('\0')
        .replace('\0', " ");
    let executable_path = fs::read_link(directory.join("exe"))
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default();
    let application_id = fs::read_to_string(directory.join("cgroup"))
        .ok()
        .and_then(|text| desktop_application_id_from_cgroup(&text))
        .unwrap_or_default();
    let application_source = system_special_cases::application_source(
        &executable_path,
        &command_arguments,
        &application_id,
    )
    .to_owned();
    ProcessMetadata {
        uid,
        user: users.get(&uid).cloned().unwrap_or_else(|| uid.to_string()),
        executable_path: executable_path.clone(),
        command_line,
        // Linux has no application bundle. The icon resolver uses this field
        // as its stable source key and maps the executable or an exact system
        // wrapper launch target to a desktop entry.
        app_bundle_path: application_source,
        application_id,
    }
}

fn desktop_application_id_from_cgroup(text: &str) -> Option<String> {
    text.lines()
        .filter_map(|line| line.rsplit_once(':').map(|(_, path)| path))
        .flat_map(|path| path.rsplit('/'))
        .find_map(desktop_application_id_from_component)
}

fn desktop_application_id_from_component(component: &str) -> Option<String> {
    let stem = component
        .strip_prefix("app-")
        .or_else(|| component.strip_prefix("apps-"))?;
    let application_id = if let Some(scope) = stem.strip_suffix(".scope") {
        let mut fields = scope.rsplit('-');
        let instance = fields.next()?;
        if instance.is_empty() {
            return None;
        }
        fields.next()?
    } else if let Some(service) = stem.strip_suffix(".service") {
        service.split('@').next()?.rsplit('-').next()?
    } else {
        let slice = stem.strip_suffix(".slice")?;
        slice.rsplit('-').next()?
    };
    if application_id.is_empty() {
        return None;
    }
    Some(unescape_systemd_component(application_id))
}

fn unescape_systemd_component(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' && bytes.get(index + 1) == Some(&b'x') && index + 3 < bytes.len() {
            let hex = &value[index + 2..index + 4];
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                result.push(byte);
                index += 4;
                continue;
            }
        }
        result.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&result).into_owned()
}

fn parse_stat(value: &str) -> Option<ProcStat> {
    let open = value.find('(')?;
    let close = value.rfind(')')?;
    let fields: Vec<_> = value.get(close + 2..)?.split_whitespace().collect();
    Some(ProcStat {
        name: value.get(open + 1..close)?.to_string(),
        status: fields.first()?.chars().next()?,
        ppid: fields.get(1)?.parse().ok()?,
        flags: fields.get(6)?.parse().ok()?,
        cpu_ticks: fields
            .get(11)?
            .parse::<u64>()
            .ok()?
            .saturating_add(fields.get(12)?.parse().ok()?),
        priority: fields.get(15)?.parse().ok()?,
        nice: fields.get(16)?.parse().ok()?,
        thread_count: fields.get(17)?.parse().ok()?,
        start_ticks: fields.get(19)?.parse().ok()?,
        virtual_memory_bytes: fields.get(20)?.parse().ok()?,
        rss_pages: fields.get(21)?.parse().ok()?,
    })
}

fn map_status(status: char) -> ProcessStatus {
    match status {
        'R' => ProcessStatus::Running,
        'S' | 'D' | 'I' => ProcessStatus::Sleeping,
        'T' | 't' => ProcessStatus::Stopped,
        'Z' => ProcessStatus::Zombie,
        _ => ProcessStatus::Unknown,
    }
}

fn clock_ticks_per_second() -> u64 {
    unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64
}

fn page_size() -> u64 {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(1) as u64
}

fn nanos_to_ticks(nanos: u64) -> u64 {
    nanos.saturating_mul(clock_ticks_per_second()) / 1_000_000_000
}

fn boot_time_unix_ms(proc_root: &Path) -> u64 {
    fs::read_to_string(proc_root.join("stat"))
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("btime ")?.parse::<u64>().ok())
        })
        .unwrap_or(0)
        .saturating_mul(1000)
}

fn load_users(root: &Path) -> HashMap<u32, String> {
    fs::read_to_string(root.join("etc/passwd"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?.to_string();
            fields.next()?;
            let uid = fields.next()?.parse().ok()?;
            Some((uid, name))
        })
        .collect()
}

pub(crate) fn host_root() -> PathBuf {
    host_root_for(
        std::env::var_os("FLATPAK_ID").is_some(),
        Path::new("/run/host/root/proc").is_dir(),
    )
}

pub(crate) fn uses_flatpak_host_root() -> bool {
    host_root() != Path::new("/")
}

fn host_root_for(is_flatpak: bool, flatpak_host_proc_exists: bool) -> PathBuf {
    if is_flatpak && flatpak_host_proc_exists {
        PathBuf::from("/run/host/root")
    } else {
        PathBuf::from("/")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_storage_io_counters_without_confusing_character_counts() {
        let counters = parse_storage_io(
            "rchar: 999\nwchar: 888\nread_bytes: 123\nwrite_bytes: 456\ncancelled_write_bytes: 7\n",
        );
        assert_eq!(counters, Some((123, 456)));
    }

    #[test]
    fn rejects_incomplete_storage_io_counters() {
        assert_eq!(parse_storage_io("read_bytes: 123\n"), None);
    }

    #[test]
    fn parses_stat_with_spaces_in_name() {
        let value =
            "42 (a process name) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22";
        let stat = parse_stat(value).expect("stat should parse");
        assert_eq!(stat.name, "a process name");
        assert_eq!(stat.ppid, 1);
        assert_eq!(stat.cpu_ticks, 23);
    }

    #[test]
    fn derives_desktop_application_id_from_systemd_cgroup() {
        let cgroup = "0::/user.slice/user-1000.slice/user@1000.service/\
                      app.slice/app-de.devmil.hoddmimis-680510.scope\n";
        assert_eq!(
            desktop_application_id_from_cgroup(cgroup).as_deref(),
            Some("de.devmil.hoddmimis")
        );
    }

    #[test]
    fn handles_launcher_prefix_service_and_systemd_escapes() {
        assert_eq!(
            desktop_application_id_from_component(r"app-flatpak-com.example.My\x2dApp-1742.scope")
                .as_deref(),
            Some("com.example.My-App")
        );
        assert_eq!(
            desktop_application_id_from_component("app-org.example.Service@wayland.service")
                .as_deref(),
            Some("org.example.Service")
        );
    }

    #[test]
    fn ignores_non_application_cgroups() {
        let cgroup = "0::/user.slice/user-1000.slice/user@1000.service/session.slice/\
                      pipewire.service\n";
        assert_eq!(desktop_application_id_from_cgroup(cgroup), None);
    }

    #[test]
    fn enumerates_current_process() {
        let records = enumerate_processes().expect("/proc should be readable");
        assert!(records
            .iter()
            .any(|record| record.pid() == std::process::id() as i32));
    }

    #[test]
    fn uses_host_root_for_flatpak_when_available() {
        assert_eq!(host_root_for(true, true), PathBuf::from("/run/host/root"));
        assert_eq!(host_root_for(true, false), PathBuf::from("/"));
        assert_eq!(host_root_for(false, true), PathBuf::from("/"));
    }

    #[test]
    fn parses_drm_engine_time_and_ignores_capacity_metadata() {
        let sample = parse_drm_fdinfo(
            "drm-driver:\tamdgpu\n\
             drm-pdev:\t0000:03:00.0\n\
             drm-client-id:\t7\n\
             drm-engine-gfx:\t1200 ns\n\
             drm-engine-compute:\t800 ns\n\
             drm-engine-capacity-gfx:\t2\n",
        )
        .expect("DRM engine sample");

        assert_eq!(sample.client_key.as_deref(), Some("0000:03:00.0:7"));
        assert_eq!(sample.engine_nanos, 2_000);
    }

    #[test]
    fn process_gpu_time_deduplicates_repeated_drm_client_descriptions() {
        let root = std::env::temp_dir().join(format!(
            "processtree-linux-gpu-{}-{}",
            std::process::id(),
            crate::unix_now_ms()
        ));
        let fdinfo = root.join("42/fdinfo");
        let descriptors = root.join("42/fd");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&fdinfo).expect("create fake fdinfo directory");
        fs::create_dir_all(&descriptors).expect("create fake descriptor directory");
        std::os::unix::fs::symlink("/dev/dri/renderD128", descriptors.join("3"))
            .expect("link first DRM descriptor");
        std::os::unix::fs::symlink("/dev/dri/renderD128", descriptors.join("4"))
            .expect("link duplicated DRM descriptor");
        std::os::unix::fs::symlink("/dev/dri/card1", descriptors.join("5"))
            .expect("link second DRM client");
        std::os::unix::fs::symlink("/tmp/plain-file", descriptors.join("6"))
            .expect("link non-DRM descriptor");
        let repeated = "drm-pdev:\t0000:03:00.0\ndrm-client-id:\t7\ndrm-engine-gfx:\t2000 ns\n";
        fs::write(fdinfo.join("3"), repeated).expect("write first DRM fdinfo");
        fs::write(fdinfo.join("4"), repeated).expect("write duplicated DRM fdinfo");
        fs::write(
            fdinfo.join("5"),
            "drm-pdev:\t0000:03:00.0\ndrm-client-id:\t8\ndrm-engine-gfx:\t500 ns\n",
        )
        .expect("write second DRM client");
        fs::write(fdinfo.join("6"), "pos:\t0\nflags:\t0100000\n").expect("write non-DRM fdinfo");

        assert_eq!(process_gpu_nanos(&root, 42), Some(2_500));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn drm_descriptor_targets_are_filtered_before_fdinfo_reads() {
        assert!(is_drm_fd_target(Path::new("/dev/dri/renderD128")));
        assert!(is_drm_fd_target(Path::new("/run/host/dev/dri/card1")));
        assert!(!is_drm_fd_target(Path::new("/dev/null")));
        assert!(!is_drm_fd_target(Path::new("/tmp/renderD128")));
    }
}
