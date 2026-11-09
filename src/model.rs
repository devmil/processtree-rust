use serde::{Deserialize, Serialize};

pub const PROCESS_TREE_FORMAT: &str = "de.devmil.processtree.snapshot";

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u32)]
pub enum ProcessStatus {
    Running = 0,
    Sleeping = 1,
    Stopped = 2,
    Zombie = 3,
    Unknown = 4,
}

impl From<u32> for ProcessStatus {
    fn from(value: u32) -> Self {
        match value {
            0 => Self::Running,
            1 => Self::Sleeping,
            2 => Self::Stopped,
            3 => Self::Zombie,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProcessIdentity {
    pub pid: i32,
    pub start_time_unix_ms: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct ProcessRecord {
    pub identity: ProcessIdentity,
    pub ppid: i32,
    pub uid: u32,
    pub user: String,
    pub status: ProcessStatus,
    pub flags: u32,
    pub rss_bytes: u64,
    pub virtual_memory_bytes: u64,
    pub cpu_time_nanos: u64,
    pub thread_count: u32,
    pub open_file_count: u32,
    /// Sorted distinct local TCP/UDP ports; None when ownership is unavailable.
    #[serde(default)]
    pub local_ports: Option<Vec<u16>>,
    /// Sorted distinct ports this process serves on, a subset of
    /// [`Self::local_ports`]: TCP listeners and UDP sockets bound to a
    /// well-known port. None when ownership is unavailable.
    #[serde(default)]
    pub listening_ports: Option<Vec<u16>>,
    pub nice: i32,
    pub priority: i32,
    pub cpu_percent: f64,
    pub gpu_percent: f64,
    pub network_in_bytes_per_second: f64,
    pub network_out_bytes_per_second: f64,
    pub total_network_in_bytes: u64,
    pub total_network_out_bytes: u64,
    #[serde(default)]
    pub storage_read_bytes_per_second: f64,
    #[serde(default)]
    pub storage_write_bytes_per_second: f64,
    #[serde(default)]
    pub total_storage_read_bytes: u64,
    #[serde(default)]
    pub total_storage_write_bytes: u64,
    #[serde(default)]
    pub storage_io_available: bool,
    pub tree_cpu_percent: f64,
    pub tree_gpu_percent: f64,
    pub tree_rss_bytes: u64,
    pub tree_network_in_bytes_per_second: f64,
    pub tree_network_out_bytes_per_second: f64,
    #[serde(default)]
    pub tree_storage_read_bytes_per_second: f64,
    #[serde(default)]
    pub tree_storage_write_bytes_per_second: f64,
    #[serde(default)]
    pub tree_storage_io_available: bool,
    pub descendant_count: usize,
    pub children: Vec<i32>,
    pub name: String,
    pub executable_path: String,
    pub command_line: String,
    /// Stable platform icon source. This is an app bundle on macOS. On Linux
    /// it is normally the executable path, but an exact system-wrapper rule
    /// may provide the wrapped application's launch target instead.
    pub app_bundle_path: String,
    /// Freedesktop desktop application ID derived from the Linux systemd
    /// cgroup. Empty on other platforms or when no desktop application owns
    /// the process.
    #[serde(default)]
    pub application_id: String,
    /// `file://` URI of a ready PNG or SVG icon for this process, or `None`
    /// when no icon is available yet. The host renders a fallback when unset.
    pub icon_uri: Option<String>,
}

impl ProcessRecord {
    pub fn synthetic(pid: i32, ppid: i32, name: impl Into<String>) -> Self {
        Self {
            identity: ProcessIdentity {
                pid,
                start_time_unix_ms: crate::unix_now_ms(),
            },
            ppid,
            uid: 0,
            user: String::new(),
            status: ProcessStatus::Running,
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
            name: name.into(),
            executable_path: String::new(),
            command_line: String::new(),
            app_bundle_path: String::new(),
            application_id: String::new(),
            icon_uri: None,
        }
    }

    pub fn pid(&self) -> i32 {
        self.identity.pid
    }

    pub fn start_time_unix_ms(&self) -> u64 {
        self.identity.start_time_unix_ms
    }

    pub fn identity_key(&self) -> (i32, u64) {
        (self.identity.pid, self.identity.start_time_unix_ms)
    }

    pub fn name_bytes_64(&self) -> [u8; 64] {
        fixed_bytes::<64>(&self.name)
    }

    pub fn path_bytes_1024(&self) -> [u8; 1024] {
        fixed_bytes::<1024>(&self.executable_path)
    }
}

fn fixed_bytes<const N: usize>(value: &str) -> [u8; N] {
    let mut out = [0u8; N];
    let len = value.len().min(N.saturating_sub(1));
    out[..len].copy_from_slice(&value.as_bytes()[..len]);
    out
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct ProcessSnapshot {
    pub format: String,
    pub version: u64,
    pub captured_at_unix_ms: u64,
    pub platform: String,
    pub processes: Vec<ProcessRecord>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Serialize)]
pub struct MetricPoint {
    pub captured_at_unix_ms: u64,
    pub cpu_percent: f64,
    pub gpu_percent: f64,
    pub rss_bytes: u64,
    pub network_in_bytes_per_second: f64,
    pub network_out_bytes_per_second: f64,
    #[serde(default)]
    pub storage_read_bytes_per_second: f64,
    #[serde(default)]
    pub storage_write_bytes_per_second: f64,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PollPhaseTiming {
    pub enumerate_micros: u64,
    pub metric_enrich_micros: u64,
    pub tree_micros: u64,
    pub delta_micros: u64,
}

impl PollPhaseTiming {
    pub fn total_micros(&self) -> u64 {
        self.enumerate_micros
            .saturating_add(self.metric_enrich_micros)
            .saturating_add(self.tree_micros)
            .saturating_add(self.delta_micros)
    }
}
