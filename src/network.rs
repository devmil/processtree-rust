#![cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]

use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "macos")]
use std::io::{self, BufRead, BufReader};
#[cfg(target_os = "macos")]
use std::os::unix::process::CommandExt;
use std::path::Path;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::process::{Child, ChildStdin, Command, Stdio};
#[cfg(target_os = "macos")]
use std::sync::mpsc::{self, Receiver};
#[cfg(target_os = "macos")]
use std::sync::{Mutex, OnceLock};
#[cfg(target_os = "linux")]
use std::sync::{Mutex, OnceLock};
#[cfg(target_os = "macos")]
use std::thread;

#[cfg(target_os = "macos")]
use crate::error::ProcessTreeError;
#[cfg(target_os = "macos")]
use crate::model::ProcessRecord;
#[cfg(target_os = "linux")]
use serde::Deserialize;

const DEFAULT_NETWORK_POLLING_INTERVAL_MS: u64 = 1_000;
pub(crate) const LINUX_NETWORK_SNAPSHOT_PATH: &str = "/run/mimameidr/network.json";
#[cfg(target_os = "linux")]
const LINUX_NETWORK_SNAPSHOT_MIN_MAX_AGE_MS: u64 = 5_000;
#[cfg(target_os = "macos")]
const NETTOP_OVERSAMPLING_FACTOR: u64 = 2;
#[cfg(target_os = "macos")]
const MIN_NETTOP_INTERVAL_SECONDS: u64 = 1;
#[cfg(target_os = "macos")]
const NETTOP_STALE_SAMPLE_GRACE_INTERVALS: u64 = 4;
#[cfg(target_os = "macos")]
const MIN_NETTOP_STALE_SAMPLE_GRACE_MS: u64 = 10_000;
#[cfg(target_os = "macos")]
const NETTOP_STUCK_CPU_PERCENT_THRESHOLD: f64 = 80.0;
#[cfg(target_os = "macos")]
const NETTOP_STUCK_CONSECUTIVE_POLLS: u32 = 5;
#[cfg(target_os = "macos")]
const SIGTERM: i32 = 15;
#[cfg(target_os = "macos")]
const SIGKILL: i32 = 9;

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn setpgid(pid: i32, pgid: i32) -> i32;
    fn kill(pid: i32, sig: i32) -> i32;
}

#[derive(Debug, Clone)]
pub struct NetworkStreamConfig {
    pub polling_interval_ms: u64,
    pub include_loopback: bool,
}

impl Default for NetworkStreamConfig {
    fn default() -> Self {
        Self {
            polling_interval_ms: DEFAULT_NETWORK_POLLING_INTERVAL_MS,
            include_loopback: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct NetworkRate {
    pub bytes_in_per_second: f64,
    pub bytes_out_per_second: f64,
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct ProcessNetworkCounters {
    pid: i32,
    bytes_in: u64,
    bytes_out: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct NetworkSample {
    timestamp_unix_ms: u64,
    counters: Vec<ProcessNetworkCounters>,
}

#[derive(Debug, Clone, Default)]
struct NetworkAccumulator {
    previous_by_pid: HashMap<i32, (u64, ProcessNetworkCounters)>,
}

impl NetworkAccumulator {
    fn apply(&mut self, sample: NetworkSample) -> HashMap<i32, NetworkRate> {
        let mut rates = HashMap::new();
        let mut next_previous = HashMap::new();

        for counters in sample.counters {
            let mut rate = NetworkRate {
                total_bytes_in: counters.bytes_in,
                total_bytes_out: counters.bytes_out,
                ..NetworkRate::default()
            };
            if let Some((previous_time, previous)) = self.previous_by_pid.get(&counters.pid) {
                let elapsed_ms = sample.timestamp_unix_ms.saturating_sub(*previous_time);
                if elapsed_ms > 0
                    && counters.bytes_in >= previous.bytes_in
                    && counters.bytes_out >= previous.bytes_out
                {
                    let elapsed_seconds = elapsed_ms as f64 / 1000.0;
                    rate.bytes_in_per_second =
                        (counters.bytes_in - previous.bytes_in) as f64 / elapsed_seconds;
                    rate.bytes_out_per_second =
                        (counters.bytes_out - previous.bytes_out) as f64 / elapsed_seconds;
                }
            }
            rates.insert(counters.pid, rate);
            next_previous.insert(counters.pid, (sample.timestamp_unix_ms, counters));
        }

        self.previous_by_pid = next_previous;
        rates
    }
}

pub fn default_network_stream_config() -> NetworkStreamConfig {
    NetworkStreamConfig::default()
}

pub fn latest_network_rates_by_pid(polling_interval_ms: u64) -> HashMap<i32, NetworkRate> {
    latest_network_rates_by_pid_from_path(
        polling_interval_ms,
        Path::new(LINUX_NETWORK_SNAPSHOT_PATH),
    )
}

pub fn latest_network_rates_by_pid_from_path(
    polling_interval_ms: u64,
    linux_snapshot_path: &Path,
) -> HashMap<i32, NetworkRate> {
    #[cfg(target_os = "macos")]
    {
        sampler()
            .latest_rates_by_pid(polling_interval_ms)
            .unwrap_or_else(|_| HashMap::new())
    }
    #[cfg(target_os = "linux")]
    {
        linux_sampler()
            .lock()
            .map(|mut sampler| {
                sampler.latest_rates_by_pid(polling_interval_ms, linux_snapshot_path)
            })
            .unwrap_or_default()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = polling_interval_ms;
        let _ = linux_snapshot_path;
        HashMap::new()
    }
}

#[cfg(target_os = "linux")]
fn linux_sampler() -> &'static Mutex<LinuxSamplerState> {
    static SAMPLER: OnceLock<Mutex<LinuxSamplerState>> = OnceLock::new();
    SAMPLER.get_or_init(|| Mutex::new(LinuxSamplerState::default()))
}

#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
struct LinuxSamplerState {
    accumulator: NetworkAccumulator,
    snapshot_path: Option<PathBuf>,
}

#[cfg(target_os = "linux")]
impl LinuxSamplerState {
    fn latest_rates_by_pid(
        &mut self,
        polling_interval_ms: u64,
        snapshot_path: &Path,
    ) -> HashMap<i32, NetworkRate> {
        if self.snapshot_path.as_deref() != Some(snapshot_path) {
            self.accumulator = NetworkAccumulator::default();
            self.snapshot_path = Some(snapshot_path.to_path_buf());
        }
        let Ok(contents) = fs::read_to_string(snapshot_path) else {
            return HashMap::new();
        };
        let Ok(snapshot) = serde_json::from_str::<LinuxNetworkSnapshot>(&contents) else {
            return HashMap::new();
        };
        let now = crate::unix_now_ms();
        let max_age_ms = polling_interval_ms
            .saturating_mul(5)
            .max(LINUX_NETWORK_SNAPSHOT_MIN_MAX_AGE_MS);
        let Some(sample) = snapshot.into_sample(now, max_age_ms) else {
            return HashMap::new();
        };
        self.accumulator.apply(sample)
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Deserialize)]
struct LinuxNetworkSnapshot {
    schema: u32,
    captured_at_unix_ms: u64,
    processes: Vec<LinuxProcessNetworkCounters>,
}

#[cfg(target_os = "linux")]
impl LinuxNetworkSnapshot {
    fn into_sample(self, now_unix_ms: u64, max_age_ms: u64) -> Option<NetworkSample> {
        if self.schema != 1
            || self.captured_at_unix_ms > now_unix_ms.saturating_add(max_age_ms)
            || now_unix_ms.saturating_sub(self.captured_at_unix_ms) > max_age_ms
        {
            return None;
        }
        Some(NetworkSample {
            timestamp_unix_ms: self.captured_at_unix_ms,
            counters: self
                .processes
                .into_iter()
                .filter(|process| process.pid > 0)
                .map(|process| ProcessNetworkCounters {
                    pid: process.pid,
                    bytes_in: process.bytes_in,
                    bytes_out: process.bytes_out,
                })
                .collect(),
        })
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Deserialize)]
struct LinuxProcessNetworkCounters {
    pid: i32,
    bytes_in: u64,
    bytes_out: u64,
}

pub fn recover_network_sampler_if_stuck(processes: &[crate::model::ProcessRecord]) {
    #[cfg(target_os = "macos")]
    sampler().recover_if_stuck(processes);
    #[cfg(not(target_os = "macos"))]
    let _ = processes;
}

pub fn shutdown_network_sampler() {
    #[cfg(target_os = "macos")]
    sampler().shutdown();
}

#[cfg(target_os = "macos")]
fn nettop_interval_seconds(polling_interval_ms: u64) -> u64 {
    let oversampled_ms = polling_interval_ms / NETTOP_OVERSAMPLING_FACTOR;
    (oversampled_ms / 1000).max(MIN_NETTOP_INTERVAL_SECONDS)
}

#[cfg(target_os = "macos")]
fn sampler() -> &'static StreamingNettopSampler {
    static SAMPLER: OnceLock<StreamingNettopSampler> = OnceLock::new();
    SAMPLER.get_or_init(StreamingNettopSampler::new)
}

#[cfg(target_os = "macos")]
struct StreamingNettopSampler {
    state: Mutex<SamplerState>,
}

#[cfg(target_os = "macos")]
struct SamplerState {
    receiver: Option<Receiver<NetworkSample>>,
    child: Option<Child>,
    child_stdin: Option<ChildStdin>,
    current_interval_seconds: Option<u64>,
    stream_started_unix_ms: Option<u64>,
    last_sample_received_unix_ms: Option<u64>,
    stuck_cpu_poll_count: u32,
    accumulator: NetworkAccumulator,
    latest_rates: HashMap<i32, NetworkRate>,
}

#[cfg(target_os = "macos")]
impl StreamingNettopSampler {
    fn new() -> Self {
        Self {
            state: Mutex::new(SamplerState {
                receiver: None,
                child: None,
                child_stdin: None,
                current_interval_seconds: None,
                stream_started_unix_ms: None,
                last_sample_received_unix_ms: None,
                stuck_cpu_poll_count: 0,
                accumulator: NetworkAccumulator::default(),
                latest_rates: HashMap::new(),
            }),
        }
    }

    fn latest_rates_by_pid(
        &self,
        polling_interval_ms: u64,
    ) -> Result<HashMap<i32, NetworkRate>, ProcessTreeError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProcessTreeError::LockPoisoned)?;
        let desired_interval_seconds = nettop_interval_seconds(polling_interval_ms);
        if !state.child_running()
            || state.current_interval_seconds != Some(desired_interval_seconds)
        {
            state.start_stream(desired_interval_seconds)?;
        }

        if let Some(receiver) = state.receiver.take() {
            while let Ok(sample) = receiver.try_recv() {
                state.latest_rates = state.accumulator.apply(sample);
                state.last_sample_received_unix_ms = Some(crate::unix_now_ms());
            }
            state.receiver = Some(receiver);
        }
        state.restart_if_stale(desired_interval_seconds)?;

        Ok(state.latest_rates.clone())
    }

    fn recover_if_stuck(&self, processes: &[ProcessRecord]) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if !state.child_running() {
            state.stuck_cpu_poll_count = 0;
            return;
        }

        let Some(root_pid) = state.child.as_ref().map(|child| child.id() as i32) else {
            state.stuck_cpu_poll_count = 0;
            return;
        };
        if nettop_process_is_over_cpu_threshold(processes, root_pid) {
            state.stuck_cpu_poll_count = state.stuck_cpu_poll_count.saturating_add(1);
        } else {
            state.stuck_cpu_poll_count = 0;
        }

        if state.stuck_cpu_poll_count >= NETTOP_STUCK_CONSECUTIVE_POLLS {
            if let Some(interval_seconds) = state.current_interval_seconds {
                let _ = state.start_stream(interval_seconds);
            } else {
                state.stop_stream();
            }
        }
    }

    fn shutdown(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.stop_stream();
        }
    }
}

#[cfg(target_os = "macos")]
impl SamplerState {
    fn child_running(&mut self) -> bool {
        match self.child.as_mut() {
            Some(child) => matches!(child.try_wait(), Ok(None)),
            None => false,
        }
    }

    fn start_stream(&mut self, interval_seconds: u64) -> Result<(), ProcessTreeError> {
        self.stop_stream();
        self.accumulator = NetworkAccumulator::default();
        self.latest_rates.clear();
        self.stream_started_unix_ms = Some(crate::unix_now_ms());
        self.last_sample_received_unix_ms = None;
        self.stuck_cpu_poll_count = 0;

        let (sender, receiver) = mpsc::channel();
        let interval_argument = interval_seconds.to_string();
        let mut command = Command::new("/usr/bin/script");
        unsafe {
            command.pre_exec(|| {
                if setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            });
        }
        let mut child = command
            .args([
                "-q",
                "/dev/null",
                "/usr/bin/nettop",
                "-P",
                "-x",
                "-J",
                "bytes_in,bytes_out",
                "-L",
                "0",
                "-s",
                interval_argument.as_str(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| {
                ProcessTreeError::Enumeration(format!("failed to start nettop: {error}"))
            })?;

        let child_stdin = child.stdin.take().ok_or_else(|| {
            ProcessTreeError::Enumeration("failed to hold nettop stdin open".to_string())
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            ProcessTreeError::Enumeration("failed to capture nettop stdout".to_string())
        })?;

        thread::spawn(move || {
            let reader = BufReader::new(stdout);
            let mut parser = NettopStreamParser::default();
            for line in reader.lines().map_while(Result::ok) {
                if let Some(sample) = parser.feed(&line, crate::unix_now_ms()) {
                    let _ = sender.send(sample);
                }
            }
            if let Some(sample) = parser.finalize() {
                let _ = sender.send(sample);
            }
        });

        self.receiver = Some(receiver);
        self.child = Some(child);
        self.child_stdin = Some(child_stdin);
        self.current_interval_seconds = Some(interval_seconds);
        Ok(())
    }

    fn restart_if_stale(&mut self, interval_seconds: u64) -> Result<(), ProcessTreeError> {
        if !sample_stream_is_stale(
            self.stream_started_unix_ms,
            self.last_sample_received_unix_ms,
            interval_seconds,
            crate::unix_now_ms(),
        ) {
            return Ok(());
        }

        self.start_stream(interval_seconds)
    }

    fn stop_stream(&mut self) {
        self.receiver = None;
        self.child_stdin = None;
        if let Some(mut child) = self.child.take() {
            let root_pid = child.id() as i32;
            unsafe {
                let _ = kill(root_pid, SIGTERM);
                let _ = kill(-root_pid, SIGTERM);
            }
            for _ in 0..20 {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            if matches!(child.try_wait(), Ok(None)) {
                unsafe {
                    let _ = kill(root_pid, SIGKILL);
                    let _ = kill(-root_pid, SIGKILL);
                }
                let _ = child.kill();
            }
            let _ = child.wait();
        }
        self.current_interval_seconds = None;
        self.stream_started_unix_ms = None;
        self.last_sample_received_unix_ms = None;
        self.stuck_cpu_poll_count = 0;
    }
}

#[cfg(target_os = "macos")]
fn nettop_process_is_over_cpu_threshold(processes: &[ProcessRecord], root_pid: i32) -> bool {
    let parent_by_pid = processes
        .iter()
        .map(|process| (process.pid(), process.ppid))
        .collect::<HashMap<_, _>>();
    processes.iter().any(|process| {
        process.cpu_percent >= NETTOP_STUCK_CPU_PERCENT_THRESHOLD
            && is_nettop_process(process)
            && is_descendant_of(process.pid(), root_pid, &parent_by_pid)
    })
}

#[cfg(target_os = "macos")]
fn is_nettop_process(process: &ProcessRecord) -> bool {
    process.name == "nettop"
        || process.executable_path == "/usr/bin/nettop"
        || process.command_line.contains("/usr/bin/nettop")
}

#[cfg(target_os = "macos")]
fn is_descendant_of(pid: i32, root_pid: i32, parent_by_pid: &HashMap<i32, i32>) -> bool {
    let mut current = pid;
    for _ in 0..parent_by_pid.len() {
        if current == root_pid {
            return true;
        }
        let Some(parent) = parent_by_pid.get(&current).copied() else {
            return false;
        };
        if parent == current {
            return false;
        }
        current = parent;
    }
    false
}

#[cfg(target_os = "macos")]
fn sample_stream_is_stale(
    stream_started_unix_ms: Option<u64>,
    last_sample_received_unix_ms: Option<u64>,
    interval_seconds: u64,
    now_unix_ms: u64,
) -> bool {
    let Some(reference_unix_ms) = last_sample_received_unix_ms.or(stream_started_unix_ms) else {
        return false;
    };
    now_unix_ms.saturating_sub(reference_unix_ms) > stale_sample_grace_ms(interval_seconds)
}

#[cfg(target_os = "macos")]
fn stale_sample_grace_ms(interval_seconds: u64) -> u64 {
    interval_seconds
        .saturating_mul(1000)
        .saturating_mul(NETTOP_STALE_SAMPLE_GRACE_INTERVALS)
        .max(MIN_NETTOP_STALE_SAMPLE_GRACE_MS)
}

#[cfg(target_os = "macos")]
#[derive(Default)]
struct NettopStreamParser {
    counters_by_pid: HashMap<i32, ProcessNetworkCounters>,
    block_started_at_unix_ms: Option<u64>,
}

#[cfg(target_os = "macos")]
impl NettopStreamParser {
    fn feed(&mut self, line: &str, now_unix_ms: u64) -> Option<NetworkSample> {
        if is_nettop_header(line) {
            return self.finalize();
        }

        let counters = parse_nettop_row(line)?;
        self.block_started_at_unix_ms.get_or_insert(now_unix_ms);
        self.counters_by_pid.insert(counters.pid, counters);
        None
    }

    fn finalize(&mut self) -> Option<NetworkSample> {
        let timestamp_unix_ms = self.block_started_at_unix_ms?;
        if self.counters_by_pid.is_empty() {
            self.block_started_at_unix_ms = None;
            return None;
        }

        let mut counters = std::mem::take(&mut self.counters_by_pid)
            .into_values()
            .collect::<Vec<_>>();
        counters.sort_by_key(|counter| counter.pid);
        self.block_started_at_unix_ms = None;
        Some(NetworkSample {
            timestamp_unix_ms,
            counters,
        })
    }
}

#[cfg(target_os = "macos")]
fn is_nettop_header(line: &str) -> bool {
    let cleaned = clean_nettop_line(line);
    cleaned.starts_with(',') || cleaned.starts_with("time,")
}

#[cfg(target_os = "macos")]
fn parse_nettop_row(line: &str) -> Option<ProcessNetworkCounters> {
    let cleaned = clean_nettop_line(line);
    let fields: Vec<&str> = cleaned.split(',').map(str::trim).collect();
    for name_index in 0..=1 {
        if fields.len() < name_index + 3 {
            continue;
        }
        let name_and_pid = fields[name_index];
        let last_dot = name_and_pid.rfind('.')?;
        let Ok(pid) = name_and_pid[last_dot + 1..].parse::<i32>() else {
            continue;
        };
        let Ok(bytes_in) = fields[name_index + 1].parse::<u64>() else {
            continue;
        };
        let Ok(bytes_out) = fields[name_index + 2].parse::<u64>() else {
            continue;
        };
        return Some(ProcessNetworkCounters {
            pid,
            bytes_in,
            bytes_out,
        });
    }
    None
}

#[cfg(target_os = "macos")]
fn clean_nettop_line(line: &str) -> &str {
    let cleaned = line.trim_matches(|c: char| c.is_control() || c == '^' || c == 'D');
    cleaned.trim()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn parses_nettop_csv_row() {
        let row = "13:24:16.953340,Vivaldi Helper.4604,2038530158,124776741,";
        let parsed = parse_nettop_row(row).expect("row");
        assert_eq!(
            parsed,
            ProcessNetworkCounters {
                pid: 4604,
                bytes_in: 2038530158,
                bytes_out: 124776741,
            }
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn nettop_interval_tracks_ui_polling_interval_with_floor() {
        assert_eq!(nettop_interval_seconds(250), 1);
        assert_eq!(nettop_interval_seconds(1000), 1);
        assert_eq!(nettop_interval_seconds(4000), 2);
        assert_eq!(nettop_interval_seconds(10_000), 5);
    }

    #[test]
    fn accumulator_computes_rates_from_cumulative_counters() {
        let mut accumulator = NetworkAccumulator::default();
        let first = NetworkSample {
            timestamp_unix_ms: 1000,
            counters: vec![ProcessNetworkCounters {
                pid: 42,
                bytes_in: 100,
                bytes_out: 500,
            }],
        };
        let second = NetworkSample {
            timestamp_unix_ms: 2000,
            counters: vec![ProcessNetworkCounters {
                pid: 42,
                bytes_in: 1100,
                bytes_out: 1500,
            }],
        };

        assert_eq!(
            accumulator.apply(first)[&42],
            NetworkRate {
                total_bytes_in: 100,
                total_bytes_out: 500,
                ..NetworkRate::default()
            }
        );
        let rates = accumulator.apply(second);

        assert_eq!(rates[&42].bytes_in_per_second, 1000.0);
        assert_eq!(rates[&42].bytes_out_per_second, 1000.0);
        assert_eq!(rates[&42].total_bytes_in, 1100);
        assert_eq!(rates[&42].total_bytes_out, 1500);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_snapshot_becomes_network_sample_when_fresh() {
        let snapshot = LinuxNetworkSnapshot {
            schema: 1,
            captured_at_unix_ms: 9_500,
            processes: vec![LinuxProcessNetworkCounters {
                pid: 42,
                bytes_in: 12_000,
                bytes_out: 34_000,
            }],
        };

        let sample = snapshot.into_sample(10_000, 1_000).expect("fresh sample");

        assert_eq!(sample.timestamp_unix_ms, 9_500);
        assert_eq!(
            sample.counters,
            vec![ProcessNetworkCounters {
                pid: 42,
                bytes_in: 12_000,
                bytes_out: 34_000,
            }]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_snapshot_rejects_stale_or_unknown_schema_data() {
        let stale = LinuxNetworkSnapshot {
            schema: 1,
            captured_at_unix_ms: 1_000,
            processes: vec![],
        };
        assert!(stale.into_sample(10_000, 5_000).is_none());

        let unknown = LinuxNetworkSnapshot {
            schema: 2,
            captured_at_unix_ms: 10_000,
            processes: vec![],
        };
        assert!(unknown.into_sample(10_000, 5_000).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_sampler_reads_the_configured_path_and_resets_between_paths() {
        let now = crate::unix_now_ms();
        let directory = std::env::temp_dir();
        let first_path = directory.join(format!(
            "processtree-network-first-{}-{now}.json",
            std::process::id()
        ));
        let second_path = directory.join(format!(
            "processtree-network-second-{}-{now}.json",
            std::process::id()
        ));
        let first = format!(
            "{{\"schema\":1,\"captured_at_unix_ms\":{now},\"processes\":[{{\"pid\":42,\"bytes_in\":100,\"bytes_out\":200}}]}}"
        );
        fs::write(&first_path, &first).expect("write first configured snapshot");
        fs::write(&second_path, &first).expect("write second configured snapshot");

        let mut sampler = LinuxSamplerState::default();
        assert_eq!(
            sampler.latest_rates_by_pid(1_000, &first_path)[&42],
            NetworkRate {
                total_bytes_in: 100,
                total_bytes_out: 200,
                ..NetworkRate::default()
            }
        );
        assert!(sampler.accumulator.previous_by_pid.contains_key(&42));
        assert_eq!(sampler.snapshot_path.as_deref(), Some(first_path.as_path()));
        assert_eq!(
            sampler.latest_rates_by_pid(1_000, &second_path)[&42],
            NetworkRate {
                total_bytes_in: 100,
                total_bytes_out: 200,
                ..NetworkRate::default()
            }
        );
        assert!(sampler.accumulator.previous_by_pid.contains_key(&42));
        assert_eq!(
            sampler.snapshot_path.as_deref(),
            Some(second_path.as_path())
        );

        fs::remove_file(first_path).expect("remove first configured snapshot");
        fs::remove_file(second_path).expect("remove second configured snapshot");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn stale_sample_detection_waits_for_grace_window() {
        assert_eq!(stale_sample_grace_ms(1), 10_000);
        assert!(!sample_stream_is_stale(Some(1_000), None, 1, 10_000));
        assert!(sample_stream_is_stale(Some(1_000), None, 1, 12_000));
        assert!(!sample_stream_is_stale(Some(1_000), Some(9_000), 1, 18_000));
        assert!(sample_stream_is_stale(Some(1_000), Some(9_000), 1, 20_000));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn high_cpu_nettop_detection_is_scoped_to_sampler_descendants() {
        let mut script = ProcessRecord::synthetic(10, 1, "script");
        script.executable_path = "/usr/bin/script".to_string();

        let mut owned_nettop = ProcessRecord::synthetic(11, 10, "nettop");
        owned_nettop.executable_path = "/usr/bin/nettop".to_string();
        owned_nettop.cpu_percent = NETTOP_STUCK_CPU_PERCENT_THRESHOLD;

        let mut unrelated_nettop = ProcessRecord::synthetic(99, 1, "nettop");
        unrelated_nettop.executable_path = "/usr/bin/nettop".to_string();
        unrelated_nettop.cpu_percent = 200.0;

        assert!(nettop_process_is_over_cpu_threshold(
            &[script.clone(), owned_nettop, unrelated_nettop.clone()],
            script.pid()
        ));
        assert!(!nettop_process_is_over_cpu_threshold(
            &[script, unrelated_nettop],
            10
        ));
    }
}

pub mod helper_snapshot;
#[cfg(target_os = "windows")]
pub mod windows;
