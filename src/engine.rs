use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::delta::{DeltaEngine, MutationBatch};
use crate::error::ProcessTreeError;
use crate::icons::{IconCache, IconCacheConfig};
use crate::model::{MetricPoint, PollPhaseTiming, ProcessSnapshot, PROCESS_TREE_FORMAT};
use crate::network::{
    latest_network_rates_by_pid_from_path, recover_network_sampler_if_stuck,
    shutdown_network_sampler, LINUX_NETWORK_SNAPSHOT_PATH,
};
use crate::platform::{
    enumerate_processes_reusing_metadata, CpuSampler, GpuSampler, ProcessMetadata,
};
use crate::storage_io::StorageIoSampler;
use crate::tree::{ProcessTopology, ProcessTreeCache};

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub polling_interval_ms: u64,
    pub metric_history_len: usize,
    pub include_network: bool,
    /// Local privileged helper endpoint. Windows uses its network snapshots.
    pub helper_endpoint: Option<PathBuf>,
    pub include_gpu: bool,
    pub include_tree_aggregates: bool,
    /// Linux eBPF helper snapshot consumed for per-process network counters.
    /// Other platforms retain this value but do not read it.
    pub linux_network_snapshot_path: PathBuf,
    /// When set, the engine owns an icon cache rooted at this directory and
    /// stamps ready icon URIs onto every snapshot. `None` disables icons.
    pub icon_cache_dir: Option<PathBuf>,
    /// Target edge size in pixels for generated icons. Larger stays crisper at
    /// the cost of bigger cache files.
    pub icon_target_px: u32,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            polling_interval_ms: 1_000,
            metric_history_len: 120,
            include_network: true,
            helper_endpoint: None,
            include_gpu: true,
            include_tree_aggregates: true,
            linux_network_snapshot_path: PathBuf::from(LINUX_NETWORK_SNAPSHOT_PATH),
            icon_cache_dir: None,
            icon_target_px: 128,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PollResult {
    pub snapshot: ProcessSnapshot,
    pub batch: MutationBatch,
}

/// One telemetry sample and its shared structural state. A metric-only update
/// retains the same topology Arc and version; clients can reuse their graph.
#[derive(Debug, Clone)]
pub struct ProcessTreeSample {
    pub snapshot: ProcessSnapshot,
    pub topology: Option<Arc<ProcessTopology>>,
}

pub struct ProcessTreeEngine {
    config: EngineConfig,
    state: Mutex<EngineState>,
    icon_cache: Option<IconCache>,
}

struct EngineState {
    version: u64,
    tree_cache: ProcessTreeCache,
    histories: HashMap<(i32, u64), Vec<MetricPoint>>,
    delta: DeltaEngine,
    cpu_sampler: CpuSampler,
    storage_io_sampler: StorageIoSampler,
    #[cfg(target_os = "windows")]
    network_sampler: crate::network::helper_snapshot::HelperNetworkAccumulator,
    gpu_sampler: GpuSampler,
    poll_count: u64,
    last_poll_timing: PollPhaseTiming,
    running: bool,
    process_metadata: HashMap<(i32, u64), ProcessMetadata>,
}

impl ProcessTreeEngine {
    pub fn new(config: EngineConfig) -> Self {
        let icon_cache = config.icon_cache_dir.as_ref().map(|cache_dir| {
            IconCache::new(IconCacheConfig {
                cache_dir: cache_dir.clone(),
                target_px: config.icon_target_px,
                ..IconCacheConfig::default()
            })
        });
        Self {
            config,
            state: Mutex::new(EngineState {
                version: 0,
                tree_cache: ProcessTreeCache::default(),
                histories: HashMap::new(),
                delta: DeltaEngine::default(),
                cpu_sampler: CpuSampler::new(),
                storage_io_sampler: StorageIoSampler::new(),
                #[cfg(target_os = "windows")]
                network_sampler: Default::default(),
                gpu_sampler: GpuSampler::new(),
                poll_count: 0,
                last_poll_timing: PollPhaseTiming::default(),
                running: false,
                process_metadata: HashMap::new(),
            }),
            icon_cache,
        }
    }

    pub fn start(&self) -> Result<(), ProcessTreeError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProcessTreeError::LockPoisoned)?;
        state.running = true;
        if self.config.include_network {
            let _ = latest_network_rates_by_pid_from_path(
                self.config.polling_interval_ms,
                &self.config.linux_network_snapshot_path,
            );
        }
        Ok(())
    }

    pub fn stop(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.running = false;
        }
        shutdown_network_sampler();
        if let Some(icon_cache) = self.icon_cache.as_ref() {
            icon_cache.shutdown();
        }
    }

    pub fn poll(&self) -> Result<PollResult, ProcessTreeError> {
        let (snapshot, batch, _) = self.collect_snapshot(true)?;
        Ok(PollResult {
            snapshot,
            batch: batch.expect("delta batch is present when requested"),
        })
    }

    pub fn snapshot(&self) -> Result<ProcessSnapshot, ProcessTreeError> {
        self.collect_snapshot(false)
            .map(|(snapshot, _, _)| snapshot)
    }

    pub fn snapshot_with_topology(&self) -> Result<ProcessTreeSample, ProcessTreeError> {
        self.collect_snapshot(false)
            .map(|(snapshot, _, topology)| ProcessTreeSample { snapshot, topology })
    }

    fn collect_snapshot(
        &self,
        compute_delta: bool,
    ) -> Result<
        (
            ProcessSnapshot,
            Option<MutationBatch>,
            Option<Arc<ProcessTopology>>,
        ),
        ProcessTreeError,
    > {
        let started = Instant::now();
        let (metadata, refresh_metadata) = {
            let state = self
                .state
                .lock()
                .map_err(|_| ProcessTreeError::LockPoisoned)?;
            (state.process_metadata.clone(), state.poll_count % 10 == 0)
        };
        let mut records = enumerate_processes_reusing_metadata(&metadata, refresh_metadata)?;
        if self.config.include_network {
            let sockets = crate::introspection::network::query_network_snapshot().ok();
            for record in &mut records {
                let endpoints = sockets
                    .as_ref()
                    .and_then(|sockets| sockets.get(&record.pid()));
                record.local_ports = endpoints.map(|endpoints| {
                    crate::introspection::network::distinct_local_ports(endpoints.iter())
                });
                record.listening_ports = endpoints.map(|endpoints| {
                    crate::introspection::network::distinct_local_ports(
                        endpoints.iter().filter(|e| e.is_listening()),
                    )
                });
            }
        }
        let enumerate_micros = started.elapsed().as_micros() as u64;

        if let Some(icon_cache) = self.icon_cache.as_ref() {
            icon_cache.stamp(&mut records);
        }

        let metric_started = Instant::now();
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProcessTreeError::LockPoisoned)?;
        state.poll_count = state.poll_count.saturating_add(1);
        state.process_metadata = records
            .iter()
            .map(|record| (record.identity_key(), ProcessMetadata::from(record)))
            .collect();
        state.running = true;
        state.cpu_sampler.apply(&mut records);
        state.storage_io_sampler.apply(&mut records);
        if self.config.include_network {
            recover_network_sampler_if_stuck(&records);
        }
        if self.config.include_gpu {
            let full_gpu_scan =
                self.config.polling_interval_ms >= 1_000 || state.poll_count % 2 == 1;
            state
                .gpu_sampler
                .apply_throttled(&mut records, full_gpu_scan);
        }
        #[cfg(target_os = "windows")]
        if self.config.include_network {
            let snapshot = self
                .config
                .helper_endpoint
                .as_deref()
                .and_then(|endpoint| crate::helper::network_snapshot(endpoint).ok())
                .unwrap_or_default();
            state.network_sampler.stamp(snapshot, &mut records);
        }
        #[cfg(not(target_os = "windows"))]
        if self.config.include_network {
            let rates = latest_network_rates_by_pid_from_path(
                self.config.polling_interval_ms,
                &self.config.linux_network_snapshot_path,
            );
            for record in &mut records {
                if let Some(rate) = rates.get(&record.pid()) {
                    record.network_in_bytes_per_second = rate.bytes_in_per_second;
                    record.network_out_bytes_per_second = rate.bytes_out_per_second;
                    record.total_network_in_bytes = rate.total_bytes_in;
                    record.total_network_out_bytes = rate.total_bytes_out;
                }
            }
        }
        let metric_enrich_micros = metric_started.elapsed().as_micros() as u64;

        let tree_started = Instant::now();
        let topology = self
            .config
            .include_tree_aggregates
            .then(|| state.tree_cache.update(&mut records));
        let tree_micros = tree_started.elapsed().as_micros() as u64;

        let delta_started = Instant::now();
        state.version = state.version.saturating_add(1);
        let snapshot = ProcessSnapshot {
            format: PROCESS_TREE_FORMAT.to_string(),
            version: state.version,
            captured_at_unix_ms: crate::unix_now_ms(),
            platform: std::env::consts::OS.to_string(),
            processes: records,
        };
        state.record_history(&snapshot, self.config.metric_history_len.max(1));
        let batch = compute_delta.then(|| state.delta.compute_batch(snapshot.clone()));
        let delta_micros = delta_started.elapsed().as_micros() as u64;

        state.last_poll_timing = PollPhaseTiming {
            enumerate_micros,
            metric_enrich_micros,
            tree_micros,
            delta_micros,
        };
        Ok((snapshot, batch, topology))
    }

    pub fn metric_history(&self, pid: i32, start_time_unix_ms: u64) -> Option<Vec<MetricPoint>> {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.histories.get(&(pid, start_time_unix_ms)).cloned())
    }

    pub fn last_poll_timing(&self) -> PollPhaseTiming {
        self.state
            .lock()
            .map(|state| state.last_poll_timing)
            .unwrap_or_default()
    }

    pub fn is_running(&self) -> bool {
        self.state
            .lock()
            .map(|state| state.running)
            .unwrap_or(false)
    }

    pub fn config(&self) -> &EngineConfig {
        &self.config
    }
}

impl Default for ProcessTreeEngine {
    fn default() -> Self {
        Self::new(EngineConfig::default())
    }
}

impl Drop for ProcessTreeEngine {
    fn drop(&mut self) {
        if self.config.include_network {
            shutdown_network_sampler();
        }
        if let Some(icon_cache) = self.icon_cache.as_ref() {
            icon_cache.shutdown();
        }
    }
}

impl EngineState {
    fn record_history(&mut self, snapshot: &ProcessSnapshot, history_len: usize) {
        let mut seen = HashSet::new();
        for record in &snapshot.processes {
            let key = record.identity_key();
            seen.insert(key);
            let history = self.histories.entry(key).or_default();
            history.push(MetricPoint {
                captured_at_unix_ms: snapshot.captured_at_unix_ms,
                cpu_percent: record.cpu_percent,
                gpu_percent: record.gpu_percent,
                rss_bytes: record.rss_bytes,
                network_in_bytes_per_second: record.network_in_bytes_per_second,
                network_out_bytes_per_second: record.network_out_bytes_per_second,
                storage_read_bytes_per_second: record.storage_read_bytes_per_second,
                storage_write_bytes_per_second: record.storage_write_bytes_per_second,
            });
            if history.len() > history_len {
                let excess = history.len() - history_len;
                history.drain(0..excess);
            }
        }
        self.histories.retain(|key, _| seen.contains(key));
    }
}
