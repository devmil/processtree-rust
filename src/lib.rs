//! Shared process tree telemetry engine for the Process Explorer apps.

pub mod action;
pub mod delta;
pub mod engine;
pub mod error;
#[cfg(any(unix, windows))]
pub mod helper;
pub mod icons;
pub mod introspection;
pub mod model;
pub mod network;
pub mod platform;
pub mod security;
mod storage_io;
pub mod tree;

pub use action::{signal_process, ProcessSignal};
pub use delta::{MutationBatch, MutationKind, TreeMutation};
pub use engine::{EngineConfig, PollResult, ProcessTreeEngine, ProcessTreeSample};
pub use error::ProcessTreeError;
pub use icons::{IconCache, IconCacheConfig};
pub use introspection::{
    inspect_process, DetailSection, FileDescriptorInfo, NetworkEndpoint, ProcessDetail,
    TaskSummary, ThreadInfo, ThreadInspection,
};
pub use model::{
    MetricPoint, PollPhaseTiming, ProcessIdentity, ProcessRecord, ProcessSnapshot, ProcessStatus,
    PROCESS_TREE_FORMAT,
};
pub use network::{
    default_network_stream_config, latest_network_rates_by_pid_from_path, shutdown_network_sampler,
    NetworkRate,
};
pub use platform::{enumerate_processes, gpu_metrics_available};
pub use security::SecurityInfo;
pub use tree::{
    synthesize_tree_and_aggregates, ProcessParent, ProcessTopology, ProcessTreeCache,
    SYNTHETIC_ROOT_PID,
};

pub fn collect_snapshot() -> Result<ProcessSnapshot, ProcessTreeError> {
    ProcessTreeEngine::default().snapshot()
}

pub fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}
