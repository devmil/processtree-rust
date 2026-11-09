use std::collections::HashMap;

use crate::model::{ProcessRecord, ProcessSnapshot};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MutationKind {
    Spawned = 1,
    Terminated = 2,
    MetricUpdated = 3,
    Reparented = 4,
    StatusChanged = 5,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TreeMutation {
    pub kind: MutationKind,
    pub pid: i32,
    pub parent_pid: i32,
    pub cpu_percent: f64,
    pub gpu_percent: f64,
    pub rss_bytes: u64,
    pub status: u32,
}

impl TreeMutation {
    fn spawned(record: &ProcessRecord) -> Self {
        Self::from_record(MutationKind::Spawned, record)
    }

    fn reparented(record: &ProcessRecord) -> Self {
        Self::from_record(MutationKind::Reparented, record)
    }

    fn status_changed(record: &ProcessRecord) -> Self {
        Self::from_record(MutationKind::StatusChanged, record)
    }

    fn metric_updated(record: &ProcessRecord) -> Self {
        Self::from_record(MutationKind::MetricUpdated, record)
    }

    fn terminated(pid: i32) -> Self {
        Self {
            kind: MutationKind::Terminated,
            pid,
            parent_pid: 0,
            cpu_percent: 0.0,
            gpu_percent: 0.0,
            rss_bytes: 0,
            status: 0,
        }
    }

    fn from_record(kind: MutationKind, record: &ProcessRecord) -> Self {
        Self {
            kind,
            pid: record.pid(),
            parent_pid: record.ppid,
            cpu_percent: record.cpu_percent,
            gpu_percent: record.gpu_percent,
            rss_bytes: record.rss_bytes,
            status: record.status as u32,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MutationBatch {
    pub version: u64,
    pub processes: Vec<ProcessRecord>,
    pub mutations: Vec<TreeMutation>,
}

#[derive(Default)]
pub(crate) struct DeltaEngine {
    previous: Option<ProcessSnapshot>,
}

impl DeltaEngine {
    pub fn compute_batch(&mut self, snapshot: ProcessSnapshot) -> MutationBatch {
        let mut structural = Vec::new();
        let mut metrics = Vec::new();

        if let Some(previous) = &self.previous {
            let prev_by_id: HashMap<(i32, u64), &ProcessRecord> = previous
                .processes
                .iter()
                .map(|record| (record.identity_key(), record))
                .collect();
            let curr_by_id: HashMap<(i32, u64), &ProcessRecord> = snapshot
                .processes
                .iter()
                .map(|record| (record.identity_key(), record))
                .collect();

            let mut terminated: Vec<i32> = prev_by_id
                .iter()
                .filter_map(|(key, record)| (!curr_by_id.contains_key(key)).then_some(record.pid()))
                .collect();
            terminated.sort_unstable_by(|a, b| b.cmp(a));
            for pid in terminated {
                structural.push(TreeMutation::terminated(pid));
            }

            let mut current_keys: Vec<_> = curr_by_id.keys().copied().collect();
            current_keys.sort_unstable();
            for key in current_keys {
                let record = curr_by_id[&key];
                if let Some(old) = prev_by_id.get(&key).copied() {
                    if old.ppid != record.ppid {
                        structural.push(TreeMutation::reparented(record));
                    }
                    if old.status != record.status {
                        structural.push(TreeMutation::status_changed(record));
                    }
                    if metrics_changed(old, record) {
                        metrics.push(TreeMutation::metric_updated(record));
                    }
                } else {
                    structural.push(TreeMutation::spawned(record));
                }
            }
        } else {
            structural.extend(snapshot.processes.iter().map(TreeMutation::spawned));
        }

        structural.sort_by_key(|mutation| match mutation.kind {
            MutationKind::Terminated => 0,
            MutationKind::Reparented => 1,
            MutationKind::Spawned => 2,
            MutationKind::StatusChanged => 3,
            MutationKind::MetricUpdated => 4,
        });
        structural.append(&mut metrics);

        let batch = MutationBatch {
            version: snapshot.version,
            processes: snapshot.processes.clone(),
            mutations: structural,
        };
        self.previous = Some(snapshot);
        batch
    }
}

fn metrics_changed(old: &ProcessRecord, current: &ProcessRecord) -> bool {
    (old.cpu_percent - current.cpu_percent).abs() > f64::EPSILON
        || (old.gpu_percent - current.gpu_percent).abs() > f64::EPSILON
        || (old.network_in_bytes_per_second - current.network_in_bytes_per_second).abs()
            > f64::EPSILON
        || (old.network_out_bytes_per_second - current.network_out_bytes_per_second).abs()
            > f64::EPSILON
        || (old.storage_read_bytes_per_second - current.storage_read_bytes_per_second).abs()
            > f64::EPSILON
        || (old.storage_write_bytes_per_second - current.storage_write_bytes_per_second).abs()
            > f64::EPSILON
        || old.storage_io_available != current.storage_io_available
        || old.rss_bytes != current.rss_bytes
}
