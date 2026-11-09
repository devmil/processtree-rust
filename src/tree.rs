use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use crate::model::{ProcessIdentity, ProcessRecord};

pub const SYNTHETIC_ROOT_PID: i32 = 0;
static NEXT_TOPOLOGY_VERSION: AtomicU64 = AtomicU64::new(1);

/// A parent edge uses process creation time as well as PID, so consumers cannot
/// accidentally attach a child to an exited process whose PID was reused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessParent {
    pub identity: ProcessIdentity,
    pub parent: Option<ProcessIdentity>,
}

/// Immutable structural state shared across metric-only samples. Versions are
/// unique within this library instance, including across engine recreation.
/// They are runtime tokens, not persistent snapshot identifiers.
#[derive(Clone, Debug)]
pub struct ProcessTopology {
    pub version: u64,
    pub parents: Vec<ProcessParent>,
}

/// Reuses parent links, child lists and bottom-up traversal while identities and
/// raw parent PIDs are unchanged. Enumeration order and metric changes do not
/// invalidate it. A cache belongs to one independently sampled process tree.
#[derive(Default)]
pub struct ProcessTreeCache {
    topology: Option<Arc<ProcessTopology>>,
    slots: HashMap<i32, usize>,
    raw_parents: Vec<i32>,
    parents: Vec<Option<usize>>,
    children: Vec<Vec<i32>>,
    postorder: Vec<usize>,
    descendants: Vec<usize>,
    indices: Vec<usize>,
    aggregates: Vec<TreeAggregate>,
}

impl ProcessTreeCache {
    pub fn update(&mut self, processes: &mut [ProcessRecord]) -> Arc<ProcessTopology> {
        let unchanged = self.topology.as_ref().is_some_and(|topology| {
            topology.parents.len() == processes.len()
                && processes.iter().all(|record| {
                    self.slots.get(&record.pid()).is_some_and(|&slot| {
                        topology.parents[slot].identity == record.identity
                            && self.raw_parents[slot] == record.ppid
                    })
                })
        });
        if !unchanged {
            self.rebuild(processes);
        }
        for (index, record) in processes.iter().enumerate() {
            let slot = self.slots[&record.pid()];
            self.indices[slot] = index;
            self.aggregates[slot] = TreeAggregate {
                cpu_percent: record.cpu_percent,
                gpu_percent: record.gpu_percent,
                rss_bytes: record.rss_bytes,
                network_in_bytes_per_second: record.network_in_bytes_per_second,
                network_out_bytes_per_second: record.network_out_bytes_per_second,
                storage_read_bytes_per_second: record.storage_read_bytes_per_second,
                storage_write_bytes_per_second: record.storage_write_bytes_per_second,
                storage_io_available: record.storage_io_available,
                descendant_count: self.descendants[slot],
            };
        }
        for &slot in &self.postorder {
            let aggregate = self.aggregates[slot];
            let record = &mut processes[self.indices[slot]];
            record.ppid = self.parents[slot].map_or(SYNTHETIC_ROOT_PID, |parent| {
                self.topology.as_ref().unwrap().parents[parent].identity.pid
            });
            record.children.clone_from(&self.children[slot]);
            record.tree_cpu_percent = aggregate.cpu_percent;
            record.tree_gpu_percent = aggregate.gpu_percent;
            record.tree_rss_bytes = aggregate.rss_bytes;
            record.tree_network_in_bytes_per_second = aggregate.network_in_bytes_per_second;
            record.tree_network_out_bytes_per_second = aggregate.network_out_bytes_per_second;
            record.tree_storage_read_bytes_per_second = aggregate.storage_read_bytes_per_second;
            record.tree_storage_write_bytes_per_second = aggregate.storage_write_bytes_per_second;
            record.tree_storage_io_available = aggregate.storage_io_available;
            record.descendant_count = aggregate.descendant_count;
            if let Some(parent) = self.parents[slot] {
                self.aggregates[parent].add_metrics(aggregate);
            }
        }
        Arc::clone(self.topology.as_ref().unwrap())
    }

    fn rebuild(&mut self, processes: &[ProcessRecord]) {
        let mut records: Vec<_> = processes.iter().collect();
        records.sort_unstable_by_key(|record| record.pid());
        self.slots = records
            .iter()
            .enumerate()
            .map(|(slot, record)| (record.pid(), slot))
            .collect();
        self.raw_parents = records.iter().map(|record| record.ppid).collect();
        self.parents = records
            .iter()
            .map(|record| {
                if record.ppid == SYNTHETIC_ROOT_PID {
                    return None;
                }
                let parent = self
                    .slots
                    .get(&record.ppid)
                    .copied()
                    .filter(|&slot| records[slot].pid() != record.pid());
                parent.or_else(|| {
                    self.slots
                        .get(&1)
                        .copied()
                        .filter(|&slot| records[slot].pid() != record.pid())
                })
            })
            .collect();

        // Break malformed cycles deterministically at their lowest PID. Use an
        // iterative walk so deep trees cannot overflow the native stack.
        let mut state = vec![0u8; records.len()];
        for start in 0..records.len() {
            let mut path = Vec::new();
            let mut cursor = Some(start);
            while let Some(slot) = cursor {
                if state[slot] == 2 {
                    break;
                }
                if state[slot] == 1 {
                    let first = path.iter().position(|&node| node == slot).unwrap();
                    let root = *path[first..].iter().min().unwrap();
                    self.parents[root] = None;
                    break;
                }
                state[slot] = 1;
                path.push(slot);
                cursor = self.parents[slot];
            }
            for slot in path {
                state[slot] = 2;
            }
        }
        self.children = vec![Vec::new(); records.len()];
        for (slot, parent) in self.parents.iter().enumerate() {
            if let Some(parent) = parent {
                self.children[*parent].push(records[slot].pid());
            }
        }
        let mut remaining: Vec<_> = self.children.iter().map(Vec::len).collect();
        self.postorder = (0..records.len())
            .filter(|&slot| remaining[slot] == 0)
            .collect();
        self.descendants = vec![0; records.len()];
        let mut cursor = 0;
        while cursor < self.postorder.len() {
            let slot = self.postorder[cursor];
            if let Some(parent) = self.parents[slot] {
                self.descendants[parent] += 1 + self.descendants[slot];
                remaining[parent] -= 1;
                if remaining[parent] == 0 {
                    self.postorder.push(parent);
                }
            }
            cursor += 1;
        }
        self.indices.resize(records.len(), 0);
        self.aggregates
            .resize(records.len(), TreeAggregate::default());
        self.topology = Some(Arc::new(ProcessTopology {
            version: NEXT_TOPOLOGY_VERSION.fetch_add(1, Ordering::Relaxed),
            parents: records
                .iter()
                .enumerate()
                .map(|(slot, record)| ProcessParent {
                    identity: record.identity,
                    parent: self.parents[slot].map(|parent| records[parent].identity),
                })
                .collect(),
        }));
    }
}

/// One-shot compatibility API. Repeated samplers should retain a
/// [ProcessTreeCache] or use [crate::ProcessTreeEngine] instead.
pub fn synthesize_tree_and_aggregates(processes: &mut [ProcessRecord]) {
    ProcessTreeCache::default().update(processes);
}

#[derive(Clone, Copy, Debug, Default)]
struct TreeAggregate {
    cpu_percent: f64,
    gpu_percent: f64,
    rss_bytes: u64,
    network_in_bytes_per_second: f64,
    network_out_bytes_per_second: f64,
    storage_read_bytes_per_second: f64,
    storage_write_bytes_per_second: f64,
    storage_io_available: bool,
    descendant_count: usize,
}

impl TreeAggregate {
    fn add_metrics(&mut self, child: Self) {
        self.cpu_percent += child.cpu_percent;
        self.gpu_percent += child.gpu_percent;
        self.rss_bytes = self.rss_bytes.saturating_add(child.rss_bytes);
        self.network_in_bytes_per_second += child.network_in_bytes_per_second;
        self.network_out_bytes_per_second += child.network_out_bytes_per_second;
        self.storage_read_bytes_per_second += child.storage_read_bytes_per_second;
        self.storage_write_bytes_per_second += child.storage_write_bytes_per_second;
        self.storage_io_available |= child.storage_io_available;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_samples_reuse_topology_even_when_enumeration_order_changes() {
        let mut cache = ProcessTreeCache::default();
        let raw = vec![
            ProcessRecord::synthetic(1, 0, "root"),
            ProcessRecord::synthetic(2, 1, "child"),
        ];
        let mut first = raw.clone();
        let topology = cache.update(&mut first);
        let mut second = raw.clone();
        second.reverse();
        second[0].cpu_percent = 42.0;
        second[0].rss_bytes = 512;
        let next = cache.update(&mut second);
        assert!(Arc::ptr_eq(&topology, &next));
        assert_eq!(second[1].tree_cpu_percent, 42.0);
        assert_eq!(second[1].tree_rss_bytes, 512);
        assert_eq!(second[1].descendant_count, 1);
        assert_eq!(topology.parents[1].parent, Some(raw[0].identity));
    }

    #[test]
    fn invalidates_on_pid_reuse_reparenting_and_parent_arrival_or_exit() {
        let mut cache = ProcessTreeCache::default();
        let mut raw = vec![ProcessRecord::synthetic(2, 1, "child")];
        let first = cache.update(&mut raw.clone());
        assert_eq!(first.parents[0].parent, None);
        raw.push(ProcessRecord::synthetic(1, 0, "parent"));
        let arrived = cache.update(&mut raw.clone());
        assert_ne!(first.version, arrived.version);
        assert_eq!(arrived.parents[1].parent, Some(raw[1].identity));
        raw[1].identity.start_time_unix_ms += 1;
        let reused = cache.update(&mut raw.clone());
        assert_ne!(arrived.version, reused.version);
        assert_eq!(reused.parents[1].parent, Some(raw[1].identity));
        assert_ne!(arrived.parents[1].parent, reused.parents[1].parent);
        raw[0].ppid = 0;
        let reparented = cache.update(&mut raw.clone());
        assert_ne!(reused.version, reparented.version);
        assert_eq!(reparented.parents[1].parent, None);
        raw.pop();
        let exited = cache.update(&mut raw);
        assert_ne!(reparented.version, exited.version);
        assert_eq!(exited.parents.len(), 1);
    }

    #[test]
    fn cycles_are_broken_deterministically_without_double_counting() {
        let mut cache = ProcessTreeCache::default();
        let mut processes = vec![
            ProcessRecord::synthetic(3, 2, "b"),
            ProcessRecord::synthetic(2, 3, "a"),
            ProcessRecord::synthetic(1, 1, "self"),
        ];
        for record in &mut processes {
            record.cpu_percent = 1.0;
        }
        cache.update(&mut processes);
        assert_eq!(processes[1].ppid, 0);
        assert_eq!(processes[1].tree_cpu_percent, 2.0);
        assert_eq!(processes[0].tree_cpu_percent, 1.0);
        assert_eq!(processes[2].ppid, 0);
        assert_eq!(processes[2].descendant_count, 0);
    }

    #[test]
    fn deep_trees_do_not_use_recursive_aggregation() {
        let mut processes: Vec<_> = (1..=20_000)
            .map(|pid| ProcessRecord::synthetic(pid, pid - 1, "node"))
            .collect();
        processes.last_mut().unwrap().cpu_percent = 7.0;
        ProcessTreeCache::default().update(&mut processes);
        assert_eq!(processes[0].descendant_count, 19_999);
        assert_eq!(processes[0].tree_cpu_percent, 7.0);
    }

    #[test]
    fn cache_matches_fresh_aggregation_through_structural_churn() {
        let mut cache = ProcessTreeCache::default();
        for tick in 0..50 {
            let mut records: Vec<_> = (1..100)
                .filter(|pid| (pid + tick) % 7 != 0)
                .map(|pid| {
                    let mut record = ProcessRecord::synthetic(pid, pid / 2, "node");
                    record.identity.start_time_unix_ms = (tick / 10) as u64;
                    record.cpu_percent = (pid + tick) as f64;
                    record.rss_bytes = (pid * 100) as u64;
                    record
                })
                .collect();
            let mut fresh = records.clone();
            synthesize_tree_and_aggregates(&mut fresh);
            cache.update(&mut records);
            assert_eq!(records, fresh);
        }
    }

    #[test]
    fn empty_samples_and_new_cache_instances_have_unambiguous_versions() {
        let mut cache = ProcessTreeCache::default();
        let empty = cache.update(&mut []);
        assert!(Arc::ptr_eq(&empty, &cache.update(&mut [])));
        let other = ProcessTreeCache::default().update(&mut []);
        assert_ne!(empty.version, other.version);
        cache.update(&mut [ProcessRecord::synthetic(1, 0, "root")]);
        let empty_again = cache.update(&mut []);
        assert_ne!(empty.version, empty_again.version);
        assert!(empty_again.parents.is_empty());
    }

    #[test]
    fn aggregates_descendant_tree_metrics() {
        let mut parent = ProcessRecord::synthetic(10, 1, "parent");
        parent.cpu_percent = 1.0;
        parent.gpu_percent = 2.0;
        parent.rss_bytes = 100;
        parent.storage_read_bytes_per_second = 5.0;
        parent.storage_write_bytes_per_second = 7.0;
        parent.storage_io_available = true;
        let mut child = ProcessRecord::synthetic(11, 10, "child");
        child.cpu_percent = 3.0;
        child.gpu_percent = 4.0;
        child.rss_bytes = 200;
        child.storage_read_bytes_per_second = 11.0;
        child.storage_write_bytes_per_second = 13.0;
        child.storage_io_available = true;
        let mut grandchild = ProcessRecord::synthetic(12, 11, "grandchild");
        grandchild.storage_io_available = true;
        let mut processes = vec![parent, child, grandchild];

        synthesize_tree_and_aggregates(&mut processes);

        let parent = processes
            .iter()
            .find(|process| process.pid() == 10)
            .unwrap();
        assert_eq!(parent.children, vec![11]);
        assert_eq!(parent.descendant_count, 2);
        assert_eq!(parent.tree_cpu_percent, 4.0);
        assert_eq!(parent.tree_gpu_percent, 6.0);
        assert_eq!(parent.tree_rss_bytes, 300);
        assert_eq!(parent.tree_storage_read_bytes_per_second, 16.0);
        assert_eq!(parent.tree_storage_write_bytes_per_second, 20.0);
        assert!(parent.tree_storage_io_available);
    }

    #[test]
    fn subtree_storage_is_available_when_a_descendant_has_counters() {
        let parent = ProcessRecord::synthetic(10, 1, "parent");
        let mut child = ProcessRecord::synthetic(11, 10, "child");
        child.storage_read_bytes_per_second = 11.0;
        child.storage_write_bytes_per_second = 13.0;
        child.storage_io_available = true;
        let mut processes = vec![parent, child];

        synthesize_tree_and_aggregates(&mut processes);

        assert!(!processes[0].storage_io_available);
        assert_eq!(processes[0].tree_storage_read_bytes_per_second, 11.0);
        assert_eq!(processes[0].tree_storage_write_bytes_per_second, 13.0);
        assert!(processes[0].tree_storage_io_available);
    }

    #[test]
    fn subtree_storage_is_unavailable_when_no_process_has_counters() {
        let parent = ProcessRecord::synthetic(10, 1, "parent");
        let child = ProcessRecord::synthetic(11, 10, "child");
        let mut processes = vec![parent, child];

        synthesize_tree_and_aggregates(&mut processes);

        assert!(!processes[0].tree_storage_io_available);
    }
}
