//! Identity-preserving counters shared by privileged collectors and clients.
#[cfg(any(target_os = "windows", test))]
use super::NetworkRate;
#[cfg(target_os = "windows")]
use crate::model::ProcessRecord;
use serde::{Deserialize, Serialize};
#[cfg(any(target_os = "windows", test))]
use std::collections::HashMap;
use std::collections::HashSet;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct HelperNetworkSnapshot {
    pub schema: u32,
    pub generation: u64,
    pub captured_at_unix_ms: u64,
    pub processes: Vec<HelperProcessCounters>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct HelperProcessCounters {
    pub pid: i32,
    pub start_time_unix_ms: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

impl HelperNetworkSnapshot {
    pub fn valid_at(&self, now: u64) -> bool {
        let mut identities = HashSet::new();
        self.schema == 1
            && self.generation != 0
            && self.captured_at_unix_ms <= now.saturating_add(1000)
            && now.saturating_sub(self.captured_at_unix_ms) <= 5000
            && self.processes.len() <= 32768
            && self.processes.iter().all(|p| {
                p.pid > 0
                    && p.start_time_unix_ms > 0
                    && identities.insert((p.pid, p.start_time_unix_ms))
            })
    }
}

#[cfg(any(target_os = "windows", test))]
#[derive(Default)]
pub(crate) struct HelperNetworkAccumulator {
    previous: Option<HelperNetworkSnapshot>,
    rates: HashMap<(i32, u64), NetworkRate>,
}

#[cfg(any(target_os = "windows", test))]
impl HelperNetworkAccumulator {
    pub fn apply(
        &mut self,
        snapshot: HelperNetworkSnapshot,
        now: u64,
    ) -> &HashMap<(i32, u64), NetworkRate> {
        if !snapshot.valid_at(now) {
            self.previous = None;
            self.rates.clear();
            return &self.rates;
        }
        if let Some(previous) = &self.previous {
            if previous.generation == snapshot.generation
                && previous.captured_at_unix_ms == snapshot.captured_at_unix_ms
            {
                return &self.rates;
            }
        }
        self.rates.clear();
        let previous = self.previous.as_ref().filter(|p| {
            p.generation == snapshot.generation
                && p.captured_at_unix_ms < snapshot.captured_at_unix_ms
        });
        let old: HashMap<_, _> = previous
            .into_iter()
            .flat_map(|s| &s.processes)
            .map(|p| ((p.pid, p.start_time_unix_ms), p))
            .collect();
        for p in &snapshot.processes {
            let mut rate = NetworkRate {
                total_bytes_in: p.bytes_in,
                total_bytes_out: p.bytes_out,
                ..NetworkRate::default()
            };
            if let (Some(s), Some(before)) = (previous, old.get(&(p.pid, p.start_time_unix_ms))) {
                if p.bytes_in >= before.bytes_in && p.bytes_out >= before.bytes_out {
                    let seconds =
                        (snapshot.captured_at_unix_ms - s.captured_at_unix_ms) as f64 / 1000.0;
                    rate.bytes_in_per_second = (p.bytes_in - before.bytes_in) as f64 / seconds;
                    rate.bytes_out_per_second = (p.bytes_out - before.bytes_out) as f64 / seconds;
                }
            }
            self.rates.insert((p.pid, p.start_time_unix_ms), rate);
        }
        self.previous = Some(snapshot);
        &self.rates
    }

    #[cfg(target_os = "windows")]
    pub fn stamp(&mut self, snapshot: HelperNetworkSnapshot, records: &mut [ProcessRecord]) {
        let rates = self.apply(snapshot, crate::unix_now_ms());
        for record in records {
            if let Some(rate) = rates.get(&record.identity_key()) {
                record.network_in_bytes_per_second = rate.bytes_in_per_second;
                record.network_out_bytes_per_second = rate.bytes_out_per_second;
                record.total_network_in_bytes = rate.total_bytes_in;
                record.total_network_out_bytes = rate.total_bytes_out;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn snapshot(time: u64, start: u64, bytes: u64) -> HelperNetworkSnapshot {
        HelperNetworkSnapshot {
            schema: 1,
            generation: 1,
            captured_at_unix_ms: time,
            processes: vec![HelperProcessCounters {
                pid: 42,
                start_time_unix_ms: start,
                bytes_in: bytes,
                bytes_out: bytes * 2,
            }],
        }
    }
    #[test]
    fn rates_use_sample_time_and_repeat_without_resetting() {
        let mut a = HelperNetworkAccumulator::default();
        assert_eq!(
            a.apply(snapshot(1000, 1, 100), 1000)[&(42, 1)].bytes_in_per_second,
            0.0
        );
        assert_eq!(
            a.apply(snapshot(1500, 1, 200), 1500)[&(42, 1)].bytes_out_per_second,
            400.0
        );
        assert_eq!(
            a.apply(snapshot(1500, 1, 200), 1600)[&(42, 1)].bytes_out_per_second,
            400.0
        );
        assert!(a.apply(snapshot(1500, 1, 200), 7000).is_empty());
    }
    #[test]
    fn reuse_restart_and_counter_reset_never_spike() {
        let mut a = HelperNetworkAccumulator::default();
        a.apply(snapshot(1000, 1, 100), 1000);
        assert_eq!(
            a.apply(snapshot(2000, 2, 1000), 2000)[&(42, 2)].bytes_in_per_second,
            0.0
        );
        assert_eq!(
            a.apply(snapshot(3000, 2, 1), 3000)[&(42, 2)].bytes_in_per_second,
            0.0
        );
        let mut restarted = snapshot(4000, 2, 9999);
        restarted.generation = 2;
        assert_eq!(a.apply(restarted, 4000)[&(42, 2)].bytes_in_per_second, 0.0);
    }
    #[test]
    fn malformed_duplicate_and_future_samples_are_rejected() {
        let mut s = snapshot(1000, 1, 1);
        s.processes.push(s.processes[0].clone());
        assert!(!s.valid_at(1000));
        assert!(!snapshot(5000, 1, 1).valid_at(1000));
        assert!(!snapshot(1000, 0, 1).valid_at(1000));
    }
}
