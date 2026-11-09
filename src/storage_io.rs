use std::collections::{HashMap, HashSet};
use std::time::Instant;

use crate::model::ProcessRecord;

#[derive(Clone, Copy)]
struct Sample {
    read_bytes: u64,
    write_bytes: u64,
}

pub(crate) struct StorageIoSampler {
    sampled_at: Option<Instant>,
    samples: HashMap<(i32, u64), Sample>,
}

impl StorageIoSampler {
    pub(crate) fn new() -> Self {
        Self {
            sampled_at: None,
            samples: HashMap::new(),
        }
    }

    pub(crate) fn apply(&mut self, records: &mut [ProcessRecord]) {
        let now = Instant::now();
        let elapsed = self
            .sampled_at
            .map(|sampled_at| now.duration_since(sampled_at).as_secs_f64());
        self.sampled_at = Some(now);
        let mut seen = HashSet::with_capacity(records.len());

        for record in records {
            let identity = record.identity_key();
            seen.insert(identity);
            record.storage_read_bytes_per_second = 0.0;
            record.storage_write_bytes_per_second = 0.0;

            if !record.storage_io_available {
                self.samples.remove(&identity);
                continue;
            }

            if let (Some(seconds), Some(previous)) = (elapsed, self.samples.get(&identity)) {
                if seconds > 0.0
                    && record.total_storage_read_bytes >= previous.read_bytes
                    && record.total_storage_write_bytes >= previous.write_bytes
                {
                    record.storage_read_bytes_per_second = record
                        .total_storage_read_bytes
                        .saturating_sub(previous.read_bytes)
                        as f64
                        / seconds;
                    record.storage_write_bytes_per_second = record
                        .total_storage_write_bytes
                        .saturating_sub(previous.write_bytes)
                        as f64
                        / seconds;
                }
            }

            self.samples.insert(
                identity,
                Sample {
                    read_bytes: record.total_storage_read_bytes,
                    write_bytes: record.total_storage_write_bytes,
                },
            );
        }

        self.samples.retain(|identity, _| seen.contains(identity));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn rates_follow_full_identity_and_available_counters() {
        let mut sampler = StorageIoSampler::new();
        let mut record = ProcessRecord::synthetic(42, 1, "worker");
        record.identity.start_time_unix_ms = 7;
        record.storage_io_available = true;
        record.total_storage_read_bytes = 100;
        record.total_storage_write_bytes = 200;
        sampler.apply(std::slice::from_mut(&mut record));

        sampler.sampled_at = Some(Instant::now() - Duration::from_secs(2));
        record.total_storage_read_bytes = 300;
        record.total_storage_write_bytes = 600;
        sampler.apply(std::slice::from_mut(&mut record));

        assert!((record.storage_read_bytes_per_second - 100.0).abs() < 1.0);
        assert!((record.storage_write_bytes_per_second - 200.0).abs() < 1.0);

        record.identity.start_time_unix_ms = 8;
        sampler.apply(std::slice::from_mut(&mut record));
        assert_eq!(record.storage_read_bytes_per_second, 0.0);
        assert_eq!(record.storage_write_bytes_per_second, 0.0);
    }
}
