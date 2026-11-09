use std::io;

const MAX_ATTEMPTS: usize = 5;

/// Read a changing macOS process table. A failed read can contain a partial
/// table; never publish it as a complete snapshot. Keep the policy testable
/// without a macOS kernel or a timing-dependent process-spawn stress test.
pub(super) fn read_process_table(
    record_size: usize,
    mut query: impl FnMut(Option<&mut [u8]>) -> io::Result<usize>,
) -> io::Result<Vec<u8>> {
    let mut previous_capacity = 0usize;
    for attempt in 0..MAX_ATTEMPTS {
        // Re-probe: Darwin can report bytes copied, rather than required, on
        // ENOMEM. The failed read's length is not a reliable sizing hint.
        let required = query(None)?;
        if required == 0 {
            return Err(io::Error::other("empty process table size probe"));
        }
        let overflow = || io::Error::other("process table buffer size overflow");
        let slack = (required / 4).max(record_size.checked_mul(32).ok_or_else(overflow)?);
        let capacity = required
            .checked_add(slack)
            .ok_or_else(overflow)?
            .max(previous_capacity.checked_mul(2).ok_or_else(overflow)?);
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(capacity)
            .map_err(io::Error::other)?;
        buffer.resize(capacity, 0);
        match query(Some(&mut buffer)) {
            Ok(written) if written <= buffer.len() => {
                buffer.truncate(written);
                return Ok(buffer);
            }
            Ok(_) => return Err(io::Error::other("invalid process table read length")),
            Err(error)
                if error.raw_os_error() == Some(libc::ENOMEM) && attempt + 1 < MAX_ATTEMPTS =>
            {
                previous_capacity = capacity;
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("the final read always returns")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn growth_races_reprobe_and_discard_partial_tables() {
        let mut probes = 0;
        let mut reads = 0;
        let mut capacities = Vec::new();
        let result = read_process_table(8, |buffer| {
            let Some(buffer) = buffer else {
                probes += 1;
                return Ok(800);
            };
            reads += 1;
            capacities.push(buffer.len());
            if reads < 3 {
                buffer.fill(99);
                return Err(io::Error::from_raw_os_error(libc::ENOMEM));
            }
            buffer[..16].fill(42);
            Ok(16)
        })
        .unwrap();
        assert_eq!(probes, 3);
        assert_eq!(capacities, vec![1056, 2112, 4224]);
        assert_eq!(result, vec![42; 16]);
    }

    #[test]
    fn slack_absorbs_growth_without_retrying() {
        let mut probes = 0;
        let result = read_process_table(8, |buffer| match buffer {
            None => {
                probes += 1;
                Ok(800)
            }
            Some(buffer) => {
                assert!(buffer.len() >= 808);
                buffer[..808].fill(7);
                Ok(808)
            }
        })
        .unwrap();
        assert_eq!(probes, 1);
        assert_eq!(result, vec![7; 808]);
    }

    #[test]
    fn sustained_churn_has_a_bounded_retry_budget() {
        let mut reads = 0;
        let error = read_process_table(8, |buffer| match buffer {
            None => Ok(800),
            Some(_) => {
                reads += 1;
                Err(io::Error::from_raw_os_error(libc::ENOMEM))
            }
        })
        .unwrap_err();
        assert_eq!(reads, MAX_ATTEMPTS);
        assert_eq!(error.raw_os_error(), Some(libc::ENOMEM));
    }

    #[test]
    fn permission_failures_are_not_retried() {
        let mut calls = 0;
        let error = read_process_table(8, |buffer| {
            calls += 1;
            match buffer {
                None => Ok(800),
                Some(_) => Err(io::Error::from_raw_os_error(libc::EPERM)),
            }
        })
        .unwrap_err();
        assert_eq!(calls, 2);
        assert_eq!(error.raw_os_error(), Some(libc::EPERM));
    }

    #[test]
    fn probe_failure_returns_immediately() {
        let mut calls = 0;
        assert!(read_process_table(8, |_| {
            calls += 1;
            Err(io::Error::from_raw_os_error(libc::EIO))
        })
        .is_err());
        assert_eq!(calls, 1);
    }

    #[test]
    fn invalid_lengths_are_rejected() {
        assert!(read_process_table(8, |_| Ok(0)).is_err());
        assert!(read_process_table(8, |_| Ok(usize::MAX)).is_err());
        assert!(read_process_table(8, |buffer| match buffer {
            None => Ok(8),
            Some(buffer) => Ok(buffer.len() + 1),
        })
        .is_err());
    }
}
