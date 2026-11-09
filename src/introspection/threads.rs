//! Thread introspection via libproc.

#[cfg(target_os = "macos")]
use std::collections::HashMap;
#[cfg(target_os = "macos")]
use std::sync::{LazyLock, Mutex};
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

use super::capability::CapabilityState;
#[cfg(target_os = "macos")]
use super::proc::{
    self, thread_run_state_name, ProcThreadInfo, PROC_PIDLISTTHREADS, PROC_PIDTHREADINFO,
};
#[cfg(target_os = "macos")]
use super::task;
use super::task::TaskSummary;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct ThreadInfo {
    pub thread_id: u64,
    /// Share of thread time deltas since last inspector sample (not system CPU %).
    pub cpu_percent: f64,
    pub cpu_percent_approximate: bool,
    pub state: String,
}

#[derive(Debug, Clone)]
pub struct ThreadResult {
    pub state: CapabilityState,
    pub threads: Vec<ThreadInfo>,
    pub task_summary: TaskSummary,
}

#[cfg(target_os = "macos")]
struct ThreadCpuSample {
    at: Instant,
    totals: HashMap<u64, u64>,
}

#[cfg(target_os = "macos")]
const MAX_THREAD_CPU_HISTORY_ENTRIES: usize = 64;
#[cfg(target_os = "macos")]
const THREAD_CPU_HISTORY_TTL: Duration = Duration::from_secs(5 * 60);

#[cfg(target_os = "macos")]
static THREAD_CPU_HISTORY: LazyLock<Mutex<HashMap<i32, ThreadCpuSample>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub fn query_threads(pid: i32) -> ThreadResult {
    #[cfg(target_os = "macos")]
    {
        query_macos(pid)
    }
    #[cfg(target_os = "linux")]
    {
        query_linux(pid)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = pid;
        ThreadResult {
            state: CapabilityState::Error {
                code: 99,
                message: "unsupported platform".into(),
            },
            threads: vec![],
            task_summary: TaskSummary::default(),
        }
    }
}

#[cfg(target_os = "linux")]
fn query_linux(pid: i32) -> ThreadResult {
    let directory = crate::platform::linux_host_root()
        .join("proc")
        .join(pid.to_string())
        .join("task");
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return ThreadResult {
                state: CapabilityState::NotFound,
                threads: vec![],
                task_summary: TaskSummary::default(),
            };
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            return ThreadResult {
                state: CapabilityState::Restricted {
                    reason: error.to_string(),
                },
                threads: vec![],
                task_summary: TaskSummary::default(),
            };
        }
        Err(error) => {
            return ThreadResult {
                state: CapabilityState::Error {
                    code: error.raw_os_error().unwrap_or_default() as u32,
                    message: error.to_string(),
                },
                threads: vec![],
                task_summary: TaskSummary::default(),
            };
        }
    };
    let mut threads = entries
        .flatten()
        .filter_map(|entry| {
            let thread_id = entry.file_name().to_string_lossy().parse::<u64>().ok()?;
            let stat = std::fs::read_to_string(entry.path().join("stat")).ok()?;
            let close = stat.rfind(')')?;
            let state = stat.get(close + 2..)?.chars().next()?;
            let state = match state {
                'R' => "running",
                'S' | 'I' => "sleeping",
                'D' => "uninterruptible",
                'T' | 't' => "stopped",
                'Z' => "zombie",
                _ => "unknown",
            };
            Some(ThreadInfo {
                thread_id,
                cpu_percent: 0.0,
                cpu_percent_approximate: true,
                state: state.into(),
            })
        })
        .collect::<Vec<_>>();
    threads.sort_by_key(|thread| thread.thread_id);
    ThreadResult {
        state: CapabilityState::Available,
        task_summary: TaskSummary {
            thread_count: threads.len() as i32,
            mach_syscall_count: 0,
            rosetta_translated: false,
        },
        threads,
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::*;

    #[test]
    fn query_self_includes_current_thread() {
        let result = query_threads(std::process::id() as i32);
        assert!(matches!(result.state, CapabilityState::Available));
        assert!(!result.threads.is_empty());
        assert_eq!(
            result.task_summary.thread_count,
            result.threads.len() as i32
        );
    }
}

#[cfg(target_os = "macos")]
fn query_macos(pid: i32) -> ThreadResult {
    if pid <= 0 {
        return ThreadResult {
            state: CapabilityState::NotFound,
            threads: vec![],
            task_summary: TaskSummary::default(),
        };
    }

    let task_summary = match task::query_task_summary(pid) {
        Ok(s) => s,
        Err(state) => {
            clear_thread_cpu_history(pid);
            return ThreadResult {
                state,
                threads: vec![],
                task_summary: TaskSummary::default(),
            };
        }
    };

    let mut buf = vec![0u8; 64 * 1024];
    let nbytes = match proc::proc_pidinfo_buffer(pid, PROC_PIDLISTTHREADS, 0, &mut buf) {
        Ok(n) => n,
        Err(state) => {
            clear_thread_cpu_history(pid);
            return ThreadResult {
                state,
                threads: vec![],
                task_summary,
            };
        }
    };

    if nbytes < 8 {
        return ThreadResult {
            state: CapabilityState::Available,
            threads: vec![],
            task_summary,
        };
    }

    let count = nbytes / 8;
    let mut parsed: Vec<(u64, u64, u32)> = Vec::new();
    for i in 0..count {
        let offset = i * 8;
        let thread_id = u64::from_ne_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]);
        if thread_id == 0 {
            continue;
        }
        let mut info = ProcThreadInfo::default();
        if proc::proc_pidinfo(pid, PROC_PIDTHREADINFO, thread_id, &mut info).is_err() {
            continue;
        }
        let total_us = info.pth_user_time.saturating_add(info.pth_system_time);
        parsed.push((thread_id, total_us, info.pth_run_state));
    }

    let (cpu_percents, cpu_approximate) = thread_cpu_percents(pid, &parsed);
    let mut threads: Vec<ThreadInfo> = parsed
        .iter()
        .enumerate()
        .map(|(idx, (thread_id, _, run_state))| ThreadInfo {
            thread_id: *thread_id,
            cpu_percent: cpu_percents.get(idx).copied().unwrap_or(0.0),
            cpu_percent_approximate: cpu_approximate,
            state: thread_run_state_name(*run_state).to_string(),
        })
        .collect();

    threads.sort_by_key(|t| t.thread_id);

    ThreadResult {
        state: CapabilityState::Available,
        threads,
        task_summary,
    }
}

#[cfg(target_os = "macos")]
fn thread_cpu_percents(pid: i32, parsed: &[(u64, u64, u32)]) -> (Vec<f64>, bool) {
    let now = Instant::now();
    let current: HashMap<u64, u64> = parsed.iter().map(|(id, total, _)| (*id, *total)).collect();

    let mut percents = vec![0.0; parsed.len()];
    let mut approximate = false;

    if let Ok(mut map) = THREAD_CPU_HISTORY.lock() {
        prune_thread_cpu_history(&mut map, now);
        if let Some(prev) = map.get(&pid) {
            let elapsed = now.duration_since(prev.at).as_secs_f64();
            if elapsed > 0.0 {
                approximate = true;
                let mut total_delta = 0u64;
                let mut deltas = Vec::new();
                for (thread_id, total, _) in parsed {
                    let prev_total = prev.totals.get(thread_id).copied().unwrap_or(0);
                    let delta = total.saturating_sub(prev_total);
                    deltas.push(delta);
                    total_delta = total_delta.saturating_add(delta);
                }
                if total_delta > 0 {
                    for (i, delta) in deltas.iter().enumerate() {
                        percents[i] = (*delta as f64 / total_delta as f64) * 100.0;
                    }
                }
            }
        }
        map.insert(
            pid,
            ThreadCpuSample {
                at: now,
                totals: current,
            },
        );
        prune_thread_cpu_history(&mut map, now);
    }

    (percents, approximate)
}

#[cfg(target_os = "macos")]
fn clear_thread_cpu_history(pid: i32) {
    if let Ok(mut map) = THREAD_CPU_HISTORY.lock() {
        map.remove(&pid);
    }
}

#[cfg(target_os = "macos")]
fn prune_thread_cpu_history(map: &mut HashMap<i32, ThreadCpuSample>, now: Instant) {
    map.retain(|_, sample| {
        now.checked_duration_since(sample.at)
            .is_some_and(|age| age <= THREAD_CPU_HISTORY_TTL)
    });
    if map.len() <= MAX_THREAD_CPU_HISTORY_ENTRIES {
        return;
    }
    let mut oldest: Vec<(i32, Instant)> =
        map.iter().map(|(pid, sample)| (*pid, sample.at)).collect();
    oldest.sort_by_key(|(_, at)| *at);
    let overflow = map.len() - MAX_THREAD_CPU_HISTORY_ENTRIES;
    for (pid, _) in oldest.into_iter().take(overflow) {
        map.remove(&pid);
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use crate::introspection::task::mach_port_summary_label;

    #[test]
    fn query_self_threads_available() {
        let pid = unsafe { libc::getpid() };
        let result = query_threads(pid);
        assert!(matches!(result.state, CapabilityState::Available));
        assert!(!mach_port_summary_label(&result.task_summary).is_empty());
    }

    #[test]
    fn query_missing_pid_is_terminated() {
        let result = query_threads(999_999_999);
        assert!(matches!(result.state, CapabilityState::Terminated));
    }

    #[test]
    fn thread_cpu_history_prunes_stale_and_caps_entries() {
        let now = Instant::now();
        let mut history = HashMap::new();
        history.insert(
            1,
            ThreadCpuSample {
                at: now - THREAD_CPU_HISTORY_TTL - Duration::from_secs(1),
                totals: HashMap::new(),
            },
        );
        for pid in 2..=(MAX_THREAD_CPU_HISTORY_ENTRIES as i32 + 4) {
            history.insert(
                pid,
                ThreadCpuSample {
                    at: now - Duration::from_secs(pid as u64),
                    totals: HashMap::new(),
                },
            );
        }

        prune_thread_cpu_history(&mut history, now);

        assert!(!history.contains_key(&1));
        assert!(history.len() <= MAX_THREAD_CPU_HISTORY_ENTRIES);
    }
}
