//! Security metadata queries.

#[cfg(target_os = "macos")]
mod macho;

#[cfg(target_os = "macos")]
use std::collections::HashMap;
#[cfg(target_os = "macos")]
use std::sync::Mutex;
#[cfg(target_os = "macos")]
use std::time::Instant;

use crate::introspection::capability::CapabilityState;
#[cfg(target_os = "macos")]
use crate::introspection::proc;
#[cfg(target_os = "macos")]
use crate::introspection::task;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Serialize)]
pub struct SecurityInfo {
    pub signing_status: String,
    pub signing_authority: String,
    pub team_id: String,
    pub bundle_id: String,
    pub entitlements_summary: String,
    pub entitlements_approximate: bool,
    pub gatekeeper_origin: String,
    pub sandbox: bool,
    pub hardened_runtime: bool,
    pub architecture: String,
    pub rosetta_translated: bool,
}

#[derive(Debug, Clone)]
pub struct SecurityResult {
    pub state: CapabilityState,
    pub info: SecurityInfo,
}

#[cfg(target_os = "macos")]
struct SecurityCacheEntry {
    info: SecurityInfo,
    last_access: Instant,
}

#[cfg(target_os = "macos")]
const MAX_SECURITY_CACHE_ENTRIES: usize = 256;

#[cfg(target_os = "macos")]
static SECURITY_CACHE: Mutex<Option<HashMap<String, SecurityCacheEntry>>> = Mutex::new(None);

pub fn query_security(pid: i32) -> SecurityResult {
    #[cfg(target_os = "macos")]
    {
        return query_macos(pid);
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        SecurityResult {
            state: CapabilityState::Error {
                code: 99,
                message: "unsupported platform".into(),
            },
            info: SecurityInfo::default(),
        }
    }
}

#[cfg(target_os = "macos")]
fn query_macos(pid: i32) -> SecurityResult {
    if pid <= 0 {
        return SecurityResult {
            state: CapabilityState::NotFound,
            info: SecurityInfo::default(),
        };
    }

    let path = proc::executable_path(pid);
    if path.is_empty() {
        return SecurityResult {
            state: CapabilityState::Terminated,
            info: SecurityInfo::default(),
        };
    }

    if let Some(cached) = cache_get(&path) {
        return SecurityResult {
            state: CapabilityState::Available,
            info: cached,
        };
    }

    let flags = code_sign_flags(pid);
    let task_summary = task::query_task_summary(pid).ok();
    let rosetta = task_summary.as_ref().is_some_and(|t| t.rosetta_translated);
    let mut architecture = if rosetta {
        "x86_64 (Rosetta)".into()
    } else {
        macho::architecture_summary(&path)
    };
    if architecture == "unknown" {
        architecture = macho::architecture_host_fallback();
    }

    let info = SecurityInfo {
        signing_status: signing_status_from_flags(flags),
        signing_authority: String::new(),
        team_id: String::new(),
        bundle_id: bundle_id_from_path(&path),
        entitlements_summary: String::new(),
        entitlements_approximate: true,
        gatekeeper_origin: String::new(),
        sandbox: flags.map(|f| f & CS_SANDBOX != 0).unwrap_or(false),
        hardened_runtime: flags.map(|f| f & CS_HARD != 0).unwrap_or(false),
        architecture,
        rosetta_translated: task_summary.as_ref().is_some_and(|t| t.rosetta_translated),
    };
    cache_insert(path, info.clone());

    SecurityResult {
        state: CapabilityState::Available,
        info,
    }
}

#[cfg(target_os = "macos")]
const CS_OPS_STATUS: u32 = 0;
#[cfg(target_os = "macos")]
const CS_VALID: u32 = 0x0000_0001;
#[cfg(target_os = "macos")]
const CS_HARD: u32 = 0x0000_0100;
#[cfg(target_os = "macos")]
const CS_SANDBOX: u32 = 0x0000_1000;

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn csops(
        pid: libc::pid_t,
        ops: u32,
        useraddr: *mut libc::c_void,
        usersize: libc::size_t,
    ) -> i32;
}

#[cfg(target_os = "macos")]
fn code_sign_flags(pid: i32) -> Option<u32> {
    let mut flags: u32 = 0;
    let ret = unsafe {
        csops(
            pid,
            CS_OPS_STATUS,
            &mut flags as *mut u32 as *mut libc::c_void,
            std::mem::size_of::<u32>(),
        )
    };
    if ret == 0 {
        Some(flags)
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn signing_status_from_flags(flags: Option<u32>) -> String {
    match flags {
        Some(f) if f & CS_VALID != 0 => "signed".into(),
        Some(_) => "unsigned".into(),
        None => "unknown".into(),
    }
}

#[cfg(target_os = "macos")]
fn bundle_id_from_path(path: &str) -> String {
    if let Some(idx) = path.find(".app/") {
        return path[..idx + 4].to_string();
    }
    String::new()
}

#[cfg(target_os = "macos")]
fn cache_get(path: &str) -> Option<SecurityInfo> {
    let mut guard = SECURITY_CACHE.lock().ok()?;
    let map = guard.as_mut()?;
    let entry = map.get_mut(path)?;
    entry.last_access = Instant::now();
    Some(entry.info.clone())
}

#[cfg(target_os = "macos")]
fn cache_insert(path: String, info: SecurityInfo) {
    if let Ok(mut guard) = SECURITY_CACHE.lock() {
        let map = guard.get_or_insert_with(HashMap::new);
        map.insert(
            path,
            SecurityCacheEntry {
                info,
                last_access: Instant::now(),
            },
        );
        prune_security_cache(map);
    }
}

#[cfg(target_os = "macos")]
fn prune_security_cache(map: &mut HashMap<String, SecurityCacheEntry>) {
    if map.len() <= MAX_SECURITY_CACHE_ENTRIES {
        return;
    }
    let mut oldest: Vec<(String, Instant)> = map
        .iter()
        .map(|(path, entry)| (path.clone(), entry.last_access))
        .collect();
    oldest.sort_by_key(|(_, last_access)| *last_access);
    let overflow = map.len() - MAX_SECURITY_CACHE_ENTRIES;
    for (path, _) in oldest.into_iter().take(overflow) {
        map.remove(&path);
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn query_self_security_available() {
        let pid = unsafe { libc::getpid() };
        let result = query_security(pid);
        assert!(matches!(result.state, CapabilityState::Available));
        assert!(!result.info.architecture.is_empty());
    }

    #[test]
    fn query_bin_ls_security() {
        let output = std::process::Command::new("/bin/ps")
            .args(["-ax", "-o", "pid=", "-c", "/bin/zsh"])
            .output()
            .ok();
        if let Some(o) = output {
            if o.status.success() {
                if let Ok(text) = String::from_utf8(o.stdout) {
                    if let Some(pid) = text.split_whitespace().next().and_then(|s| s.parse().ok()) {
                        let result = query_security(pid);
                        assert!(matches!(result.state, CapabilityState::Available));
                        return;
                    }
                }
            }
        }
        // Fallback: self
        let pid = unsafe { libc::getpid() };
        assert!(matches!(
            query_security(pid).state,
            CapabilityState::Available
        ));
    }

    #[test]
    fn query_missing_pid_is_terminated() {
        let result = query_security(999_999_999);
        assert!(matches!(
            result.state,
            CapabilityState::Terminated | CapabilityState::NotFound
        ));
    }

    #[test]
    fn security_cache_is_bounded() {
        let mut map = HashMap::new();
        for i in 0..(MAX_SECURITY_CACHE_ENTRIES + 8) {
            map.insert(
                format!("/tmp/ygg-test-{i}"),
                SecurityCacheEntry {
                    info: SecurityInfo::default(),
                    last_access: Instant::now() - std::time::Duration::from_secs(i as u64),
                },
            );
        }

        prune_security_cache(&mut map);

        assert!(map.len() <= MAX_SECURITY_CACHE_ENTRIES);
    }
}
