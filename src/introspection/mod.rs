//! On-demand per-process detail inspection.

pub mod capability;
#[cfg(target_os = "macos")]
mod fd_detail;
pub mod files;
pub mod network;
#[cfg(target_os = "macos")]
pub(crate) mod proc;
#[cfg(target_os = "macos")]
mod socket_parse;
pub(crate) mod task;
pub mod threads;

use serde::{Deserialize, Serialize};

use crate::model::ProcessIdentity;

pub use capability::CapabilityState;
pub use files::FileDescriptorInfo;
pub use network::NetworkEndpoint;
pub use task::TaskSummary;
pub use threads::ThreadInfo;

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct ProcessDetail {
    pub identity: ProcessIdentity,
    pub files: DetailSection<Vec<FileDescriptorInfo>>,
    pub sockets: DetailSection<Vec<NetworkEndpoint>>,
    pub threads: DetailSection<ThreadInspection>,
    pub security: DetailSection<crate::security::SecurityInfo>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct ThreadInspection {
    pub summary: Option<TaskSummary>,
    pub threads: Vec<ThreadInfo>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "value")]
pub enum DetailSection<T> {
    Available(T),
    Restricted { reason: String },
    Unsupported { reason: String },
    NotFound { reason: String },
}

pub fn inspect_process(identity: ProcessIdentity) -> ProcessDetail {
    let pid = identity.pid;
    ProcessDetail {
        identity,
        files: files_section(pid),
        sockets: sockets_section(pid),
        threads: threads_section(pid),
        security: security_section(pid),
    }
}

fn files_section(pid: i32) -> DetailSection<Vec<FileDescriptorInfo>> {
    let result = files::query_file_descriptors(pid);
    section_from_capability(result.state, result.descriptors)
}

fn sockets_section(pid: i32) -> DetailSection<Vec<NetworkEndpoint>> {
    let result = network::query_network(pid);
    section_from_capability(result.state, result.endpoints)
}

fn threads_section(pid: i32) -> DetailSection<ThreadInspection> {
    let result = threads::query_threads(pid);
    section_from_capability(
        result.state,
        ThreadInspection {
            summary: Some(result.task_summary),
            threads: result.threads,
        },
    )
}

fn security_section(pid: i32) -> DetailSection<crate::security::SecurityInfo> {
    let result = crate::security::query_security(pid);
    section_from_capability(result.state, result.info)
}

fn section_from_capability<T>(state: CapabilityState, value: T) -> DetailSection<T> {
    match state {
        CapabilityState::Available => DetailSection::Available(value),
        CapabilityState::Restricted { reason } => DetailSection::Restricted { reason },
        CapabilityState::NotFound => DetailSection::NotFound {
            reason: "process not found".to_string(),
        },
        CapabilityState::Terminated => DetailSection::NotFound {
            reason: "process terminated".to_string(),
        },
        CapabilityState::Error { code: 99, message } => {
            DetailSection::Unsupported { reason: message }
        }
        CapabilityState::Error { message, .. } => DetailSection::Restricted { reason: message },
    }
}
