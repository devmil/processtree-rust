//! Capability result model for detail queries.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "reason")]
pub enum CapabilityState {
    Available,
    Restricted { reason: String },
    NotFound,
    Terminated,
    Error { code: u32, message: String },
}
