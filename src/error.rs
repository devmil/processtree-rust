use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProcessTreeError {
    #[error("lock poisoned")]
    LockPoisoned,
    #[error("process enumeration failed: {0}")]
    Enumeration(String),
    #[error("invalid configuration")]
    InvalidConfig,
    #[error("process is no longer running")]
    ProcessNotFound,
    #[error("process identity changed before action could run")]
    ProcessIdentityChanged,
    #[error("process action failed: {0}")]
    ProcessAction(String),
    #[error("process enumeration is not implemented for this platform yet")]
    UnsupportedPlatform,
}

impl ProcessTreeError {
    pub fn code(&self) -> u32 {
        match self {
            Self::LockPoisoned => 1,
            Self::Enumeration(_) => 2,
            Self::InvalidConfig => 3,
            Self::ProcessNotFound => 4,
            Self::ProcessIdentityChanged => 5,
            Self::ProcessAction(_) => 6,
            Self::UnsupportedPlatform => 99,
        }
    }
}
