use crate::error::ProcessTreeError;
use crate::model::ProcessIdentity;
use crate::platform::send_process_signal;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProcessSignal {
    Terminate,
    Kill,
    Suspend,
    Resume,
}

impl ProcessSignal {
    #[cfg(unix)]
    pub(crate) fn unix_signal(self) -> i32 {
        match self {
            // `libc` resolves the platform-correct signal numbers, which matter
            // for SIGSTOP/SIGCONT (they differ between macOS and Linux).
            Self::Terminate => libc::SIGTERM,
            Self::Kill => libc::SIGKILL,
            Self::Suspend => libc::SIGSTOP,
            Self::Resume => libc::SIGCONT,
        }
    }
}

pub fn signal_process(
    identity: ProcessIdentity,
    signal: ProcessSignal,
) -> Result<(), ProcessTreeError> {
    send_process_signal(identity, signal)
}
