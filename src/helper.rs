//! Bounded local helper protocol. Requests can only read network counters or
//! list open-file metadata for an exact process lifetime. No paths, commands,
//! file contents, or process actions are accepted from clients.
use crate::introspection::{capability::CapabilityState, files::FileDescriptorResult};
use crate::network::helper_snapshot::HelperNetworkSnapshot;
use crate::ProcessIdentity;
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as transport;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as transport;
#[cfg(windows)]
pub mod service;

const MAX_MESSAGE: usize = 4 * 1024 * 1024;
const MAX_REQUEST: usize = 512;
const TIMEOUT: Duration = Duration::from_secs(2);
const RETRY: Duration = Duration::from_millis(10);

#[derive(Deserialize, Serialize)]
#[serde(tag = "request", deny_unknown_fields)]
enum Request {
    Network {
        version: u32,
    },
    Files {
        version: u32,
        identity: ProcessIdentity,
    },
}
#[derive(Deserialize, Serialize)]
#[serde(tag = "response")]
enum Response {
    Network {
        snapshot: HelperNetworkSnapshot,
    },
    Files {
        identity: ProcessIdentity,
        result: FileDescriptorResult,
    },
    Unavailable,
}

fn transfer<T>(deadline: Instant, mut operation: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    loop {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        match operation() {
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                thread::sleep(RETRY)
            }
            result => return result,
        }
    }
}
fn read_frame(stream: &mut impl Read, limit: usize, deadline: Instant) -> io::Result<Vec<u8>> {
    fn exact(stream: &mut impl Read, buffer: &mut [u8], deadline: Instant) -> io::Result<()> {
        let mut filled = 0;
        while filled < buffer.len() {
            let n = transfer(deadline, || stream.read(&mut buffer[filled..]))?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            filled += n;
        }
        Ok(())
    }
    let mut size = [0; 4];
    exact(stream, &mut size, deadline)?;
    let len = u32::from_le_bytes(size) as usize;
    if len == 0 || len > limit {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut buffer = vec![0; len];
    exact(stream, &mut buffer, deadline)?;
    Ok(buffer)
}
fn write_frame(stream: &mut impl Write, data: &[u8], deadline: Instant) -> io::Result<()> {
    if data.len() > MAX_MESSAGE {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let size = (data.len() as u32).to_le_bytes();
    for mut buffer in [size.as_slice(), data] {
        while !buffer.is_empty() {
            let n = transfer(deadline, || stream.write(buffer))?;
            if n == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            buffer = &buffer[n..];
        }
    }
    Ok(())
}
fn request(endpoint: &Path, request: Request) -> io::Result<Response> {
    let deadline = Instant::now() + TIMEOUT;
    let mut stream = transfer(deadline, || transport::connect(endpoint))?;
    write_frame(&mut stream, &serde_json::to_vec(&request)?, deadline)?;
    let response = read_frame(&mut stream, MAX_MESSAGE, deadline)?;
    let result = serde_json::from_slice(&response).map_err(io::Error::other);
    let _ = transfer(deadline, || stream.write(&[1]));
    result
}
pub fn network_snapshot(endpoint: &Path) -> io::Result<HelperNetworkSnapshot> {
    match request(endpoint, Request::Network { version: 1 })? {
        Response::Network { snapshot } if snapshot.valid_at(crate::unix_now_ms()) => Ok(snapshot),
        _ => Err(io::ErrorKind::InvalidData.into()),
    }
}
pub fn file_descriptors(endpoint: &Path, identity: ProcessIdentity) -> FileDescriptorResult {
    match request(
        endpoint,
        Request::Files {
            version: 1,
            identity,
        },
    ) {
        Ok(Response::Files {
            identity: returned,
            result,
        }) if returned == identity && result.descriptors.len() <= 4096 => result,
        _ => restricted(),
    }
}
fn restricted() -> FileDescriptorResult {
    FileDescriptorResult {
        state: CapabilityState::Restricted {
            reason: "file inspection helper unavailable".into(),
        },
        descriptors: vec![],
    }
}

/// Stop-and-join local request server. Sampling runs independently; a slow file
/// query cannot stop the network collector. Each client and child has a deadline.
pub struct HelperServer {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}
impl HelperServer {
    pub fn start(
        endpoint: PathBuf,
        network: impl Fn() -> Option<HelperNetworkSnapshot> + Send + Sync + 'static,
    ) -> io::Result<Self> {
        let mut listener = transport::Listener::bind(&endpoint)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let network = Arc::new(network);
        let worker = thread::Builder::new()
            .name("process-helper".into())
            .spawn(move || {
                let mut clients: Vec<JoinHandle<()>> = Vec::new();
                while !stopped.load(Ordering::Acquire) {
                    let mut index = 0;
                    while index < clients.len() {
                        if clients[index].is_finished() {
                            let _ = clients.swap_remove(index).join();
                        } else {
                            index += 1;
                        }
                    }
                    if clients.len() >= 4 {
                        thread::sleep(RETRY);
                        continue;
                    }
                    let stream = match listener.accept() {
                        Ok(stream) => stream,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(RETRY);
                            continue;
                        }
                        Err(_) => break,
                    };
                    let network = Arc::clone(&network);
                    if let Ok(client) =
                        thread::Builder::new()
                            .name("helper-request".into())
                            .spawn(move || {
                                serve_client(stream, &*network);
                            })
                    {
                        clients.push(client);
                    }
                }
                for client in clients {
                    let _ = client.join();
                }
            })?;
        Ok(Self {
            stop,
            worker: Some(worker),
        })
    }
}
fn serve_client(
    mut stream: impl Read + Write,
    network: &impl Fn() -> Option<HelperNetworkSnapshot>,
) {
    let deadline = Instant::now() + TIMEOUT;
    let result = read_frame(&mut stream, MAX_REQUEST, deadline)
        .and_then(|bytes| serde_json::from_slice::<Request>(&bytes).map_err(io::Error::other));
    let response = match result {
        Ok(Request::Network { version: 1 }) => network()
            .map(|snapshot| Response::Network { snapshot })
            .unwrap_or(Response::Unavailable),
        Ok(Request::Files {
            version: 1,
            identity,
        }) if identity.pid > 0 && identity.start_time_unix_ms > 0 => Response::Files {
            identity,
            result: query_files_isolated(identity, deadline),
        },
        _ => Response::Unavailable,
    };
    if let Ok(bytes) = serde_json::to_vec(&response) {
        if write_frame(&mut stream, &bytes, deadline).is_ok() {
            let mut ack = [0];
            let _ = transfer(deadline, || stream.read(&mut ack));
        }
    }
}
impl Drop for HelperServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

// File-name queries can block inside filesystem drivers. Run them in a finite
// child of the helper so deadline expiry can terminate and reap the work.
fn query_files_isolated(
    identity: ProcessIdentity,
    request_deadline: Instant,
) -> FileDescriptorResult {
    use std::process::{Command, Stdio};
    let Ok(exe) = std::env::current_exe() else {
        return restricted();
    };
    let Ok(mut child) = Command::new(exe)
        .arg("--helper-files")
        .arg(identity.pid.to_string())
        .arg(identity.start_time_unix_ms.to_string())
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
    else {
        return restricted();
    };
    let stdout = child.stdout.take().expect("piped child output");
    let reader = thread::Builder::new()
        .name("helper-file-output".into())
        .spawn(move || {
            let mut data = Vec::new();
            stdout
                .take((MAX_MESSAGE + 1) as u64)
                .read_to_end(&mut data)
                .map(|_| data)
        });
    let Ok(reader) = reader else {
        let _ = child.kill();
        let _ = child.wait();
        return restricted();
    };
    let deadline = request_deadline.min(Instant::now() + Duration::from_millis(1200));
    let success = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.success(),
            Ok(None) if Instant::now() < deadline => thread::sleep(RETRY),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break false;
            }
        }
    };
    let Ok(Ok(bytes)) = reader.join() else {
        return restricted();
    };
    if !success || bytes.len() > MAX_MESSAGE {
        return restricted();
    }
    serde_json::from_slice(&bytes).unwrap_or_else(|_| restricted())
}

/// Call before starting a helper's workers. This fixed internal subcommand is
/// also used for bounded native validation; it never reads file contents.
pub fn handle_files_subcommand() -> bool {
    let args: Vec<_> = std::env::args_os()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    if args.get(1).is_none_or(|arg| arg != "--helper-files") {
        return false;
    }
    let identity = args
        .get(2)
        .and_then(|s| s.parse::<i32>().ok())
        .zip(args.get(3).and_then(|s| s.parse::<u64>().ok()))
        .filter(|(pid, start)| *pid > 0 && *start > 0)
        .map(|(pid, start_time_unix_ms)| ProcessIdentity {
            pid,
            start_time_unix_ms,
        });
    let result = identity
        .map(query_files_validated)
        .unwrap_or_else(restricted);
    if let Ok(data) = serde_json::to_vec(&result) {
        if data.len() <= MAX_MESSAGE {
            let _ = io::stdout().write_all(&data);
        }
    }
    true
}
pub fn query_files_validated(identity: ProcessIdentity) -> FileDescriptorResult {
    let valid = || {
        crate::enumerate_processes()
            .is_ok_and(|records| records.iter().any(|p| p.identity == identity))
    };
    if !valid() {
        return FileDescriptorResult {
            state: CapabilityState::NotFound,
            descriptors: vec![],
        };
    }
    let mut result = crate::introspection::files::query_file_descriptors(identity.pid);
    result.descriptors.truncate(4096);
    // Transport contains typed/bounded failures, never OS diagnostic strings.
    if matches!(
        result.state,
        CapabilityState::Restricted { .. } | CapabilityState::Error { .. }
    ) {
        result.state = restricted().state;
    }
    if !valid() {
        return FileDescriptorResult {
            state: CapabilityState::NotFound,
            descriptors: vec![],
        };
    }
    result
}

/// Exercise the actual local protocol and isolated file-query child. Called by
/// a helper executable during native verification, without starting collection.
pub fn self_test_files() -> io::Result<()> {
    let nonce = format!("{}-{}", std::process::id(), crate::unix_now_ms());
    let file_path = std::env::temp_dir().join(format!("processtree-open-file-{nonce}"));
    let _file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&file_path)?;
    #[cfg(unix)]
    let endpoint = std::env::temp_dir().join(format!("processtree-helper-{nonce}.sock"));
    #[cfg(windows)]
    let endpoint = PathBuf::from(format!(r"\\.\pipe\processtree-helper-{nonce}"));
    let server = HelperServer::start(endpoint.clone(), || None)?;
    let identity = crate::enumerate_processes()
        .map_err(io::Error::other)?
        .into_iter()
        .find(|p| p.pid() == std::process::id() as i32)
        .ok_or_else(|| io::Error::other("self process missing"))?
        .identity;
    let result = file_descriptors(&endpoint, identity);
    let filename = file_path.file_name().unwrap().to_string_lossy();
    let found = result
        .descriptors
        .iter()
        .any(|d| d.path.ends_with(&*filename));
    let stale = file_descriptors(
        &endpoint,
        ProcessIdentity {
            start_time_unix_ms: 1,
            ..identity
        },
    );
    drop(server);
    drop(_file);
    let _ = std::fs::remove_file(file_path);
    if !found || stale.state != CapabilityState::NotFound || !stale.descriptors.is_empty() {
        return Err(io::Error::other(format!(
            "helper file/identity probe failed: state={:?}, count={}, found={found}, stale={:?}",
            result.state,
            result.descriptors.len(),
            stale.state
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn framing_rejects_oversized_and_truncated_input() {
        assert!(read_frame(
            &mut &u32::MAX.to_le_bytes()[..],
            MAX_REQUEST,
            Instant::now() + TIMEOUT
        )
        .is_err());
        assert!(read_frame(
            &mut &[3, 0, 0, 0, 1][..],
            MAX_REQUEST,
            Instant::now() + TIMEOUT
        )
        .is_err());
    }
    #[test]
    fn protocol_accepts_no_paths_or_actions() {
        assert!(serde_json::from_str::<Request>(r#"{"request":"Files","version":1,"identity":{"pid":1,"start_time_unix_ms":1},"path":"/etc/shadow"}"#).is_err());
        assert!(serde_json::from_str::<Request>(r#"{"request":"Kill","version":1}"#).is_err());
    }
    #[test]
    fn wrong_start_time_returns_no_files() {
        let result = query_files_validated(ProcessIdentity {
            pid: std::process::id() as i32,
            start_time_unix_ms: 1,
        });
        assert_eq!(result.state, CapabilityState::NotFound);
        assert!(result.descriptors.is_empty());
    }
}
