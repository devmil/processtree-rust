//! A single owned ETW system logger. Used by a privileged helper, never started
//! implicitly by a desktop engine. Only TCP/UDP send/receive byte counts survive
//! the callback; addresses and packet contents are not retained.
use super::helper_snapshot::{HelperNetworkSnapshot, HelperProcessCounters};
use std::collections::HashMap;
use std::io;
use std::mem::{offset_of, size_of};
use std::ptr;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS};
use windows_sys::Win32::System::Diagnostics::Etw::*;

const TCP: GUID = GUID::from_u128(0x9a280ac0_c8e0_11d1_84e2_00c04fb998a2);
const UDP: GUID = GUID::from_u128(0xbf3a50c5_a9c9_4988_a005_2df0b7c80f80);
const UNIX_EPOCH: u64 = 116_444_736_000_000_000;

#[repr(C)]
struct Properties {
    properties: EVENT_TRACE_PROPERTIES,
    name: [u16; 128],
}
impl Properties {
    fn new() -> Self {
        let mut value = Self {
            properties: EVENT_TRACE_PROPERTIES::default(),
            name: [0; 128],
        };
        value.properties.Wnode.BufferSize = size_of::<Self>() as u32;
        value.properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        value.properties.Wnode.ClientContext = 1; // QPC; ProcessTrace converts to FILETIME.
        value.properties.LoggerNameOffset = offset_of!(Self, name) as u32;
        value.properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE
            | EVENT_TRACE_SYSTEM_LOGGER_MODE
            | EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING;
        value.properties.EnableFlags = EVENT_TRACE_FLAG_NETWORK_TCPIP;
        value.properties.BufferSize = 64;
        value.properties.MinimumBuffers = 4;
        value.properties.MaximumBuffers = 64;
        value.properties.FlushTimer = 1;
        value
    }
}

#[derive(Default)]
struct Counters {
    by_pid: HashMap<i32, HelperProcessCounters>,
}
impl Counters {
    fn event(&mut self, pid: i32, timestamp_ms: u64, received: bool, bytes: u32) {
        let Some(p) = self.by_pid.get_mut(&pid) else {
            return;
        };
        // Buffered events from a previous lifetime must never enter a reused PID.
        if timestamp_ms < p.start_time_unix_ms {
            return;
        }
        let total = if received {
            &mut p.bytes_in
        } else {
            &mut p.bytes_out
        };
        *total = total.saturating_add(u64::from(bytes));
    }
    fn refresh(&mut self, records: &[crate::ProcessRecord]) {
        let mut next = HashMap::with_capacity(records.len());
        for record in records {
            let p = self
                .by_pid
                .remove(&record.pid())
                .filter(|p| p.start_time_unix_ms == record.start_time_unix_ms())
                .unwrap_or(HelperProcessCounters {
                    pid: record.pid(),
                    start_time_unix_ms: record.start_time_unix_ms(),
                    ..Default::default()
                });
            next.insert(p.pid, p);
        }
        self.by_pid = next;
    }
}

/// Owns the ETW session, callback state, and consumer thread. Dropping stops the
/// session and closes the consumer before joining; callback context stays alive.
pub struct WindowsNetworkCollector {
    session: CONTROLTRACE_HANDLE,
    trace: PROCESSTRACE_HANDLE,
    worker: Option<JoinHandle<u32>>,
    counters: Arc<Mutex<Counters>>,
    generation: u64,
}
impl WindowsNetworkCollector {
    /// `session_name` is the application's fixed, descriptive private name.
    /// Only an orphan with exactly this name is reclaimed after a helper crash.
    pub fn start(session_name: &str) -> io::Result<Self> {
        let mut name: Vec<u16> = session_name.encode_utf16().chain(Some(0)).collect();
        if name.len() > 128 || name.len() < 2 || name[..name.len() - 1].contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid trace name",
            ));
        }
        let mut properties = Properties::new();
        let mut session = CONTROLTRACE_HANDLE::default();
        let mut status =
            unsafe { StartTraceW(&mut session, name.as_ptr(), &mut properties.properties) };
        if status == ERROR_ALREADY_EXISTS {
            unsafe {
                ControlTraceW(
                    CONTROLTRACE_HANDLE::default(),
                    name.as_ptr(),
                    &mut properties.properties,
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
            properties = Properties::new();
            status =
                unsafe { StartTraceW(&mut session, name.as_ptr(), &mut properties.properties) };
        }
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let counters = Arc::new(Mutex::new(Counters::default()));
        if let Ok(records) = crate::enumerate_processes() {
            counters.lock().unwrap().refresh(&records);
        }
        let mut log = EVENT_TRACE_LOGFILEW {
            LoggerName: name.as_mut_ptr(),
            Context: Arc::as_ptr(&counters) as *mut _,
            ..Default::default()
        };
        log.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        log.Anonymous2.EventRecordCallback = Some(on_event);
        let trace = unsafe { OpenTraceW(&mut log) };
        if trace.Value == u64::MAX {
            let error = io::Error::last_os_error();
            unsafe {
                ControlTraceW(
                    session,
                    ptr::null(),
                    &mut properties.properties,
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
            return Err(error);
        }
        let context = Arc::clone(&counters);
        let worker = thread::Builder::new()
            .name("network-etw".into())
            .spawn(move || {
                let _keep_context_alive = context;
                unsafe { ProcessTrace(&trace, 1, ptr::null(), ptr::null()) }
            });
        let worker = match worker {
            Ok(worker) => worker,
            Err(error) => {
                unsafe {
                    CloseTrace(trace);
                    ControlTraceW(
                        session,
                        ptr::null(),
                        &mut properties.properties,
                        EVENT_TRACE_CONTROL_STOP,
                    );
                }
                return Err(error);
            }
        };
        Ok(Self {
            session,
            trace,
            worker: Some(worker),
            counters,
            generation: crate::unix_now_ms().max(1),
        })
    }
    pub fn snapshot(&self) -> io::Result<HelperNetworkSnapshot> {
        if self.worker.as_ref().is_none_or(JoinHandle::is_finished) {
            return Err(io::Error::other("network trace ended"));
        }
        let records = crate::enumerate_processes().map_err(io::Error::other)?;
        let mut counters = self
            .counters
            .lock()
            .map_err(|_| io::Error::other("network state unavailable"))?;
        counters.refresh(&records);
        Ok(HelperNetworkSnapshot {
            schema: 1,
            generation: self.generation,
            captured_at_unix_ms: crate::unix_now_ms(),
            processes: counters.by_pid.values().cloned().collect(),
        })
    }
}
impl Drop for WindowsNetworkCollector {
    fn drop(&mut self) {
        let mut properties = Properties::new();
        unsafe {
            ControlTraceW(
                self.session,
                ptr::null(),
                &mut properties.properties,
                EVENT_TRACE_CONTROL_STOP,
            );
            CloseTrace(self.trace);
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

// Microsoft ETW TcpIp/UdpIp v2: PID and size are the first two uint32 fields
// for IPv4 (10/11) and IPv6 (26/27). Header.ProcessId is *not* the traffic owner.
unsafe extern "system" fn on_event(event: *mut EVENT_RECORD) {
    let Some(event) = (unsafe { event.as_ref() }) else {
        return;
    };
    if event.UserContext.is_null() || event.UserData.is_null() || event.UserDataLength < 8 {
        return;
    }
    let provider = event.EventHeader.ProviderId;
    let same_guid = |a: GUID, b: GUID| {
        a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
    };
    if !same_guid(provider, TCP) && !same_guid(provider, UDP) {
        return;
    }
    if event.EventHeader.EventDescriptor.Version != 2 {
        return;
    }
    let received = match event.EventHeader.EventDescriptor.Opcode {
        10 | 26 => false,
        11 | 27 => true,
        _ => return,
    };
    let bytes = unsafe { std::slice::from_raw_parts(event.UserData.cast::<u8>(), 8) };
    let Ok(pid) = i32::try_from(u32::from_le_bytes(bytes[..4].try_into().unwrap())) else {
        return;
    };
    let size = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let timestamp_ms = (event.EventHeader.TimeStamp as u64).saturating_sub(UNIX_EPOCH) / 10_000;
    let counters = unsafe { &*event.UserContext.cast::<Mutex<Counters>>() };
    if let Ok(mut counters) = counters.lock() {
        counters.event(pid, timestamp_ms, received, size);
    }
}

/// Native elevated verification: exercise IPv4/IPv6 TCP and UDP with bounded
/// loopback transfers, verify identity-backed byte counters, then restart ETW.
pub fn self_test() -> io::Result<()> {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream, UdpSocket};
    use std::time::{Duration, Instant};
    let collector = WindowsNetworkCollector::start("Hoddmimis Network Verification")?;
    let pid = std::process::id() as i32;
    for (address, udp) in [
        ("127.0.0.1:0", false),
        ("[::1]:0", false),
        ("127.0.0.1:0", true),
        ("[::1]:0", true),
    ] {
        let before = collector
            .snapshot()?
            .processes
            .into_iter()
            .find(|p| p.pid == pid)
            .ok_or_else(|| io::Error::other("probe process missing"))?;
        let payload = [23u8; 1024];
        if udp {
            let receiver = UdpSocket::bind(address)?;
            let sender = UdpSocket::bind(address)?;
            receiver.set_read_timeout(Some(Duration::from_secs(1)))?;
            sender.set_write_timeout(Some(Duration::from_secs(1)))?;
            for _ in 0..32 {
                sender.send_to(&payload, receiver.local_addr()?)?;
                let mut buffer = [0; 1024];
                receiver.recv_from(&mut buffer)?;
            }
        } else {
            let listener = TcpListener::bind(address)?;
            let mut sender =
                TcpStream::connect_timeout(&listener.local_addr()?, Duration::from_secs(1))?;
            let (mut receiver, _) = listener.accept()?;
            sender.set_write_timeout(Some(Duration::from_secs(1)))?;
            receiver.set_read_timeout(Some(Duration::from_secs(1)))?;
            for _ in 0..32 {
                sender.write_all(&payload)?;
                let mut buffer = [0; 1024];
                receiver.read_exact(&mut buffer)?;
            }
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            std::thread::sleep(Duration::from_millis(100));
            let after = collector
                .snapshot()?
                .processes
                .into_iter()
                .find(|p| p.pid == pid)
                .ok_or_else(|| io::Error::other("probe process disappeared"))?;
            if after.start_time_unix_ms == before.start_time_unix_ms
                && after.bytes_in >= before.bytes_in + 32768
                && after.bytes_out >= before.bytes_out + 32768
            {
                break;
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other(format!(
                    "ETW byte probe failed for {address}, UDP={udp}"
                )));
            }
        }
    }
    drop(collector);
    drop(WindowsNetworkCollector::start(
        "Hoddmimis Network Verification",
    )?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn delayed_events_cannot_enter_a_reused_pid() {
        let mut counters = Counters::default();
        counters.by_pid.insert(
            42,
            HelperProcessCounters {
                pid: 42,
                start_time_unix_ms: 500,
                ..Default::default()
            },
        );
        counters.event(42, 499, true, 100);
        counters.event(42, 500, false, 200);
        counters.event(99, 600, true, 999);
        assert_eq!(counters.by_pid[&42].bytes_in, 0);
        assert_eq!(counters.by_pid[&42].bytes_out, 200);
        assert_eq!(counters.by_pid.len(), 1);
    }
}
