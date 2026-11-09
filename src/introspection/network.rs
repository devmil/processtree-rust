//! Network socket introspection via libproc.

use super::capability::CapabilityState;
#[cfg(target_os = "macos")]
use super::proc::{
    self, is_socket_fd, proc_pidfdinfo_buffer, ProcFdInfo, PROC_PIDFDSOCKETINFO, PROC_PIDLISTFDS,
};
#[cfg(target_os = "macos")]
use super::socket_parse;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct NetworkEndpoint {
    pub protocol: String,
    pub local_address: String,
    pub local_port: u16,
    pub local_address_approximate: bool,
    pub remote_address: String,
    pub remote_port: u16,
    pub remote_address_approximate: bool,
    pub state: String,
}

/// Ports below this bound are IANA well-known ports.
pub const WELL_KNOWN_PORT_LIMIT: u16 = 1024;

impl NetworkEndpoint {
    /// Whether this socket serves inbound traffic: a TCP listener, or a UDP
    /// socket bound to a well-known port. UDP has no listen state, so other
    /// bound UDP sockets cannot be told apart from clients.
    pub fn is_listening(&self) -> bool {
        let protocol = self.protocol.to_ascii_lowercase();
        if protocol.starts_with("tcp") {
            self.state.eq_ignore_ascii_case("listen")
        } else if protocol.starts_with("udp") {
            self.local_port != 0 && self.local_port < WELL_KNOWN_PORT_LIMIT
        } else {
            false
        }
    }
}

/// Sorted distinct non-zero local ports of `endpoints`.
pub fn distinct_local_ports<'a>(endpoints: impl Iterator<Item = &'a NetworkEndpoint>) -> Vec<u16> {
    let mut ports: Vec<u16> = endpoints
        .map(|e| e.local_port)
        .filter(|p| *p != 0)
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

#[derive(Debug, Clone)]
pub struct NetworkResult {
    pub state: CapabilityState,
    pub endpoints: Vec<NetworkEndpoint>,
}

pub fn query_network(pid: i32) -> NetworkResult {
    #[cfg(target_os = "macos")]
    return query_macos(pid);
    #[cfg(not(target_os = "macos"))]
    match query_network_snapshot() {
        Ok(mut sockets) => NetworkResult {
            state: CapabilityState::Available,
            endpoints: sockets.remove(&pid).unwrap_or_default(),
        },
        Err(state) => NetworkResult {
            state,
            endpoints: vec![],
        },
    }
}

#[cfg(target_os = "macos")]
fn query_macos(pid: i32) -> NetworkResult {
    if pid <= 0 {
        return NetworkResult {
            state: CapabilityState::NotFound,
            endpoints: vec![],
        };
    }

    let fd_size = proc::PROC_FDINFO_SIZE;
    let mut buf = vec![0u8; fd_size.saturating_mul(500).max(64 * 1024)];
    let nbytes = match proc::proc_pidinfo_buffer(pid, PROC_PIDLISTFDS, 0, &mut buf) {
        Ok(n) => n,
        Err(state) => {
            return NetworkResult {
                state,
                endpoints: vec![],
            };
        }
    };

    let count = nbytes / fd_size;
    let mut endpoints = Vec::new();
    let mut sock_buf = vec![0u8; 8192];
    for i in 0..count.min(500) {
        let offset = i * fd_size;
        let fdinfo =
            unsafe { std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const ProcFdInfo) };
        if !is_socket_fd(&fdinfo) {
            continue;
        }
        let ret =
            match proc_pidfdinfo_buffer(pid, fdinfo.proc_fd, PROC_PIDFDSOCKETINFO, &mut sock_buf) {
                Ok(n) => n,
                Err(_) => continue,
            };
        if let Some(parsed) = socket_parse::parse_socket_fdinfo(&sock_buf[..ret]) {
            endpoints.push(NetworkEndpoint {
                protocol: parsed.protocol,
                local_address: parsed.local_address,
                local_port: parsed.local_port,
                local_address_approximate: false,
                remote_address: parsed.remote_address,
                remote_port: parsed.remote_port,
                remote_address_approximate: false,
                state: parsed.state,
            });
        }
    }

    NetworkResult {
        state: CapabilityState::Available,
        endpoints,
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn query_self_network_available() {
        let pid = unsafe { libc::getpid() };
        let result = query_network(pid);
        assert!(matches!(result.state, CapabilityState::Available));
        eprintln!("self network endpoints={}", result.endpoints.len());
    }

    #[test]
    fn query_missing_pid_is_terminated() {
        let result = query_network(999_999_999);
        assert!(matches!(result.state, CapabilityState::Terminated));
    }
}

/// One OS socket-table scan with one PID ownership lookup, shared by all rows.
/// Missing PIDs can also mean OS permissions hid their descriptors.
pub fn query_network_snapshot(
) -> Result<std::collections::HashMap<i32, Vec<NetworkEndpoint>>, CapabilityState> {
    use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
    let sockets = get_sockets_info(
        AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6,
        ProtocolFlags::TCP | ProtocolFlags::UDP,
    )
    .map_err(|_| CapabilityState::Restricted {
        reason: "socket table unavailable".into(),
    })?;
    let mut result: std::collections::HashMap<i32, Vec<NetworkEndpoint>> =
        std::collections::HashMap::new();
    for socket in sockets {
        let endpoint = match socket.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp) => NetworkEndpoint {
                protocol: "TCP".into(),
                local_address: tcp.local_addr.to_string(),
                local_port: tcp.local_port,
                local_address_approximate: false,
                remote_address: tcp.remote_addr.to_string(),
                remote_port: tcp.remote_port,
                remote_address_approximate: false,
                state: format!("{:?}", tcp.state),
            },
            ProtocolSocketInfo::Udp(udp) => NetworkEndpoint {
                protocol: "UDP".into(),
                local_address: udp.local_addr.to_string(),
                local_port: udp.local_port,
                local_address_approximate: false,
                remote_address: String::new(),
                remote_port: 0,
                remote_address_approximate: false,
                state: "Bound".into(),
            },
        };
        for pid in socket.associated_pids {
            if let Ok(pid) = i32::try_from(pid) {
                result.entry(pid).or_default().push(endpoint.clone());
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
mod port_tests {
    use super::*;
    #[test]
    fn finds_tcp_and_udp_ports_owned_by_this_process() {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let sockets = query_network_snapshot().unwrap();
        let own = &sockets[&(std::process::id() as i32)];
        assert!(own
            .iter()
            .any(|e| e.protocol == "TCP" && e.local_port == tcp.local_addr().unwrap().port()));
        assert!(own
            .iter()
            .any(|e| e.protocol == "UDP" && e.local_port == udp.local_addr().unwrap().port()));
    }

    #[test]
    fn reports_tcp_listeners_as_listening_and_connections_as_not() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let server_port = listener.local_addr().unwrap().port();
        let client = std::net::TcpStream::connect(("127.0.0.1", server_port)).unwrap();
        let client_port = client.local_addr().unwrap().port();
        let sockets = query_network_snapshot().unwrap();
        let own = &sockets[&(std::process::id() as i32)];
        let listening = distinct_local_ports(own.iter().filter(|e| e.is_listening()));
        assert!(listening.contains(&server_port));
        assert!(!listening.contains(&client_port));
        assert!(distinct_local_ports(own.iter()).contains(&client_port));
    }

    fn endpoint(protocol: &str, port: u16, state: &str) -> NetworkEndpoint {
        NetworkEndpoint {
            protocol: protocol.into(),
            local_address: "0.0.0.0".into(),
            local_port: port,
            local_address_approximate: false,
            remote_address: String::new(),
            remote_port: 0,
            remote_address_approximate: false,
            state: state.into(),
        }
    }

    #[test]
    fn udp_listens_only_on_well_known_ports() {
        assert!(endpoint("UDP", 53, "Bound").is_listening());
        assert!(endpoint("udp/6", 123, "state=0").is_listening());
        assert!(!endpoint("UDP", 5353, "Bound").is_listening());
        assert!(!endpoint("UDP", 0, "Bound").is_listening());
    }

    #[test]
    fn tcp_listens_only_in_listen_state() {
        assert!(endpoint("TCP", 8080, "Listen").is_listening());
        assert!(endpoint("tcp/4", 8080, "LISTEN").is_listening());
        assert!(!endpoint("TCP", 8080, "Established").is_listening());
        assert!(!endpoint("unix", 0, "—").is_listening());
    }
}
