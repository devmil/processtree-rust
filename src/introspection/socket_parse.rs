//! Parse `socket_fdinfo` / `in_sockinfo` payloads (macOS `proc_info.h` layout).

use super::proc::{tcp_state_name, SOCKINFO_IN, SOCKINFO_TCP, SOCKINFO_UN};

/// Byte offsets within `struct socket_fdinfo` (macOS 26 arm64 SDK).
mod layout {
    pub const SOI_KIND: usize = 24 + 232;
    pub const SOI_FAMILY: usize = 24 + 160;
    pub const SOI_PROTOCOL: usize = 24 + 156;
    pub const SOI_STATE: usize = 24 + 168;
    pub const SOI_PROTO_INI: usize = 24 + 240;
    pub const UNIX_SUN_PATH: usize = 282;
    pub const INI_FPORT: usize = SOI_PROTO_INI;
    pub const INI_LPORT: usize = SOI_PROTO_INI + 4;
    pub const INI_VFLAG: usize = SOI_PROTO_INI + 24;
    pub const INI_FADDR4: usize = SOI_PROTO_INI + 32 + 12;
    pub const INI_LADDR4: usize = SOI_PROTO_INI + 48 + 12;
    pub const TCP_STATE: usize = SOI_PROTO_INI + 80;
}

#[derive(Debug, Clone)]
pub struct ParsedSocket {
    pub protocol: String,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub state: String,
}

pub fn parse_socket_fdinfo(buf: &[u8]) -> Option<ParsedSocket> {
    if buf.len() < layout::SOI_PROTO_INI + 80 {
        return None;
    }
    let kind = read_i32(buf, layout::SOI_KIND)?;
    let family = read_i32(buf, layout::SOI_FAMILY)?;
    let protocol = read_i32(buf, layout::SOI_PROTOCOL)?;
    let soi_state = read_i16(buf, layout::SOI_STATE)?;

    let proto_label = protocol_label(protocol, family);

    match kind {
        SOCKINFO_TCP | SOCKINFO_IN => {
            let (local_address, local_port, remote_address, remote_port) = parse_in_sockinfo(buf)?;
            let state = if kind == SOCKINFO_TCP {
                tcp_state_name(read_i32(buf, layout::TCP_STATE).unwrap_or(-1)).to_string()
            } else {
                format!("state={soi_state}")
            };
            Some(ParsedSocket {
                protocol: proto_label,
                local_address,
                local_port,
                remote_address,
                remote_port,
                state,
            })
        }
        SOCKINFO_UN => {
            let path = cstr_at(buf, layout::UNIX_SUN_PATH);
            Some(ParsedSocket {
                protocol: "unix".into(),
                local_address: if path.is_empty() { "—".into() } else { path },
                local_port: 0,
                remote_address: "—".into(),
                remote_port: 0,
                state: "—".into(),
            })
        }
        _ => Some(ParsedSocket {
            protocol: proto_label,
            local_address: "—".into(),
            local_port: 0,
            remote_address: "—".into(),
            remote_port: 0,
            state: format!("kind={kind}"),
        }),
    }
}

pub fn socket_summary_from_buf(buf: &[u8]) -> String {
    parse_socket_fdinfo(buf)
        .map(|p| {
            if p.local_port > 0 || p.local_address != "—" {
                format!(
                    "{} · {}:{} → {}:{} · {}",
                    p.protocol,
                    p.local_address,
                    p.local_port,
                    p.remote_address,
                    p.remote_port,
                    p.state
                )
            } else {
                format!("{} · {} · {}", p.protocol, p.local_address, p.state)
            }
        })
        .unwrap_or_else(|| "socket".into())
}

fn parse_in_sockinfo(buf: &[u8]) -> Option<(String, u16, String, u16)> {
    let vflag = *buf.get(layout::INI_VFLAG)?;
    let fport = read_i32(buf, layout::INI_FPORT).unwrap_or(0);
    let lport = read_i32(buf, layout::INI_LPORT).unwrap_or(0);
    if vflag & 0x1 != 0 {
        let local = ipv4_at(buf, layout::INI_LADDR4)?;
        let remote = ipv4_at(buf, layout::INI_FADDR4)?;
        return Some((
            local,
            u16::try_from(lport.max(0)).unwrap_or(0),
            remote,
            u16::try_from(fport.max(0)).unwrap_or(0),
        ));
    }
    Some(("—".into(), 0, "—".into(), 0))
}

fn ipv4_at(buf: &[u8], offset: usize) -> Option<String> {
    let b = buf.get(offset..offset + 4)?;
    Some(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]))
}

fn protocol_label(protocol: i32, family: i32) -> String {
    let proto = match protocol {
        x if x == libc::IPPROTO_TCP as i32 => "tcp",
        x if x == libc::IPPROTO_UDP as i32 => "udp",
        _ => "ip",
    };
    let fam = match family {
        libc::AF_INET => "4",
        libc::AF_INET6 => "6",
        libc::AF_UNIX => "unix",
        _ => "?",
    };
    format!("{proto}/{fam}")
}

fn read_i32(buf: &[u8], off: usize) -> Option<i32> {
    let bytes: [u8; 4] = buf.get(off..off + 4)?.try_into().ok()?;
    Some(i32::from_ne_bytes(bytes))
}

fn read_i16(buf: &[u8], off: usize) -> Option<i16> {
    let bytes: [u8; 2] = buf.get(off..off + 2)?.try_into().ok()?;
    Some(i16::from_ne_bytes(bytes))
}

fn cstr_at(buf: &[u8], off: usize) -> String {
    let tail = buf.get(off..).unwrap_or(&[]);
    let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
    String::from_utf8_lossy(&tail[..end]).into_owned()
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::super::proc::{
        ProcFdInfo, PROC_PIDFDSOCKETINFO, PROC_PIDLISTFDS, PROX_FDTYPE_SOCKET,
    };
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn parses_self_unix_or_inet_socket() {
        let _socket_pair = UnixStream::pair().expect("create test socket pair");
        let pid = unsafe { libc::getpid() };
        let fd_size = std::mem::size_of::<ProcFdInfo>();
        let mut buf = vec![0u8; fd_size * 512];
        let nbytes = unsafe {
            libc::proc_pidinfo(
                pid,
                PROC_PIDLISTFDS,
                0,
                buf.as_mut_ptr() as *mut _,
                buf.len() as i32,
            )
        };
        assert!(nbytes > 0);
        let count = nbytes as usize / fd_size;
        let mut parsed_any = false;
        for i in 0..count {
            let off = i * fd_size;
            let fdinfo =
                unsafe { std::ptr::read_unaligned(buf.as_ptr().add(off) as *const ProcFdInfo) };
            if fdinfo.proc_fdtype != PROX_FDTYPE_SOCKET {
                continue;
            }
            let mut sbuf = vec![0u8; 8192];
            let ret = unsafe {
                libc::proc_pidfdinfo(
                    pid,
                    fdinfo.proc_fd,
                    PROC_PIDFDSOCKETINFO,
                    sbuf.as_mut_ptr() as *mut _,
                    sbuf.len() as i32,
                )
            };
            if ret <= 0 {
                continue;
            }
            let parsed = parse_socket_fdinfo(&sbuf[..ret as usize]);
            eprintln!("fd={} parsed={parsed:?}", fdinfo.proc_fd);
            if parsed.is_some() {
                parsed_any = true;
                break;
            }
        }
        assert!(parsed_any, "expected at least one parseable socket on self");
    }
}
