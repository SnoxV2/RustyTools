//! Minimal ICMP echo implementation (Unix) with strict reply validation.
//!
//! The previous `ping` crate accepted any incoming ICMP packet as a reply,
//! which produced false "OK" results: with several targets probed in
//! parallel (or a router answering "destination unreachable"), a packet
//! belonging to another probe could be counted as a success. Here every
//! reply must be an echo-reply whose identifier and sequence number match
//! the probe, received on a socket connect()ed to the target.

use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

#[derive(Debug)]
pub enum PingError {
    /// No valid reply before the deadline (counts as packet loss). Also used
    /// for ICMP "destination unreachable" and OS-level unreachable errors,
    /// which are loss conditions, not fatal errors.
    Timeout,
    /// Fatal error (permissions, socket failure): the worker should stop.
    Other(String),
}

const PAYLOAD_LEN: usize = 24;
const PAYLOAD_BYTE: u8 = 0x52; // 'R'

static IDENT_COUNTER: AtomicU16 = AtomicU16::new(0);

pub struct Pinger {
    sock: Socket,
    ident: u16,
    is_v4: bool,
    /// Linux ICMP datagram sockets: the kernel rewrites the identifier on the
    /// wire and already demultiplexes replies per socket, so the identifier
    /// of received packets cannot be compared with ours.
    kernel_ident: bool,
}

impl Pinger {
    pub fn new(ip: IpAddr) -> Result<Self, String> {
        let domain = if ip.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        let proto = if ip.is_ipv4() { Protocol::ICMPV4 } else { Protocol::ICMPV6 };

        // Unprivileged ICMP datagram socket first, raw socket as fallback.
        let (sock, dgram) = match Socket::new(domain, Type::DGRAM, Some(proto)) {
            Ok(s) => (s, true),
            Err(dgram_err) => match Socket::new(domain, Type::RAW, Some(proto)) {
                Ok(s) => (s, false),
                Err(raw_err) => {
                    let permission = [&dgram_err, &raw_err]
                        .iter()
                        .any(|e| e.kind() == std::io::ErrorKind::PermissionDenied);
                    return Err(if permission {
                        "insufficient permissions to open an ICMP socket — run as root/sudo, \
                         or on Linux: sysctl -w net.ipv4.ping_group_range='0 65535'"
                            .to_string()
                    } else {
                        format!("cannot open ICMP socket (dgram: {dgram_err}; raw: {raw_err})")
                    });
                }
            },
        };

        // connect() pins the peer: the kernel drops packets from other sources.
        sock.connect(&SocketAddr::new(ip, 0).into())
            .map_err(|e| format!("cannot connect ICMP socket to {ip}: {e}"))?;

        let ident = (std::process::id() as u16) ^ IDENT_COUNTER.fetch_add(1, Ordering::Relaxed);
        Ok(Pinger {
            sock,
            ident,
            is_v4: ip.is_ipv4(),
            kernel_ident: cfg!(target_os = "linux") && dgram,
        })
    }

    /// Sends one echo request and waits for the matching echo reply.
    /// Returns the precise RTT (send → validated reply).
    pub fn ping(&self, seq: u16, timeout: Duration) -> Result<Duration, PingError> {
        let packet = build_echo_request(self.is_v4, self.ident, seq);
        let start = Instant::now();
        if let Err(e) = self.sock.send(&packet) {
            return Err(map_io_error(e, "send failed"));
        }
        let deadline = start + timeout;
        let mut buf = [MaybeUninit::<u8>::uninit(); 2048];

        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(PingError::Timeout);
            }
            let _ = self.sock.set_read_timeout(Some((deadline - now).max(Duration::from_millis(1))));
            match self.sock.recv(&mut buf) {
                Ok(n) => {
                    let data = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
                    match self.classify(data, seq) {
                        Some(Reply::Echo) => return Ok(start.elapsed()),
                        // Unreachable = the probe was lost; count it as loss.
                        Some(Reply::Unreachable) => return Err(PingError::Timeout),
                        None => continue, // unrelated packet: keep waiting
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(PingError::Timeout)
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(map_io_error(e, "receive failed")),
            }
        }
    }

    /// Validates a received packet against the probe (type + ident + seq).
    fn classify(&self, data: &[u8], seq: u16) -> Option<Reply> {
        // Raw IPv4 sockets (and macOS ICMP datagram sockets) deliver the IP
        // header; Linux datagram sockets and all ICMPv6 sockets do not.
        let icmp = if self.is_v4 && data.len() >= 20 && data[0] >> 4 == 4 {
            let ihl = usize::from(data[0] & 0x0f) * 4;
            data.get(ihl..)?
        } else {
            data
        };
        if icmp.len() < 8 {
            return None;
        }
        let (echo_reply, unreachable) = if self.is_v4 { (0u8, [3u8, 11u8]) } else { (129, [1, 3]) };
        let kind = icmp[0];

        if kind == echo_reply {
            let ident = u16::from_be_bytes([icmp[4], icmp[5]]);
            let rseq = u16::from_be_bytes([icmp[6], icmp[7]]);
            let ident_ok = self.kernel_ident || ident == self.ident;
            return (ident_ok && rseq == seq).then_some(Reply::Echo);
        }

        if unreachable.contains(&kind) {
            // The error message embeds the original packet (IP header + ICMP
            // echo request): make sure it is really ours.
            let inner = icmp.get(8..)?;
            let inner_icmp = if self.is_v4 {
                if inner.len() < 20 || inner[0] >> 4 != 4 {
                    return None;
                }
                let ihl = usize::from(inner[0] & 0x0f) * 4;
                inner.get(ihl..)?
            } else {
                inner.get(40..)? // fixed IPv6 header
            };
            if inner_icmp.len() < 8 {
                return None;
            }
            let echo_request = if self.is_v4 { 8 } else { 128 };
            let ident = u16::from_be_bytes([inner_icmp[4], inner_icmp[5]]);
            let rseq = u16::from_be_bytes([inner_icmp[6], inner_icmp[7]]);
            let ident_ok = self.kernel_ident || ident == self.ident;
            return (inner_icmp[0] == echo_request && ident_ok && rseq == seq)
                .then_some(Reply::Unreachable);
        }
        None
    }
}

enum Reply {
    Echo,
    Unreachable,
}

/// "Host/network unreachable" while sending is a loss condition (e.g. ARP
/// failure on the local subnet), not a fatal socket error.
fn map_io_error(e: std::io::Error, context: &str) -> PingError {
    // EHOSTDOWN(64/112), EHOSTUNREACH(65/113), ENETUNREACH(51/101),
    // ENETDOWN(50/100), ECONNREFUSED — macOS/Linux values.
    const LOSS_ERRNOS: [i32; 9] = [50, 51, 64, 65, 100, 101, 111, 112, 113];
    if e.raw_os_error().is_some_and(|code| LOSS_ERRNOS.contains(&code)) {
        PingError::Timeout
    } else {
        PingError::Other(format!("{context}: {e}"))
    }
}

fn build_echo_request(is_v4: bool, ident: u16, seq: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(8 + PAYLOAD_LEN);
    packet.push(if is_v4 { 8 } else { 128 }); // echo request
    packet.push(0); // code
    packet.extend_from_slice(&[0, 0]); // checksum, filled below
    packet.extend_from_slice(&ident.to_be_bytes());
    packet.extend_from_slice(&seq.to_be_bytes());
    packet.extend(std::iter::repeat(PAYLOAD_BYTE).take(PAYLOAD_LEN));
    if is_v4 {
        // ICMPv6 checksums are computed by the kernel (pseudo-header needed);
        // for ICMPv4 we always provide it (the kernel recomputes it on Linux
        // datagram sockets after rewriting the identifier).
        let ck = checksum(&packet);
        packet[2..4].copy_from_slice(&ck.to_be_bytes());
    }
    packet
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let [b] = chunks.remainder() {
        sum += u32::from(*b) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localhost_replies() {
        let pinger = Pinger::new("127.0.0.1".parse().unwrap()).unwrap();
        let rtt = pinger.ping(1, Duration::from_secs(2)).expect("localhost must reply");
        assert!(rtt < Duration::from_secs(1));
    }

    #[test]
    fn dead_address_does_not_reply() {
        // 192.0.2.1 (TEST-NET-1, RFC 5737) must never answer: any Ok here
        // means we matched a packet that was not ours.
        let pinger = Pinger::new("192.0.2.1".parse().unwrap()).unwrap();
        let started = Instant::now();
        match pinger.ping(7, Duration::from_secs(2)) {
            Ok(_) => panic!("got a reply from TEST-NET-1: reply matching is broken"),
            Err(PingError::Timeout) => {}
            Err(PingError::Other(e)) => panic!("unexpected fatal error: {e}"),
        }
        assert!(started.elapsed() >= Duration::from_millis(500));
    }

    #[test]
    fn concurrent_targets_do_not_cross_talk() {
        // One responsive target and one dead target probed at the same time:
        // the dead one must stay dead even while replies are flowing in.
        let alive = std::thread::spawn(|| {
            let pinger = Pinger::new("127.0.0.1".parse().unwrap()).unwrap();
            for seq in 0..20 {
                let _ = pinger.ping(seq, Duration::from_millis(200));
            }
        });
        let pinger = Pinger::new("192.0.2.1".parse().unwrap()).unwrap();
        for seq in 0..3 {
            assert!(
                pinger.ping(seq, Duration::from_millis(700)).is_err(),
                "dead target reported alive: cross-talk between probes"
            );
        }
        alive.join().unwrap();
    }
}
