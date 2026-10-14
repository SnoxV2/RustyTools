//! Packet sender: sends UDP datagrams or opens TCP connections to a
//! destination, optionally from a chosen local address, and reports what
//! came back. One log file per run in logs/packet/.

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

use crate::app::Event;
use crate::util;

/// How long a reply is awaited.
const TIMEOUT: Duration = Duration::from_secs(2);
/// TCP connect timeout. Windows retries after a refusal and only reports it
/// after ~2 s, so a shorter limit would show a closed port as "timed out".
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, PartialEq)]
pub enum Proto {
    Udp,
    Tcp,
}

impl Proto {
    pub fn label(self) -> &'static str {
        match self {
            Proto::Udp => "UDP",
            Proto::Tcp => "TCP",
        }
    }
}

pub struct PacketParams {
    pub target: String,
    pub port: u16,
    pub proto: Proto,
    pub payload: Vec<u8>,
    pub count: u32,
    pub interval: Duration,
    pub source: util::SourceConfig,
}

pub struct PacketSession {
    stop: Arc<AtomicBool>,
    handle: JoinHandle<()>,
    pub log_file: PathBuf,
}

impl PacketSession {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    pub fn is_running(&self) -> bool {
        !self.handle.is_finished()
    }
}

/// Sends `count` packets in a background thread; every result line goes to
/// the log file and to the UI.
pub fn start(params: PacketParams, log_dir: &str, tx: Sender<Event>) -> Result<PacketSession, String> {
    if params.target.trim().is_empty() {
        return Err("Enter a destination (IP or FQDN).".to_string());
    }
    if params.port == 0 {
        return Err("Enter a destination port (1-65535).".to_string());
    }
    let dir = util::ensure_log_dir(log_dir, "packet")
        .map_err(|e| format!("failed to create log directory: {e}"))?;
    let path = dir.join(format!("packet_{}.log", util::now_file_str()));
    let mut file = File::create(&path)
        .map_err(|e| format!("failed to create log file {}: {e}", path.display()))?;

    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = stop.clone();
    let handle = std::thread::spawn(move || {
        let mut emit = |line: String| {
            let line = format!("[{}] {line}", util::now_str());
            let _ = writeln!(file, "{line}");
            let _ = file.flush();
            let _ = tx.send(Event::Packet(line));
        };
        let proto = params.proto.label();
        let target = params.target.trim();

        let resolved = util::resolve_host(target)
            .and_then(|ip| params.source.bind_ip_for(&ip).map(|bind| (ip, bind)));
        let (ip, bind_ip) = match resolved {
            Ok(r) => r,
            Err(e) => return emit(format!("{proto} {target}:{} ERROR: {e}", params.port)),
        };
        let dst = SocketAddr::new(ip, params.port);

        for i in 1..=params.count {
            if stop_flag.load(Ordering::SeqCst) {
                break;
            }
            let started = Instant::now();
            match send_one(params.proto, dst, bind_ip, &params.payload) {
                Ok(outcome) => emit(format!("#{i} {proto} {dst} {outcome}")),
                Err(e) => emit(format!("#{i} {proto} {dst} ERROR: {e}")),
            }
            // Wait until the next packet, interruptible by Stop.
            while i < params.count
                && started.elapsed() < params.interval
                && !stop_flag.load(Ordering::SeqCst)
            {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    });

    Ok(PacketSession { stop, handle, log_file: path })
}

/// Sends one packet from `bind_ip` (None = system routing) and describes the
/// outcome: the local address really used, and the reply if any.
fn send_one(
    proto: Proto,
    dst: SocketAddr,
    bind_ip: Option<IpAddr>,
    payload: &[u8],
) -> Result<String, String> {
    let any = if dst.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    let local = SocketAddr::new(bind_ip.unwrap_or(any), 0);
    let bind_err = |e: std::io::Error| format!("cannot bind to source {}: {e}", local.ip());
    let started = Instant::now();
    let mut buf = [0u8; 2048];

    match proto {
        Proto::Udp => {
            let sock = UdpSocket::bind(local).map_err(bind_err)?;
            sock.connect(dst).map_err(|e| format!("cannot reach {dst}: {e}"))?;
            let sent = sock.send(payload).map_err(|e| format!("send failed: {e}"))?;
            let from = sock.local_addr().map_err(|e| e.to_string())?;
            let _ = sock.set_read_timeout(Some(TIMEOUT));
            let reply = describe_reply(sock.recv(&mut buf), &buf, started);
            Ok(format!("from {from}: sent {sent} byte(s), {reply}"))
        }
        Proto::Tcp => {
            // socket2: std cannot bind a TCP socket before connecting it.
            let sock = Socket::new(Domain::for_address(dst), Type::STREAM, Some(Protocol::TCP))
                .map_err(|e| format!("cannot open socket: {e}"))?;
            if bind_ip.is_some() {
                sock.bind(&local.into()).map_err(bind_err)?;
            }
            sock.connect_timeout(&dst.into(), CONNECT_TIMEOUT).map_err(|e| match e.kind() {
                std::io::ErrorKind::ConnectionRefused => "connection refused (port closed)".to_string(),
                std::io::ErrorKind::TimedOut => "connection timed out".to_string(),
                _ => format!("connection failed: {e}"),
            })?;
            let connect_ms = started.elapsed().as_secs_f64() * 1000.0;
            let mut stream: TcpStream = sock.into();
            let from = stream.local_addr().map_err(|e| e.to_string())?;
            if payload.is_empty() {
                return Ok(format!("from {from}: connected in {connect_ms:.1} ms"));
            }
            stream.write_all(payload).map_err(|e| format!("send failed: {e}"))?;
            let _ = stream.set_read_timeout(Some(TIMEOUT));
            let reply = describe_reply(stream.read(&mut buf), &buf, started);
            Ok(format!(
                "from {from}: connected in {connect_ms:.1} ms, sent {} byte(s), {reply}",
                payload.len()
            ))
        }
    }
}

fn describe_reply(result: std::io::Result<usize>, buf: &[u8], started: Instant) -> String {
    use std::io::ErrorKind::{ConnectionRefused, ConnectionReset, TimedOut, WouldBlock};
    match result {
        Ok(0) => "no data in reply".to_string(),
        Ok(n) => format!(
            "reply {n} byte(s) in {:.1} ms: {:?}",
            started.elapsed().as_secs_f64() * 1000.0,
            String::from_utf8_lossy(&buf[..n.min(64)])
        ),
        Err(e) if matches!(e.kind(), WouldBlock | TimedOut) => {
            format!("no reply within {} s", TIMEOUT.as_secs())
        }
        // UDP: the destination answered "port unreachable".
        Err(e) if matches!(e.kind(), ConnectionReset | ConnectionRefused) => {
            "rejected by the destination (port closed)".to_string()
        }
        Err(e) => format!("receive failed: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_and_tcp_from_a_chosen_source() {
        let source: IpAddr = "127.0.0.1".parse().unwrap();

        // UDP echo server.
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp_addr = udp.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            let (n, from) = udp.recv_from(&mut buf).unwrap();
            assert_eq!(from.ip(), source);
            udp.send_to(&buf[..n], from).unwrap();
        });
        let out = send_one(Proto::Udp, udp_addr, Some(source), b"ping").unwrap();
        assert!(out.contains("from 127.0.0.1:") && out.contains("reply 4 byte(s)"), "{out}");

        // TCP echo server.
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp_addr = tcp.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut s, from) = tcp.accept().unwrap();
            assert_eq!(from.ip(), source);
            let mut buf = [0u8; 64];
            let n = s.read(&mut buf).unwrap();
            s.write_all(&buf[..n]).unwrap();
        });
        let out = send_one(Proto::Tcp, tcp_addr, Some(source), b"hello").unwrap();
        assert!(out.contains("connected in") && out.contains("reply 5 byte(s)"), "{out}");

        // Closed TCP port: reported as refused, not as a timeout.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let err = send_one(Proto::Tcp, closed, None, b"").unwrap_err();
        assert!(err.contains("refused"), "{err}");
    }
}
