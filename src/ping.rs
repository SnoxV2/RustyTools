use std::fs::File;
use std::io::Write as _;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::app::Event;
use crate::util;

pub enum PingStatus {
    Ok { rtt: Duration, jitter: Option<Duration> },
    Timeout,
    Error(String),
}

pub struct PingEvent {
    pub target: String,
    pub ip: Option<IpAddr>,
    pub seq: u64,
    pub status: PingStatus,
    pub timestamp: String,
}

pub struct PingSession {
    stop: Arc<AtomicBool>,
    handles: Vec<JoinHandle<()>>,
    pub log_files: Vec<PathBuf>,
}

impl PingSession {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    pub fn is_running(&self) -> bool {
        self.handles.iter().any(|h| !h.is_finished())
    }
}

/// Starts a continuous ping session: one thread and one log file per target.
pub fn start(
    targets: Vec<String>,
    interval: Duration,
    timeout: Duration,
    log_dir: &str,
    tx: Sender<Event>,
) -> Result<PingSession, String> {
    let dir = util::ensure_log_dir(log_dir, "ping")
        .map_err(|e| format!("failed to create log directory: {e}"))?;
    let stamp = util::now_file_str();
    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();
    let mut log_files = Vec::new();

    for target in targets {
        let path = dir.join(format!("ping_{stamp}_{}.csv", util::sanitize_filename(&target)));
        let mut file = File::create(&path)
            .map_err(|e| format!("failed to create log file {}: {e}", path.display()))?;
        let _ = writeln!(file, "timestamp;target;ip;seq;status;rtt_ms;jitter_ms");
        log_files.push(path);

        let stop = stop.clone();
        let tx = tx.clone();
        handles.push(std::thread::spawn(move || {
            worker(target, interval, timeout, file, stop, tx);
        }));
    }

    Ok(PingSession { stop, handles, log_files })
}

fn worker(
    target: String,
    interval: Duration,
    timeout: Duration,
    mut file: File,
    stop: Arc<AtomicBool>,
    tx: Sender<Event>,
) {
    let ip = match util::resolve_host(&target) {
        Ok(ip) => ip,
        Err(e) => {
            let timestamp = util::now_str();
            let _ = writeln!(file, "{timestamp};{target};;0;ERROR: {};;", e.replace(';', ","));
            let _ = tx.send(Event::Ping(PingEvent {
                target,
                ip: None,
                seq: 0,
                status: PingStatus::Error(e),
                timestamp,
            }));
            return;
        }
    };

    let mut backend = Backend::new();
    let mut seq: u64 = 0;
    let mut prev_rtt: Option<Duration> = None;

    while !stop.load(Ordering::SeqCst) {
        seq += 1;
        let started = Instant::now();
        let result = backend.ping(ip, timeout, seq as u16);
        let timestamp = util::now_str();

        let status = match result {
            Ok(rtt) => {
                let jitter = prev_rtt.map(|p| if rtt > p { rtt - p } else { p - rtt });
                prev_rtt = Some(rtt);
                PingStatus::Ok { rtt, jitter }
            }
            Err(PingErr::Timeout) => PingStatus::Timeout,
            Err(PingErr::Other(msg)) => PingStatus::Error(msg),
        };

        let log_line = match &status {
            PingStatus::Ok { rtt, jitter } => format!(
                "{timestamp};{target};{ip};{seq};OK;{:.3};{}",
                rtt.as_secs_f64() * 1000.0,
                jitter
                    .map(|j| format!("{:.3}", j.as_secs_f64() * 1000.0))
                    .unwrap_or_default()
            ),
            PingStatus::Timeout => format!("{timestamp};{target};{ip};{seq};TIMEOUT;;"),
            PingStatus::Error(msg) => {
                format!("{timestamp};{target};{ip};{seq};ERROR: {};;", msg.replace(';', ","))
            }
        };
        let _ = writeln!(file, "{log_line}");
        let _ = file.flush();

        let fatal = matches!(&status, PingStatus::Error(_));
        let _ = tx.send(Event::Ping(PingEvent {
            target: target.clone(),
            ip: Some(ip),
            seq,
            status,
            timestamp,
        }));
        // A socket error (permissions, network down) would repeat identically:
        // stop this worker instead of spamming the log.
        if fatal {
            return;
        }

        // Wait until the next probe, interruptible by Stop.
        loop {
            let elapsed = started.elapsed();
            if elapsed >= interval || stop.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep((interval - elapsed).min(Duration::from_millis(100)));
        }
    }
}

pub(crate) enum PingErr {
    Timeout,
    Other(String),
}

#[cfg(unix)]
pub(crate) struct Backend {
    pinger: Option<(IpAddr, crate::icmp::Pinger)>,
}

#[cfg(unix)]
impl Backend {
    pub(crate) fn new() -> Self {
        Backend { pinger: None }
    }

    pub(crate) fn ping(
        &mut self,
        ip: IpAddr,
        timeout: Duration,
        seq: u16,
    ) -> Result<Duration, PingErr> {
        if self.pinger.as_ref().is_none_or(|(cached, _)| *cached != ip) {
            let pinger = crate::icmp::Pinger::new(ip).map_err(PingErr::Other)?;
            self.pinger = Some((ip, pinger));
        }
        match self.pinger.as_ref().unwrap().1.ping(seq, timeout) {
            Ok(rtt) => Ok(rtt),
            Err(crate::icmp::PingError::Timeout) => Err(PingErr::Timeout),
            Err(crate::icmp::PingError::Other(msg)) => Err(PingErr::Other(msg)),
        }
    }
}

#[cfg(windows)]
fn looks_like_timeout(msg: &str, elapsed: Duration, timeout: Duration) -> bool {
    let m = msg.to_lowercase();
    m.contains("timeout")
        || m.contains("timed out")
        || m.contains("temporarily unavailable")
        || m.contains("would block")
        || elapsed >= timeout.mul_f64(0.95)
}

#[cfg(windows)]
pub(crate) struct Backend {
    pinger: Option<winping::Pinger>,
}

#[cfg(windows)]
impl Backend {
    pub(crate) fn new() -> Self {
        Backend { pinger: winping::Pinger::new().ok() }
    }

    pub(crate) fn ping(
        &mut self,
        ip: IpAddr,
        timeout: Duration,
        _seq: u16,
    ) -> Result<Duration, PingErr> {
        let Some(pinger) = self.pinger.as_mut() else {
            return Err(PingErr::Other("ICMP initialization failed (IcmpCreateFile)".into()));
        };
        pinger.set_timeout(timeout.as_millis().max(1) as u32);
        let started = Instant::now();
        let mut buffer = winping::Buffer::new();
        match pinger.send(ip, &mut buffer) {
            Ok(rtt_ms) => Ok(Duration::from_millis(rtt_ms as u64)),
            Err(e) => {
                let msg = e.to_string();
                // 11010 = IP_REQ_TIMED_OUT
                if msg.contains("11010") || looks_like_timeout(&msg, started.elapsed(), timeout) {
                    Err(PingErr::Timeout)
                } else {
                    Err(PingErr::Other(msg))
                }
            }
        }
    }
}
