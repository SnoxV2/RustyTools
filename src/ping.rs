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
    /// Don't Fragment was set and the packet is larger than the path MTU.
    TooBig,
    Error(String),
}

/// Shape of the echo requests: payload size (like `ping -l` / `ping -s`) and
/// the Don't Fragment flag, which together test the path MTU.
#[derive(Clone, Copy)]
pub struct EchoOptions {
    pub size: u16,
    pub dont_fragment: bool,
}

impl Default for EchoOptions {
    fn default() -> Self {
        // 32 bytes, like the Windows ping command.
        EchoOptions { size: 32, dont_fragment: false }
    }
}

pub struct PingEvent {
    pub target: String,
    pub ip: Option<IpAddr>,
    pub seq: u64,
    pub status: PingStatus,
    pub timestamp: String,
    /// When the probe was sent (x axis of the latency graph).
    pub at: Instant,
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
    echo: EchoOptions,
    source: crate::util::SourceConfig,
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
        let source = source.clone();
        handles.push(std::thread::spawn(move || {
            worker(target, interval, timeout, Backend::new(source).with_echo(echo), file, stop, tx);
        }));
    }

    Ok(PingSession { stop, handles, log_files })
}

#[allow(clippy::too_many_arguments)]
fn worker(
    target: String,
    interval: Duration,
    timeout: Duration,
    backend: Backend,
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
                at: Instant::now(),
            }));
            return;
        }
    };

    let mut prev_rtt: Option<Duration> = None;
    probe_loop(ip, interval, timeout, backend, &stop, |seq, at, result| {
        let timestamp = util::now_str();
        let status = match result {
            Ok(rtt) => {
                let jitter = prev_rtt.map(|p| rtt.abs_diff(p));
                prev_rtt = Some(rtt);
                PingStatus::Ok { rtt, jitter }
            }
            Err(PingErr::Timeout) => PingStatus::Timeout,
            Err(PingErr::TooBig) => PingStatus::TooBig,
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
            PingStatus::TooBig => format!("{timestamp};{target};{ip};{seq};TOO_BIG;;"),
            PingStatus::Error(msg) => {
                format!("{timestamp};{target};{ip};{seq};ERROR: {};;", msg.replace(';', ","))
            }
        };
        let _ = writeln!(file, "{log_line}");
        let _ = file.flush();

        let _ = tx.send(Event::Ping(PingEvent {
            target: target.clone(),
            ip: Some(ip),
            seq,
            status,
            timestamp,
            at,
        }));
    });
}

/// Probes `ip` every `interval` until `stop` is set, handing each result
/// (sequence number, send time, outcome) to `on_result`. A fatal error
/// (permissions, socket failure) would repeat identically, so the loop ends
/// after reporting it instead of spamming the log.
pub(crate) fn probe_loop(
    ip: IpAddr,
    interval: Duration,
    timeout: Duration,
    mut backend: Backend,
    stop: &AtomicBool,
    mut on_result: impl FnMut(u64, Instant, Result<Duration, PingErr>),
) {
    let mut seq: u64 = 0;

    while !stop.load(Ordering::SeqCst) {
        seq += 1;
        let started = Instant::now();
        let result = backend.ping(ip, timeout, seq as u16);
        let fatal = matches!(result, Err(PingErr::Other(_)));
        on_result(seq, started, result);
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
    /// Larger than the path MTU with Don't Fragment set: a result, not a failure.
    TooBig,
    Other(String),
}

#[cfg(unix)]
pub(crate) struct Backend {
    source: crate::util::SourceConfig,
    echo: EchoOptions,
    pinger: Option<(IpAddr, crate::icmp::Pinger)>,
}

#[cfg(unix)]
impl Backend {
    pub(crate) fn new(source: crate::util::SourceConfig) -> Self {
        Backend { source, echo: EchoOptions::default(), pinger: None }
    }

    pub(crate) fn with_echo(mut self, echo: EchoOptions) -> Self {
        self.echo = echo;
        self
    }

    pub(crate) fn ping(
        &mut self,
        ip: IpAddr,
        timeout: Duration,
        seq: u16,
    ) -> Result<Duration, PingErr> {
        if self.pinger.as_ref().is_none_or(|(cached, _)| *cached != ip) {
            let pinger =
                crate::icmp::Pinger::new(ip, &self.source, self.echo).map_err(PingErr::Other)?;
            self.pinger = Some((ip, pinger));
        }
        match self.pinger.as_ref().unwrap().1.ping(seq, timeout) {
            Ok(rtt) => Ok(rtt),
            Err(crate::icmp::PingError::Timeout) => Err(PingErr::Timeout),
            Err(crate::icmp::PingError::TooBig) => Err(PingErr::TooBig),
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
    source: crate::util::SourceConfig,
    echo: EchoOptions,
    pinger: Option<winping::Pinger>,
}

#[cfg(windows)]
impl Backend {
    pub(crate) fn new(source: crate::util::SourceConfig) -> Self {
        Backend { source, echo: EchoOptions::default(), pinger: winping::Pinger::new().ok() }
    }

    pub(crate) fn with_echo(mut self, echo: EchoOptions) -> Self {
        self.echo = echo;
        self
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
        pinger.set_df(self.echo.dont_fragment);
        let bind_ip = self.source.bind_ip_for(&ip).map_err(PingErr::Other)?;
        let started = Instant::now();
        let mut buffer = winping::Buffer::with_data(vec![b'R'; usize::from(self.echo.size)]);
        // IcmpSendEcho2Ex (send*_from) handles the optional source address.
        let result = match (bind_ip, ip) {
            (Some(std::net::IpAddr::V4(src)), std::net::IpAddr::V4(dst)) => {
                pinger.send4_from(src, dst, &mut buffer)
            }
            (Some(std::net::IpAddr::V6(src)), std::net::IpAddr::V6(dst)) => {
                pinger.send6_from(src, dst, &mut buffer)
            }
            _ => pinger.send(ip, &mut buffer),
        };
        match result {
            // The API only reports whole milliseconds: use our own timer.
            Ok(_) => Ok(started.elapsed()),
            Err(e) => Err(classify_win_error(e, started.elapsed(), timeout)),
        }
    }
}

/// Loss or fatal error? Unreachable replies are loss, as on Unix: the worker
/// must keep probing so the target is seen again when it comes back.
#[cfg(windows)]
fn classify_win_error(e: winping::Error, elapsed: Duration, timeout: Duration) -> PingErr {
    match e {
        winping::Error::Timeout
        | winping::Error::HostUnreachable
        | winping::Error::NetUnreachable
        | winping::Error::TtlExpired => PingErr::Timeout,
        winping::Error::NeedsFragmented => PingErr::TooBig,
        e => {
            let msg = e.to_string();
            if looks_like_timeout(&msg, elapsed, timeout) {
                PingErr::Timeout
            } else {
                PingErr::Other(msg)
            }
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn unreachable_is_loss_not_fatal() {
        let quick = Duration::from_millis(5);
        let timeout = Duration::from_secs(2);
        for e in [winping::Error::HostUnreachable, winping::Error::NetUnreachable] {
            assert!(matches!(classify_win_error(e, quick, timeout), PingErr::Timeout));
        }
        // Too big for the path MTU with Don't Fragment: its own result.
        let big = classify_win_error(winping::Error::NeedsFragmented, quick, timeout);
        assert!(matches!(big, PingErr::TooBig));
        // A real failure stops the worker...
        let fatal = classify_win_error(winping::Error::Other(1), quick, timeout);
        assert!(matches!(fatal, PingErr::Other(_)));
        // ...unless it came after the whole timeout, which is loss.
        let late = classify_win_error(winping::Error::Other(1), timeout, timeout);
        assert!(matches!(late, PingErr::Timeout));
    }
}
