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

/// Démarre une session de ping continu : un thread par cible, un fichier de log par cible.
pub fn start(
    targets: Vec<String>,
    interval: Duration,
    timeout: Duration,
    log_dir: &str,
    tx: Sender<Event>,
) -> Result<PingSession, String> {
    let dir = util::ensure_log_dir(log_dir)
        .map_err(|e| format!("création du répertoire de logs impossible : {e}"))?;
    let stamp = util::now_file_str();
    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();
    let mut log_files = Vec::new();

    for target in targets {
        let path = dir.join(format!("ping_{stamp}_{}.csv", util::sanitize_filename(&target)));
        let mut file = File::create(&path)
            .map_err(|e| format!("création du fichier de log {} impossible : {e}", path.display()))?;
        let _ = writeln!(file, "horodatage;cible;ip;seq;statut;rtt_ms;gigue_ms");
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
            let _ = writeln!(file, "{timestamp};{target};;0;ERREUR: {};;", e.replace(';', ","));
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
                format!("{timestamp};{target};{ip};{seq};ERREUR: {};;", msg.replace(';', ","))
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
        // Une erreur de socket (permissions, réseau hors service) se répéterait à
        // l'identique : on arrête ce worker plutôt que de spammer le journal.
        if fatal {
            return;
        }

        // Attente jusqu'au prochain envoi, interruptible par Arrêter.
        loop {
            let elapsed = started.elapsed();
            if elapsed >= interval || stop.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep((interval - elapsed).min(Duration::from_millis(100)));
        }
    }
}

enum PingErr {
    Timeout,
    Other(String),
}

fn looks_like_timeout(msg: &str, elapsed: Duration, timeout: Duration) -> bool {
    let m = msg.to_lowercase();
    m.contains("timeout")
        || m.contains("timed out")
        || m.contains("temporarily unavailable")
        || m.contains("would block")
        || elapsed >= timeout.mul_f64(0.95)
}

#[cfg(unix)]
struct Backend {
    use_raw: bool,
    ident: u16,
}

#[cfg(unix)]
impl Backend {
    fn new() -> Self {
        Backend { use_raw: false, ident: (std::process::id() & 0xffff) as u16 }
    }

    fn ping(&mut self, ip: IpAddr, timeout: Duration, seq: u16) -> Result<Duration, PingErr> {
        let started = Instant::now();
        let result = if self.use_raw {
            ping::rawsock::ping(ip, Some(timeout), Some(64), Some(self.ident), Some(seq), None)
        } else {
            ping::dgramsock::ping(ip, Some(timeout), Some(64), Some(self.ident), Some(seq), None)
        };
        match result {
            Ok(()) => Ok(started.elapsed()),
            Err(e) => {
                let msg = e.to_string();
                let permission = {
                    let m = msg.to_lowercase();
                    m.contains("permission") || m.contains("not permitted")
                };
                if permission && !self.use_raw {
                    // Socket ICMP non privilégié indisponible (ping_group_range sous
                    // Linux) : on retente en socket brut.
                    self.use_raw = true;
                    return self.ping(ip, timeout, seq);
                }
                if permission {
                    return Err(PingErr::Other(
                        "permissions insuffisantes pour ouvrir un socket ICMP — relancez en \
                         root/sudo, ou sous Linux : sysctl -w net.ipv4.ping_group_range='0 65535'"
                            .to_string(),
                    ));
                }
                if looks_like_timeout(&msg, started.elapsed(), timeout) {
                    Err(PingErr::Timeout)
                } else {
                    Err(PingErr::Other(msg))
                }
            }
        }
    }
}

#[cfg(windows)]
struct Backend {
    pinger: Option<winping::Pinger>,
}

#[cfg(windows)]
impl Backend {
    fn new() -> Self {
        Backend { pinger: winping::Pinger::new().ok() }
    }

    fn ping(&mut self, ip: IpAddr, timeout: Duration, _seq: u16) -> Result<Duration, PingErr> {
        let Some(pinger) = self.pinger.as_mut() else {
            return Err(PingErr::Other("initialisation ICMP impossible (IcmpCreateFile)".into()));
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
