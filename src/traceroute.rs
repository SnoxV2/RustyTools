//! MTR-style trace engine: the path is discovered once with the system
//! traceroute (unprivileged), then every responding hop is pinged
//! continuously so each hop gets live loss/latency statistics, like
//! WinMTR or PingPlotter.

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{BufRead, BufReader, Write as _};
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::app::Event;
use crate::ping::{Backend, PingErr};
use crate::util;

#[derive(Clone)]
pub struct HopInfo {
    pub hop: u8,
    pub ip: Option<IpAddr>,
    pub hostname: Option<String>,
    pub is_destination: bool,
}

pub enum ProbeStatus {
    Ok { rtt: Duration },
    Timeout,
    Error(String),
}

pub enum TraceEvent {
    /// Discovery progress / engine status, shown under the target header.
    Status { target: String, message: String },
    /// Discovered path (sent again when hostnames are resolved).
    Hops { target: String, hops: Vec<HopInfo> },
    /// One probe result for one hop (full details go to the CSV log).
    Sample { target: String, hop: u8, status: ProbeStatus },
}

type ChildMap = Arc<Mutex<HashMap<u64, Child>>>;

pub struct TraceSession {
    stop: Arc<AtomicBool>,
    children: ChildMap,
    handles: Vec<JoinHandle<()>>,
    pub log_files: Vec<PathBuf>,
}

impl TraceSession {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Ok(mut children) = self.children.lock() {
            for child in children.values_mut() {
                let _ = child.kill();
            }
        }
    }

    pub fn is_running(&self) -> bool {
        self.handles.iter().any(|h| !h.is_finished())
    }
}

pub struct TraceParams {
    pub max_hops: u8,
    pub probe_interval: Duration,
    pub probe_timeout: Duration,
    pub resolve_names: bool,
}

/// Starts one MTR-style monitoring thread per target.
pub fn start(
    targets: Vec<String>,
    params: TraceParams,
    log_dir: &str,
    tx: Sender<Event>,
) -> Result<TraceSession, String> {
    let dir = util::ensure_log_dir(log_dir, "traceroute")
        .map_err(|e| format!("failed to create log directory: {e}"))?;
    let stamp = util::now_file_str();
    let stop = Arc::new(AtomicBool::new(false));
    let children: ChildMap = Arc::new(Mutex::new(HashMap::new()));
    let params = Arc::new(params);
    let mut handles = Vec::new();
    let mut log_files = Vec::new();

    for (idx, target) in targets.into_iter().enumerate() {
        let safe = util::sanitize_filename(&target);
        let discovery_path = dir.join(format!("discovery_{stamp}_{safe}.log"));
        let csv_path = dir.join(format!("mtr_{stamp}_{safe}.csv"));
        let discovery_file = File::create(&discovery_path)
            .map_err(|e| format!("failed to create log file {}: {e}", discovery_path.display()))?;
        let mut csv_file = File::create(&csv_path)
            .map_err(|e| format!("failed to create log file {}: {e}", csv_path.display()))?;
        let _ = writeln!(csv_file, "timestamp;target;hop;ip;seq;status;rtt_ms");
        log_files.push(discovery_path);
        log_files.push(csv_path);

        let stop = stop.clone();
        let children = children.clone();
        let tx = tx.clone();
        let params = params.clone();
        handles.push(std::thread::spawn(move || {
            target_worker(
                idx as u64,
                target,
                params,
                discovery_file,
                csv_file,
                stop,
                children,
                tx,
            );
        }));
    }

    Ok(TraceSession { stop, children, handles, log_files })
}

#[allow(clippy::too_many_arguments)]
fn target_worker(
    worker_id: u64,
    target: String,
    params: Arc<TraceParams>,
    mut discovery_file: File,
    csv_file: File,
    stop: Arc<AtomicBool>,
    children: ChildMap,
    tx: Sender<Event>,
) {
    let status = |message: String| {
        let _ = tx.send(Event::Trace(TraceEvent::Status { target: target.clone(), message }));
    };

    let target_ip = match util::resolve_host(&target) {
        Ok(ip) => ip,
        Err(e) => {
            status(format!("error: {e}"));
            return;
        }
    };

    status(format!("discovering path (max {} hops)…", params.max_hops));

    // --- Path discovery via the system traceroute, numeric output only ---
    let mut hops: BTreeMap<u8, Option<IpAddr>> = BTreeMap::new();
    match spawn_traceroute(&target_ip.to_string(), params.max_hops) {
        Err(e) => {
            status(e);
            return;
        }
        Ok(mut child) => {
            let stdout = child.stdout.take();
            let stderr = child.stderr.take();
            children.lock().unwrap().insert(worker_id, child);

            if let Some(stdout) = stdout {
                for line in BufReader::new(stdout).lines() {
                    let Ok(line) = line else { break };
                    let _ = writeln!(discovery_file, "[{}] {line}", util::now_str());
                    if let Some((hop, ip)) = parse_hop_line(&line) {
                        let entry = hops.entry(hop).or_insert(None);
                        if entry.is_none() {
                            *entry = ip;
                        }
                        let _ = tx.send(Event::Trace(TraceEvent::Hops {
                            target: target.clone(),
                            hops: build_hop_infos(&hops, target_ip),
                        }));
                    }
                }
            }
            if let Some(stderr) = stderr {
                for line in BufReader::new(stderr).lines() {
                    let Ok(line) = line else { break };
                    if !line.trim().is_empty() {
                        let _ = writeln!(discovery_file, "[{}] [stderr] {line}", util::now_str());
                    }
                }
            }
            let _ = discovery_file.flush();
            if let Some(mut child) = children.lock().unwrap().remove(&worker_id) {
                let _ = child.wait();
            }
        }
    }

    if stop.load(Ordering::SeqCst) {
        status("stopped".to_string());
        return;
    }

    let mut infos = build_hop_infos(&hops, target_ip);
    if infos.is_empty() {
        status("path discovery produced no hops (see discovery log)".to_string());
        return;
    }

    // --- Optional reverse DNS on each hop ---
    if params.resolve_names {
        status("resolving hop hostnames…".to_string());
        for info in &mut infos {
            if let Some(ip) = info.ip {
                info.hostname = dns_lookup::lookup_addr(&ip).ok().filter(|h| *h != ip.to_string());
            }
        }
    }
    let _ = tx.send(Event::Trace(TraceEvent::Hops { target: target.clone(), hops: infos.clone() }));

    let responding = infos.iter().filter(|i| i.ip.is_some()).count();
    status(format!(
        "monitoring {responding} hop(s) every {:.1} s — silent hops (*) are not probed",
        params.probe_interval.as_secs_f64()
    ));

    // --- Continuous probing: one thread per responding hop ---
    let csv = Arc::new(Mutex::new(csv_file));
    let mut hop_handles = Vec::new();
    for info in infos {
        let Some(ip) = info.ip else { continue };
        let stop = stop.clone();
        let tx = tx.clone();
        let csv = csv.clone();
        let target = target.clone();
        let interval = params.probe_interval;
        let timeout = params.probe_timeout;
        let hop = info.hop;
        hop_handles.push(std::thread::spawn(move || {
            hop_worker(target, hop, ip, interval, timeout, csv, stop, tx);
        }));
    }
    for handle in hop_handles {
        let _ = handle.join();
    }
    status("stopped".to_string());
}

#[allow(clippy::too_many_arguments)]
fn hop_worker(
    target: String,
    hop: u8,
    ip: IpAddr,
    interval: Duration,
    timeout: Duration,
    csv: Arc<Mutex<File>>,
    stop: Arc<AtomicBool>,
    tx: Sender<Event>,
) {
    let mut backend = Backend::new();
    let mut seq: u64 = 0;

    while !stop.load(Ordering::SeqCst) {
        seq += 1;
        let started = Instant::now();
        let result = backend.ping(ip, timeout, seq as u16);
        let timestamp = util::now_str();

        let status = match result {
            Ok(rtt) => ProbeStatus::Ok { rtt },
            Err(PingErr::Timeout) => ProbeStatus::Timeout,
            Err(PingErr::Other(msg)) => ProbeStatus::Error(msg),
        };

        let csv_line = match &status {
            ProbeStatus::Ok { rtt } => format!(
                "{timestamp};{target};{hop};{ip};{seq};OK;{:.3}",
                rtt.as_secs_f64() * 1000.0
            ),
            ProbeStatus::Timeout => format!("{timestamp};{target};{hop};{ip};{seq};TIMEOUT;"),
            ProbeStatus::Error(msg) => {
                format!("{timestamp};{target};{hop};{ip};{seq};ERROR: {};", msg.replace(';', ","))
            }
        };
        if let Ok(mut file) = csv.lock() {
            let _ = writeln!(file, "{csv_line}");
            let _ = file.flush();
        }

        let fatal = matches!(&status, ProbeStatus::Error(_));
        let _ = tx.send(Event::Trace(TraceEvent::Sample { target: target.clone(), hop, status }));
        if fatal {
            return;
        }

        loop {
            let elapsed = started.elapsed();
            if elapsed >= interval || stop.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep((interval - elapsed).min(Duration::from_millis(100)));
        }
    }
}

/// Turns the discovered hop map into an ordered list, making sure the final
/// destination is always present (and probed) even when discovery was
/// truncated by the hop limit or by a non-responding tail.
fn build_hop_infos(hops: &BTreeMap<u8, Option<IpAddr>>, target_ip: IpAddr) -> Vec<HopInfo> {
    let mut infos: Vec<HopInfo> = hops
        .iter()
        .map(|(hop, ip)| HopInfo { hop: *hop, ip: *ip, hostname: None, is_destination: *ip == Some(target_ip) })
        .collect();
    // Discovery stops at the destination: drop anything traceroute printed
    // after it (some implementations keep probing).
    if let Some(pos) = infos.iter().position(|i| i.is_destination) {
        infos.truncate(pos + 1);
    } else {
        let next = infos.last().map(|i| i.hop.saturating_add(1)).unwrap_or(1);
        infos.push(HopInfo { hop: next, ip: Some(target_ip), hostname: None, is_destination: true });
    }
    infos
}

/// Parses one traceroute/tracert/tracepath output line into (hop, ip).
/// Works across locales: hop number is the first integer token, the hop
/// address is the first token that parses as an IP.
fn parse_hop_line(line: &str) -> Option<(u8, Option<IpAddr>)> {
    let mut tokens = line.split_whitespace();
    let first = tokens.next()?;
    let hop: u8 = first.trim_end_matches(':').parse().ok()?;
    if hop == 0 {
        return None;
    }
    for token in tokens {
        let t = token.trim_matches(|c| matches!(c, '(' | ')' | '[' | ']' | ','));
        if let Ok(ip) = t.parse::<IpAddr>() {
            return Some((hop, Some(ip)));
        }
    }
    Some((hop, None))
}

fn spawn_traceroute(target: &str, max_hops: u8) -> Result<Child, String> {
    let candidates = traceroute_commands(target, max_hops);
    let mut last_err = String::new();
    for (prog, args) in &candidates {
        let mut cmd = util::os_command(prog);
        cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
        set_locale_c(&mut cmd);
        match cmd.spawn() {
            Ok(child) => return Ok(child),
            Err(e) => last_err = format!("`{prog}`: {e}"),
        }
    }
    Err(format!(
        "could not launch a traceroute ({last_err}). On Linux, install the `traceroute` \
         package (e.g. apt install traceroute)."
    ))
}

#[allow(unused_variables)]
fn set_locale_c(cmd: &mut Command) {
    #[cfg(unix)]
    cmd.env("LC_ALL", "C");
}

#[cfg(windows)]
fn traceroute_commands(target: &str, max_hops: u8) -> Vec<(String, Vec<String>)> {
    vec![(
        "tracert".to_string(),
        vec![
            "-d".to_string(),
            "-h".to_string(),
            max_hops.to_string(),
            "-w".to_string(),
            "1000".to_string(),
            target.to_string(),
        ],
    )]
}

#[cfg(unix)]
fn traceroute_commands(target: &str, max_hops: u8) -> Vec<(String, Vec<String>)> {
    vec![
        (
            "traceroute".to_string(),
            vec![
                "-n".to_string(),
                "-m".to_string(),
                max_hops.to_string(),
                "-w".to_string(),
                "2".to_string(),
                target.to_string(),
            ],
        ),
        // tracepath is the fallback on Linux when traceroute is not installed.
        (
            "tracepath".to_string(),
            vec!["-n".to_string(), "-m".to_string(), max_hops.to_string(), target.to_string()],
        ),
    ]
}
