//! DNS lookup feature: resolves names (or reverse-resolves IPs) using the
//! system resolver and/or a list of custom DNS servers, so answers from
//! different servers can be compared (e.g. 8.8.8.8 vs a local AD).

use std::fs::File;
use std::io::Write as _;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use std::net::SocketAddr;

use hickory_resolver::config::{
    NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig, ResolverOpts,
};
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::Resolver;

use crate::app::Event;
use crate::util;

pub const RECORD_TYPES: [&str; 9] = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "PTR"];

pub struct DnsAnswer {
    pub timestamp: String,
    pub query: String,
    pub rtype: String,
    pub server: String,
    pub records: Vec<String>,
    pub duration_ms: f64,
    pub error: Option<String>,
}

pub enum DnsEvent {
    Answer(DnsAnswer),
    Done,
}

/// Runs every query (target × server) in a background thread; one log file
/// per run in logs/dns/. Returns the log file path.
#[allow(clippy::too_many_arguments)]
pub fn start(
    targets: Vec<String>,
    rtype: String,
    use_system: bool,
    custom: Vec<IpAddr>,
    source: crate::util::SourceConfig,
    log_dir: &str,
    tx: Sender<Event>,
) -> Result<PathBuf, String> {
    if targets.is_empty() {
        return Err("Enter at least one name or IP to resolve.".to_string());
    }
    if !use_system && custom.is_empty() {
        return Err("Enable system DNS or provide at least one custom server.".to_string());
    }
    let record_type = RecordType::from_str(rtype.trim())
        .map_err(|_| format!("unsupported record type: {rtype}"))?;
    let dir = util::ensure_log_dir(log_dir, "dns")
        .map_err(|e| format!("failed to create log directory: {e}"))?;
    let path = dir.join(format!("dns_{}.log", util::now_file_str()));
    let mut file = File::create(&path)
        .map_err(|e| format!("failed to create log file {}: {e}", path.display()))?;

    std::thread::spawn(move || {
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(3);
        opts.attempts = 1;

        let mut servers: Vec<(String, Resolver)> = Vec::new();
        if use_system {
            match Resolver::from_system_conf() {
                Ok(r) => servers.push(("system".to_string(), r)),
                Err(e) => {
                    let answer = DnsAnswer {
                        timestamp: util::now_str(),
                        query: "(resolver setup)".to_string(),
                        rtype: rtype.clone(),
                        server: "system".to_string(),
                        records: Vec::new(),
                        duration_ms: 0.0,
                        error: Some(format!("cannot read system DNS configuration: {e}")),
                    };
                    log_answer(&mut file, &answer);
                    let _ = tx.send(Event::Dns(DnsEvent::Answer(answer)));
                }
            }
        }
        for ip in custom {
            // The source (custom IP or interface address) only applies to
            // custom servers; the system resolver keeps its own routing.
            let bind_addr = match source.bind_ip_for(&ip) {
                Ok(bind) => bind.map(|b| SocketAddr::new(b, 0)),
                Err(e) => {
                    let answer = DnsAnswer {
                        timestamp: util::now_str(),
                        query: "(resolver setup)".to_string(),
                        rtype: rtype.clone(),
                        server: ip.to_string(),
                        records: Vec::new(),
                        duration_ms: 0.0,
                        error: Some(e),
                    };
                    log_answer(&mut file, &answer);
                    let _ = tx.send(Event::Dns(DnsEvent::Answer(answer)));
                    continue;
                }
            };
            let mut group = NameServerConfigGroup::new();
            for protocol in [Protocol::Udp, Protocol::Tcp] {
                let mut ns = NameServerConfig::new(SocketAddr::new(ip, 53), protocol);
                ns.trust_negative_responses = true;
                ns.bind_addr = bind_addr;
                group.push(ns);
            }
            let config = ResolverConfig::from_parts(None, Vec::new(), group);
            match Resolver::new(config, opts.clone()) {
                Ok(r) => servers.push((ip.to_string(), r)),
                Err(e) => {
                    let answer = DnsAnswer {
                        timestamp: util::now_str(),
                        query: "(resolver setup)".to_string(),
                        rtype: rtype.clone(),
                        server: ip.to_string(),
                        records: Vec::new(),
                        duration_ms: 0.0,
                        error: Some(e.to_string()),
                    };
                    log_answer(&mut file, &answer);
                    let _ = tx.send(Event::Dns(DnsEvent::Answer(answer)));
                }
            }
        }

        for target in &targets {
            for (label, resolver) in &servers {
                let started = Instant::now();
                // An IP as input means a reverse (PTR) lookup, whatever the
                // selected record type.
                let (effective_type, result) = match target.parse::<IpAddr>() {
                    Ok(ip) => (
                        "PTR".to_string(),
                        resolver
                            .reverse_lookup(ip)
                            .map(|l| l.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                            .map_err(|e| e.to_string()),
                    ),
                    Err(_) => (
                        rtype.clone(),
                        resolver
                            .lookup(target.as_str(), record_type)
                            .map(|l| l.iter().map(|r| r.to_string()).collect::<Vec<_>>())
                            .map_err(|e| e.to_string()),
                    ),
                };
                let duration_ms = started.elapsed().as_secs_f64() * 1000.0;
                let answer = match result {
                    Ok(records) => DnsAnswer {
                        timestamp: util::now_str(),
                        query: target.clone(),
                        rtype: effective_type,
                        server: label.clone(),
                        records,
                        duration_ms,
                        error: None,
                    },
                    Err(e) => DnsAnswer {
                        timestamp: util::now_str(),
                        query: target.clone(),
                        rtype: effective_type,
                        server: label.clone(),
                        records: Vec::new(),
                        duration_ms,
                        error: Some(e),
                    },
                };
                log_answer(&mut file, &answer);
                let _ = tx.send(Event::Dns(DnsEvent::Answer(answer)));
            }
        }
        let _ = tx.send(Event::Dns(DnsEvent::Done));
    });

    Ok(path)
}

fn log_answer(file: &mut File, a: &DnsAnswer) {
    let outcome = match &a.error {
        Some(e) => format!("ERROR: {e}"),
        None => a.records.join(", "),
    };
    let _ = writeln!(
        file,
        "[{}] server={} type={} query={} ({:.1} ms) -> {outcome}",
        a.timestamp, a.server, a.rtype, a.query, a.duration_ms
    );
    let _ = file.flush();
}
