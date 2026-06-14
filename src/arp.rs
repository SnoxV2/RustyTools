//! ARP feature: lists the devices present in the host ARP/neighbor table
//! and identifies MAC vendors on demand using the embedded IEEE OUI
//! database (offline, crate mac_oui).

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::app::Event;
use crate::util;

pub struct ArpEntry {
    pub ip: String,
    pub mac: String,
    pub iface: String,
    pub state: String,
}

pub enum ArpEvent {
    Vendor { oui: String, vendor: String },
    Error(String),
    Done,
    ScanProgress { done: usize, total: usize, alive: usize },
    ScanDone { alive: usize },
}

/// A local IPv4 subnet that can be ICMP-swept.
#[derive(Clone)]
pub struct Subnet {
    pub label: String,
    pub hosts: Vec<Ipv4Addr>,
}

/// Lists the local IPv4 subnets of up interfaces that are small enough to
/// sweep (≤ 1024 hosts, i.e. prefix ≥ 22).
pub fn local_subnets() -> Vec<Subnet> {
    let mut out: Vec<Subnet> = Vec::new();
    let mut seen = HashSet::new();
    for itf in netdev::get_interfaces() {
        if !itf.is_up() {
            continue;
        }
        for net in &itf.ipv4 {
            let prefix = net.prefix_len();
            if !(22..=30).contains(&prefix) {
                continue;
            }
            let hosts = enumerate_hosts(net.addr(), prefix);
            if hosts.is_empty() || hosts.len() > 1024 {
                continue;
            }
            let network = hosts[0];
            if !seen.insert((network, prefix)) {
                continue;
            }
            out.push(Subnet {
                label: format!("{} — {}/{} ({} hosts)", itf.name, network, prefix, hosts.len()),
                hosts,
            });
        }
    }
    out
}

/// All usable host addresses of `addr/prefix` (network and broadcast excluded).
fn enumerate_hosts(addr: Ipv4Addr, prefix: u8) -> Vec<Ipv4Addr> {
    let ip = u32::from(addr);
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix as u32) };
    let network = ip & mask;
    let broadcast = network | !mask;
    if broadcast <= network + 1 {
        return Vec::new();
    }
    (network + 1..broadcast).map(Ipv4Addr::from).collect()
}

/// ICMP-sweeps the given hosts (one probe each, 1 s timeout) using a pool of
/// worker threads. Responding hosts get their ARP entry populated by the OS;
/// the caller re-reads the ARP table on ScanDone. Progress is streamed.
pub fn scan_subnet(hosts: Vec<Ipv4Addr>, tx: Sender<Event>) {
    std::thread::spawn(move || {
        let total = hosts.len();
        if total == 0 {
            let _ = tx.send(Event::Arp(ArpEvent::ScanDone { alive: 0 }));
            return;
        }
        let hosts = Arc::new(hosts);
        let next = Arc::new(AtomicUsize::new(0));
        let done = Arc::new(AtomicUsize::new(0));
        let alive = Arc::new(AtomicUsize::new(0));
        let workers = 64.min(total);

        let mut handles = Vec::new();
        for _ in 0..workers {
            let hosts = hosts.clone();
            let next = next.clone();
            let done = done.clone();
            let alive = alive.clone();
            let tx = tx.clone();
            handles.push(std::thread::spawn(move || {
                let mut backend = crate::ping::Backend::new(crate::util::SourceConfig::default());
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= hosts.len() {
                        break;
                    }
                    let ip = IpAddr::V4(hosts[i]);
                    let seq = (i as u16).wrapping_add(1);
                    if backend.ping(ip, Duration::from_secs(1), seq).is_ok() {
                        alive.fetch_add(1, Ordering::Relaxed);
                    }
                    let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                    let _ = tx.send(Event::Arp(ArpEvent::ScanProgress {
                        done: d,
                        total,
                        alive: alive.load(Ordering::Relaxed),
                    }));
                }
            }));
        }
        for h in handles {
            let _ = h.join();
        }
        let _ = tx.send(Event::Arp(ArpEvent::ScanDone { alive: alive.load(Ordering::Relaxed) }));
    });
}

/// Reads the ARP/neighbor table. Returns the parsed entries plus the raw
/// command output for verification.
pub fn gather() -> (Vec<ArpEntry>, String) {
    let (mut entries, raw) = gather_os();
    // Multicast/broadcast pseudo-entries are noise for an inventory view.
    entries.retain(|e| {
        let multicast =
            e.ip.parse::<IpAddr>().map(|ip| ip.is_multicast()).unwrap_or(false);
        !multicast && e.ip != "255.255.255.255" && e.mac != "ff:ff:ff:ff:ff:ff"
    });
    entries.sort_by(|a, b| {
        let key = |s: &ArpEntry| s.ip.parse::<IpAddr>().ok();
        key(a).cmp(&key(b))
    });
    (entries, raw)
}

/// Normalizes a MAC to lowercase, ':'-separated, zero-padded groups
/// (macOS arp prints "a4:2b:b0:1:2:3"). Returns None for non-MAC tokens.
pub fn normalize_mac(mac: &str) -> Option<String> {
    let groups: Vec<String> = mac
        .trim()
        .to_lowercase()
        .replace('-', ":")
        .split(':')
        .map(|g| format!("{g:0>2}"))
        .collect();
    let valid = groups.len() == 6
        && groups.iter().all(|g| g.len() == 2 && g.chars().all(|c| c.is_ascii_hexdigit()));
    valid.then(|| groups.join(":"))
}

/// OUI prefix (first 3 bytes) used as the vendor cache key.
pub fn oui_of(mac: &str) -> Option<String> {
    normalize_mac(mac).map(|m| m[..8].to_string())
}

/// Whether an entry is a real, reachable device: it has a valid MAC and its
/// state is not an incomplete/failed one. Works across the per-OS states
/// (macOS reachable/incomplete, Linux REACHABLE/STALE/INCOMPLETE→lowercased,
/// Windows dynamic/static).
pub fn is_reachable(entry: &ArpEntry) -> bool {
    normalize_mac(&entry.mac).is_some()
        && !matches!(entry.state.as_str(), "incomplete" | "failed" | "none")
}

/// The embedded IEEE OUI database, built once and reused. Building it parses
/// ~30k entries (~0.4 s); lookups are then essentially free, so caching it
/// makes bulk and per-row resolves instant instead of rebuilding every time.
fn oui_db() -> Option<&'static mac_oui::Oui> {
    static DB: OnceLock<Option<mac_oui::Oui>> = OnceLock::new();
    DB.get_or_init(|| mac_oui::Oui::default().ok()).as_ref()
}

/// Pre-builds the OUI database off the UI thread (call at startup) so the
/// first local vendor resolve doesn't pay the ~0.4 s build cost.
pub fn warm_oui_db() {
    std::thread::spawn(|| {
        let _ = oui_db();
    });
}

/// Resolves vendors for the given MACs in a background thread (cached
/// embedded IEEE OUI database — works offline, instant after warm-up).
pub fn lookup_vendors(macs: Vec<String>, tx: Sender<Event>) {
    std::thread::spawn(move || {
        let Some(db) = oui_db() else {
            let _ = tx
                .send(Event::Arp(ArpEvent::Error("failed to load the OUI database".to_string())));
            let _ = tx.send(Event::Arp(ArpEvent::Done));
            return;
        };
        for mac in macs {
            let Some(normalized) = normalize_mac(&mac) else { continue };
            let Some(oui) = oui_of(&mac) else { continue };
            let vendor = match db.lookup_by_mac(&normalized) {
                Ok(Some(entry)) => entry.company_name.clone(),
                Ok(None) => "Unknown (not in OUI database)".to_string(),
                Err(e) => format!("lookup failed: {e}"),
            };
            let _ = tx.send(Event::Arp(ArpEvent::Vendor { oui, vendor }));
        }
        let _ = tx.send(Event::Arp(ArpEvent::Done));
    });
}

/// Resolves vendors online via the macvendors.com API, using the system
/// `curl`. Only the OUI prefix (zero-padded to a full MAC) is sent — never
/// the full device MAC. Unique OUIs are queried once, throttled to respect
/// the free API's ~1 request/second limit.
pub fn lookup_vendors_online(macs: Vec<String>, tx: Sender<Event>) {
    std::thread::spawn(move || {
        let mut seen = HashSet::new();
        let mut first = true;
        for mac in macs {
            let Some(oui) = oui_of(&mac) else { continue };
            if !seen.insert(oui.clone()) {
                continue;
            }
            if !first {
                std::thread::sleep(Duration::from_millis(1100));
            }
            first = false;
            let vendor = query_macvendors(&oui);
            let _ = tx.send(Event::Arp(ArpEvent::Vendor { oui, vendor }));
        }
        let _ = tx.send(Event::Arp(ArpEvent::Done));
    });
}

fn query_macvendors(oui: &str) -> String {
    let url = format!("https://api.macvendors.com/{oui}:00:00:00");
    let output = util::os_command("curl")
        .args(["-s", "--max-time", "6", "-w", "\n%{http_code}", &url])
        .output();
    match output {
        Ok(o) => {
            let body = String::from_utf8_lossy(&o.stdout);
            let mut lines: Vec<&str> = body.lines().collect();
            let code = lines.pop().unwrap_or("").trim();
            let text = lines.join(" ").trim().to_string();
            match code {
                "200" if !text.is_empty() => text,
                "200" => "Unknown".to_string(),
                "404" => "Unknown (not found online)".to_string(),
                "429" => "rate limited — try again".to_string(),
                "000" | "" => "network error (curl could not connect)".to_string(),
                c => format!("HTTP {c}"),
            }
        }
        Err(e) => format!("cannot run curl: {e}"),
    }
}

/// Exports the table (with resolved vendors) to logs/arp/.
pub fn export(
    entries: &[ArpEntry],
    vendors: &std::collections::HashMap<String, String>,
    raw: &str,
    log_dir: &str,
) -> Result<PathBuf, String> {
    let dir = util::ensure_log_dir(log_dir, "arp")
        .map_err(|e| format!("failed to create log directory: {e}"))?;
    let path = dir.join(format!("arp_{}.txt", util::now_file_str()));
    let mut s = format!("ARP TABLE — generated {}\n\n", util::now_str());
    s.push_str(&format!(
        "{:<40} {:<18} {:<30} {:<10} {}\n",
        "IP", "MAC", "Vendor", "Interface", "State"
    ));
    for e in entries {
        let vendor = oui_of(&e.mac)
            .and_then(|oui| vendors.get(&oui).cloned())
            .unwrap_or_else(|| "-".to_string());
        s.push_str(&format!(
            "{:<40} {:<18} {:<30} {:<10} {}\n",
            e.ip, e.mac, vendor, e.iface, e.state
        ));
    }
    s.push_str("\n=== RAW OUTPUT ===\n");
    s.push_str(raw);
    std::fs::write(&path, s).map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    Ok(path)
}

#[cfg(target_os = "macos")]
fn gather_os() -> (Vec<ArpEntry>, String) {
    let raw = util::run_capture("arp", &["-an"]);
    (parse_bsd_arp(&raw), raw)
}

#[cfg(windows)]
fn gather_os() -> (Vec<ArpEntry>, String) {
    let raw = util::run_capture("arp", &["-a"]);
    let mut entries = Vec::new();
    let mut iface = String::new();
    for line in raw.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        // Locale-independent: "Interface: 192.168.1.10 --- 0x4" always has
        // an IP as the second token.
        if tokens.len() >= 2 && line.contains("---") {
            if let Some(ip) = tokens.iter().find(|t| t.parse::<std::net::Ipv4Addr>().is_ok()) {
                iface = ip.to_string();
            }
            continue;
        }
        if tokens.len() >= 3 && tokens[0].parse::<std::net::Ipv4Addr>().is_ok() {
            if let Some(mac) = normalize_mac(tokens[1]) {
                entries.push(ArpEntry {
                    ip: tokens[0].to_string(),
                    mac,
                    iface: iface.clone(),
                    state: tokens[2].to_string(),
                });
            }
        }
    }
    (entries, raw)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn gather_os() -> (Vec<ArpEntry>, String) {
    let raw = util::run_capture("ip", &["neigh", "show"]);
    if !raw.starts_with("Cannot run") {
        let mut entries = Vec::new();
        // "192.168.1.1 dev eth0 lladdr a4:2b:b0:11:22:33 REACHABLE"
        for line in raw.lines() {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.is_empty() || tokens[0].parse::<IpAddr>().is_err() {
                continue;
            }
            let after = |key: &str| {
                tokens.iter().position(|t| *t == key).and_then(|i| tokens.get(i + 1)).copied()
            };
            let mac = after("lladdr").and_then(normalize_mac);
            let state = tokens
                .last()
                .filter(|t| t.chars().all(|c| c.is_ascii_uppercase()))
                .unwrap_or(&"?")
                .to_string();
            entries.push(ArpEntry {
                ip: tokens[0].to_string(),
                mac: mac.unwrap_or_else(|| "(incomplete)".to_string()),
                iface: after("dev").unwrap_or("?").to_string(),
                state: state.to_lowercase(),
            });
        }
        (entries, raw)
    } else {
        let raw = util::run_capture("arp", &["-an"]);
        (parse_bsd_arp(&raw), raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_normalization() {
        // macOS arp drops leading zeros; Windows uses dashes.
        assert_eq!(normalize_mac("a4:2b:b0:1:2:3").as_deref(), Some("a4:2b:b0:01:02:03"));
        assert_eq!(normalize_mac("A4-2B-B0-11-22-33").as_deref(), Some("a4:2b:b0:11:22:33"));
        assert_eq!(normalize_mac("(incomplete)"), None);
        assert_eq!(oui_of("A4-2B-B0-11-22-33").as_deref(), Some("a4:2b:b0"));
    }

    #[cfg(unix)]
    #[test]
    fn bsd_arp_parsing() {
        let raw = "? (192.168.1.1) at a4:2b:b0:1:22:33 on en0 ifscope [ethernet]\n\
                   ? (192.168.1.50) at (incomplete) on en0 ifscope [ethernet]\n";
        let entries = parse_bsd_arp(raw);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].ip, "192.168.1.1");
        assert_eq!(entries[0].mac, "a4:2b:b0:01:22:33");
        assert_eq!(entries[0].iface, "en0");
        assert_eq!(entries[1].state, "incomplete");
    }

    #[test]
    fn oui_database_lookup() {
        // 00:00:0c is Cisco's historic OUI — a stable fixture to validate the
        // embedded database and our full-MAC lookup usage.
        let db = mac_oui::Oui::default().expect("embedded OUI database must load");
        let entry = db
            .lookup_by_mac("00:00:0c:12:34:56")
            .expect("lookup must not fail")
            .expect("Cisco OUI must be present");
        assert!(entry.company_name.to_lowercase().contains("cisco"), "{}", entry.company_name);
    }
}

/// "? (192.168.1.1) at a4:2b:b0:11:22:33 on en0 ifscope [ethernet]"
#[cfg(unix)]
fn parse_bsd_arp(raw: &str) -> Vec<ArpEntry> {
    let mut entries = Vec::new();
    for line in raw.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let ip = tokens
            .iter()
            .find(|t| t.starts_with('(') && t.ends_with(')'))
            .map(|t| t.trim_matches(|c| c == '(' || c == ')').to_string());
        let after = |key: &str| {
            tokens.iter().position(|t| *t == key).and_then(|i| tokens.get(i + 1)).copied()
        };
        let Some(ip) = ip else { continue };
        let raw_mac = after("at").unwrap_or("(incomplete)");
        let mac = normalize_mac(raw_mac);
        entries.push(ArpEntry {
            ip,
            state: if mac.is_some() { "reachable" } else { "incomplete" }.to_string(),
            mac: mac.unwrap_or_else(|| "(incomplete)".to_string()),
            iface: after("on").unwrap_or("?").to_string(),
        });
    }
    entries
}
