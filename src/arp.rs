//! ARP feature: lists the devices present in the host ARP/neighbor table
//! and identifies MAC vendors on demand using the embedded IEEE OUI
//! database (offline, crate mac_oui).

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::mpsc::Sender;

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

/// Resolves vendors for the given MACs in a background thread (embedded
/// IEEE OUI database — works offline).
pub fn lookup_vendors(macs: Vec<String>, tx: Sender<Event>) {
    std::thread::spawn(move || {
        let db = match mac_oui::Oui::default() {
            Ok(db) => db,
            Err(e) => {
                let _ = tx.send(Event::Arp(ArpEvent::Error(format!(
                    "failed to load the OUI database: {e}"
                ))));
                let _ = tx.send(Event::Arp(ArpEvent::Done));
                return;
            }
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
