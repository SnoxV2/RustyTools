use std::net::Ipv4Addr;
use std::path::PathBuf;

use crate::util;

pub struct IfaceInfo {
    pub name: String,
    pub friendly_name: Option<String>,
    pub mac: Option<String>,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub gateway: Option<String>,
    pub is_up: bool,
    pub is_default: bool,
    pub if_type: String,
    pub dns: Vec<String>,
}

pub struct RouteEntry {
    pub destination: String,
    pub gateway: String,
    pub interface: String,
    pub info: String,
    pub is_ipv6: bool,
}

pub struct NetReport {
    pub generated_at: String,
    pub hostname: String,
    pub domain: Option<String>,
    pub dns_servers: Vec<String>,
    pub interfaces: Vec<IfaceInfo>,
    pub routes: Vec<RouteEntry>,
    pub routes_raw: String,
    pub raw_sections: Vec<(String, String)>,
}

fn prefix_to_mask(prefix: u8) -> Ipv4Addr {
    let bits: u32 = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix.min(32) as u32) };
    Ipv4Addr::from(bits)
}

/// Collects the host network configuration (interfaces, DNS, gateways, routes).
pub fn gather() -> NetReport {
    let hostname = gethostname::gethostname().to_string_lossy().into_owned();

    let mut interfaces = Vec::new();
    let mut dns_servers: Vec<String> = Vec::new();

    for itf in netdev::get_interfaces() {
        let ipv4 = itf
            .ipv4
            .iter()
            .map(|net| {
                format!(
                    "{}/{} (mask {})",
                    net.addr(),
                    net.prefix_len(),
                    prefix_to_mask(net.prefix_len())
                )
            })
            .collect();
        let ipv6 = itf.ipv6.iter().map(|net| format!("{}/{}", net.addr(), net.prefix_len())).collect();
        let gateway = itf.gateway.as_ref().map(|gw| {
            let v4: Vec<String> = gw.ipv4.iter().map(|ip| ip.to_string()).collect();
            let v6: Vec<String> = gw.ipv6.iter().map(|ip| ip.to_string()).collect();
            let mut parts = v4;
            parts.extend(v6);
            format!("{} (MAC {})", parts.join(", "), gw.mac_addr)
        });
        let dns: Vec<String> = itf.dns_servers.iter().map(|ip| ip.to_string()).collect();
        for d in &dns {
            if !dns_servers.contains(d) {
                dns_servers.push(d.clone());
            }
        }

        interfaces.push(IfaceInfo {
            name: itf.name.clone(),
            friendly_name: itf.friendly_name.clone(),
            mac: itf.mac_addr.as_ref().map(|m| m.to_string()),
            ipv4,
            ipv6,
            gateway,
            is_up: itf.is_up(),
            is_default: itf.default,
            if_type: format!("{:?}", itf.if_type),
            dns,
        });
    }
    // Default and active interfaces first.
    interfaces.sort_by_key(|i| (!i.is_default, !i.is_up, i.name.clone()));

    let (domain, mut extra_dns) = domain_and_dns();
    for d in extra_dns.drain(..) {
        if !dns_servers.contains(&d) {
            dns_servers.push(d);
        }
    }

    let (routes, routes_raw) = gather_routes();
    let raw_sections = raw_sections(&routes_raw);
    NetReport {
        generated_at: util::now_str(),
        hostname,
        domain,
        dns_servers,
        interfaces,
        routes,
        routes_raw,
        raw_sections,
    }
}

/// DNS domain and extra DNS servers, per OS.
fn domain_and_dns() -> (Option<String>, Vec<String>) {
    #[cfg(windows)]
    {
        (std::env::var("USERDNSDOMAIN").ok().filter(|s| !s.is_empty()), Vec::new())
    }
    #[cfg(unix)]
    {
        let mut domain = None;
        let mut dns = Vec::new();
        if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
            for line in content.lines() {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix("domain ") {
                    domain = Some(rest.trim().to_string());
                } else if let Some(rest) = line.strip_prefix("search ") {
                    if domain.is_none() {
                        domain = rest.split_whitespace().next().map(str::to_string);
                    }
                } else if let Some(rest) = line.strip_prefix("nameserver ") {
                    dns.push(rest.trim().to_string());
                }
            }
        }
        (domain, dns)
    }
}

/// Returns the parsed routing table plus the raw command output it came from.
fn gather_routes() -> (Vec<RouteEntry>, String) {
    #[cfg(windows)]
    {
        let raw = util::run_capture("route", &["print"]);
        (parse_routes_win(&raw), raw)
    }
    #[cfg(target_os = "macos")]
    {
        let raw = util::run_capture("netstat", &["-rn"]);
        (parse_routes_bsd(&raw), raw)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let v4 = util::run_capture("ip", &["route", "show"]);
        if v4.starts_with("Cannot run") {
            let raw = util::run_capture("netstat", &["-rn"]);
            let parsed = parse_routes_bsd(&raw);
            return (parsed, raw);
        }
        let v6 = util::run_capture("ip", &["-6", "route", "show"]);
        let raw = format!("# IPv4\n{v4}\n# IPv6\n{v6}");
        (parse_routes_iproute(&raw), raw)
    }
}

/// Helper: the token right after `key` in a whitespace-split line.
#[cfg(all(unix, not(target_os = "macos")))]
fn token_after<'a>(tokens: &'a [&'a str], key: &str) -> Option<&'a str> {
    tokens.iter().position(|t| *t == key).and_then(|i| tokens.get(i + 1)).copied()
}

/// Parses `netstat -rn` (macOS / BSD; also the Linux fallback).
/// Columns per section: Destination Gateway Flags Netif [Expire].
#[cfg(unix)]
fn parse_routes_bsd(raw: &str) -> Vec<RouteEntry> {
    let mut out = Vec::new();
    let mut in_table = false;
    let mut is_v6 = false;
    for line in raw.lines() {
        let t: Vec<&str> = line.split_whitespace().collect();
        if t.is_empty() {
            in_table = false;
            continue;
        }
        if t[0] == "Internet:" {
            is_v6 = false;
            in_table = false;
            continue;
        }
        if t[0] == "Internet6:" {
            is_v6 = true;
            in_table = false;
            continue;
        }
        if t[0] == "Destination" {
            in_table = true;
            continue;
        }
        if !in_table || t.len() < 4 {
            continue;
        }
        out.push(RouteEntry {
            destination: t[0].to_string(),
            gateway: t[1].to_string(),
            interface: t[3].to_string(),
            info: format!("flags {}", t[2]),
            is_ipv6: is_v6,
        });
    }
    out
}

/// Parses `ip route show` (Linux).
#[cfg(all(unix, not(target_os = "macos")))]
fn parse_routes_iproute(raw: &str) -> Vec<RouteEntry> {
    let mut out = Vec::new();
    let mut is_v6 = false;
    for line in raw.lines() {
        let line = line.trim();
        if line == "# IPv4" {
            is_v6 = false;
            continue;
        }
        if line == "# IPv6" {
            is_v6 = true;
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let t: Vec<&str> = line.split_whitespace().collect();
        let mut info = Vec::new();
        for key in ["proto", "scope", "metric", "src"] {
            if let Some(v) = token_after(&t, key) {
                info.push(format!("{key} {v}"));
            }
        }
        out.push(RouteEntry {
            destination: t[0].to_string(),
            gateway: token_after(&t, "via").unwrap_or("on-link").to_string(),
            interface: token_after(&t, "dev").unwrap_or("?").to_string(),
            info: info.join(", "),
            is_ipv6: is_v6 || t[0].contains(':'),
        });
    }
    out
}

/// Parses the active routes of `route print` (Windows). Rows are recognized
/// by their shape, not by section titles: those are translated on a
/// non-English system ("Itinéraires actifs", …).
#[cfg(windows)]
fn parse_routes_win(raw: &str) -> Vec<RouteEntry> {
    let is_v4 = |s: &str| s.parse::<Ipv4Addr>().is_ok();
    let is_num = |s: &str| s.parse::<u32>().is_ok();
    let mut out = Vec::new();
    let mut v6_seen = false;
    let mut v6_done = false;
    let mut lines = raw.lines();
    while let Some(line) = lines.next() {
        let t: Vec<&str> = line.split_whitespace().collect();
        let n = t.len();
        if n >= 5 && is_v4(t[0]) && is_v4(t[1]) && is_v4(t[n - 2]) && is_num(t[n - 1]) {
            // Destination  Netmask  Gateway  Interface  Metric. Persistent
            // routes have no Interface column, so they never match.
            out.push(RouteEntry {
                destination: format!("{} {}", t[0], t[1]),
                gateway: t[2..n - 2].join(" "),
                interface: t[n - 2].to_string(),
                info: format!("metric {}", t[n - 1]),
                is_ipv6: false,
            });
        } else if !v6_done && n >= 3 && is_num(t[0]) && is_num(t[1]) && t[2].contains(':') {
            // If  Metric  Destination  Gateway. A long destination pushes
            // the gateway to the next line.
            let gateway = if n > 3 {
                t[3..].join(" ")
            } else {
                lines.next().unwrap_or("").trim().to_string()
            };
            v6_seen = true;
            out.push(RouteEntry {
                destination: t[2].to_string(),
                gateway,
                interface: format!("if {}", t[0]),
                info: format!("metric {}", t[1]),
                is_ipv6: true,
            });
        } else if v6_seen && line.starts_with('=') {
            // The separator after the active IPv6 rows: what follows is the
            // persistent table, which has the same row shape.
            v6_done = true;
        }
    }
    out
}

/// Raw output of the system tools, for verification or copy/paste. The
/// routing table output is reused rather than running the tool a second time.
#[cfg_attr(all(unix, not(target_os = "macos")), allow(unused_variables))]
fn raw_sections(routes_raw: &str) -> Vec<(String, String)> {
    #[cfg(windows)]
    {
        vec![
            ("ipconfig /all".to_string(), util::run_capture("ipconfig", &["/all"])),
            ("route print".to_string(), routes_raw.to_string()),
        ]
    }
    #[cfg(target_os = "macos")]
    {
        vec![
            ("ifconfig -a".to_string(), util::run_capture("ifconfig", &["-a"])),
            ("netstat -rn".to_string(), routes_raw.to_string()),
            ("scutil --dns".to_string(), util::run_capture("scutil", &["--dns"])),
        ]
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let resolv = std::fs::read_to_string("/etc/resolv.conf")
            .unwrap_or_else(|e| format!("could not read: {e}"));
        vec![
            ("ip addr".to_string(), util::run_capture("ip", &["addr"])),
            ("ip route".to_string(), util::run_capture("ip", &["route"])),
            ("/etc/resolv.conf".to_string(), resolv),
        ]
    }
}

/// Full text report, for the file export.
pub fn report_text(report: &NetReport) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "NETWORK CONFIGURATION REPORT — generated {}\n\n",
        report.generated_at
    ));
    s.push_str(&format!("Hostname : {}\n", report.hostname));
    s.push_str(&format!("Domain   : {}\n", report.domain.as_deref().unwrap_or("(none)")));
    s.push_str(&format!(
        "DNS      : {}\n\n",
        if report.dns_servers.is_empty() {
            "(none detected)".to_string()
        } else {
            report.dns_servers.join(", ")
        }
    ));

    s.push_str("=== INTERFACES ===\n");
    for itf in &report.interfaces {
        s.push_str(&format!(
            "\n[{}]{}{}\n",
            itf.name,
            itf.friendly_name
                .as_ref()
                .filter(|f| *f != &itf.name)
                .map(|f| format!(" ({f})"))
                .unwrap_or_default(),
            if itf.is_default { "  [default interface]" } else { "" }
        ));
        s.push_str(&format!("  State   : {}\n", if itf.is_up { "UP" } else { "DOWN" }));
        s.push_str(&format!("  Type    : {}\n", itf.if_type));
        if let Some(mac) = &itf.mac {
            s.push_str(&format!("  MAC     : {mac}\n"));
        }
        for ip in &itf.ipv4 {
            s.push_str(&format!("  IPv4    : {ip}\n"));
        }
        for ip in &itf.ipv6 {
            s.push_str(&format!("  IPv6    : {ip}\n"));
        }
        if let Some(gw) = &itf.gateway {
            s.push_str(&format!("  Gateway : {gw}\n"));
        }
        if !itf.dns.is_empty() {
            s.push_str(&format!("  DNS     : {}\n", itf.dns.join(", ")));
        }
    }

    s.push_str("\n=== ROUTES ===\n");
    if report.routes.is_empty() {
        s.push_str(&report.routes_raw);
    } else {
        for (label, v6) in [("IPv4", false), ("IPv6", true)] {
            let rows: Vec<&RouteEntry> =
                report.routes.iter().filter(|r| r.is_ipv6 == v6).collect();
            if rows.is_empty() {
                continue;
            }
            s.push_str(&format!("\n-- {label} --\n"));
            s.push_str(&format!(
                "{:<28} {:<20} {:<10} {}\n",
                "Destination", "Gateway", "Interface", "Info"
            ));
            for r in rows {
                s.push_str(&format!(
                    "{:<28} {:<20} {:<10} {}\n",
                    r.destination, r.gateway, r.interface, r.info
                ));
            }
        }
    }

    for (title, content) in &report.raw_sections {
        s.push_str(&format!("\n=== {title} ===\n{content}\n"));
    }
    s
}

/// Exports the report into the netconfig log subfolder and returns the path.
pub fn export(report: &NetReport, log_dir: &str) -> Result<PathBuf, String> {
    let dir = util::ensure_log_dir(log_dir, "netconfig")
        .map_err(|e| format!("failed to create log directory: {e}"))?;
    let path = dir.join(format!("netconfig_{}.txt", util::now_file_str()));
    std::fs::write(&path, report_text(report))
        .map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    Ok(path)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    // Real `route print` output of a French Windows 11 (shortened).
    const FRENCH: &str = "\
IPv4 Table de routage
===========================================================================
Itinéraires actifs :
Destination réseau    Masque réseau  Adr. passerelle   Adr. interface Métrique
          0.0.0.0          0.0.0.0    192.168.1.254     192.168.1.36     40
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
      192.168.2.0    255.255.255.0    192.168.1.210     192.168.1.36     21
===========================================================================
Itinéraires persistants :
  Adresse réseau    Masque réseau  Adresse passerelle Métrique
      192.168.2.0    255.255.255.0    192.168.1.210       1
===========================================================================

IPv6 Table de routage
===========================================================================
Itinéraires actifs :
 If Metric Network Destination      Gateway
 11    276 ::/0                     fe80::3a07:16ff:fe1d:7d0
  1    331 ::1/128                  On-link
 11    276 2a01:e0a:11b2:9590:203c:bb5a:4d36:9a4c/128
                                    On-link
===========================================================================
Itinéraires persistants :
  Aucun
";

    const ENGLISH: &str = "\
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.10     25
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
===========================================================================
Persistent Routes:
  None

IPv6 Route Table
===========================================================================
Active Routes:
 If Metric Network Destination      Gateway
  1    331 ::1/128                  On-link
===========================================================================
Persistent Routes:
 If Metric Network Destination      Gateway
  0 4294967295 2001:db8::/32        fe80::1
";

    #[test]
    fn route_print_french() {
        let routes = parse_routes_win(FRENCH);
        let v4: Vec<_> = routes.iter().filter(|r| !r.is_ipv6).collect();
        let v6: Vec<_> = routes.iter().filter(|r| r.is_ipv6).collect();
        // 3 active IPv4 routes; the persistent one is not repeated.
        assert_eq!(v4.len(), 3);
        assert_eq!(v4[0].gateway, "192.168.1.254");
        assert_eq!(v4[0].interface, "192.168.1.36");
        assert_eq!(v4[1].gateway, "On-link");
        assert_eq!(v4[2].info, "metric 21");
        assert_eq!(v6.len(), 3);
        // Gateway wrapped onto the next line.
        assert_eq!(v6[2].destination, "2a01:e0a:11b2:9590:203c:bb5a:4d36:9a4c/128");
        assert_eq!(v6[2].gateway, "On-link");
    }

    #[test]
    fn route_print_english_skips_persistent_ipv6() {
        let routes = parse_routes_win(ENGLISH);
        assert_eq!(routes.iter().filter(|r| !r.is_ipv6).count(), 2);
        let v6: Vec<_> = routes.iter().filter(|r| r.is_ipv6).collect();
        assert_eq!(v6.len(), 1);
        assert_eq!(v6[0].destination, "::1/128");
    }
}
