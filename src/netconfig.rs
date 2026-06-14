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
    NetReport {
        generated_at: util::now_str(),
        hostname,
        domain,
        dns_servers,
        interfaces,
        routes,
        routes_raw,
        raw_sections: raw_sections(),
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
    for line in raw.lines() {
        let t: Vec<&str> = line.split_whitespace().collect();
        if t.is_empty() {
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
        });
    }
    out
}

/// Parses `ip route show` (Linux).
#[cfg(all(unix, not(target_os = "macos")))]
fn parse_routes_iproute(raw: &str) -> Vec<RouteEntry> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
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
        });
    }
    out
}

/// Parses the "Active Routes" IPv4 table of `route print` (Windows).
#[cfg(windows)]
fn parse_routes_win(raw: &str) -> Vec<RouteEntry> {
    let mut out = Vec::new();
    let mut in_active = false;
    for line in raw.lines() {
        let tl = line.trim();
        if tl.starts_with("Active Routes:") {
            in_active = true;
            continue;
        }
        if !in_active {
            continue;
        }
        if tl.starts_with("Network Destination") {
            continue;
        }
        if tl.starts_with('=') || tl.is_empty() || tl.starts_with("Persistent") {
            in_active = false;
            continue;
        }
        let t: Vec<&str> = tl.split_whitespace().collect();
        if t.len() >= 5 && t[0].parse::<std::net::Ipv4Addr>().is_ok() {
            out.push(RouteEntry {
                destination: format!("{} {}", t[0], t[1]),
                gateway: t[2].to_string(),
                interface: t[3].to_string(),
                info: format!("metric {}", t[4]),
            });
        }
    }
    out
}

/// Raw output of the system tools, for verification or copy/paste.
fn raw_sections() -> Vec<(String, String)> {
    #[cfg(windows)]
    {
        vec![
            ("ipconfig /all".to_string(), util::run_capture("ipconfig", &["/all"])),
            ("route print".to_string(), util::run_capture("route", &["print"])),
        ]
    }
    #[cfg(target_os = "macos")]
    {
        vec![
            ("ifconfig -a".to_string(), util::run_capture("ifconfig", &["-a"])),
            ("netstat -rn".to_string(), util::run_capture("netstat", &["-rn"])),
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
        s.push_str(&format!(
            "{:<28} {:<20} {:<10} {}\n",
            "Destination", "Gateway", "Interface", "Info"
        ));
        for r in &report.routes {
            s.push_str(&format!(
                "{:<28} {:<20} {:<10} {}\n",
                r.destination, r.gateway, r.interface, r.info
            ));
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
