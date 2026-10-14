use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Human-readable timestamp for log lines: 2026-06-11 14:03:27.123
pub fn now_str() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string()
}

/// Compact timestamp for file names: 20260611_140327123 (milliseconds, so
/// two runs in the same second never overwrite each other's log).
pub fn now_file_str() -> String {
    chrono::Local::now().format("%Y%m%d_%H%M%S%3f").to_string()
}

/// Sanitizes a target (IP/FQDN) so it can be used in a file name.
pub fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect()
}

/// Resolves a target (literal IP or FQDN) to an IP address, preferring IPv4.
pub fn resolve_host(target: &str) -> Result<IpAddr, String> {
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(ip);
    }
    let addrs: Vec<_> = (target, 0)
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed: {e}"))?
        .collect();
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .map(|a| a.ip())
        .ok_or_else(|| "DNS resolution returned no address".to_string())
}

/// Creates `<base>/<sub>` (e.g. logs/ping) if needed and returns it.
pub fn ensure_log_dir(base: &str, sub: &str) -> std::io::Result<PathBuf> {
    let mut path = if base.trim().is_empty() {
        PathBuf::from("logs")
    } else {
        PathBuf::from(base.trim())
    };
    path.push(sub);
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

/// The token right after `key` in a whitespace-split line of tool output.
#[cfg(unix)]
pub fn token_after<'a>(tokens: &[&'a str], key: &str) -> Option<&'a str> {
    tokens.iter().position(|t| *t == key).and_then(|i| tokens.get(i + 1)).copied()
}

/// Optional probe source: a specific local IP and/or a network interface.
/// Default (both None) keeps the OS routing behavior.
#[derive(Clone, Default)]
pub struct SourceConfig {
    pub ip: Option<IpAddr>,
    pub iface: Option<IfaceSource>,
}

#[derive(Clone)]
pub struct IfaceSource {
    pub name: String,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub index: u32,
    pub addrs: Vec<IpAddr>,
}

impl SourceConfig {
    pub fn is_default(&self) -> bool {
        self.ip.is_none() && self.iface.is_none()
    }

    /// Local address to bind for a given target, enforcing family match.
    pub fn bind_ip_for(&self, target: &IpAddr) -> Result<Option<IpAddr>, String> {
        if let Some(ip) = self.ip {
            if ip.is_ipv4() == target.is_ipv4() {
                Ok(Some(ip))
            } else {
                Err(format!(
                    "source IP {ip} and target {target} are not in the same address family"
                ))
            }
        } else if let Some(iface) = &self.iface {
            iface
                .addrs
                .iter()
                .find(|a| a.is_ipv4() == target.is_ipv4())
                .copied()
                .map(Some)
                .ok_or_else(|| {
                    format!(
                        "interface {} has no address in the same family as {target}",
                        iface.name
                    )
                })
        } else {
            Ok(None)
        }
    }
}

/// Deletes the log files we wrote in `<base>/<sub>` (other files and
/// subfolders untouched). Returns the number of deleted files; a missing
/// folder counts as 0.
pub fn clear_log_files(base: &str, sub: &str) -> Result<usize, String> {
    let dir = PathBuf::from(if base.trim().is_empty() { "logs" } else { base.trim() }).join(sub);
    let entries = match std::fs::read_dir(&dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(format!("cannot read {}: {e}", dir.display())),
        Ok(entries) => entries,
    };
    let mut deleted = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() && is_our_log(sub, &entry.file_name().to_string_lossy()) {
            std::fs::remove_file(&path)
                .map_err(|e| format!("cannot delete {}: {e}", path.display()))?;
            deleted += 1;
        }
    }
    Ok(deleted)
}

/// The log files each feature writes: (subfolder, file name prefixes).
const LOG_FILES: [(&str, &[&str]); 6] = [
    ("ping", &["ping_"]),
    ("traceroute", &["discovery_", "mtr_"]),
    ("dns", &["dns_"]),
    ("arp", &["arp_"]),
    ("netconfig", &["netconfig_"]),
    ("packet", &["packet_"]),
];

/// Whether `name` is a log file we write in the `sub` log subfolder. The log
/// folder is user-chosen, so nothing else may ever be deleted from it.
fn is_our_log(sub: &str, name: &str) -> bool {
    let prefix_ok = LOG_FILES
        .iter()
        .filter(|(s, _)| *s == sub)
        .any(|(_, prefixes)| prefixes.iter().any(|p| name.starts_with(p)));
    prefix_ok
        && matches!(Path::new(name).extension().and_then(|e| e.to_str()), Some("csv" | "log" | "txt"))
}

/// Deletes the log files we wrote, then each subfolder and the log folder
/// itself if nothing else is left in them. The folder is user-chosen (it
/// could be Documents), so only files matching our own names are removed and
/// folders are only ever removed empty. A missing folder is treated as success.
pub fn delete_log_dir(base: &str) -> Result<(), String> {
    let dir = PathBuf::from(if base.trim().is_empty() { "logs" } else { base.trim() });
    for (sub, _) in LOG_FILES {
        clear_log_files(base, sub)?;
        // Non-recursive on purpose: fails (and is ignored) when other files remain.
        let _ = std::fs::remove_dir(dir.join(sub));
    }
    let _ = std::fs::remove_dir(&dir);
    Ok(())
}

/// Builds a system command without spawning a console window on Windows.
pub fn os_command(prog: &str) -> Command {
    #[allow(unused_mut)]
    let mut cmd = Command::new(prog);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// Runs a command and returns stdout+stderr as text, or an error message.
pub fn run_capture(prog: &str, args: &[&str]) -> String {
    match os_command(prog).args(args).output() {
        Ok(out) => {
            let mut s = decode_console(&out.stdout);
            let err = decode_console(&out.stderr);
            if !err.trim().is_empty() {
                s.push_str(&err);
            }
            if s.trim().is_empty() {
                format!("({prog}: no output)")
            } else {
                s
            }
        }
        Err(e) => format!("Cannot run `{prog}`: {e}"),
    }
}

/// Decodes the output of a system tool. On Windows these tools write in the
/// OEM code page (CP850 on a French system), not UTF-8: reading it as UTF-8
/// turns every accented letter into a replacement character.
#[cfg(windows)]
pub fn decode_console(bytes: &[u8]) -> String {
    #[link(name = "kernel32")]
    extern "system" {
        fn MultiByteToWideChar(
            code_page: u32,
            flags: u32,
            src: *const u8,
            src_len: i32,
            dst: *mut u16,
            dst_len: i32,
        ) -> i32;
    }
    const CP_OEMCP: u32 = 1;
    // A byte never decodes to more than one UTF-16 unit, so this is enough.
    let mut wide = vec![0u16; bytes.len()];
    let written = unsafe {
        MultiByteToWideChar(
            CP_OEMCP,
            0,
            bytes.as_ptr(),
            bytes.len() as i32,
            wide.as_mut_ptr(),
            wide.len() as i32,
        )
    };
    String::from_utf16_lossy(&wide[..written.max(0) as usize])
}

#[cfg(not(windows))]
pub fn decode_console(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Opens a folder in the platform file manager.
pub fn open_in_file_manager(path: &Path) {
    #[cfg(target_os = "macos")]
    let _ = os_command("open").arg(path).spawn();
    #[cfg(windows)]
    let _ = os_command("explorer").arg(path).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let _ = os_command("xdg-open").arg(path).spawn();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clear_log_files_keeps_foreign_files() {
        let base = std::env::temp_dir().join(format!("rustytools_clear_{}", std::process::id()));
        std::fs::create_dir_all(base.join("dns")).unwrap();
        std::fs::write(base.join("dns").join("dns_20260101.log"), "x").unwrap();
        std::fs::write(base.join("dns").join("zones.txt"), "mine").unwrap();
        // Another feature's prefix is not ours in this subfolder.
        std::fs::write(base.join("dns").join("ping_x.csv"), "mine").unwrap();

        assert_eq!(clear_log_files(base.to_str().unwrap(), "dns").unwrap(), 1);
        assert!(base.join("dns").join("zones.txt").exists());
        assert!(base.join("dns").join("ping_x.csv").exists());
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn delete_log_dir_keeps_foreign_files() {
        let base = std::env::temp_dir().join(format!("rustytools_test_{}", std::process::id()));
        std::fs::create_dir_all(base.join("ping")).unwrap();
        std::fs::create_dir_all(base.join("dns").join("zones")).unwrap();
        std::fs::write(base.join("ping").join("ping_20260101_8.8.8.8.csv"), "x").unwrap();
        std::fs::write(base.join("dns").join("dns_20260101.log"), "x").unwrap();
        // Files that are not ours: beside the subfolders, and inside them.
        std::fs::write(base.join("thesis.docx"), "mine").unwrap();
        std::fs::write(base.join("dns").join("my-zone.txt"), "mine").unwrap();
        std::fs::write(base.join("dns").join("zones").join("dns_keep.log"), "mine").unwrap();

        delete_log_dir(base.to_str().unwrap()).unwrap();
        assert!(!base.join("ping").exists(), "an emptied log subfolder must go");
        assert!(!base.join("dns").join("dns_20260101.log").exists());
        assert!(base.join("thesis.docx").exists(), "a file we did not create was deleted");
        assert!(base.join("dns").join("my-zone.txt").exists());
        assert!(base.join("dns").join("zones").join("dns_keep.log").exists());

        // With nothing foreign left, the folder itself goes away.
        std::fs::remove_file(base.join("thesis.docx")).unwrap();
        std::fs::remove_dir_all(base.join("dns")).unwrap();
        delete_log_dir(base.to_str().unwrap()).unwrap();
        assert!(!base.exists());
    }
}
