use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Human-readable timestamp for log lines: 2026-06-11 14:03:27.123
pub fn now_str() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string()
}

/// Compact timestamp for file names: 20260611_140327
pub fn now_file_str() -> String {
    chrono::Local::now().format("%Y%m%d_%H%M%S").to_string()
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
            let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
            let err = String::from_utf8_lossy(&out.stderr);
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

/// Opens a folder in the platform file manager.
pub fn open_in_file_manager(path: &Path) {
    #[cfg(target_os = "macos")]
    let _ = os_command("open").arg(path).spawn();
    #[cfg(windows)]
    let _ = os_command("explorer").arg(path).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let _ = os_command("xdg-open").arg(path).spawn();
}
