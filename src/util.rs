use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Horodatage lisible pour les logs : 2026-06-11 14:03:27.123
pub fn now_str() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string()
}

/// Horodatage compact pour les noms de fichiers : 20260611_140327
pub fn now_file_str() -> String {
    chrono::Local::now().format("%Y%m%d_%H%M%S").to_string()
}

/// Nettoie une cible (IP/FQDN) pour l'utiliser dans un nom de fichier.
pub fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect()
}

/// Résout une cible (IP littérale ou FQDN) en adresse IP, IPv4 en priorité.
pub fn resolve_host(target: &str) -> Result<IpAddr, String> {
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(ip);
    }
    let addrs: Vec<_> = (target, 0)
        .to_socket_addrs()
        .map_err(|e| format!("résolution DNS impossible : {e}"))?
        .collect();
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .map(|a| a.ip())
        .ok_or_else(|| "résolution DNS : aucune adresse retournée".to_string())
}

/// Crée le répertoire de logs s'il n'existe pas et le retourne.
pub fn ensure_log_dir(dir: &str) -> std::io::Result<PathBuf> {
    let path = if dir.trim().is_empty() {
        Path::new("logs").to_path_buf()
    } else {
        PathBuf::from(dir.trim())
    };
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

/// Construit une commande système sans faire apparaître de console sous Windows.
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

/// Exécute une commande et retourne stdout+stderr en texte, ou un message d'erreur.
pub fn run_capture(prog: &str, args: &[&str]) -> String {
    match os_command(prog).args(args).output() {
        Ok(out) => {
            let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
            let err = String::from_utf8_lossy(&out.stderr);
            if !err.trim().is_empty() {
                s.push_str(&err);
            }
            if s.trim().is_empty() {
                format!("({prog} : aucune sortie)")
            } else {
                s
            }
        }
        Err(e) => format!("Impossible d'exécuter `{prog}` : {e}"),
    }
}
