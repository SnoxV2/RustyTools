use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write as _};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::app::Event;
use crate::util;

pub struct TraceEvent {
    pub target: String,
    pub line: String,
    pub finished: bool,
    pub timestamp: String,
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

/// Lance un traceroute (système) par cible, avec répétition optionnelle.
pub fn start(
    targets: Vec<String>,
    resolve_names: bool,
    repeat: bool,
    interval: Duration,
    log_dir: &str,
    tx: Sender<Event>,
) -> Result<TraceSession, String> {
    let dir = util::ensure_log_dir(log_dir)
        .map_err(|e| format!("création du répertoire de logs impossible : {e}"))?;
    let stamp = util::now_file_str();
    let stop = Arc::new(AtomicBool::new(false));
    let children: ChildMap = Arc::new(Mutex::new(HashMap::new()));
    let mut handles = Vec::new();
    let mut log_files = Vec::new();

    for (idx, target) in targets.into_iter().enumerate() {
        let path = dir.join(format!("traceroute_{stamp}_{}.log", util::sanitize_filename(&target)));
        let file = File::create(&path)
            .map_err(|e| format!("création du fichier de log {} impossible : {e}", path.display()))?;
        log_files.push(path);

        let stop = stop.clone();
        let children = children.clone();
        let tx = tx.clone();
        handles.push(std::thread::spawn(move || {
            worker(idx as u64, target, resolve_names, repeat, interval, file, stop, children, tx);
        }));
    }

    Ok(TraceSession { stop, children, handles, log_files })
}

#[allow(clippy::too_many_arguments)]
fn worker(
    worker_id: u64,
    target: String,
    resolve_names: bool,
    repeat: bool,
    interval: Duration,
    mut file: File,
    stop: Arc<AtomicBool>,
    children: ChildMap,
    tx: Sender<Event>,
) {
    let mut iteration: u64 = 0;
    loop {
        iteration += 1;
        let child_key = worker_id * 1_000_000 + iteration;

        if repeat {
            emit(&tx, &mut file, &target, format!("--- passe n°{iteration} ---"), false);
        }

        match spawn_traceroute(&target, resolve_names) {
            Err(e) => {
                emit(&tx, &mut file, &target, e, false);
                break;
            }
            Ok(mut child) => {
                let stdout = child.stdout.take();
                let stderr = child.stderr.take();
                children.lock().unwrap().insert(child_key, child);

                if let Some(stdout) = stdout {
                    for line in BufReader::new(stdout).lines() {
                        let Ok(line) = line else { break };
                        if !line.trim().is_empty() {
                            emit(&tx, &mut file, &target, line, false);
                        }
                    }
                }
                // Le flux d'erreur est lu après coup : traceroute y écrit peu
                // (cible inconnue, options invalides) et échoue vite dans ce cas.
                if let Some(stderr) = stderr {
                    for line in BufReader::new(stderr).lines() {
                        let Ok(line) = line else { break };
                        if !line.trim().is_empty() {
                            emit(&tx, &mut file, &target, format!("[stderr] {line}"), false);
                        }
                    }
                }
                if let Some(mut child) = children.lock().unwrap().remove(&child_key) {
                    let _ = child.wait();
                }
            }
        }

        if !repeat || stop.load(Ordering::SeqCst) {
            break;
        }
        // Attente entre deux passes, interruptible par Arrêter.
        let mut waited = Duration::ZERO;
        while waited < interval && !stop.load(Ordering::SeqCst) {
            let step = (interval - waited).min(Duration::from_millis(100));
            std::thread::sleep(step);
            waited += step;
        }
        if stop.load(Ordering::SeqCst) {
            break;
        }
    }

    let timestamp = util::now_str();
    let _ = tx.send(Event::Trace(TraceEvent {
        target,
        line: "terminé".to_string(),
        finished: true,
        timestamp,
    }));
}

fn emit(tx: &Sender<Event>, file: &mut File, target: &str, line: String, finished: bool) {
    let timestamp = util::now_str();
    let _ = writeln!(file, "[{timestamp}] {line}");
    let _ = file.flush();
    let _ = tx.send(Event::Trace(TraceEvent {
        target: target.to_string(),
        line,
        finished,
        timestamp,
    }));
}

/// Construit et lance la commande traceroute adaptée à l'OS.
fn spawn_traceroute(target: &str, resolve_names: bool) -> Result<Child, String> {
    let candidates = traceroute_commands(target, resolve_names);
    let mut last_err = String::new();
    for (prog, args) in &candidates {
        let mut cmd = util::os_command(prog);
        cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
        set_locale_c(&mut cmd);
        match cmd.spawn() {
            Ok(child) => return Ok(child),
            Err(e) => last_err = format!("`{prog}` : {e}"),
        }
    }
    Err(format!(
        "Impossible de lancer un traceroute ({last_err}). Sous Linux, installez le paquet \
         `traceroute` (ex. apt install traceroute)."
    ))
}

#[allow(unused_variables)]
fn set_locale_c(cmd: &mut Command) {
    #[cfg(unix)]
    cmd.env("LC_ALL", "C");
}

#[cfg(windows)]
fn traceroute_commands(target: &str, resolve_names: bool) -> Vec<(String, Vec<String>)> {
    let mut args = Vec::new();
    if !resolve_names {
        args.push("-d".to_string());
    }
    args.extend(["-w".to_string(), "1000".to_string(), target.to_string()]);
    vec![("tracert".to_string(), args)]
}

#[cfg(unix)]
fn traceroute_commands(target: &str, resolve_names: bool) -> Vec<(String, Vec<String>)> {
    let mut tr_args = Vec::new();
    if !resolve_names {
        tr_args.push("-n".to_string());
    }
    tr_args.extend(["-w".to_string(), "2".to_string(), target.to_string()]);

    // tracepath sert de secours sous Linux quand traceroute n'est pas installé.
    let mut tp_args = Vec::new();
    if !resolve_names {
        tp_args.push("-n".to_string());
    }
    tp_args.push(target.to_string());

    vec![("traceroute".to_string(), tr_args), ("tracepath".to_string(), tp_args)]
}
