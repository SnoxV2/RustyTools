use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Duration;

use eframe::egui;

use crate::netconfig::{self, NetReport};
use crate::ping::{self, PingSession, PingStatus};
use crate::traceroute::{self, TraceSession};

pub enum Event {
    Ping(ping::PingEvent),
    Trace(traceroute::TraceEvent),
}

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Ping,
    Traceroute,
    NetConfig,
}

#[derive(Default)]
struct TargetStats {
    ip: Option<IpAddr>,
    sent: u64,
    received: u64,
    last_rtt: Option<Duration>,
    min_rtt: Option<Duration>,
    max_rtt: Option<Duration>,
    sum_rtt: Duration,
    last_jitter: Option<Duration>,
    sum_jitter: Duration,
    jitter_count: u64,
    last_status: String,
}

impl TargetStats {
    fn loss_pct(&self) -> f64 {
        if self.sent == 0 {
            0.0
        } else {
            (self.sent - self.received) as f64 * 100.0 / self.sent as f64
        }
    }

    fn avg_rtt(&self) -> Option<Duration> {
        (self.received > 0).then(|| self.sum_rtt / self.received as u32)
    }

    fn avg_jitter(&self) -> Option<Duration> {
        (self.jitter_count > 0).then(|| self.sum_jitter / self.jitter_count as u32)
    }
}

pub struct RustyToolsApp {
    tab: Tab,
    tx: Sender<Event>,
    rx: Receiver<Event>,
    log_dir: String,

    // Ping
    ping_targets_text: String,
    ping_interval_s: f32,
    ping_timeout_s: f32,
    ping_session: Option<PingSession>,
    ping_stats: Vec<(String, TargetStats)>,
    ping_log: VecDeque<String>,
    ping_error: Option<String>,

    // Traceroute
    trace_targets_text: String,
    trace_resolve_names: bool,
    trace_repeat: bool,
    trace_interval_s: f32,
    trace_session: Option<TraceSession>,
    trace_output: VecDeque<String>,
    trace_error: Option<String>,

    // Configuration réseau
    net_report: Option<NetReport>,
    net_message: Option<String>,
}

impl RustyToolsApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let (tx, rx) = channel();
        Self {
            tab: Tab::Ping,
            tx,
            rx,
            log_dir: "logs".to_string(),
            ping_targets_text: String::new(),
            ping_interval_s: 1.0,
            ping_timeout_s: 2.0,
            ping_session: None,
            ping_stats: Vec::new(),
            ping_log: VecDeque::new(),
            ping_error: None,
            trace_targets_text: String::new(),
            trace_resolve_names: false,
            trace_repeat: false,
            trace_interval_s: 10.0,
            trace_session: None,
            trace_output: VecDeque::new(),
            trace_error: None,
            net_report: None,
            net_message: None,
        }
    }

    fn drain_events(&mut self) {
        while let Ok(event) = self.rx.try_recv() {
            match event {
                Event::Ping(ev) => self.on_ping_event(ev),
                Event::Trace(ev) => {
                    if !ev.finished {
                        push_capped(
                            &mut self.trace_output,
                            format!("[{}] {:<24} {}", ev.timestamp, ev.target, ev.line),
                            5000,
                        );
                    }
                }
            }
        }
    }

    fn on_ping_event(&mut self, ev: ping::PingEvent) {
        let stats = match self.ping_stats.iter_mut().find(|(t, _)| *t == ev.target) {
            Some((_, s)) => s,
            None => {
                self.ping_stats.push((ev.target.clone(), TargetStats::default()));
                &mut self.ping_stats.last_mut().unwrap().1
            }
        };
        if stats.ip.is_none() {
            stats.ip = ev.ip;
        }

        let line = match &ev.status {
            PingStatus::Ok { rtt, jitter } => {
                stats.sent += 1;
                stats.received += 1;
                stats.last_rtt = Some(*rtt);
                stats.sum_rtt += *rtt;
                stats.min_rtt = Some(stats.min_rtt.map_or(*rtt, |m| m.min(*rtt)));
                stats.max_rtt = Some(stats.max_rtt.map_or(*rtt, |m| m.max(*rtt)));
                stats.last_jitter = *jitter;
                if let Some(j) = jitter {
                    stats.sum_jitter += *j;
                    stats.jitter_count += 1;
                }
                stats.last_status = "OK".to_string();
                format!(
                    "[{}] {:<24} seq={:<5} RTT={}{}",
                    ev.timestamp,
                    ev.target,
                    ev.seq,
                    fmt_ms(*rtt),
                    jitter.map(|j| format!("  gigue={}", fmt_ms(j))).unwrap_or_default()
                )
            }
            PingStatus::Timeout => {
                stats.sent += 1;
                stats.last_status = "TIMEOUT".to_string();
                format!(
                    "[{}] {:<24} seq={:<5} TIMEOUT (perte de paquet)",
                    ev.timestamp, ev.target, ev.seq
                )
            }
            PingStatus::Error(msg) => {
                if ev.seq > 0 {
                    stats.sent += 1;
                }
                stats.last_status = format!("ERREUR : {msg}");
                format!("[{}] {:<24} ERREUR : {msg}", ev.timestamp, ev.target)
            }
        };
        push_capped(&mut self.ping_log, line, 2000);
    }

    fn start_ping(&mut self) {
        self.ping_error = None;
        let targets = parse_targets(&self.ping_targets_text);
        if targets.is_empty() {
            self.ping_error = Some("Saisissez au moins une cible (IP ou FQDN).".to_string());
            return;
        }
        self.ping_stats = targets.iter().map(|t| (t.clone(), TargetStats::default())).collect();
        self.ping_log.clear();
        match ping::start(
            targets,
            Duration::from_secs_f32(self.ping_interval_s),
            Duration::from_secs_f32(self.ping_timeout_s),
            &self.log_dir,
            self.tx.clone(),
        ) {
            Ok(session) => self.ping_session = Some(session),
            Err(e) => self.ping_error = Some(e),
        }
    }

    fn start_trace(&mut self) {
        self.trace_error = None;
        let targets = parse_targets(&self.trace_targets_text);
        if targets.is_empty() {
            self.trace_error = Some("Saisissez au moins une cible (IP ou FQDN).".to_string());
            return;
        }
        self.trace_output.clear();
        match traceroute::start(
            targets,
            self.trace_resolve_names,
            self.trace_repeat,
            Duration::from_secs_f32(self.trace_interval_s),
            &self.log_dir,
            self.tx.clone(),
        ) {
            Ok(session) => self.trace_session = Some(session),
            Err(e) => self.trace_error = Some(e),
        }
    }

    fn ui_ping(&mut self, ctx: &egui::Context) {
        let running = self.ping_session.as_ref().is_some_and(|s| s.is_running());
        if !running {
            self.ping_session = None;
        }

        egui::SidePanel::left("ping_side").default_width(300.0).show(ctx, |ui| {
            ui.add_space(6.0);
            ui.heading("Ping continu");
            ui.add_space(6.0);
            ui.label("Cibles (une IP ou un FQDN par ligne) :");
            ui.add_enabled(
                !running,
                egui::TextEdit::multiline(&mut self.ping_targets_text)
                    .desired_rows(8)
                    .desired_width(f32::INFINITY)
                    .hint_text("8.8.8.8\ngoogle.com\nsrv-ad01.mondomaine.local"),
            );
            ui.add_space(6.0);
            ui.add_enabled(
                !running,
                egui::Slider::new(&mut self.ping_interval_s, 0.2..=10.0)
                    .text("Intervalle (s)")
                    .fixed_decimals(1),
            );
            ui.add_enabled(
                !running,
                egui::Slider::new(&mut self.ping_timeout_s, 0.5..=5.0)
                    .text("Timeout (s)")
                    .fixed_decimals(1),
            );
            ui.add_space(6.0);
            ui.label("Répertoire des logs :");
            ui.add_enabled(
                !running,
                egui::TextEdit::singleline(&mut self.log_dir).desired_width(f32::INFINITY),
            );
            ui.add_space(10.0);

            if running {
                if ui
                    .add_sized([ui.available_width(), 32.0], egui::Button::new("⏹ Arrêter"))
                    .clicked()
                {
                    if let Some(session) = &self.ping_session {
                        session.stop();
                    }
                }
            } else if ui
                .add_sized([ui.available_width(), 32.0], egui::Button::new("▶ Démarrer"))
                .clicked()
            {
                self.start_ping();
            }

            if let Some(err) = &self.ping_error {
                ui.add_space(6.0);
                ui.colored_label(egui::Color32::LIGHT_RED, err);
            }

            if let Some(session) = &self.ping_session {
                ui.add_space(10.0);
                ui.label("Fichiers de log :");
                for path in &session.log_files {
                    ui.monospace(path.display().to_string());
                }
            }
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(4.0);
            ui.heading("Statistiques");
            ui.add_space(4.0);
            egui::ScrollArea::horizontal().id_salt("ping_stats_scroll").show(ui, |ui| {
                egui::Grid::new("ping_stats").striped(true).min_col_width(60.0).show(ui, |ui| {
                    for header in [
                        "Cible", "IP", "Envoyés", "Reçus", "Perte", "Dernier RTT", "Min", "Moy",
                        "Max", "Gigue (moy)", "Statut",
                    ] {
                        ui.strong(header);
                    }
                    ui.end_row();
                    for (target, stats) in &self.ping_stats {
                        ui.label(target);
                        ui.label(stats.ip.map(|ip| ip.to_string()).unwrap_or_else(|| "—".into()));
                        ui.label(stats.sent.to_string());
                        ui.label(stats.received.to_string());
                        let loss = stats.loss_pct();
                        let loss_color = if loss > 5.0 {
                            egui::Color32::LIGHT_RED
                        } else if loss > 0.0 {
                            egui::Color32::YELLOW
                        } else {
                            egui::Color32::LIGHT_GREEN
                        };
                        ui.colored_label(loss_color, format!("{loss:.1} %"));
                        ui.label(fmt_ms_opt(stats.last_rtt));
                        ui.label(fmt_ms_opt(stats.min_rtt));
                        ui.label(fmt_ms_opt(stats.avg_rtt()));
                        ui.label(fmt_ms_opt(stats.max_rtt));
                        ui.label(fmt_ms_opt(stats.avg_jitter()));
                        if stats.last_status.starts_with("ERREUR") {
                            ui.colored_label(egui::Color32::LIGHT_RED, &stats.last_status);
                        } else if stats.last_status == "TIMEOUT" {
                            ui.colored_label(egui::Color32::YELLOW, &stats.last_status);
                        } else {
                            ui.label(&stats.last_status);
                        }
                        ui.end_row();
                    }
                });
            });

            ui.add_space(8.0);
            ui.separator();
            ui.horizontal(|ui| {
                ui.heading("Journal");
                if ui.button("Effacer").clicked() {
                    self.ping_log.clear();
                }
            });
            egui::ScrollArea::vertical()
                .id_salt("ping_log_scroll")
                .stick_to_bottom(true)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for line in &self.ping_log {
                        ui.monospace(line);
                    }
                });
        });
    }

    fn ui_trace(&mut self, ctx: &egui::Context) {
        let running = self.trace_session.as_ref().is_some_and(|s| s.is_running());
        if !running {
            self.trace_session = None;
        }

        egui::SidePanel::left("trace_side").default_width(300.0).show(ctx, |ui| {
            ui.add_space(6.0);
            ui.heading("Traceroute");
            ui.add_space(6.0);
            ui.label("Cibles (une IP ou un FQDN par ligne) :");
            ui.add_enabled(
                !running,
                egui::TextEdit::multiline(&mut self.trace_targets_text)
                    .desired_rows(8)
                    .desired_width(f32::INFINITY)
                    .hint_text("8.8.8.8\ngoogle.com"),
            );
            ui.add_space(6.0);
            ui.add_enabled_ui(!running, |ui| {
                ui.checkbox(&mut self.trace_resolve_names, "Résoudre les noms des sauts");
                ui.checkbox(&mut self.trace_repeat, "Répéter en continu");
                if self.trace_repeat {
                    ui.add(
                        egui::Slider::new(&mut self.trace_interval_s, 1.0..=300.0)
                            .text("Intervalle entre passes (s)")
                            .fixed_decimals(0),
                    );
                }
            });
            ui.add_space(6.0);
            ui.label("Répertoire des logs :");
            ui.add_enabled(
                !running,
                egui::TextEdit::singleline(&mut self.log_dir).desired_width(f32::INFINITY),
            );
            ui.add_space(10.0);

            if running {
                if ui
                    .add_sized([ui.available_width(), 32.0], egui::Button::new("⏹ Arrêter"))
                    .clicked()
                {
                    if let Some(session) = &self.trace_session {
                        session.stop();
                    }
                }
            } else if ui
                .add_sized([ui.available_width(), 32.0], egui::Button::new("▶ Lancer"))
                .clicked()
            {
                self.start_trace();
            }

            if let Some(err) = &self.trace_error {
                ui.add_space(6.0);
                ui.colored_label(egui::Color32::LIGHT_RED, err);
            }

            if let Some(session) = &self.trace_session {
                ui.add_space(10.0);
                ui.label("Fichiers de log :");
                for path in &session.log_files {
                    ui.monospace(path.display().to_string());
                }
            }
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.heading("Résultats");
                if running {
                    ui.spinner();
                    ui.label("en cours…");
                }
                if ui.button("Effacer").clicked() {
                    self.trace_output.clear();
                }
            });
            ui.add_space(4.0);
            egui::ScrollArea::vertical()
                .id_salt("trace_scroll")
                .stick_to_bottom(true)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for line in &self.trace_output {
                        ui.monospace(line);
                    }
                });
        });
    }

    fn ui_netconfig(&mut self, ctx: &egui::Context) {
        if self.net_report.is_none() {
            self.net_report = Some(netconfig::gather());
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.heading("Configuration réseau du poste");
                if ui.button("🔄 Actualiser").clicked() {
                    self.net_report = Some(netconfig::gather());
                    self.net_message = None;
                }
                if ui.button("💾 Exporter le rapport").clicked() {
                    if let Some(report) = &self.net_report {
                        self.net_message = Some(match netconfig::export(report, &self.log_dir) {
                            Ok(path) => format!("Rapport exporté : {}", path.display()),
                            Err(e) => format!("Échec de l'export : {e}"),
                        });
                    }
                }
            });
            if let Some(msg) = &self.net_message {
                ui.label(msg.clone());
            }
            ui.add_space(6.0);

            let Some(report) = &self.net_report else { return };
            egui::ScrollArea::vertical().id_salt("net_scroll").auto_shrink([false, false]).show(
                ui,
                |ui| {
                    egui::Grid::new("net_summary").show(ui, |ui| {
                        ui.strong("Généré le");
                        ui.label(&report.generated_at);
                        ui.end_row();
                        ui.strong("Nom d'hôte");
                        ui.label(&report.hostname);
                        ui.end_row();
                        ui.strong("Domaine");
                        ui.label(report.domain.as_deref().unwrap_or("(aucun)"));
                        ui.end_row();
                        ui.strong("Serveurs DNS");
                        ui.label(if report.dns_servers.is_empty() {
                            "(aucun détecté)".to_string()
                        } else {
                            report.dns_servers.join(", ")
                        });
                        ui.end_row();
                    });
                    ui.add_space(8.0);

                    ui.heading("Interfaces");
                    for itf in &report.interfaces {
                        let title = format!(
                            "{}{}  —  {}{}",
                            itf.name,
                            itf.friendly_name
                                .as_ref()
                                .filter(|f| *f != &itf.name)
                                .map(|f| format!(" ({f})"))
                                .unwrap_or_default(),
                            if itf.is_up { "UP" } else { "DOWN" },
                            if itf.is_default { "  [par défaut]" } else { "" }
                        );
                        egui::CollapsingHeader::new(title)
                            .default_open(itf.is_default)
                            .show(ui, |ui| {
                                egui::Grid::new(format!("itf_{}", itf.name)).show(ui, |ui| {
                                    ui.strong("Type");
                                    ui.label(&itf.if_type);
                                    ui.end_row();
                                    if let Some(mac) = &itf.mac {
                                        ui.strong("MAC");
                                        ui.label(mac);
                                        ui.end_row();
                                    }
                                    for ip in &itf.ipv4 {
                                        ui.strong("IPv4");
                                        ui.label(ip);
                                        ui.end_row();
                                    }
                                    for ip in &itf.ipv6 {
                                        ui.strong("IPv6");
                                        ui.label(ip);
                                        ui.end_row();
                                    }
                                    if let Some(gw) = &itf.gateway {
                                        ui.strong("Passerelle");
                                        ui.label(gw);
                                        ui.end_row();
                                    }
                                    if !itf.dns.is_empty() {
                                        ui.strong("DNS");
                                        ui.label(itf.dns.join(", "));
                                        ui.end_row();
                                    }
                                });
                            });
                    }

                    ui.add_space(8.0);
                    egui::CollapsingHeader::new("Table de routage").default_open(true).show(
                        ui,
                        |ui| {
                            ui.add(
                                egui::TextEdit::multiline(&mut report.routes.as_str())
                                    .font(egui::TextStyle::Monospace)
                                    .desired_width(f32::INFINITY),
                            );
                        },
                    );

                    for (title, content) in &report.raw_sections {
                        egui::CollapsingHeader::new(format!("Sortie brute : {title}"))
                            .default_open(false)
                            .show(ui, |ui| {
                                ui.add(
                                    egui::TextEdit::multiline(&mut content.as_str())
                                        .font(egui::TextStyle::Monospace)
                                        .desired_width(f32::INFINITY),
                                );
                            });
                    }
                },
            );
        });
    }
}

impl eframe::App for RustyToolsApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_events();

        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.heading("RustyTools");
                ui.separator();
                ui.selectable_value(&mut self.tab, Tab::Ping, "📡 Ping");
                ui.selectable_value(&mut self.tab, Tab::Traceroute, "🛣 Traceroute");
                ui.selectable_value(&mut self.tab, Tab::NetConfig, "🖧 Configuration réseau");
            });
            ui.add_space(4.0);
        });

        match self.tab {
            Tab::Ping => self.ui_ping(ctx),
            Tab::Traceroute => self.ui_trace(ctx),
            Tab::NetConfig => self.ui_netconfig(ctx),
        }

        if self.ping_session.is_some() || self.trace_session.is_some() {
            ctx.request_repaint_after(Duration::from_millis(200));
        }
    }
}

fn parse_targets(text: &str) -> Vec<String> {
    let mut targets = Vec::new();
    for line in text.lines() {
        let t = line.trim().to_string();
        if !t.is_empty() && !targets.contains(&t) {
            targets.push(t);
        }
    }
    targets
}

fn push_capped(buf: &mut VecDeque<String>, line: String, cap: usize) {
    buf.push_back(line);
    while buf.len() > cap {
        buf.pop_front();
    }
}

fn fmt_ms(d: Duration) -> String {
    format!("{:.1} ms", d.as_secs_f64() * 1000.0)
}

fn fmt_ms_opt(d: Option<Duration>) -> String {
    d.map(fmt_ms).unwrap_or_else(|| "—".to_string())
}
