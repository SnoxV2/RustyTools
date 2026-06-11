use std::collections::VecDeque;
use std::net::IpAddr;
use std::path::Path;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};

use eframe::egui;
use egui_plot::{Legend, Line, MarkerShape, Plot, PlotPoints, Points};

use crate::netconfig::{self, NetReport};
use crate::ping::{self, PingSession, PingStatus};
use crate::settings::{self, AppConfig};
use crate::traceroute::{self, HopInfo, ProbeStatus, TraceParams, TraceSession};

pub enum Event {
    Ping(ping::PingEvent),
    Trace(traceroute::TraceEvent),
}

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Ping,
    Traceroute,
    NetConfig,
    Settings,
}

const PALETTE: [egui::Color32; 10] = [
    egui::Color32::from_rgb(0x4f, 0xc3, 0xf7),
    egui::Color32::from_rgb(0xff, 0xb7, 0x4d),
    egui::Color32::from_rgb(0x81, 0xc7, 0x84),
    egui::Color32::from_rgb(0xe5, 0x73, 0x73),
    egui::Color32::from_rgb(0xba, 0x68, 0xc8),
    egui::Color32::from_rgb(0xff, 0xd5, 0x4f),
    egui::Color32::from_rgb(0x4d, 0xb6, 0xac),
    egui::Color32::from_rgb(0xa1, 0x88, 0x7f),
    egui::Color32::from_rgb(0x90, 0xa4, 0xae),
    egui::Color32::from_rgb(0xf0, 0x62, 0x92),
];

#[derive(Default)]
struct Stats {
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

impl Stats {
    fn record_ok(&mut self, rtt: Duration, jitter: Option<Duration>) {
        self.sent += 1;
        self.received += 1;
        self.last_rtt = Some(rtt);
        self.sum_rtt += rtt;
        self.min_rtt = Some(self.min_rtt.map_or(rtt, |m| m.min(rtt)));
        self.max_rtt = Some(self.max_rtt.map_or(rtt, |m| m.max(rtt)));
        self.last_jitter = jitter;
        if let Some(j) = jitter {
            self.sum_jitter += j;
            self.jitter_count += 1;
        }
        self.last_status = "OK".to_string();
    }

    fn record_timeout(&mut self) {
        self.sent += 1;
        self.last_status = "TIMEOUT".to_string();
    }

    fn record_error(&mut self, msg: &str) {
        self.last_status = format!("ERROR: {msg}");
    }

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

struct PingTargetState {
    target: String,
    ip: Option<IpAddr>,
    stats: Stats,
    /// (seconds since session start, rtt in ms; None = packet loss)
    samples: VecDeque<(f64, Option<f64>)>,
}

struct HopRow {
    info: HopInfo,
    stats: Stats,
    prev_rtt: Option<Duration>,
}

struct TraceTargetState {
    target: String,
    status: String,
    hops: Vec<HopRow>,
}

pub struct RustyToolsApp {
    tab: Tab,
    tx: Sender<Event>,
    rx: Receiver<Event>,
    config: AppConfig,
    config_dirty: bool,
    settings_message: Option<String>,

    // Ping
    ping_targets_text: String,
    ping_session: Option<PingSession>,
    ping_started: Option<Instant>,
    ping_targets_state: Vec<PingTargetState>,
    ping_log: VecDeque<String>,
    ping_error: Option<String>,

    // Traceroute
    trace_targets_text: String,
    trace_session: Option<TraceSession>,
    trace_targets_state: Vec<TraceTargetState>,
    trace_error: Option<String>,

    // Network configuration
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
            config: AppConfig::load(),
            config_dirty: false,
            settings_message: None,
            ping_targets_text: String::new(),
            ping_session: None,
            ping_started: None,
            ping_targets_state: Vec::new(),
            ping_log: VecDeque::new(),
            ping_error: None,
            trace_targets_text: String::new(),
            trace_session: None,
            trace_targets_state: Vec::new(),
            trace_error: None,
            net_report: None,
            net_message: None,
        }
    }

    fn drain_events(&mut self) {
        while let Ok(event) = self.rx.try_recv() {
            match event {
                Event::Ping(ev) => self.on_ping_event(ev),
                Event::Trace(ev) => self.on_trace_event(ev),
            }
        }
    }

    fn on_ping_event(&mut self, ev: ping::PingEvent) {
        let x = self.ping_started.map(|s| s.elapsed().as_secs_f64()).unwrap_or(0.0);
        let state = match self.ping_targets_state.iter_mut().find(|s| s.target == ev.target) {
            Some(s) => s,
            None => {
                self.ping_targets_state.push(PingTargetState {
                    target: ev.target.clone(),
                    ip: None,
                    stats: Stats::default(),
                    samples: VecDeque::new(),
                });
                self.ping_targets_state.last_mut().unwrap()
            }
        };
        if state.ip.is_none() {
            state.ip = ev.ip;
        }

        let line = match &ev.status {
            PingStatus::Ok { rtt, jitter } => {
                state.stats.record_ok(*rtt, *jitter);
                state.samples.push_back((x, Some(rtt.as_secs_f64() * 1000.0)));
                format!(
                    "[{}] {:<24} seq={:<5} RTT={}{}",
                    ev.timestamp,
                    ev.target,
                    ev.seq,
                    fmt_ms(*rtt),
                    jitter.map(|j| format!("  jitter={}", fmt_ms(j))).unwrap_or_default()
                )
            }
            PingStatus::Timeout => {
                state.stats.record_timeout();
                state.samples.push_back((x, None));
                format!(
                    "[{}] {:<24} seq={:<5} TIMEOUT (packet loss)",
                    ev.timestamp, ev.target, ev.seq
                )
            }
            PingStatus::Error(msg) => {
                if ev.seq > 0 {
                    state.stats.sent += 1;
                }
                state.stats.record_error(msg);
                format!("[{}] {:<24} ERROR: {msg}", ev.timestamp, ev.target)
            }
        };
        while state.samples.len() > 7200 {
            state.samples.pop_front();
        }
        push_capped(&mut self.ping_log, line, 2000);
    }

    fn on_trace_event(&mut self, ev: traceroute::TraceEvent) {
        let target_name = match &ev {
            traceroute::TraceEvent::Status { target, .. }
            | traceroute::TraceEvent::Hops { target, .. }
            | traceroute::TraceEvent::Sample { target, .. } => target.clone(),
        };
        let state = match self.trace_targets_state.iter_mut().find(|s| s.target == target_name) {
            Some(s) => s,
            None => {
                self.trace_targets_state.push(TraceTargetState {
                    target: target_name,
                    status: String::new(),
                    hops: Vec::new(),
                });
                self.trace_targets_state.last_mut().unwrap()
            }
        };

        match ev {
            traceroute::TraceEvent::Status { message, .. } => state.status = message,
            traceroute::TraceEvent::Hops { hops, .. } => {
                let old = std::mem::take(&mut state.hops);
                state.hops = hops
                    .into_iter()
                    .map(|info| {
                        let recycled = old
                            .iter()
                            .find(|r| r.info.hop == info.hop && r.info.ip == info.ip)
                            .map(|r| (clone_stats(&r.stats), r.prev_rtt));
                        let (stats, prev_rtt) = recycled.unwrap_or_default();
                        HopRow { info, stats, prev_rtt }
                    })
                    .collect();
            }
            traceroute::TraceEvent::Sample { hop, status, .. } => {
                if let Some(row) = state.hops.iter_mut().find(|r| r.info.hop == hop) {
                    match status {
                        ProbeStatus::Ok { rtt } => {
                            let jitter = row
                                .prev_rtt
                                .map(|p| if rtt > p { rtt - p } else { p - rtt });
                            row.prev_rtt = Some(rtt);
                            row.stats.record_ok(rtt, jitter);
                        }
                        ProbeStatus::Timeout => row.stats.record_timeout(),
                        ProbeStatus::Error(msg) => {
                            row.stats.sent += 1;
                            row.stats.record_error(&msg);
                        }
                    }
                }
            }
        }
    }

    // ---------------------------------------------------------------- Ping

    fn start_ping(&mut self) {
        self.ping_error = None;
        let targets = parse_targets(&self.ping_targets_text);
        if targets.is_empty() {
            self.ping_error = Some("Enter at least one target (IP or FQDN).".to_string());
            return;
        }
        self.ping_targets_state = targets
            .iter()
            .map(|t| PingTargetState {
                target: t.clone(),
                ip: None,
                stats: Stats::default(),
                samples: VecDeque::new(),
            })
            .collect();
        self.ping_log.clear();
        match ping::start(
            targets,
            Duration::from_secs_f32(self.config.ping_interval_s.max(0.1)),
            Duration::from_secs_f32(self.config.ping_timeout_s.max(0.1)),
            &self.config.log_dir,
            self.tx.clone(),
        ) {
            Ok(session) => {
                self.ping_session = Some(session);
                self.ping_started = Some(Instant::now());
            }
            Err(e) => self.ping_error = Some(e),
        }
    }

    fn ui_ping(&mut self, ctx: &egui::Context) {
        let running = self.ping_session.as_ref().is_some_and(|s| s.is_running());
        if !running {
            self.ping_session = None;
        }

        egui::SidePanel::left("ping_side").default_width(290.0).show(ctx, |ui| {
            ui.add_space(6.0);
            ui.heading("Continuous ping");
            ui.add_space(6.0);
            ui.label("Targets (one IP or FQDN per line):");
            ui.add_enabled(
                !running,
                egui::TextEdit::multiline(&mut self.ping_targets_text)
                    .desired_rows(8)
                    .desired_width(f32::INFINITY)
                    .hint_text("8.8.8.8\ngoogle.com\nsrv-ad01.mydomain.local"),
            );
            ui.add_space(6.0);
            egui::Grid::new("ping_params").num_columns(2).show(ui, |ui| {
                ui.label("Interval (s):");
                if ui
                    .add_enabled(
                        !running,
                        egui::DragValue::new(&mut self.config.ping_interval_s)
                            .range(0.1..=3600.0)
                            .speed(0.1)
                            .fixed_decimals(1),
                    )
                    .changed()
                {
                    self.config_dirty = true;
                }
                ui.end_row();
                ui.label("Timeout (s):");
                if ui
                    .add_enabled(
                        !running,
                        egui::DragValue::new(&mut self.config.ping_timeout_s)
                            .range(0.1..=60.0)
                            .speed(0.1)
                            .fixed_decimals(1),
                    )
                    .changed()
                {
                    self.config_dirty = true;
                }
                ui.end_row();
            });
            ui.add_space(10.0);

            if running {
                if ui
                    .add_sized([ui.available_width(), 32.0], egui::Button::new("⏹ Stop"))
                    .clicked()
                {
                    if let Some(session) = &self.ping_session {
                        session.stop();
                    }
                }
            } else if ui
                .add_sized([ui.available_width(), 32.0], egui::Button::new("▶ Start"))
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
                ui.label("Log files:");
                for path in &session.log_files {
                    ui.monospace(path.display().to_string());
                }
            }
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(4.0);
            egui::ScrollArea::horizontal().id_salt("ping_stats_scroll").show(ui, |ui| {
                egui::Grid::new("ping_stats").striped(true).min_col_width(56.0).show(ui, |ui| {
                    for header in [
                        "Target", "IP", "Sent", "Recv", "Loss", "Last", "Min", "Avg", "Max",
                        "Jitter", "Status",
                    ] {
                        ui.strong(header);
                    }
                    ui.end_row();
                    for (i, state) in self.ping_targets_state.iter().enumerate() {
                        let color = PALETTE[i % PALETTE.len()];
                        ui.colored_label(color, &state.target);
                        ui.label(state.ip.map(|ip| ip.to_string()).unwrap_or_else(|| "—".into()));
                        ui.label(state.stats.sent.to_string());
                        ui.label(state.stats.received.to_string());
                        let loss = state.stats.loss_pct();
                        ui.colored_label(loss_color(loss), format!("{loss:.1} %"));
                        ui.label(fmt_ms_opt(state.stats.last_rtt));
                        ui.label(fmt_ms_opt(state.stats.min_rtt));
                        ui.label(fmt_ms_opt(state.stats.avg_rtt()));
                        ui.label(fmt_ms_opt(state.stats.max_rtt));
                        ui.label(fmt_ms_opt(state.stats.avg_jitter()));
                        status_label(ui, &state.stats.last_status);
                        ui.end_row();
                    }
                });
            });

            ui.add_space(6.0);

            // Latency graph — the main view, PingPlotter style.
            let log_open_height = 160.0;
            let plot_height = (ui.available_height() - log_open_height).max(120.0);

            let mut series: Vec<(usize, Vec<Vec<[f64; 2]>>)> = Vec::new();
            let mut losses: Vec<[f64; 2]> = Vec::new();
            for (i, state) in self.ping_targets_state.iter().enumerate() {
                let mut segments: Vec<Vec<[f64; 2]>> = Vec::new();
                let mut current: Vec<[f64; 2]> = Vec::new();
                for (x, y) in &state.samples {
                    match y {
                        Some(ms) => current.push([*x, *ms]),
                        None => {
                            losses.push([*x, 0.0]);
                            if !current.is_empty() {
                                segments.push(std::mem::take(&mut current));
                            }
                        }
                    }
                }
                if !current.is_empty() {
                    segments.push(current);
                }
                series.push((i, segments));
            }

            Plot::new("ping_plot")
                .legend(Legend::default())
                .include_y(0.0)
                .height(plot_height)
                .x_axis_formatter(|mark, _range| fmt_mmss(mark.value))
                .label_formatter(|name, value| {
                    if name.is_empty() {
                        format!("{} — {:.1} ms", fmt_mmss(value.x), value.y)
                    } else {
                        format!("{name}\n{} — {:.1} ms", fmt_mmss(value.x), value.y)
                    }
                })
                .show(ui, |plot_ui| {
                    for (i, segments) in &series {
                        let color = PALETTE[i % PALETTE.len()];
                        let name = &self.ping_targets_state[*i].target;
                        for segment in segments {
                            plot_ui.line(
                                Line::new(PlotPoints::from(segment.clone()))
                                    .color(color)
                                    .name(name),
                            );
                        }
                    }
                    if !losses.is_empty() {
                        plot_ui.points(
                            Points::new(PlotPoints::from(losses.clone()))
                                .color(egui::Color32::RED)
                                .shape(MarkerShape::Cross)
                                .radius(5.0)
                                .name("packet loss"),
                        );
                    }
                });

            egui::CollapsingHeader::new("Event log").default_open(false).show(ui, |ui| {
                if ui.button("Clear").clicked() {
                    self.ping_log.clear();
                }
                egui::ScrollArea::vertical()
                    .id_salt("ping_log_scroll")
                    .stick_to_bottom(true)
                    .max_height(log_open_height)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        for line in &self.ping_log {
                            ui.monospace(line);
                        }
                    });
            });
        });
    }

    // ----------------------------------------------------------- Traceroute

    fn start_trace(&mut self) {
        self.trace_error = None;
        let targets = parse_targets(&self.trace_targets_text);
        if targets.is_empty() {
            self.trace_error = Some("Enter at least one target (IP or FQDN).".to_string());
            return;
        }
        self.trace_targets_state = targets
            .iter()
            .map(|t| TraceTargetState {
                target: t.clone(),
                status: "starting…".to_string(),
                hops: Vec::new(),
            })
            .collect();
        let params = TraceParams {
            max_hops: self.config.trace_max_hops.max(1),
            probe_interval: Duration::from_secs_f32(self.config.trace_interval_s.max(0.1)),
            probe_timeout: Duration::from_secs_f32(self.config.trace_timeout_s.max(0.1)),
            resolve_names: self.config.trace_resolve_names,
        };
        match traceroute::start(targets, params, &self.config.log_dir, self.tx.clone()) {
            Ok(session) => self.trace_session = Some(session),
            Err(e) => self.trace_error = Some(e),
        }
    }

    fn ui_trace(&mut self, ctx: &egui::Context) {
        let running = self.trace_session.as_ref().is_some_and(|s| s.is_running());
        if !running {
            self.trace_session = None;
        }

        egui::SidePanel::left("trace_side").default_width(290.0).show(ctx, |ui| {
            ui.add_space(6.0);
            ui.heading("Trace (MTR-style)");
            ui.add_space(6.0);
            ui.label("Targets (one IP or FQDN per line):");
            ui.add_enabled(
                !running,
                egui::TextEdit::multiline(&mut self.trace_targets_text)
                    .desired_rows(8)
                    .desired_width(f32::INFINITY)
                    .hint_text("8.8.8.8\ngoogle.com"),
            );
            ui.add_space(6.0);
            egui::Grid::new("trace_params").num_columns(2).show(ui, |ui| {
                ui.label("Max hops:");
                if ui
                    .add_enabled(
                        !running,
                        egui::DragValue::new(&mut self.config.trace_max_hops).range(1..=64),
                    )
                    .changed()
                {
                    self.config_dirty = true;
                }
                ui.end_row();
                ui.label("Probe interval (s):");
                if ui
                    .add_enabled(
                        !running,
                        egui::DragValue::new(&mut self.config.trace_interval_s)
                            .range(0.1..=3600.0)
                            .speed(0.1)
                            .fixed_decimals(1),
                    )
                    .changed()
                {
                    self.config_dirty = true;
                }
                ui.end_row();
                ui.label("Probe timeout (s):");
                if ui
                    .add_enabled(
                        !running,
                        egui::DragValue::new(&mut self.config.trace_timeout_s)
                            .range(0.1..=60.0)
                            .speed(0.1)
                            .fixed_decimals(1),
                    )
                    .changed()
                {
                    self.config_dirty = true;
                }
                ui.end_row();
            });
            if ui
                .add_enabled(
                    !running,
                    egui::Checkbox::new(
                        &mut self.config.trace_resolve_names,
                        "Resolve hop hostnames",
                    ),
                )
                .changed()
            {
                self.config_dirty = true;
            }
            ui.add_space(10.0);

            if running {
                if ui
                    .add_sized([ui.available_width(), 32.0], egui::Button::new("⏹ Stop"))
                    .clicked()
                {
                    if let Some(session) = &self.trace_session {
                        session.stop();
                    }
                }
            } else if ui
                .add_sized([ui.available_width(), 32.0], egui::Button::new("▶ Start"))
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
                ui.label("Log files:");
                for path in &session.log_files {
                    ui.monospace(path.display().to_string());
                }
            }
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(4.0);
            if self.trace_targets_state.is_empty() {
                ui.label(
                    "Start a trace to see the path to each target with live per-hop \
                     loss and latency statistics (WinMTR / PingPlotter style).",
                );
                return;
            }
            egui::ScrollArea::vertical().id_salt("trace_scroll").auto_shrink([false, false]).show(
                ui,
                |ui| {
                    for state in &self.trace_targets_state {
                        ui.horizontal(|ui| {
                            ui.heading(&state.target);
                            if running {
                                ui.spinner();
                            }
                            ui.weak(&state.status);
                        });
                        ui.add_space(2.0);
                        egui::Grid::new(format!("mtr_{}", state.target))
                            .striped(true)
                            .min_col_width(52.0)
                            .show(ui, |ui| {
                                for header in [
                                    "Hop", "Host", "Loss", "Sent", "Last", "Avg", "Best",
                                    "Worst", "Jitter",
                                ] {
                                    ui.strong(header);
                                }
                                ui.end_row();
                                for row in &state.hops {
                                    ui.label(row.info.hop.to_string());
                                    let host = match (&row.info.ip, &row.info.hostname) {
                                        (Some(ip), Some(name)) => format!("{name} ({ip})"),
                                        (Some(ip), None) => ip.to_string(),
                                        (None, _) => "*".to_string(),
                                    };
                                    if row.info.is_destination {
                                        ui.strong(format!("{host}  ⏵ destination"));
                                    } else {
                                        ui.label(host);
                                    }
                                    if row.info.ip.is_some() {
                                        let loss = row.stats.loss_pct();
                                        ui.colored_label(loss_color(loss), format!("{loss:.1} %"));
                                        ui.label(row.stats.sent.to_string());
                                        ui.label(fmt_ms_opt(row.stats.last_rtt));
                                        ui.label(fmt_ms_opt(row.stats.avg_rtt()));
                                        ui.label(fmt_ms_opt(row.stats.min_rtt));
                                        ui.label(fmt_ms_opt(row.stats.max_rtt));
                                        ui.label(fmt_ms_opt(row.stats.avg_jitter()));
                                    } else {
                                        for _ in 0..7 {
                                            ui.label("—");
                                        }
                                    }
                                    ui.end_row();
                                }
                            });
                        ui.add_space(12.0);
                        ui.separator();
                    }
                },
            );
        });
    }

    // ------------------------------------------------------- Network config

    fn ui_netconfig(&mut self, ctx: &egui::Context) {
        if self.net_report.is_none() {
            self.net_report = Some(netconfig::gather());
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.heading("Host network configuration");
                if ui.button("🔄 Refresh").clicked() {
                    self.net_report = Some(netconfig::gather());
                    self.net_message = None;
                }
                if ui.button("💾 Export report").clicked() {
                    if let Some(report) = &self.net_report {
                        self.net_message =
                            Some(match netconfig::export(report, &self.config.log_dir) {
                                Ok(path) => format!("Report exported: {}", path.display()),
                                Err(e) => format!("Export failed: {e}"),
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
                        ui.strong("Generated");
                        ui.label(&report.generated_at);
                        ui.end_row();
                        ui.strong("Hostname");
                        ui.label(&report.hostname);
                        ui.end_row();
                        ui.strong("Domain");
                        ui.label(report.domain.as_deref().unwrap_or("(none)"));
                        ui.end_row();
                        ui.strong("DNS servers");
                        ui.label(if report.dns_servers.is_empty() {
                            "(none detected)".to_string()
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
                            if itf.is_default { "  [default]" } else { "" }
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
                                        ui.strong("Gateway");
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
                    egui::CollapsingHeader::new("Routing table").default_open(true).show(
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
                        egui::CollapsingHeader::new(format!("Raw output: {title}"))
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

    // ------------------------------------------------------------- Settings

    fn ui_settings(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(4.0);
            ui.heading("Settings");
            ui.add_space(10.0);

            ui.label("Log folder:");
            ui.horizontal(|ui| {
                if ui
                    .add(
                        egui::TextEdit::singleline(&mut self.config.log_dir)
                            .desired_width(420.0),
                    )
                    .changed()
                {
                    self.config_dirty = true;
                }
                if ui.button("📁 Browse…").clicked() {
                    let mut dialog = rfd::FileDialog::new().set_title("Select log folder");
                    let current = Path::new(&self.config.log_dir);
                    if current.is_dir() {
                        dialog = dialog.set_directory(current);
                    }
                    if let Some(folder) = dialog.pick_folder() {
                        self.config.log_dir = folder.to_string_lossy().into_owned();
                        self.config_dirty = true;
                    }
                }
                if ui.button("Open").clicked() {
                    let path = Path::new(&self.config.log_dir);
                    let _ = std::fs::create_dir_all(path);
                    util::open_in_file_manager(path);
                }
            });
            ui.weak(
                "Subfolders ping/, traceroute/ and netconfig/ are created automatically \
                 inside the log folder.",
            );

            ui.add_space(16.0);
            ui.separator();
            ui.add_space(8.0);
            ui.weak(format!(
                "Settings are saved automatically and persist across restarts.\nConfig file: {}",
                settings::config_path().display()
            ));
            if let Some(msg) = &self.settings_message {
                ui.add_space(6.0);
                ui.colored_label(egui::Color32::LIGHT_RED, msg);
            }
        });
    }
}

use crate::util;

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
                ui.selectable_value(&mut self.tab, Tab::NetConfig, "🖧 Network config");
                ui.selectable_value(&mut self.tab, Tab::Settings, "⚙ Settings");
            });
            ui.add_space(4.0);
        });

        match self.tab {
            Tab::Ping => self.ui_ping(ctx),
            Tab::Traceroute => self.ui_trace(ctx),
            Tab::NetConfig => self.ui_netconfig(ctx),
            Tab::Settings => self.ui_settings(ctx),
        }

        if self.config_dirty {
            self.settings_message = self.config.save().err();
            self.config_dirty = false;
        }

        if self.ping_session.is_some() || self.trace_session.is_some() {
            ctx.request_repaint_after(Duration::from_millis(200));
        }
    }
}

fn clone_stats(s: &Stats) -> Stats {
    Stats {
        sent: s.sent,
        received: s.received,
        last_rtt: s.last_rtt,
        min_rtt: s.min_rtt,
        max_rtt: s.max_rtt,
        sum_rtt: s.sum_rtt,
        last_jitter: s.last_jitter,
        sum_jitter: s.sum_jitter,
        jitter_count: s.jitter_count,
        last_status: s.last_status.clone(),
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

fn loss_color(loss: f64) -> egui::Color32 {
    if loss > 5.0 {
        egui::Color32::LIGHT_RED
    } else if loss > 0.0 {
        egui::Color32::YELLOW
    } else {
        egui::Color32::LIGHT_GREEN
    }
}

fn status_label(ui: &mut egui::Ui, status: &str) {
    if status.starts_with("ERROR") {
        ui.colored_label(egui::Color32::LIGHT_RED, status);
    } else if status == "TIMEOUT" {
        ui.colored_label(egui::Color32::YELLOW, status);
    } else {
        ui.label(status);
    }
}

fn fmt_ms(d: Duration) -> String {
    format!("{:.1} ms", d.as_secs_f64() * 1000.0)
}

fn fmt_ms_opt(d: Option<Duration>) -> String {
    d.map(fmt_ms).unwrap_or_else(|| "—".to_string())
}

fn fmt_mmss(seconds: f64) -> String {
    let s = seconds.max(0.0) as u64;
    format!("{}:{:02}", s / 60, s % 60)
}
