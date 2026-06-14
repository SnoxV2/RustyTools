use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};

use eframe::egui;
use egui_plot::{Legend, Line, MarkerShape, Plot, PlotPoints, Points};

use crate::arp::{self, ArpEntry, ArpEvent};
use crate::dns::{self, DnsAnswer, DnsEvent};
use crate::netconfig::{self, NetReport};
use crate::ping::{self, PingSession, PingStatus};
use crate::settings::{self, AppConfig};
use crate::traceroute::{self, HopInfo, ProbeStatus, TraceParams, TraceSession};

pub enum Event {
    Ping(ping::PingEvent),
    Trace(traceroute::TraceEvent),
    Dns(DnsEvent),
    Arp(ArpEvent),
}

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Ping,
    Traceroute,
    Dns,
    Arp,
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

#[derive(PartialEq, Clone, Copy)]
enum SourceSel {
    Default,
    Iface(usize),
    CustomIp,
}

/// "Advanced > Source" selector state (one per feature tab).
struct SourceUi {
    sel: SourceSel,
    custom_ip: String,
}

impl Default for SourceUi {
    fn default() -> Self {
        SourceUi { sel: SourceSel::Default, custom_ip: String::new() }
    }
}

struct IfaceChoice {
    label: String,
    source: util::IfaceSource,
}

fn gather_ifaces() -> Vec<IfaceChoice> {
    let mut out = Vec::new();
    for itf in netdev::get_interfaces() {
        let mut addrs: Vec<IpAddr> = itf.ipv4.iter().map(|n| IpAddr::V4(n.addr())).collect();
        addrs.extend(itf.ipv6.iter().map(|n| IpAddr::V6(n.addr())));
        if addrs.is_empty() {
            continue;
        }
        let display = addrs.iter().find(|a| a.is_ipv4()).unwrap_or(&addrs[0]);
        out.push(IfaceChoice {
            label: format!("{} ({display})", itf.name),
            source: util::IfaceSource { name: itf.name.clone(), index: itf.index, addrs },
        });
    }
    out.sort_by(|a, b| a.label.cmp(&b.label));
    out
}

/// Draws the source selector; default keeps the OS routing behavior.
fn source_selector(ui: &mut egui::Ui, id: &str, src: &mut SourceUi, ifaces: &[IfaceChoice]) {
    ui.horizontal(|ui| {
        ui.label("Source:");
        let selected = match src.sel {
            SourceSel::Default => "Default (system routing)".to_string(),
            SourceSel::Iface(i) => {
                ifaces.get(i).map(|c| c.label.clone()).unwrap_or_else(|| "?".to_string())
            }
            SourceSel::CustomIp => "Custom IP…".to_string(),
        };
        egui::ComboBox::from_id_salt(id.to_string()).selected_text(selected).show_ui(ui, |ui| {
            ui.selectable_value(&mut src.sel, SourceSel::Default, "Default (system routing)");
            for (i, choice) in ifaces.iter().enumerate() {
                ui.selectable_value(&mut src.sel, SourceSel::Iface(i), &choice.label);
            }
            ui.selectable_value(&mut src.sel, SourceSel::CustomIp, "Custom IP…");
        });
    });
    if src.sel == SourceSel::CustomIp {
        ui.horizontal(|ui| {
            ui.label("Source IP:");
            ui.add(
                egui::TextEdit::singleline(&mut src.custom_ip)
                    .desired_width(160.0)
                    .hint_text("192.168.1.10"),
            );
        });
    }
}

/// Converts the selector state into the engine-side source config.
fn source_config(src: &SourceUi, ifaces: &[IfaceChoice]) -> Result<util::SourceConfig, String> {
    match src.sel {
        SourceSel::Default => Ok(util::SourceConfig::default()),
        SourceSel::Iface(i) => Ok(util::SourceConfig {
            ip: None,
            iface: Some(
                ifaces
                    .get(i)
                    .ok_or("the interface list changed — reselect the source interface")?
                    .source
                    .clone(),
            ),
        }),
        SourceSel::CustomIp => {
            let text = src.custom_ip.trim();
            let ip =
                text.parse::<IpAddr>().map_err(|_| format!("invalid source IP: {text:?}"))?;
            Ok(util::SourceConfig { ip: Some(ip), iface: None })
        }
    }
}

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

    // DNS
    dns_targets_text: String,
    dns_results: Vec<DnsAnswer>,
    dns_running: bool,
    dns_error: Option<String>,
    dns_log_file: Option<PathBuf>,

    // ARP
    arp_entries: Vec<ArpEntry>,
    arp_raw: String,
    arp_vendors: HashMap<String, String>,
    arp_vendor_running: bool,
    arp_message: Option<String>,
    arp_auto: bool,
    arp_last_refresh: Instant,

    // Network configuration
    net_report: Option<NetReport>,
    net_message: Option<String>,
    net_auto: bool,
    net_last_refresh: Instant,

    // Log deletion (two-step confirmation), shared by all tabs
    delete_confirm: Option<&'static str>,
    logs_message: Option<String>,

    // Advanced source selection (per feature) + detected interfaces
    ifaces: Vec<IfaceChoice>,
    ping_source: SourceUi,
    trace_source: SourceUi,
    dns_source: SourceUi,

    // Logo texture, built once from the rendered RGBA buffer.
    logo_tex: Option<egui::TextureHandle>,
    // Nav rail expands on hover, collapses to icons otherwise.
    nav_hovered: bool,
}

impl RustyToolsApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        crate::theme::apply(&cc.egui_ctx);
        let logo_size = 64;
        let logo_image = egui::ColorImage::from_rgba_unmultiplied(
            [logo_size, logo_size],
            &crate::logo::render_rgba(logo_size as u32),
        );
        let logo_tex = Some(cc.egui_ctx.load_texture("logo", logo_image, egui::TextureOptions::LINEAR));
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
            dns_targets_text: String::new(),
            dns_results: Vec::new(),
            dns_running: false,
            dns_error: None,
            dns_log_file: None,
            arp_entries: Vec::new(),
            arp_raw: String::new(),
            arp_vendors: HashMap::new(),
            arp_vendor_running: false,
            arp_message: None,
            arp_auto: false,
            arp_last_refresh: Instant::now(),
            net_report: None,
            net_message: None,
            net_auto: false,
            net_last_refresh: Instant::now(),
            delete_confirm: None,
            logs_message: None,
            ifaces: gather_ifaces(),
            ping_source: SourceUi::default(),
            trace_source: SourceUi::default(),
            dns_source: SourceUi::default(),
            logo_tex,
            nav_hovered: false,
        }
    }

    /// "Advanced" section shared by the feature tabs (source selection).
    fn advanced_source_ui(&mut self, ui: &mut egui::Ui, id: &str, which: Tab, enabled: bool) {
        egui::CollapsingHeader::new("Advanced").id_salt(format!("{id}_adv")).show(ui, |ui| {
            ui.add_enabled_ui(enabled, |ui| {
                let src = match which {
                    Tab::Ping => &mut self.ping_source,
                    Tab::Traceroute => &mut self.trace_source,
                    _ => &mut self.dns_source,
                };
                source_selector(ui, id, src, &self.ifaces);
                if which == Tab::Dns {
                    ui.weak("Applies to custom DNS servers only.");
                }
                if ui.small_button("🔄 Refresh interface list").clicked() {
                    self.ifaces = gather_ifaces();
                    for src in
                        [&mut self.ping_source, &mut self.trace_source, &mut self.dns_source]
                    {
                        if matches!(src.sel, SourceSel::Iface(i) if i >= self.ifaces.len()) {
                            src.sel = SourceSel::Default;
                        }
                    }
                }
            });
        });
    }

    fn drain_events(&mut self) {
        while let Ok(event) = self.rx.try_recv() {
            match event {
                Event::Ping(ev) => self.on_ping_event(ev),
                Event::Trace(ev) => self.on_trace_event(ev),
                Event::Dns(DnsEvent::Answer(answer)) => self.dns_results.push(answer),
                Event::Dns(DnsEvent::Done) => self.dns_running = false,
                Event::Arp(ArpEvent::Vendor { oui, vendor }) => {
                    self.arp_vendors.insert(oui, vendor);
                }
                Event::Arp(ArpEvent::Error(msg)) => self.arp_message = Some(msg),
                Event::Arp(ArpEvent::Done) => self.arp_vendor_running = false,
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

    /// "Delete log files" button with a two-step inline confirmation.
    /// Deletes every file in the tab's log subfolder.
    /// Log action buttons added inline to the current row (no wrapping
    /// layout): open the tab's log subfolder, and delete its logs (two-step
    /// confirmation, disabled while a session is writing). The status message
    /// is shown by `logs_message_ui`.
    fn log_action_buttons(&mut self, ui: &mut egui::Ui, sub: &'static str, enabled: bool) {
        if ui
            .button("📂 Open folder")
            .on_hover_text(format!("Open {sub}/ in the file manager"))
            .clicked()
        {
            match util::ensure_log_dir(&self.config.log_dir, sub) {
                Ok(path) => util::open_in_file_manager(&path),
                Err(e) => self.logs_message = Some(format!("cannot open {sub}/: {e}")),
            }
        }
        if self.delete_confirm == Some(sub) {
            ui.colored_label(crate::theme::DANGER, format!("Delete all files in {sub}/?"));
            if ui.button("Yes, delete").clicked() {
                self.logs_message = Some(match util::clear_log_files(&self.config.log_dir, sub) {
                    Ok(n) => format!("{n} log file(s) deleted."),
                    Err(e) => e,
                });
                self.delete_confirm = None;
            }
            if ui.button("Cancel").clicked() {
                self.delete_confirm = None;
            }
        } else if ui
            .add_enabled(enabled, egui::Button::new("🗑 Delete log files"))
            .on_disabled_hover_text("Stop the running session first")
            .clicked()
        {
            self.delete_confirm = Some(sub);
            self.logs_message = None;
        }
    }

    fn logs_message_ui(&self, ui: &mut egui::Ui) {
        if self.delete_confirm.is_none() {
            if let Some(msg) = &self.logs_message {
                ui.weak(msg.clone());
            }
        }
    }

    /// Stacked log actions (own row + message) for the vertical side panels.
    fn delete_logs_ui(&mut self, ui: &mut egui::Ui, sub: &'static str, enabled: bool) {
        ui.horizontal(|ui| self.log_action_buttons(ui, sub, enabled));
        self.logs_message_ui(ui);
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
        let source = match source_config(&self.ping_source, &self.ifaces) {
            Ok(s) => s,
            Err(e) => {
                self.ping_error = Some(e);
                return;
            }
        };
        match ping::start(
            targets,
            Duration::from_secs_f32(self.config.ping_interval_s.max(0.1)),
            Duration::from_secs_f32(self.config.ping_timeout_s.max(0.1)),
            source,
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

        egui::SidePanel::left("ping_side")
            .resizable(true)
            .default_width(290.0)
            .width_range(190.0..=440.0)
            .show(ctx, |ui| {
            ui.add_space(6.0);
            ui.heading("Continuous ping");
            ui.add_space(6.0);
            ui.label("Targets (one IP or FQDN per line):");
            multiline_input(
                ui,
                &mut self.ping_targets_text,
                !running,
                8,
                "8.8.8.8\ngoogle.com\nsrv-ad01.mydomain.local",
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
            self.advanced_source_ui(ui, "ping_source", Tab::Ping, !running);
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
                ui.colored_label(crate::theme::DANGER, err);
            }

            ui.add_space(10.0);
            if ui.button("🧹 Clear results").clicked() {
                for state in &mut self.ping_targets_state {
                    state.stats = Stats::default();
                    state.samples.clear();
                }
                if !running {
                    self.ping_targets_state.clear();
                }
                self.ping_log.clear();
            }
            self.delete_logs_ui(ui, "ping", !running);

            if let Some(session) = &self.ping_session {
                ui.add_space(10.0);
                ui.label("Log files:");
                for path in &session.log_files {
                    ui.monospace(path.display().to_string());
                }
            }
        });

        egui::CentralPanel::default().show(ctx, |ui| {
          egui::ScrollArea::vertical()
            .id_salt("ping_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
            ui.add_space(4.0);
            ui.heading("Statistics");
            ui.add_space(4.0);
            egui::ScrollArea::horizontal().id_salt("ping_stats_scroll").show(ui, |ui| {
                egui::Grid::new("ping_stats")
                    .striped(true)
                    .min_col_width(56.0)
                    .spacing(egui::vec2(14.0, 6.0))
                    .show(ui, |ui| {
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

            ui.add_space(12.0);
            ui.heading("Latency");
            ui.add_space(4.0);

            // Latency graph — capped to ~half the window so the stats stay
            // prominent and the page keeps breathing room below.
            let plot_height = (ctx.screen_rect().height() * 0.48).clamp(200.0, 440.0);

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
                                .color(crate::theme::DANGER)
                                .shape(MarkerShape::Cross)
                                .radius(5.0)
                                .name("packet loss"),
                        );
                    }
                });

            ui.add_space(12.0);
            egui::CollapsingHeader::new("Event log").default_open(false).show(ui, |ui| {
                if ui.button("Clear").clicked() {
                    self.ping_log.clear();
                }
                egui::ScrollArea::vertical()
                    .id_salt("ping_log_scroll")
                    .stick_to_bottom(true)
                    .max_height(180.0)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        for line in &self.ping_log {
                            ui.monospace(line);
                        }
                    });
            });
            ui.add_space(16.0);
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
        let source = match source_config(&self.trace_source, &self.ifaces) {
            Ok(s) => s,
            Err(e) => {
                self.trace_error = Some(e);
                return;
            }
        };
        let params = TraceParams {
            max_hops: self.config.trace_max_hops.max(1),
            probe_interval: Duration::from_secs_f32(self.config.trace_interval_s.max(0.1)),
            probe_timeout: Duration::from_secs_f32(self.config.trace_timeout_s.max(0.1)),
            resolve_names: self.config.trace_resolve_names,
            source,
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

        egui::SidePanel::left("trace_side")
            .resizable(true)
            .default_width(290.0)
            .width_range(190.0..=440.0)
            .show(ctx, |ui| {
            ui.add_space(6.0);
            ui.heading("Trace (MTR-style)");
            ui.add_space(6.0);
            ui.label("Targets (one IP or FQDN per line):");
            multiline_input(ui, &mut self.trace_targets_text, !running, 8, "8.8.8.8\ngoogle.com");
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
            self.advanced_source_ui(ui, "trace_source", Tab::Traceroute, !running);
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
                ui.colored_label(crate::theme::DANGER, err);
            }

            ui.add_space(10.0);
            if ui
                .add_enabled(!running, egui::Button::new("🧹 Clear results"))
                .on_disabled_hover_text("Stop the running session first")
                .clicked()
            {
                self.trace_targets_state.clear();
            }
            self.delete_logs_ui(ui, "traceroute", !running);

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

    // ----------------------------------------------------------------- DNS

    fn start_dns(&mut self) {
        self.dns_error = None;
        let targets = parse_targets(&self.dns_targets_text);
        let mut custom = Vec::new();
        let mut bad = Vec::new();
        for line in self.config.dns_custom_servers.lines() {
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            match t.parse::<IpAddr>() {
                Ok(ip) => custom.push(ip),
                Err(_) => bad.push(t.to_string()),
            }
        }
        if !bad.is_empty() {
            self.dns_error = Some(format!("Invalid DNS server address: {}", bad.join(", ")));
            return;
        }
        let source = match source_config(&self.dns_source, &self.ifaces) {
            Ok(s) => s,
            Err(e) => {
                self.dns_error = Some(e);
                return;
            }
        };
        match dns::start(
            targets,
            self.config.dns_record_type.clone(),
            self.config.dns_use_system,
            custom,
            source,
            &self.config.log_dir,
            self.tx.clone(),
        ) {
            Ok(path) => {
                self.dns_log_file = Some(path);
                self.dns_running = true;
            }
            Err(e) => self.dns_error = Some(e),
        }
    }

    fn ui_dns(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("dns_side")
            .resizable(true)
            .default_width(290.0)
            .width_range(190.0..=440.0)
            .show(ctx, |ui| {
            ui.add_space(6.0);
            ui.heading("DNS lookup");
            ui.add_space(6.0);
            ui.label("Names or IPs (one per line, IP = reverse lookup):");
            multiline_input(
                ui,
                &mut self.dns_targets_text,
                !self.dns_running,
                6,
                "google.com\nsrv-ad01.mydomain.local\n192.168.1.10",
            );
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("Record type:");
                egui::ComboBox::from_id_salt("dns_rtype")
                    .selected_text(&self.config.dns_record_type)
                    .show_ui(ui, |ui| {
                        for t in dns::RECORD_TYPES {
                            if ui
                                .selectable_value(
                                    &mut self.config.dns_record_type,
                                    t.to_string(),
                                    t,
                                )
                                .changed()
                            {
                                self.config_dirty = true;
                            }
                        }
                    });
            });
            if ui
                .checkbox(&mut self.config.dns_use_system, "Use system DNS")
                .changed()
            {
                self.config_dirty = true;
            }
            ui.label("Custom DNS servers (one per line):");
            if multiline_input(
                ui,
                &mut self.config.dns_custom_servers,
                true,
                4,
                "8.8.8.8\n1.1.1.1\n192.168.1.5",
            )
            .changed()
            {
                self.config_dirty = true;
            }
            self.advanced_source_ui(ui, "dns_source", Tab::Dns, !self.dns_running);
            ui.add_space(10.0);

            ui.add_enabled_ui(!self.dns_running, |ui| {
                if ui
                    .add_sized([ui.available_width(), 32.0], egui::Button::new("🔍 Resolve"))
                    .clicked()
                {
                    self.start_dns();
                }
            });
            if self.dns_running {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("resolving…");
                });
            }
            if let Some(err) = &self.dns_error {
                ui.add_space(6.0);
                ui.colored_label(crate::theme::DANGER, err);
            }

            ui.add_space(10.0);
            if ui.button("🧹 Clear results").clicked() {
                self.dns_results.clear();
            }
            self.delete_logs_ui(ui, "dns", !self.dns_running);

            if let Some(path) = &self.dns_log_file {
                ui.add_space(10.0);
                ui.label("Log file:");
                ui.monospace(path.display().to_string());
            }
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(4.0);
            if self.dns_results.is_empty() {
                ui.label(
                    "Run a lookup to compare answers from the system resolver and/or \
                     custom DNS servers (public resolvers, local AD, …).",
                );
                return;
            }
            egui::ScrollArea::both().id_salt("dns_scroll").auto_shrink([false, false]).show(
                ui,
                |ui| {
                    egui::Grid::new("dns_results").striped(true).min_col_width(60.0).show(
                        ui,
                        |ui| {
                            for header in ["Time", "Query", "Type", "Server", "Duration", "Answer"]
                            {
                                ui.strong(header);
                            }
                            ui.end_row();
                            for answer in &self.dns_results {
                                ui.label(&answer.timestamp);
                                ui.label(&answer.query);
                                ui.label(&answer.rtype);
                                ui.label(&answer.server);
                                ui.label(format!("{:.1} ms", answer.duration_ms));
                                match &answer.error {
                                    Some(e) => {
                                        ui.colored_label(crate::theme::DANGER, e);
                                    }
                                    None => {
                                        ui.label(answer.records.join("\n"));
                                    }
                                }
                                ui.end_row();
                            }
                        },
                    );
                },
            );
        });
    }

    // ----------------------------------------------------------------- ARP

    fn ui_arp(&mut self, ctx: &egui::Context) {
        if self.arp_auto && self.arp_last_refresh.elapsed() >= Duration::from_secs(3) {
            let (entries, raw) = arp::gather();
            self.arp_entries = entries;
            self.arp_raw = raw;
            self.arp_last_refresh = Instant::now();
        }
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                ui.heading("ARP table");
                if ui.button("🔄 Refresh").clicked() {
                    let (entries, raw) = arp::gather();
                    self.arp_entries = entries;
                    self.arp_raw = raw;
                    self.arp_message = None;
                    self.arp_last_refresh = Instant::now();
                }
                if ui.checkbox(&mut self.arp_auto, "Auto 3s").changed() {
                    self.arp_last_refresh = Instant::now();
                }
                let unresolved: Vec<String> = self
                    .arp_entries
                    .iter()
                    .filter_map(|e| arp::oui_of(&e.mac))
                    .filter(|oui| !self.arp_vendors.contains_key(oui))
                    .collect();
                if ui
                    .add_enabled(
                        !self.arp_vendor_running && !unresolved.is_empty(),
                        egui::Button::new("🏷 Resolve vendors"),
                    )
                    .on_hover_text("Identify manufacturers from the embedded IEEE OUI database")
                    .clicked()
                {
                    self.arp_vendor_running = true;
                    let macs: Vec<String> =
                        self.arp_entries.iter().map(|e| e.mac.clone()).collect();
                    arp::lookup_vendors(macs, self.tx.clone());
                }
                if self.arp_vendor_running {
                    ui.spinner();
                }
                if ui
                    .add_enabled(!self.arp_entries.is_empty(), egui::Button::new("💾 Export"))
                    .clicked()
                {
                    self.arp_message = Some(
                        match arp::export(
                            &self.arp_entries,
                            &self.arp_vendors,
                            &self.arp_raw,
                            &self.config.log_dir,
                        ) {
                            Ok(path) => format!("Exported: {}", path.display()),
                            Err(e) => format!("Export failed: {e}"),
                        },
                    );
                }
                ui.separator();
                self.log_action_buttons(ui, "arp", true);
            });
            self.logs_message_ui(ui);
            if let Some(msg) = &self.arp_message {
                ui.label(msg.clone());
            }
            ui.add_space(6.0);

            if self.arp_entries.is_empty() {
                ui.label(
                    "Press Refresh to list the devices present in the ARP/neighbor table \
                     of this host, then resolve MAC vendors on demand.",
                );
                return;
            }
            egui::ScrollArea::vertical().id_salt("arp_scroll").auto_shrink([false, false]).show(
                ui,
                |ui| {
                    egui::Grid::new("arp_table").striped(true).min_col_width(80.0).show(
                        ui,
                        |ui| {
                            for header in ["IP", "MAC", "Vendor", "Interface", "State"] {
                                ui.strong(header);
                            }
                            ui.end_row();
                            for entry in &self.arp_entries {
                                ui.label(&entry.ip);
                                ui.monospace(&entry.mac);
                                match arp::oui_of(&entry.mac)
                                    .and_then(|oui| self.arp_vendors.get(&oui))
                                {
                                    Some(vendor) => ui.label(vendor),
                                    None if self.arp_vendor_running => ui.weak("…"),
                                    None => ui.weak("—"),
                                };
                                ui.label(&entry.iface);
                                let state_color = match entry.state.as_str() {
                                    "reachable" => crate::theme::OK,
                                    "incomplete" | "failed" => crate::theme::TEXT_MUTED,
                                    _ => crate::theme::WARN,
                                };
                                ui.colored_label(state_color, &entry.state);
                                ui.end_row();
                            }
                        },
                    );
                    ui.add_space(8.0);
                    egui::CollapsingHeader::new("Raw output").default_open(false).show(
                        ui,
                        |ui| {
                            ui.add(
                                egui::TextEdit::multiline(&mut self.arp_raw.as_str())
                                    .font(egui::TextStyle::Monospace)
                                    .desired_width(f32::INFINITY),
                            );
                        },
                    );
                },
            );
        });
    }

    // ------------------------------------------------------- Network config

    fn ui_netconfig(&mut self, ctx: &egui::Context) {
        if self.net_report.is_none()
            || (self.net_auto && self.net_last_refresh.elapsed() >= Duration::from_secs(3))
        {
            self.net_report = Some(netconfig::gather());
            self.net_last_refresh = Instant::now();
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                ui.heading("Network configuration");
                if ui.button("🔄 Refresh").clicked() {
                    self.net_report = Some(netconfig::gather());
                    self.net_message = None;
                    self.net_last_refresh = Instant::now();
                }
                if ui.checkbox(&mut self.net_auto, "Auto 3s").changed() {
                    self.net_last_refresh = Instant::now();
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
                ui.separator();
                self.log_action_buttons(ui, "netconfig", true);
            });
            self.logs_message_ui(ui);
            if let Some(msg) = &self.net_message {
                ui.label(msg.clone());
            }
            ui.add_space(8.0);

            let Some(report) = &self.net_report else { return };
            egui::ScrollArea::vertical().id_salt("net_scroll").auto_shrink([false, false]).show(
                ui,
                |ui| {
                    ui.heading("Overview");
                    ui.add_space(4.0);
                    egui::Grid::new("net_summary")
                        .num_columns(2)
                        .spacing(egui::vec2(18.0, 6.0))
                        .show(ui, |ui| {
                            let key = |ui: &mut egui::Ui, k: &str| {
                                ui.colored_label(crate::theme::TEXT_MUTED, k);
                            };
                            key(ui, "Hostname");
                            ui.strong(&report.hostname);
                            ui.end_row();
                            key(ui, "Domain");
                            ui.label(report.domain.as_deref().unwrap_or("(none)"));
                            ui.end_row();
                            key(ui, "DNS servers");
                            if report.dns_servers.is_empty() {
                                ui.weak("(none detected)");
                            } else {
                                ui.monospace(report.dns_servers.join(", "));
                            }
                            ui.end_row();
                            key(ui, "Generated");
                            ui.weak(&report.generated_at);
                            ui.end_row();
                        });
                    ui.add_space(12.0);

                    let draw_iface = |ui: &mut egui::Ui, itf: &netconfig::IfaceInfo| {
                        let dot = if itf.is_up {
                            crate::theme::OK
                        } else {
                            crate::theme::DANGER
                        };
                        let name_color = if itf.is_default {
                            crate::theme::ORANGE
                        } else if !itf.is_up {
                            crate::theme::TEXT_MUTED
                        } else {
                            crate::theme::TEXT
                        };
                        let id = ui.make_persistent_id(format!("itf_{}", itf.name));
                        egui::collapsing_header::CollapsingState::load_with_default_open(
                            ui.ctx(),
                            id,
                            itf.is_up,
                        )
                        .show_header(ui, |ui| {
                            let (rect, _) =
                                ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::hover());
                            ui.painter().circle_filled(rect.center(), 4.5, dot);
                            let mut title = itf.name.clone();
                            if let Some(f) =
                                itf.friendly_name.as_ref().filter(|f| *f != &itf.name)
                            {
                                title.push_str(&format!("  ({f})"));
                            }
                            ui.label(egui::RichText::new(title).color(name_color).size(15.0));
                            if itf.is_default {
                                ui.colored_label(crate::theme::ORANGE, "default route");
                            }
                        })
                        .body(|ui| {
                            ui.weak(&itf.if_type);
                            ui.add_space(2.0);
                            egui::Grid::new(format!("itf_grid_{}", itf.name))
                                .num_columns(2)
                                .spacing(egui::vec2(18.0, 5.0))
                                .show(ui, |ui| {
                                    let key = |ui: &mut egui::Ui, k: &str| {
                                        ui.colored_label(crate::theme::TEXT_MUTED, k);
                                    };
                                    if let Some(mac) = &itf.mac {
                                        key(ui, "MAC");
                                        ui.monospace(mac);
                                        ui.end_row();
                                    }
                                    for ip in &itf.ipv4 {
                                        key(ui, "IPv4");
                                        ui.monospace(ip);
                                        ui.end_row();
                                    }
                                    for ip in &itf.ipv6 {
                                        key(ui, "IPv6");
                                        ui.monospace(ip);
                                        ui.end_row();
                                    }
                                    if let Some(gw) = &itf.gateway {
                                        key(ui, "Gateway");
                                        ui.monospace(gw);
                                        ui.end_row();
                                    }
                                    if !itf.dns.is_empty() {
                                        key(ui, "DNS");
                                        ui.monospace(itf.dns.join(", "));
                                        ui.end_row();
                                    }
                                });
                        });
                    };

                    let up: Vec<&netconfig::IfaceInfo> =
                        report.interfaces.iter().filter(|i| i.is_up).collect();
                    let down: Vec<&netconfig::IfaceInfo> =
                        report.interfaces.iter().filter(|i| !i.is_up).collect();

                    ui.heading(format!("Active interfaces ({})", up.len()));
                    ui.add_space(4.0);
                    for itf in &up {
                        draw_iface(ui, itf);
                    }
                    if up.is_empty() {
                        ui.weak("(none up)");
                    }

                    if !down.is_empty() {
                        ui.add_space(12.0);
                        ui.heading(
                            egui::RichText::new(format!("Inactive interfaces ({})", down.len()))
                                .color(crate::theme::TEXT_MUTED),
                        );
                        ui.add_space(4.0);
                        for itf in &down {
                            draw_iface(ui, itf);
                        }
                    }

                    ui.add_space(12.0);
                    ui.heading("Routing table");
                    ui.add_space(4.0);
                    if report.routes.is_empty() {
                        ui.add(
                            egui::TextEdit::multiline(&mut report.routes_raw.as_str())
                                .font(egui::TextStyle::Monospace)
                                .desired_width(f32::INFINITY),
                        );
                    } else {
                        let routes_grid =
                            |ui: &mut egui::Ui, id: &str, rows: &[&netconfig::RouteEntry]| {
                                egui::ScrollArea::horizontal().id_salt(id).show(ui, |ui| {
                                    egui::Grid::new(format!("{id}_grid"))
                                        .striped(true)
                                        .spacing(egui::vec2(16.0, 5.0))
                                        .show(ui, |ui| {
                                            for h in
                                                ["Destination", "Gateway", "Interface", "Info"]
                                            {
                                                ui.strong(h);
                                            }
                                            ui.end_row();
                                            for r in rows {
                                                ui.monospace(&r.destination);
                                                ui.monospace(&r.gateway);
                                                ui.label(&r.interface);
                                                ui.weak(&r.info);
                                                ui.end_row();
                                            }
                                        });
                                });
                            };
                        let v4: Vec<&netconfig::RouteEntry> =
                            report.routes.iter().filter(|r| !r.is_ipv6).collect();
                        let v6: Vec<&netconfig::RouteEntry> =
                            report.routes.iter().filter(|r| r.is_ipv6).collect();
                        if !v4.is_empty() {
                            ui.label(egui::RichText::new("IPv4").strong());
                            routes_grid(ui, "routes_v4", &v4);
                        }
                        if !v6.is_empty() {
                            ui.add_space(8.0);
                            ui.label(egui::RichText::new("IPv6").strong());
                            routes_grid(ui, "routes_v6", &v6);
                        }
                        ui.add_space(4.0);
                        egui::CollapsingHeader::new("Raw output").default_open(false).show(
                            ui,
                            |ui| {
                                ui.add(
                                    egui::TextEdit::multiline(&mut report.routes_raw.as_str())
                                        .font(egui::TextStyle::Monospace)
                                        .desired_width(f32::INFINITY),
                                );
                            },
                        );
                    }

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
                "Subfolders are created automatically inside the log folder. \
                 Use the buttons below to jump straight to one.",
            );
            ui.add_space(10.0);
            ui.label("Open a log subfolder:");
            ui.horizontal_wrapped(|ui| {
                for (sub, label) in [
                    ("ping", "📡 Ping"),
                    ("traceroute", "🛣 Traceroute"),
                    ("dns", "🌐 DNS"),
                    ("arp", "📇 ARP"),
                    ("netconfig", "🖧 Network config"),
                ] {
                    if ui.button(label).clicked() {
                        match util::ensure_log_dir(&self.config.log_dir, sub) {
                            Ok(path) => util::open_in_file_manager(&path),
                            Err(e) => self.settings_message = Some(format!("cannot open {sub}/: {e}")),
                        }
                    }
                }
            });

            ui.add_space(16.0);
            ui.separator();
            ui.add_space(8.0);
            ui.weak(format!(
                "Settings are saved automatically and persist across restarts.\nConfig file: {}",
                settings::config_path().display()
            ));
            if let Some(msg) = &self.settings_message {
                ui.add_space(6.0);
                ui.colored_label(crate::theme::DANGER, msg);
            }
        });
    }
}

use crate::util;

impl RustyToolsApp {
    /// Logo + one nav row per page. `compact` shows icons only.
    fn nav_contents(&mut self, ui: &mut egui::Ui, compact: bool) {
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if let Some(tex) = &self.logo_tex {
                ui.add(egui::Image::new(egui::load::SizedTexture::new(
                    tex.id(),
                    egui::vec2(30.0, 30.0),
                )));
            }
            if !compact {
                ui.label(
                    egui::RichText::new("RustyTools")
                        .family(egui::FontFamily::Name(crate::theme::ZILLA_BOLD.into()))
                        .size(19.0)
                        .color(crate::theme::TEXT),
                );
            }
        });
        ui.add_space(10.0);
        ui.separator();
        ui.add_space(6.0);

        let items = [
            (Tab::Ping, "📡", "Ping"),
            (Tab::Traceroute, "\u{1F5FA}", "Traceroute"),
            (Tab::Dns, "🌐", "DNS"),
            (Tab::Arp, "📇", "ARP"),
            (Tab::NetConfig, "🖧", "Network config"),
            (Tab::Settings, "⚙", "Settings"),
        ];
        for (tab, icon, label) in items {
            let text = if compact { icon.to_string() } else { format!("{icon}  {label}") };
            let resp = ui.add_sized(
                [ui.available_width(), 34.0],
                egui::SelectableLabel::new(self.tab == tab, text),
            );
            if compact {
                resp.clone().on_hover_text(label);
            }
            if resp.clicked() {
                self.tab = tab;
            }
        }
    }

    /// A persistent icon-only rail that reserves layout space; on hover an
    /// expanded version with labels floats OVER the content (no reflow).
    fn nav_rail(&mut self, ctx: &egui::Context) {
        let panel = egui::SidePanel::left("nav_rail")
            .exact_width(58.0)
            .resizable(false)
            .frame(
                egui::Frame::default()
                    .fill(crate::theme::BG_SURFACE)
                    .inner_margin(egui::Margin::same(8)),
            )
            .show(ctx, |ui| self.nav_contents(ui, true));
        let rect = panel.response.rect;
        let mut hovered = panel.response.contains_pointer();

        if self.nav_hovered {
            let area = egui::Area::new(egui::Id::new("nav_overlay"))
                .order(egui::Order::Foreground)
                .fixed_pos(rect.left_top())
                .show(ctx, |ui| {
                    egui::Frame::default()
                        .fill(crate::theme::BG_SURFACE)
                        .stroke(egui::Stroke::new(1.0, crate::theme::BORDER))
                        .inner_margin(egui::Margin::same(8))
                        .show(ui, |ui| {
                            ui.set_width(166.0);
                            ui.set_min_height(rect.height() - 16.0);
                            self.nav_contents(ui, false);
                        });
                });
            hovered |= area.response.contains_pointer();
        }

        if hovered != self.nav_hovered {
            self.nav_hovered = hovered;
            ctx.request_repaint();
        }
    }
}

impl eframe::App for RustyToolsApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_events();

        self.nav_rail(ctx);

        match self.tab {
            Tab::Ping => self.ui_ping(ctx),
            Tab::Traceroute => self.ui_trace(ctx),
            Tab::Dns => self.ui_dns(ctx),
            Tab::Arp => self.ui_arp(ctx),
            Tab::NetConfig => self.ui_netconfig(ctx),
            Tab::Settings => self.ui_settings(ctx),
        }

        if self.config_dirty {
            self.settings_message = self.config.save().err();
            self.config_dirty = false;
        }

        if self.ping_session.is_some()
            || self.trace_session.is_some()
            || self.dns_running
            || self.arp_vendor_running
        {
            ctx.request_repaint_after(Duration::from_millis(200));
        } else if self.arp_auto || self.net_auto {
            ctx.request_repaint_after(Duration::from_millis(750));
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

/// A multiline text box with a manually-drawn dim placeholder (egui's own
/// hint color is too bright — see theme::HINT).
fn multiline_input(
    ui: &mut egui::Ui,
    text: &mut String,
    enabled: bool,
    rows: usize,
    hint: &str,
) -> egui::Response {
    let resp = ui.add_enabled(
        enabled,
        egui::TextEdit::multiline(text).desired_rows(rows).desired_width(f32::INFINITY),
    );
    if text.is_empty() {
        ui.painter_at(resp.rect).text(
            resp.rect.left_top() + egui::vec2(6.0, 4.0),
            egui::Align2::LEFT_TOP,
            hint,
            egui::FontId::proportional(14.0),
            crate::theme::HINT,
        );
    }
    resp
}

fn loss_color(loss: f64) -> egui::Color32 {
    if loss > 5.0 {
        crate::theme::DANGER
    } else if loss > 0.0 {
        crate::theme::WARN
    } else {
        crate::theme::OK
    }
}

fn status_label(ui: &mut egui::Ui, status: &str) {
    if status.starts_with("ERROR") {
        ui.colored_label(crate::theme::DANGER, status);
    } else if status == "TIMEOUT" {
        ui.colored_label(crate::theme::WARN, status);
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
