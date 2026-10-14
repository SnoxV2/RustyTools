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
use crate::packet::{self, PacketParams, PacketSession, Proto};
use crate::ping::{self, PingSession, PingStatus};
use crate::settings::{self, AppConfig};
use crate::traceroute::{self, HopInfo, ProbeStatus, TraceParams, TraceSession};
use crate::util;

mod arp_tab;
mod dns_tab;
mod netconfig_tab;
mod packet_tab;
mod ping_tab;
mod settings_tab;
mod trace_tab;

pub enum Event {
    Ping(ping::PingEvent),
    Trace(traceroute::TraceEvent),
    Dns(DnsEvent),
    Arp(ArpEvent),
    /// One result line of the packet sender.
    Packet(String),
    /// A freshly gathered network configuration report.
    NetConfig(NetReport),
}

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Ping,
    Traceroute,
    Dns,
    Arp,
    Packet,
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
            // On Windows `name` is the adapter GUID; the friendly name is "Wi-Fi".
            label: format!("{} ({display})", itf.friendly_name.as_deref().unwrap_or(&itf.name)),
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
                    .margin(crate::theme::TEXT_EDIT_MARGIN)
                    .desired_width(160.0)
                    .hint_text(egui::RichText::new("192.168.1.10").color(crate::theme::HINT)),
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

#[derive(Default, Clone)]
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
    arp_vendor_online: bool,
    arp_filter: String,
    arp_only_reachable: bool,
    arp_message: Option<String>,
    arp_auto: bool,
    arp_last_refresh: Instant,
    arp_subnets: Vec<arp::Subnet>,
    arp_subnets_loaded: bool,
    arp_subnet_sel: usize,
    arp_scanning: bool,
    arp_scan: Option<(usize, usize, usize)>,

    // Packet sender
    packet_target: String,
    packet_port: u16,
    packet_proto: Proto,
    packet_payload: String,
    packet_count: u32,
    packet_interval_s: f32,
    packet_session: Option<PacketSession>,
    packet_log: VecDeque<String>,
    packet_error: Option<String>,

    // Network configuration
    net_report: Option<NetReport>,
    net_message: Option<String>,
    net_auto: bool,
    net_last_refresh: Instant,
    net_loading: bool,

    // Log deletion (two-step confirmation), shared by all tabs
    delete_confirm: Option<&'static str>,
    logs_message: Option<String>,

    // Advanced source selection (per feature) + detected interfaces
    ifaces: Vec<IfaceChoice>,
    ping_source: SourceUi,
    trace_source: SourceUi,
    dns_source: SourceUi,
    packet_source: SourceUi,

    // Logo texture, built once from the rendered RGBA buffer.
    logo_tex: Option<egui::TextureHandle>,
    // Settings "delete everything" two-step confirmation.
    delete_all_confirm: bool,
    // Settings "quit and remove all traces" two-step confirmation.
    wipe_confirm: bool,
}

impl RustyToolsApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        crate::theme::apply(&cc.egui_ctx);
        crate::arp::warm_oui_db();
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
            arp_vendor_online: false,
            arp_filter: String::new(),
            arp_only_reachable: false,
            arp_message: None,
            arp_auto: false,
            arp_last_refresh: Instant::now(),
            arp_subnets: Vec::new(),
            arp_subnets_loaded: false,
            arp_subnet_sel: 0,
            arp_scanning: false,
            arp_scan: None,
            packet_target: String::new(),
            packet_port: 80,
            packet_proto: Proto::Udp,
            packet_payload: String::new(),
            packet_count: 1,
            packet_interval_s: 1.0,
            packet_session: None,
            packet_log: VecDeque::new(),
            packet_error: None,
            net_report: None,
            net_message: None,
            net_auto: false,
            net_last_refresh: Instant::now(),
            net_loading: false,
            delete_confirm: None,
            logs_message: None,
            ifaces: gather_ifaces(),
            ping_source: SourceUi::default(),
            trace_source: SourceUi::default(),
            dns_source: SourceUi::default(),
            packet_source: SourceUi::default(),
            logo_tex,
            delete_all_confirm: false,
            wipe_confirm: false,
        }
    }

    /// "Advanced" section shared by the feature tabs (source selection).
    fn advanced_source_ui(&mut self, ui: &mut egui::Ui, id: &str, which: Tab, enabled: bool) {
        egui::CollapsingHeader::new("Advanced")
            .id_salt(format!("{id}_adv"))
            // Choosing the source is the point of the packet page.
            .default_open(which == Tab::Packet)
            .show(ui, |ui| {
            ui.add_enabled_ui(enabled, |ui| {
                let src = match which {
                    Tab::Ping => &mut self.ping_source,
                    Tab::Traceroute => &mut self.trace_source,
                    Tab::Packet => &mut self.packet_source,
                    _ => &mut self.dns_source,
                };
                source_selector(ui, id, src, &self.ifaces);
                if which == Tab::Dns {
                    ui.weak("Applies to custom DNS servers only.");
                }
                if ui.small_button("🔄 Refresh interface list").clicked() {
                    self.ifaces = gather_ifaces();
                    for src in [
                        &mut self.ping_source,
                        &mut self.trace_source,
                        &mut self.dns_source,
                        &mut self.packet_source,
                    ] {
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
                Event::Packet(line) => push_capped(&mut self.packet_log, line, 2000),
                Event::NetConfig(report) => {
                    self.net_report = Some(report);
                    self.net_loading = false;
                    self.net_last_refresh = Instant::now();
                }
                Event::Arp(ArpEvent::Vendor { oui, vendor }) => {
                    self.arp_vendors.insert(oui, vendor);
                }
                Event::Arp(ArpEvent::Error(msg)) => self.arp_message = Some(msg),
                Event::Arp(ArpEvent::Done) => self.arp_vendor_running = false,
                Event::Arp(ArpEvent::ScanProgress { done, total, alive }) => {
                    self.arp_scan = Some((done, total, alive));
                }
                Event::Arp(ArpEvent::ScanDone { alive }) => {
                    self.arp_scanning = false;
                    self.arp_scan = None;
                    let (entries, raw) = arp::gather();
                    self.arp_entries = entries;
                    self.arp_raw = raw;
                    self.arp_last_refresh = Instant::now();
                    self.arp_message = Some(format!(
                        "Scan complete: {alive} host(s) responded. ARP table refreshed."
                    ));
                }
            }
        }
    }

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
}

impl RustyToolsApp {
    /// Logo + one nav row per page.
    fn nav_contents(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if let Some(tex) = &self.logo_tex {
                ui.add(egui::Image::new(egui::load::SizedTexture::new(
                    tex.id(),
                    egui::vec2(30.0, 30.0),
                )));
            }
            ui.label(
                egui::RichText::new("RustyTools")
                    .family(egui::FontFamily::Name(crate::theme::ZILLA_BOLD.into()))
                    .size(19.0)
                    .color(crate::theme::TEXT),
            );
        });
        ui.add_space(10.0);
        ui.separator();
        ui.add_space(6.0);

        let items = [
            (Tab::Ping, "📡", "Ping"),
            (Tab::Traceroute, "\u{1F5FA}", "Traceroute"),
            (Tab::Dns, "🌐", "DNS"),
            (Tab::Arp, "📇", "ARP"),
            (Tab::Packet, "📨", "Packet sender"),
            (Tab::NetConfig, "🖧", "Network config"),
            (Tab::Settings, "⚙", "Settings"),
        ];
        for (tab, icon, label) in items {
            let resp = ui.add_sized(
                [ui.available_width(), 34.0],
                egui::SelectableLabel::new(self.tab == tab, format!("{icon}  {label}")),
            );
            if resp.clicked() {
                self.tab = tab;
            }
        }
    }

    /// Fixed navigation menu, always expanded (icons + labels).
    fn nav_rail(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("nav_rail")
            .exact_width(182.0)
            .resizable(false)
            .frame(
                egui::Frame::default()
                    .fill(crate::theme::BG_SURFACE)
                    .inner_margin(egui::Margin::same(8)),
            )
            .show(ctx, |ui| self.nav_contents(ui));
    }
}

impl eframe::App for RustyToolsApp {
    /// Don't persist egui memory across runs (panel sizes, etc.) so the layout
    /// always starts from our defined defaults — our own settings are saved
    /// separately in settings.json.
    fn persist_egui_memory(&self) -> bool {
        false
    }

    /// Clear to the window background so any uncovered sliver between panels
    /// blends in instead of showing as a black bar.
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        crate::theme::BG_WINDOW.to_normalized_gamma_f32()
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_events();

        self.nav_rail(ctx);

        match self.tab {
            Tab::Ping => self.ui_ping(ctx),
            Tab::Traceroute => self.ui_trace(ctx),
            Tab::Dns => self.ui_dns(ctx),
            Tab::Arp => self.ui_arp(ctx),
            Tab::Packet => self.ui_packet(ctx),
            Tab::NetConfig => self.ui_netconfig(ctx),
            Tab::Settings => self.ui_settings(ctx),
        }

        if self.config_dirty {
            self.settings_message = self.config.save().err();
            self.config_dirty = false;
        }

        if self.ping_session.as_ref().is_some_and(|s| s.is_running())
            || self.trace_session.as_ref().is_some_and(|s| s.is_running())
            || self.dns_running
            || self.arp_vendor_running
            || self.arp_scanning
            || self.packet_session.as_ref().is_some_and(|s| s.is_running())
            || self.net_loading
        {
            ctx.request_repaint_after(Duration::from_millis(200));
        } else if self.arp_auto || self.net_auto {
            ctx.request_repaint_after(Duration::from_millis(750));
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

/// A multiline text box with a dim placeholder. egui places the hint exactly
/// where typed text goes; only its color is ours (the default one is too
/// bright — see theme::HINT).
fn multiline_input(
    ui: &mut egui::Ui,
    text: &mut String,
    enabled: bool,
    rows: usize,
    hint: &str,
) -> egui::Response {
    ui.add_enabled(
        enabled,
        egui::TextEdit::multiline(text)
            .margin(crate::theme::TEXT_EDIT_MARGIN)
            .desired_rows(rows)
            .desired_width(f32::INFINITY)
            .hint_text(egui::RichText::new(hint).color(crate::theme::HINT)),
    )
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
