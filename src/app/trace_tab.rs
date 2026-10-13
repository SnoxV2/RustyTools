//! Traceroute page of the application.

use super::*;

impl RustyToolsApp {
    pub(super) fn on_trace_event(&mut self, ev: traceroute::TraceEvent) {
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
                            .map(|r| (r.stats.clone(), r.prev_rtt));
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

    pub(super) fn ui_trace(&mut self, ctx: &egui::Context) {
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
}
