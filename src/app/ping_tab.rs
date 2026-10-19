//! Ping page of the application.

use super::*;

impl RustyToolsApp {
    pub(super) fn on_ping_event(&mut self, ev: ping::PingEvent) {
        // Probe send time, not the time this frame happened to read the event.
        let x = self
            .ping_started
            .map(|s| ev.at.saturating_duration_since(s).as_secs_f64())
            .unwrap_or(0.0);
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
            PingStatus::TooBig => {
                state.stats.record_too_big();
                state.samples.push_back((x, None));
                format!(
                    "[{}] {:<24} seq={:<5} TOO BIG (larger than the path MTU, fragmentation needed)",
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
            ping::EchoOptions {
                size: self.config.ping_size,
                dont_fragment: self.config.ping_dont_fragment,
            },
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

    pub(super) fn ui_ping(&mut self, ctx: &egui::Context) {
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
                ui.label("Packet size (bytes):");
                if ui
                    .add_enabled(
                        !running,
                        // 65500: the largest ICMP payload Windows accepts.
                        egui::DragValue::new(&mut self.config.ping_size).range(0..=65500),
                    )
                    .on_hover_text("ICMP payload size, like ping -l (Windows) or ping -s (Unix)")
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
                        &mut self.config.ping_dont_fragment,
                        "Don't fragment (path MTU test)",
                    ),
                )
                .changed()
            {
                self.config_dirty = true;
            }
            if self.config.ping_dont_fragment {
                // IPv4 header (20) + ICMP header (8) on top of the payload.
                ui.weak(format!(
                    "IPv4 packet: {} bytes. A 1500-byte MTU allows a payload of 1472.",
                    u32::from(self.config.ping_size) + 28
                ));
            }
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
            if ui.button("✖ Clear results").clicked() {
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
                    for (i, segments) in series {
                        let color = PALETTE[i % PALETTE.len()];
                        let name = &self.ping_targets_state[i].target;
                        for segment in segments {
                            plot_ui.line(
                                Line::new(PlotPoints::from(segment))
                                    .color(color)
                                    .name(name),
                            );
                        }
                    }
                    if !losses.is_empty() {
                        plot_ui.points(
                            Points::new(PlotPoints::from(losses))
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
                // show_rows only lays out the visible lines (the log holds 2000).
                let row_height = ui.text_style_height(&egui::TextStyle::Monospace);
                egui::ScrollArea::vertical()
                    .id_salt("ping_log_scroll")
                    .stick_to_bottom(true)
                    .max_height(180.0)
                    .auto_shrink([false, true])
                    .show_rows(ui, row_height, self.ping_log.len(), |ui, rows| {
                        for line in self.ping_log.range(rows) {
                            ui.monospace(line);
                        }
                    });
            });
            ui.add_space(16.0);
          });
        });
    }
}
