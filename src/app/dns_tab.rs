//! DNS page of the application.

use super::*;

impl RustyToolsApp {
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

    pub(super) fn ui_dns(&mut self, ctx: &egui::Context) {
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
}
