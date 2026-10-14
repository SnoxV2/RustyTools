//! Network config page of the application.

use super::*;

impl RustyToolsApp {
    /// Gathers the report in a background thread: the system tools take
    /// ~100 ms, which would freeze the window on every refresh.
    fn refresh_netconfig(&mut self) {
        if self.net_loading {
            return;
        }
        self.net_loading = true;
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(Event::NetConfig(netconfig::gather()));
        });
    }

    pub(super) fn ui_netconfig(&mut self, ctx: &egui::Context) {
        if self.net_report.is_none()
            || (self.net_auto && self.net_last_refresh.elapsed() >= Duration::from_secs(3))
        {
            self.refresh_netconfig();
        }

        egui::SidePanel::left("net_side")
            .resizable(false)
            .exact_width(270.0)
            .show(ctx, |ui| {
                ui.set_max_width(246.0);
                ui.add_space(6.0);
                ui.heading("Network config");
                ui.add_space(8.0);
                if ui
                    .add_sized([ui.available_width(), 30.0], egui::Button::new("🔄 Refresh"))
                    .clicked()
                {
                    self.refresh_netconfig();
                    self.net_message = None;
                }
                if ui.checkbox(&mut self.net_auto, "Auto-refresh (3 s)").changed() {
                    self.net_last_refresh = Instant::now();
                }
                ui.add_space(10.0);
                if ui
                    .add_sized(
                        [ui.available_width(), 28.0],
                        egui::Button::new("💾 Export report"),
                    )
                    .clicked()
                {
                    if let Some(report) = &self.net_report {
                        self.net_message =
                            Some(match netconfig::export(report, &self.config.log_dir) {
                                Ok(path) => format!("Report exported: {}", path.display()),
                                Err(e) => format!("Export failed: {e}"),
                            });
                    }
                }
                ui.add_space(10.0);
                self.delete_logs_ui(ui, "netconfig", true);
                if let Some(msg) = &self.net_message {
                    ui.add_space(4.0);
                    ui.label(msg.clone());
                }
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(4.0);
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
                            if report.dns_servers.is_empty() {
                                key(ui, "DNS servers");
                                ui.weak("(none detected)");
                                ui.end_row();
                            }
                            // One per row: a joined list runs off the window.
                            for (i, server) in report.dns_servers.iter().enumerate() {
                                key(ui, if i == 0 { "DNS servers" } else { "" });
                                ui.monospace(server);
                                ui.end_row();
                            }
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
                            // On Windows `name` is the adapter GUID: the readable
                            // name is the title, the GUID goes to the body.
                            let title = itf.friendly_name.as_deref().unwrap_or(&itf.name);
                            ui.label(egui::RichText::new(title).color(name_color).size(15.0));
                            if itf.is_default {
                                ui.colored_label(crate::theme::ORANGE, "default route");
                            }
                        })
                        .body(|ui| {
                            match itf.friendly_name.as_ref().filter(|f| *f != &itf.name) {
                                Some(_) => ui.weak(format!("{} · {}", itf.if_type, itf.name)),
                                None => ui.weak(&itf.if_type),
                            };
                            ui.add_space(2.0);
                            egui::Grid::new(format!("itf_grid_{}", itf.name))
                                .num_columns(2)
                                // Same label column on every interface so values line up.
                                .min_col_width(60.0)
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
                                    for server in &itf.dns {
                                        key(ui, "DNS");
                                        ui.monospace(server);
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
                                .margin(crate::theme::TEXT_EDIT_MARGIN)
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
                                        .margin(crate::theme::TEXT_EDIT_MARGIN)
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
                                        .margin(crate::theme::TEXT_EDIT_MARGIN)
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
