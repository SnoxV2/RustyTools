//! ARP page of the application.

use super::*;

impl RustyToolsApp {
    pub(super) fn ui_arp(&mut self, ctx: &egui::Context) {
        if self.arp_auto && self.arp_last_refresh.elapsed() >= Duration::from_secs(3) {
            let (entries, raw) = arp::gather();
            self.arp_entries = entries;
            self.arp_raw = raw;
            self.arp_last_refresh = Instant::now();
        }
        if !self.arp_subnets_loaded {
            self.arp_subnets = arp::local_subnets();
            self.arp_subnets_loaded = true;
        }
        egui::SidePanel::left("arp_side")
            .resizable(false)
            .exact_width(280.0)
            .show(ctx, |ui| {
                ui.set_max_width(256.0);
                ui.add_space(6.0);
                ui.heading("ARP");
                ui.add_space(8.0);
                if ui
                    .add_sized([ui.available_width(), 30.0], egui::Button::new("🔄 Refresh"))
                    .clicked()
                {
                    let (entries, raw) = arp::gather();
                    self.arp_entries = entries;
                    self.arp_raw = raw;
                    self.arp_message = None;
                    self.arp_last_refresh = Instant::now();
                    self.arp_subnets = arp::local_subnets();
                }
                if ui.checkbox(&mut self.arp_auto, "Auto-refresh (3 s)").changed() {
                    self.arp_last_refresh = Instant::now();
                }

                ui.add_space(10.0);
                ui.label("Subnet ICMP scan:");
                if self.arp_subnets.is_empty() {
                    ui.weak("No scannable local subnet detected.");
                } else {
                    let sel = self.arp_subnet_sel.min(self.arp_subnets.len() - 1);
                    self.arp_subnet_sel = sel;
                    let options: Vec<(usize, String)> = self
                        .arp_subnets
                        .iter()
                        .enumerate()
                        .map(|(i, s)| (i, s.label.clone()))
                        .collect();
                    egui::ComboBox::from_id_salt("arp_subnet")
                        .width(ui.available_width())
                        // A long label must not widen this fixed-width panel.
                        .truncate()
                        .selected_text(self.arp_subnets[sel].label.clone())
                        .show_ui(ui, |ui| {
                            for (i, label) in &options {
                                ui.selectable_value(&mut self.arp_subnet_sel, *i, label);
                            }
                        });
                    if self.arp_scanning {
                        let (done, total, alive) = self.arp_scan.unwrap_or((0, 0, 0));
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label(format!("Scanning {done}/{total} — {alive} up"));
                        });
                    } else if ui
                        .add_sized(
                            [ui.available_width(), 30.0],
                            egui::Button::new("📡 Scan subnet (ICMP)"),
                        )
                        .on_hover_text(
                            "Ping every host (1 probe, 1 s timeout) to reveal devices and \
                             populate the ARP table",
                        )
                        .clicked()
                    {
                        let hosts = self.arp_subnets[sel].hosts.clone();
                        self.arp_scan = Some((0, hosts.len(), 0));
                        self.arp_scanning = true;
                        arp::scan_subnet(hosts, self.tx.clone());
                    }
                }

                ui.add_space(10.0);
                ui.label("Search (IP or MAC):");
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.arp_filter)
                            .margin(crate::theme::TEXT_EDIT_MARGIN)
                            // Room for the clear button; egui adds the margin
                            // outside the desired width.
                            .desired_width(
                                ui.available_width() - 40.0 - crate::theme::TEXT_EDIT_MARGIN.sum().x,
                            )
                            .hint_text(
                                egui::RichText::new("e.g. 192.168.1 or a4:2b")
                                    .color(crate::theme::HINT),
                            ),
                    );
                    if ui.button("✖").on_hover_text("Clear search").clicked() {
                        self.arp_filter.clear();
                    }
                });
                ui.checkbox(&mut self.arp_only_reachable, "Reachable only (hide incomplete)");

                ui.add_space(10.0);
                ui.label("Vendor source:");
                egui::ComboBox::from_id_salt("arp_vendor_source")
                    .width(ui.available_width())
                    .truncate()
                    .selected_text(if self.arp_vendor_online {
                        "Online (macvendors.com)"
                    } else {
                        "Local OUI database"
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.arp_vendor_online, false, "Local OUI database");
                        ui.selectable_value(
                            &mut self.arp_vendor_online,
                            true,
                            "Online (macvendors.com)",
                        );
                    });
                let resolvable = self.arp_entries.iter().any(|e| arp::oui_of(&e.mac).is_some());
                let resolve_hint = if self.arp_vendor_online {
                    "Query macvendors.com for each unique OUI (~1/s, OUI only)"
                } else {
                    "Identify manufacturers from the embedded IEEE OUI database"
                };
                if ui
                    .add_enabled(
                        !self.arp_vendor_running && resolvable,
                        egui::Button::new("🏷 Resolve vendors")
                            .min_size(egui::vec2(ui.available_width(), 30.0)),
                    )
                    .on_hover_text(resolve_hint)
                    .clicked()
                {
                    self.arp_vendor_running = true;
                    // A new run replaces the previous results (e.g. after
                    // switching between the local and online source).
                    self.arp_vendors.clear();
                    let macs: Vec<String> =
                        self.arp_entries.iter().map(|e| e.mac.clone()).collect();
                    if self.arp_vendor_online {
                        arp::lookup_vendors_online(macs, self.tx.clone());
                    } else {
                        arp::lookup_vendors(macs, self.tx.clone());
                    }
                }
                if self.arp_vendor_running {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("resolving…");
                    });
                }

                ui.add_space(10.0);
                if ui
                    .add_enabled(
                        !self.arp_entries.is_empty(),
                        egui::Button::new("💾 Export")
                            .min_size(egui::vec2(ui.available_width(), 28.0)),
                    )
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

                ui.add_space(10.0);
                self.delete_logs_ui(ui, "arp", true);
                if let Some(msg) = &self.arp_message {
                    ui.add_space(4.0);
                    ui.label(msg.clone());
                }
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(4.0);
            let total = self.arp_entries.len();
            let filter = self.arp_filter.trim().to_lowercase();
            let entries: Vec<&ArpEntry> = self
                .arp_entries
                .iter()
                .filter(|e| !self.arp_only_reachable || arp::is_reachable(e))
                .filter(|e| {
                    filter.is_empty()
                        || e.ip.to_lowercase().contains(&filter)
                        || e.mac.to_lowercase().contains(&filter)
                })
                .collect();
            if filter.is_empty() {
                ui.heading(format!("Devices ({total})"));
            } else {
                ui.heading(format!("Devices ({} / {total})", entries.len()));
            }
            ui.add_space(4.0);
            if total == 0 {
                ui.label(
                    "Press Refresh to list the devices present in the ARP/neighbor table \
                     of this host, then resolve MAC vendors on demand.",
                );
                return;
            }
            if entries.is_empty() {
                ui.weak("No device matches the search.");
                return;
            }

            // Single-row resolve is recorded here and dispatched after the
            // table (which holds an immutable borrow of self.arp_entries).
            let mut resolve_one: Option<String> = None;
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
                            for entry in &entries {
                                ui.label(&entry.ip);
                                ui.monospace(&entry.mac);
                                match arp::oui_of(&entry.mac)
                                    .and_then(|oui| self.arp_vendors.get(&oui))
                                {
                                    Some(vendor) => {
                                        ui.label(vendor);
                                    }
                                    None if self.arp_vendor_running => {
                                        ui.weak("…");
                                    }
                                    None => {
                                        if ui
                                            .small_button("Resolve")
                                            .on_hover_text("Resolve this vendor only")
                                            .clicked()
                                        {
                                            resolve_one = Some(entry.mac.clone());
                                        }
                                    }
                                }
                                ui.label(&entry.iface);
                                let state_color = match entry.state.as_str() {
                                    "incomplete" | "failed" => crate::theme::TEXT_MUTED,
                                    // Linux neighbor states that need a recheck.
                                    "stale" | "delay" | "probe" => crate::theme::WARN,
                                    // reachable, permanent, Windows dynamic/static…
                                    _ => crate::theme::OK,
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
                                    .margin(crate::theme::TEXT_EDIT_MARGIN)
                                    .font(egui::TextStyle::Monospace)
                                    .desired_width(f32::INFINITY),
                            );
                        },
                    );
                },
            );

            drop(entries);
            if let Some(mac) = resolve_one {
                self.arp_vendor_running = true;
                if self.arp_vendor_online {
                    arp::lookup_vendors_online(vec![mac], self.tx.clone());
                } else {
                    arp::lookup_vendors(vec![mac], self.tx.clone());
                }
            }
        });
    }
}
