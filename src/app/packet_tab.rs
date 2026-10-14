//! Packet sender page of the application.

use super::*;

impl RustyToolsApp {
    fn start_packet(&mut self) {
        self.packet_error = None;
        let source = match source_config(&self.packet_source, &self.ifaces) {
            Ok(s) => s,
            Err(e) => {
                self.packet_error = Some(e);
                return;
            }
        };
        let params = PacketParams {
            target: self.packet_target.clone(),
            port: self.packet_port,
            proto: self.packet_proto,
            payload: self.packet_payload.clone().into_bytes(),
            count: self.packet_count.max(1),
            interval: Duration::from_secs_f32(self.packet_interval_s.max(0.1)),
            source,
        };
        match packet::start(params, &self.config.log_dir, self.tx.clone()) {
            Ok(session) => self.packet_session = Some(session),
            Err(e) => self.packet_error = Some(e),
        }
    }

    pub(super) fn ui_packet(&mut self, ctx: &egui::Context) {
        let running = self.packet_session.as_ref().is_some_and(|s| s.is_running());

        egui::SidePanel::left("packet_side")
            .resizable(true)
            .default_width(290.0)
            .width_range(190.0..=440.0)
            .show(ctx, |ui| {
            ui.add_space(6.0);
            ui.heading("Packet sender");
            ui.add_space(6.0);
            ui.add_enabled_ui(!running, |ui| {
                ui.label("Destination (IP or FQDN):");
                ui.add(
                    egui::TextEdit::singleline(&mut self.packet_target)
                        .margin(crate::theme::TEXT_EDIT_MARGIN)
                        .desired_width(f32::INFINITY)
                        .hint_text(egui::RichText::new("192.168.1.10").color(crate::theme::HINT)),
                );
                ui.add_space(6.0);
                egui::Grid::new("packet_params").num_columns(2).show(ui, |ui| {
                    ui.label("Protocol:");
                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut self.packet_proto, Proto::Udp, "UDP");
                        ui.selectable_value(&mut self.packet_proto, Proto::Tcp, "TCP");
                    });
                    ui.end_row();
                    ui.label("Port:");
                    ui.add(egui::DragValue::new(&mut self.packet_port).range(1..=65535));
                    ui.end_row();
                    ui.label("Count:");
                    ui.add(egui::DragValue::new(&mut self.packet_count).range(1..=1000));
                    ui.end_row();
                    ui.label("Interval (s):");
                    ui.add(
                        egui::DragValue::new(&mut self.packet_interval_s)
                            .range(0.1..=3600.0)
                            .speed(0.1)
                            .fixed_decimals(1),
                    );
                    ui.end_row();
                });
                ui.add_space(6.0);
                ui.label("Payload (text, optional):");
            });
            multiline_input(ui, &mut self.packet_payload, !running, 3, "hello");
            if self.packet_proto == Proto::Tcp {
                ui.weak("Empty payload: only tests that the port accepts a connection.");
            }
            self.advanced_source_ui(ui, "packet_source", Tab::Packet, !running);
            ui.add_space(10.0);

            if running {
                if ui
                    .add_sized([ui.available_width(), 32.0], egui::Button::new("⏹ Stop"))
                    .clicked()
                {
                    if let Some(session) = &self.packet_session {
                        session.stop();
                    }
                }
            } else if ui
                .add_sized([ui.available_width(), 32.0], egui::Button::new("▶ Send"))
                .clicked()
            {
                self.start_packet();
            }

            if let Some(err) = &self.packet_error {
                ui.add_space(6.0);
                ui.colored_label(crate::theme::DANGER, err);
            }

            ui.add_space(10.0);
            if ui.button("✖ Clear results").clicked() {
                self.packet_log.clear();
            }
            self.delete_logs_ui(ui, "packet", !running);

            if let Some(session) = &self.packet_session {
                ui.add_space(10.0);
                ui.label("Log file:");
                ui.monospace(session.log_file.display().to_string());
            }
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(4.0);
            if self.packet_log.is_empty() {
                ui.label(
                    "Send UDP datagrams or open TCP connections to a destination, from the \
                     source interface or IP of your choice, and see what comes back.",
                );
                return;
            }
            let row_height = ui.text_style_height(&egui::TextStyle::Monospace);
            egui::ScrollArea::both()
                .id_salt("packet_scroll")
                .stick_to_bottom(true)
                .auto_shrink([false, false])
                .show_rows(ui, row_height, self.packet_log.len(), |ui, rows| {
                    for line in self.packet_log.range(rows) {
                        if line.contains("ERROR:") {
                            ui.colored_label(
                                crate::theme::DANGER,
                                egui::RichText::new(line).monospace(),
                            );
                        } else {
                            ui.monospace(line);
                        }
                    }
                });
        });
    }
}
