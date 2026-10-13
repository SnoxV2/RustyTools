//! Settings page of the application.

use super::*;

impl RustyToolsApp {
    pub(super) fn ui_settings(&mut self, ctx: &egui::Context) {
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
                    ("packet", "📨 Packet sender"),
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
            ui.label(egui::RichText::new("Danger zone").color(crate::theme::DANGER).strong());
            ui.weak("Delete every log file written by RustyTools. Folders are removed only when empty.");
            ui.add_space(4.0);
            if self.delete_all_confirm {
                ui.colored_label(
                    crate::theme::DANGER,
                    format!("Really delete all logs in {}?", self.config.log_dir),
                );
                ui.horizontal(|ui| {
                    if ui.button("Yes, delete everything").clicked() {
                        self.logs_message =
                            Some(match util::delete_log_dir(&self.config.log_dir) {
                                Ok(()) => "All logs were deleted.".to_string(),
                                Err(e) => e,
                            });
                        self.delete_all_confirm = false;
                    }
                    if ui.button("Cancel").clicked() {
                        self.delete_all_confirm = false;
                    }
                });
            } else if ui.button("🗑 Delete all logs").clicked() {
                self.delete_all_confirm = true;
                self.logs_message = None;
            }
            if !self.delete_all_confirm {
                if let Some(msg) = &self.logs_message {
                    ui.add_space(4.0);
                    ui.weak(msg.clone());
                }
            }

            ui.add_space(12.0);
            ui.weak(
                "Quit and leave nothing on this computer: deletes the log files written by                  RustyTools and its settings file. Other files are never touched.",
            );
            ui.add_space(4.0);
            // Running sessions keep their log files open, so they must end first.
            let busy = self.ping_session.as_ref().is_some_and(|s| s.is_running())
                || self.trace_session.as_ref().is_some_and(|s| s.is_running())
                || self.packet_session.as_ref().is_some_and(|s| s.is_running())
                || self.dns_running
                || self.arp_scanning
                || self.arp_vendor_running;
            if self.wipe_confirm {
                ui.colored_label(
                    crate::theme::DANGER,
                    format!(
                        "Delete all logs in {} and {}, then quit?",
                        self.config.log_dir,
                        settings::config_path().display()
                    ),
                );
                ui.horizontal(|ui| {
                    if ui.button("Yes, remove everything and quit").clicked() {
                        self.wipe_confirm = false;
                        match settings::remove_traces(&self.config.log_dir) {
                            Ok(()) => {
                                // Nothing must rewrite the config we just deleted.
                                self.config_dirty = false;
                                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                            }
                            Err(e) => self.settings_message = Some(e),
                        }
                    }
                    if ui.button("Cancel").clicked() {
                        self.wipe_confirm = false;
                    }
                });
            } else if ui
                .add_enabled(!busy, egui::Button::new("🧹 Remove all traces and quit"))
                .on_disabled_hover_text("Stop the running sessions first")
                .clicked()
            {
                self.wipe_confirm = true;
            }

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
