#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;

mod app;
mod arp;
mod dns;
#[cfg(unix)]
mod icmp;
mod logo;
mod netconfig;
mod ping;
mod settings;
mod theme;
mod traceroute;
mod util;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 720.0])
            .with_min_inner_size([640.0, 460.0])
            .with_icon(logo::icon()),
        ..Default::default()
    };
    eframe::run_native(
        "RustyTools — Network Diagnostics",
        options,
        Box::new(|cc| Ok(Box::new(app::RustyToolsApp::new(cc)))),
    )
}
