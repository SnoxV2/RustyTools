#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;

mod app;
mod netconfig;
mod ping;
mod settings;
mod traceroute;
mod util;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 720.0])
            .with_min_inner_size([800.0, 500.0]),
        ..Default::default()
    };
    eframe::run_native(
        "RustyTools — Network Diagnostics",
        options,
        Box::new(|cc| Ok(Box::new(app::RustyToolsApp::new(cc)))),
    )
}
