use colored::Colorize;
use std::time::Duration;
use sysinfo::Networks;
use tokio::time::sleep;

pub async fn run(interval: u64) {
    let mut networks = Networks::new_with_refreshed_list();

    loop {
        sleep(Duration::from_secs(interval)).await;
        networks.refresh();

        // Clear screen
        print!("\x1B[2J\x1B[1;1H");

        println!("{}", "Network Monitor".bold().underline());
        println!(
            "{}",
            format!("Refreshing every {}s — Ctrl+C to stop", interval).dimmed()
        );
        println!();
        println!(
            "{:<20} {:>16} {:>16} {:>12} {:>12}",
            "Interface".bold(),
            "RX Total".bold(),
            "TX Total".bold(),
            "RX/s".bold(),
            "TX/s".bold(),
        );
        println!("{}", "─".repeat(80).dimmed());

        for (name, data) in &networks {
            let rx_per_sec = data.received() / interval;
            let tx_per_sec = data.transmitted() / interval;
            println!(
                "{:<20} {:>16} {:>16} {:>12} {:>12}",
                name.cyan(),
                format_bytes(data.total_received()),
                format_bytes(data.total_transmitted()),
                format!("{}/s", format_bytes(rx_per_sec)).green(),
                format!("{}/s", format_bytes(tx_per_sec)).yellow(),
            );
        }
    }
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
