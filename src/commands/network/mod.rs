use clap::Subcommand;
use colored::Colorize;
use std::net::IpAddr;

mod config;
mod monitor;
mod ping;
mod traceroute;

#[derive(Subcommand)]
pub enum NetCommands {
    /// Show network interfaces and their configuration
    Config,
    /// Ping a host and display statistics
    Ping {
        /// Target hostname or IP address
        host: String,
        /// Number of packets to send
        #[arg(short, long, default_value = "4")]
        count: u16,
    },
    /// Trace the route to a host (requires root)
    Traceroute {
        /// Target hostname or IP address
        host: String,
        /// Maximum number of hops
        #[arg(short = 'H', long, default_value = "30")]
        max_hops: u8,
    },
    /// Monitor network interface statistics
    Monitor {
        /// Refresh interval in seconds
        #[arg(short, long, default_value = "2")]
        interval: u64,
    },
}

pub async fn run(command: NetCommands) {
    match command {
        NetCommands::Config => config::run(),
        NetCommands::Ping { host, count } => ping::run(&host, count).await,
        NetCommands::Traceroute { host, max_hops } => traceroute::run(&host, max_hops).await,
        NetCommands::Monitor { interval } => monitor::run(interval).await,
    }
}

pub(crate) async fn resolve(host: &str) -> Option<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip);
    }
    match tokio::net::lookup_host(format!("{}:0", host)).await {
        Ok(mut addrs) => addrs.next().map(|a| a.ip()),
        Err(e) => {
            eprintln!("{} Could not resolve '{}': {}", "Error:".red().bold(), host, e);
            None
        }
    }
}
