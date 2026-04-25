use colored::Colorize;
use pnet::datalink;

pub fn run() {
    println!("{}", "Network Interfaces".bold().underline());
    println!();

    for iface in datalink::interfaces() {
        let status = if iface.is_up() {
            "UP".green().bold()
        } else {
            "DOWN".red().bold()
        };

        println!("{}  [{}]", iface.name.cyan().bold(), status);

        if let Some(mac) = iface.mac {
            println!("  MAC   {}", mac);
        }

        for ip in &iface.ips {
            println!("  IP    {}", ip);
        }

        let mut flags = Vec::new();
        if iface.is_loopback() {
            flags.push("LOOPBACK");
        }
        if iface.is_multicast() {
            flags.push("MULTICAST");
        }
        if iface.is_broadcast() {
            flags.push("BROADCAST");
        }

        if !flags.is_empty() {
            println!("  Flags {}", flags.join(", ").dimmed());
        }

        println!();
    }
}
