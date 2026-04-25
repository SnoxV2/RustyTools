use colored::Colorize;
use rand::random;
use std::net::IpAddr;
use std::time::Duration;
use surge_ping::{Client, Config, IcmpPacket, PingIdentifier, PingSequence, ICMP};
use tokio::time::sleep;

pub async fn run(host: &str, count: u16) {
    let ip = match super::resolve(host).await {
        Some(ip) => ip,
        None => return,
    };

    let protocol = match ip {
        IpAddr::V4(_) => ICMP::V4,
        IpAddr::V6(_) => ICMP::V6,
    };

    let config = Config::builder().kind(protocol).build();
    let client = match Client::new(&config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} {} (try running as root)", "Error:".red().bold(), e);
            return;
        }
    };

    println!("PING {} ({}) — {} packets", host.cyan(), ip, count);
    println!();

    let mut pinger = client.pinger(ip, PingIdentifier(random())).await;
    pinger.timeout(Duration::from_secs(2));

    let mut received = 0u16;
    let mut rtts: Vec<f64> = Vec::new();

    for seq in 0..count {
        match pinger.ping(PingSequence(seq), &[]).await {
            Ok((IcmpPacket::V4(packet), rtt)) => {
                let ms = rtt.as_secs_f64() * 1000.0;
                println!(
                    "{} bytes from {}: icmp_seq={} ttl={} time={:.2} ms",
                    packet.get_size().to_string().yellow(),
                    ip.to_string().cyan(),
                    seq,
                    packet.get_ttl().unwrap_or(0),
                    ms,
                );
                rtts.push(ms);
                received += 1;
            }
            Ok((IcmpPacket::V6(packet), rtt)) => {
                let ms = rtt.as_secs_f64() * 1000.0;
                println!(
                    "{} bytes from {}: icmp_seq={} hop_limit={} time={:.2} ms",
                    packet.get_size().to_string().yellow(),
                    ip.to_string().cyan(),
                    seq,
                    packet.get_max_hop_limit(),
                    ms,
                );
                rtts.push(ms);
                received += 1;
            }
            Err(e) => {
                println!("icmp_seq={}  {}", seq, e.to_string().red());
            }
        }

        if seq < count - 1 {
            sleep(Duration::from_secs(1)).await;
        }
    }

    println!();
    println!("--- {} ping statistics ---", host.cyan());
    let loss = (count - received) as f64 / count as f64 * 100.0;
    println!(
        "{} transmitted, {} received, {:.0}% packet loss",
        count,
        received.to_string().green(),
        loss,
    );

    if !rtts.is_empty() {
        let min = rtts.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = rtts.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;
        println!("rtt min/avg/max = {:.2}/{:.2}/{:.2} ms", min, avg, max);
    }
}
