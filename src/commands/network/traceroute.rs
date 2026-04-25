use colored::Colorize;
use pnet::packet::{
    icmp::{echo_request::MutableEchoRequestPacket, IcmpCode, IcmpTypes},
    ip::IpNextHeaderProtocols,
    ipv4::MutableIpv4Packet,
    Packet,
};
use pnet::transport::{
    icmp_packet_iter, transport_channel,
    TransportChannelType::{Layer3, Layer4},
    TransportProtocol::Ipv4 as TIpv4,
};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

const IPV4_HEADER_LEN: usize = 20;
const ICMP_ECHO_LEN: usize = 8;
const PACKET_SIZE: usize = IPV4_HEADER_LEN + ICMP_ECHO_LEN;

pub async fn run(host: &str, max_hops: u8) {
    let target = match super::resolve(host).await {
        Some(IpAddr::V4(ip)) => ip,
        _ => {
            eprintln!(
                "{} Could not resolve '{}' to an IPv4 address",
                "Error:".red().bold(),
                host
            );
            return;
        }
    };

    println!(
        "Traceroute to {} ({}), {} hops max",
        host.cyan(),
        target,
        max_hops
    );
    println!();

    // Layer3 TX: we control the full IP header to set TTL
    let (mut tx, _) = match transport_channel(PACKET_SIZE, Layer3(IpNextHeaderProtocols::Icmp)) {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!(
                "{} {} — run as root/administrator",
                "Error:".red().bold(),
                e
            );
            return;
        }
    };

    // Layer4 RX: receive ICMP responses (TTL exceeded + echo replies)
    let (_, mut rx) =
        match transport_channel(65535, Layer4(TIpv4(IpNextHeaderProtocols::Icmp))) {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!(
                    "{} {} — run as root/administrator",
                    "Error:".red().bold(),
                    e
                );
                return;
            }
        };

    let mut iter = icmp_packet_iter(&mut rx);

    for ttl in 1u8..=max_hops {
        let mut buf = vec![0u8; PACKET_SIZE];
        build_packet(&mut buf, target, ttl, ttl as u16);

        let ipv4 = match pnet::packet::ipv4::Ipv4Packet::new(&buf) {
            Some(p) => p,
            None => continue,
        };

        let dest = IpAddr::V4(target);
        let send_time = Instant::now();

        if let Err(e) = tx.send_to(ipv4, dest) {
            eprintln!("send error: {}", e);
            println!("{:3}  *", ttl);
            continue;
        }

        let deadline = Instant::now() + Duration::from_secs(3);
        let mut found = false;

        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match iter.next_with_timeout(remaining) {
                Ok(Some((packet, addr))) => {
                    let rtt = send_time.elapsed().as_secs_f64() * 1000.0;
                    match packet.get_icmp_type() {
                        IcmpTypes::TimeExceeded => {
                            println!(
                                "{:3}  {}  {:.2} ms",
                                ttl,
                                addr.to_string().cyan(),
                                rtt
                            );
                            found = true;
                            break;
                        }
                        IcmpTypes::EchoReply => {
                            println!(
                                "{:3}  {}  {:.2} ms",
                                ttl,
                                addr.to_string().green(),
                                rtt
                            );
                            println!();
                            println!("Reached {} in {} hops.", host.green().bold(), ttl);
                            return;
                        }
                        _ => {}
                    }
                }
                Ok(None) | Err(_) => break,
            }
        }

        if !found {
            println!("{:3}  {}", ttl, "* * * (timeout)".dimmed());
        }
    }

    println!();
    println!(
        "Max hops ({}) reached — destination may be unreachable.",
        max_hops
    );
}

fn build_packet(buf: &mut [u8], dest: Ipv4Addr, ttl: u8, seq: u16) {
    {
        let mut icmp = MutableEchoRequestPacket::new(&mut buf[IPV4_HEADER_LEN..]).unwrap();
        icmp.set_icmp_type(IcmpTypes::EchoRequest);
        icmp.set_icmp_code(IcmpCode::new(0));
        icmp.set_identifier(0xCAFE);
        icmp.set_sequence_number(seq);
        let checksum = pnet::util::checksum(icmp.packet(), 1);
        icmp.set_checksum(checksum);
    }
    {
        let mut ipv4 = MutableIpv4Packet::new(buf).unwrap();
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_total_length(PACKET_SIZE as u16);
        ipv4.set_ttl(ttl);
        ipv4.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        ipv4.set_destination(dest);
        ipv4.set_flags(pnet::packet::ipv4::Ipv4Flags::DontFragment);
    }
}
