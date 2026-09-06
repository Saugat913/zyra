use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::{eth::{EthHdr, EtherType}, ip::{IpProto, Ipv4Hdr}, tcp::TcpHdr, udp::UdpHdr};
use zyra_common::{FlowDirection, Rule, RuleAction, RuleKey, Event, LogEvent};
use crate::{maps::{EVENTS, RULES}, utils::parsing::ptr_at};

fn lookup_rule(ip: u32, port: u16, protocol: u8) -> Option<Rule> {
    // Eight bounded candidates cover exact and wildcard forms without a linear scan.
    let keys = [
        RuleKey { ip, port, protocol, direction: FlowDirection::INGRESS },
        RuleKey { ip, port: 0, protocol, direction: FlowDirection::INGRESS },
        RuleKey { ip, port, protocol: 0, direction: FlowDirection::INGRESS },
        RuleKey { ip, port: 0, protocol: 0, direction: FlowDirection::INGRESS },
        RuleKey { ip: 0, port, protocol, direction: FlowDirection::INGRESS },
        RuleKey { ip: 0, port: 0, protocol, direction: FlowDirection::INGRESS },
        RuleKey { ip: 0, port, protocol: 0, direction: FlowDirection::INGRESS },
        RuleKey { ip: 0, port: 0, protocol: 0, direction: FlowDirection::INGRESS },
    ];

    let mut best: Option<Rule> = None;
    let mut i = 0;
    while i < keys.len() {
        if let Some(rule) = RULES.get(&keys[i]) {
            if best.map_or(true, |current| rule.priority < current.priority || (rule.priority == current.priority && rule.id < current.id)) {
                best = Some(*rule);
            }
        }
        i += 1;
    }
    best
}

pub fn try_use_xdp(ctx: XdpContext) -> Result<u32, ()> {
    let eth_hdr: *const EthHdr = ptr_at(&ctx, 0)?;
    if unsafe { (*eth_hdr).ether_type() } != Ok(EtherType::Ipv4) { return Ok(xdp_action::XDP_PASS); }

    let ipv4_hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let src_addr = u32::from_be_bytes(unsafe { (*ipv4_hdr).src_addr });
    let protocol = match unsafe { (*ipv4_hdr).proto } {
        IpProto::Tcp => 6,
        IpProto::Udp => 17,
        _ => return Ok(xdp_action::XDP_PASS),
    };

    let src_port = if protocol == 6 {
        let hdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
        u16::from_be_bytes(unsafe { (*hdr).source })
    } else {
        let hdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
        u16::from_be_bytes(unsafe { (*hdr).src })
    };

    let action = lookup_rule(src_addr, src_port, protocol).map(|r| r.action);
    if let Some(RuleAction::BLOCK) = action {
        return Ok(xdp_action::XDP_DROP);
    }

    let event = Event::LogEvent(LogEvent {
        port: src_port,
        direction: FlowDirection::INGRESS,
        src_addr,
        packet_type: if protocol == 6 { zyra_common::PacketType::TCP } else { zyra_common::PacketType::UDP },
    });
    if let Some(mut slot) = EVENTS.reserve::<Event>(0) { slot.write(event); slot.submit(0); }
    info!(&ctx, "Packet passed through Zyra rule engine");
    Ok(xdp_action::XDP_PASS)
}
