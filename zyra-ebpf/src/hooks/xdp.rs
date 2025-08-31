use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use zyra_common::{Event, LogEvent, PacketType};

use crate::{maps::EVENTS, utils::parsing::ptr_at};

pub fn try_use_xdp(ctx: XdpContext) -> Result<u32, ()> {
    let ethr_hdr: *const EthHdr = ptr_at(&ctx, 0)?;

    match unsafe { *ethr_hdr }.ether_type() {
        Ok(EtherType::Ipv4) => {}
        _ => {}
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let src_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });

    let (packet_type, src_port) = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcp_hdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
           
            (
                PacketType::TCP,
                u16::from_be_bytes(unsafe { (*tcp_hdr).source }),
            )
        }
        IpProto::Udp => {
            let udp_hdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            (
                PacketType::UDP,
                u16::from_be_bytes(unsafe { (*udp_hdr).src }),
            )
        }
        _ => return Err(()),
    };
    let event = Event::LogEvent(LogEvent {
        port: src_port,
        direction: zyra_common::FlowDirection::INGRESS,
        src_addr: src_addr,
        packet_type: packet_type,
    });

    // Reserve space in the ring buffer
    if let Some(mut slot) = EVENTS.reserve::<Event>(0) {
        slot.write(event);
        info!(&ctx, "Emitted the events");
        slot.submit(0);
    }

    Ok(xdp_action::XDP_PASS)
}
