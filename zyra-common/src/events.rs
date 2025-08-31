use crate::{flow_direction::FlowDirection, packet_type::PacketType};

#[repr(C)]
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct LogEvent {
    pub src_addr: u32,
    pub port:u16,
    pub packet_type: PacketType,
    pub direction: FlowDirection,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum Event {
    LogEvent(LogEvent),
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for Event {}
}
