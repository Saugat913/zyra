use crate::flow_direction::FlowDirection;
use crate::packet_type::PacketType;

/// Maximum number of bytes used by an address field in the current IPv4 rule ABI.
pub const ANY_U16: u16 = 0;
pub const ANY_U8: u8 = 0;

#[repr(C)]
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum RuleAction {
    ALLOW,
    BLOCK,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct RuleKey {
    /// Stable rule selector. Zero means wildcard for the current matcher.
    pub ip: u32,
    /// Zero means any port.
    pub port: u16,
    /// Packet type discriminant. Zero means any protocol.
    pub packet_type: PacketType,
    pub direction: FlowDirection,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct Rule {
    /// Stable userspace rule identifier.
    pub id: u32,
    /// Lower values have higher precedence when rules are compiled by the engine.
    pub priority: u16,
    pub key: RuleKey,
    pub action: RuleAction,
}

impl Rule {
    pub const fn new(
        id: u32,
        priority: u16,
        ip: u32,
        port: u16,
        packet_type: PacketType,
        direction: FlowDirection,
        action: RuleAction,
    ) -> Self {
        Self {
            id,
            priority,
            key: RuleKey { ip, port, packet_type, direction },
            action,
        }
    }
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for RuleKey {}
    unsafe impl aya::Pod for Rule {}
}
