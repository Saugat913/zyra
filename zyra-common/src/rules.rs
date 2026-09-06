use crate::flow_direction::FlowDirection;

pub const ANY_PORT: u16 = 0;
pub const ANY_PROTOCOL: u8 = 0;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum RuleAction {
    ALLOW = 0,
    BLOCK = 1,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct RuleKey {
    /// IPv4 address in network byte order. Zero means any IPv4 address.
    pub ip: u32,
    /// Zero means any port.
    pub port: u16,
    /// IANA IP protocol number. Zero means any protocol.
    pub protocol: u8,
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
        protocol: u8,
        direction: FlowDirection,
        action: RuleAction,
    ) -> Self {
        Self {
            id,
            priority,
            key: RuleKey { ip, port, protocol, direction },
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
