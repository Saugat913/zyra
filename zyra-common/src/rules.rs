use crate::flow_direction::FlowDirection;

#[repr(C)]
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum RuleAction {
    ALLOW,
    BLOCK,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct Rule {
    pub ip: u32,
    pub port: u16,

    pub action: RuleAction,
    pub direction: FlowDirection,
}

impl Rule {
    pub fn new(ip: u32, port: u16, direction: FlowDirection, action: RuleAction) -> Self {
        return Self {
            ip: ip,
            port: port,

            direction: direction,
            action: action,
        };
    }
}



#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for Rule {}
}
