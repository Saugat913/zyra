
#[repr(C)]
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum PacketType {
    TCP,
    UDP,
}
