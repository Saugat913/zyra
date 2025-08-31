#[repr(C)]
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum FlowDirection {
    INGRESS,
    EGRESS,
}