#![no_std]
#![no_main]

mod hooks;
mod maps;
mod parsers;
mod utils;

use crate::hooks::{try_use_tc_egress, try_use_xdp};
use aya_ebpf::{
    bindings::{TC_ACT_SHOT, xdp_action},
    macros::{classifier, xdp},
    programs::{TcContext, XdpContext},
};

#[xdp]
pub fn zyra_xdp(ctx: XdpContext) -> u32 {
    match try_use_xdp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[classifier]
pub fn zyra_tc(ctx: TcContext) -> i32 {
    match try_use_tc_egress(ctx) {
        Ok(action) => action,
        Err(()) => TC_ACT_SHOT,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
