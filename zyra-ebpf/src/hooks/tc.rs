use aya_ebpf::{bindings::TC_ACT_PIPE, programs::TcContext};
use network_types::eth::EthHdr;

pub fn try_use_tc_egress(ctx: TcContext) -> Result<i32, ()> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_|())?;


    Ok(TC_ACT_PIPE)
}
