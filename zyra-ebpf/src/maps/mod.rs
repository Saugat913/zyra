use core::mem;

use aya_ebpf::{macros::map, maps::{HashMap, RingBuf}};
use zyra_common::{Event, Rule, RuleKey};

pub const MAX_RULES: u32 = 1025;

#[map]
pub static RULES: HashMap<RuleKey, Rule> = HashMap::with_max_entries(MAX_RULES, 0);

const EVENT_BYTES: usize = mem::size_of::<Event>();

#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size((EVENT_BYTES as u32) * 1024, 0);
