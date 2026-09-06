use anyhow::{Context, Ok, anyhow};
use aya::{Ebpf, maps::{HashMap, Map, MapData, RingBuf}, programs::{Xdp, XdpFlags}};
use aya_obj::programs::XdpAttachType;
use log::{debug, warn};
use std::ops::Deref as _;
use tokio::sync::mpsc;
use tokio::io::unix::AsyncFd;

use super::{Event, Rule};
use crate::{firewall::Firewall, rule_engine::RuleEngine};

const PIN_BASE_PATH: &str = "/sys/fs/bpf/zyra";
const RULES_MAP_NAME: &str = "RULES";
const EVENT_QUEUE_NAME: &str = "EVENTS";

pub struct EbpfFirewall {
    ebpf: Ebpf,
    rules: Option<HashMap<MapData, zyra_common::RuleKey, Rule>>,
    events: Option<RingBuf<MapData>>,
    xdp_program: Option<Xdp>,
}

impl Firewall for EbpfFirewall {
    fn add_rule(&mut self, rule: Rule) -> anyhow::Result<()> {
        RuleEngine::validate(&rule)?;
        let rules_map = self.rules.as_mut().ok_or_else(|| anyhow!("Firewall is not started"))?;
        rules_map.insert(rule.key, rule, 0)?;
        Ok(())
    }

    fn list_rules(&mut self) -> anyhow::Result<Vec<Rule>> {
        let rules_map = self.rules.as_mut().ok_or_else(|| anyhow!("Firewall is not started"))?;
        let mut rules = Vec::new();
        for key in rules_map.keys() {
            if let Ok(key) = key {
                if let Ok(rule) = rules_map.get(&key, 0) { rules.push(rule); }
            }
        }
        rules.sort_by_key(|r| (r.priority, r.id));
        Ok(rules)
    }

    fn reload_rule(&mut self) -> anyhow::Result<()> { Ok(()) }

    async fn listen_event(&mut self) -> anyhow::Result<mpsc::Receiver<Event>> {
        let (tx, rx) = mpsc::channel::<Event>(60);
        let events = self.events.take().ok_or_else(|| anyhow!("Firewall is not started"))?;
        tokio::spawn(async move {
            let mut async_fd = match AsyncFd::new(events) {
                Ok(fd) => fd,
                Err(e) => { eprintln!("Async failed:{e}"); return; }
            };
            loop {
                let mut guard = match async_fd.readable_mut().await { Ok(g) => g, Err(_) => continue };
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    let bytes = item.deref();
                    if bytes.len() == std::mem::size_of::<Event>() {
                        let ev = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const Event) };
                        if tx.send(ev).await.is_err() { return; }
                    } else if !bytes.is_empty() { eprintln!("Unexpected event size {}", bytes.len()); }
                }
                guard.clear_ready();
            }
        });
        Ok(rx)
    }

    fn start(&mut self, interface: &str) -> anyhow::Result<()> {
        if let Err(e) = aya_log::EbpfLogger::init(&mut self.ebpf) { warn!("failed to initialize eBPF logger: {e}"); }
        let mut is_started_already = false;
        std::fs::create_dir_all(PIN_BASE_PATH).context("Failed to create the base pin path")?;

        match self.xdp_program {
            Some(_) => { is_started_already = true; debug!("Xdp program is already pinned"); }
            None => {
                let program: &mut Xdp = self.ebpf.program_mut("zyra_xdp").unwrap().try_into()?;
                program.load()?;
                program.attach(interface, XdpFlags::default()).context("failed to attach the XDP program")?;
                program.pin(format!("{}/xdp", PIN_BASE_PATH)).context("Cannot pin the program")?;
            }
        }
        match self.events {
            Some(_) => { is_started_already = true; debug!("Events map is already pinned"); }
            None => if let Some(event_map) = self.ebpf.map_mut(EVENT_QUEUE_NAME) {
                event_map.pin(format!("{}/events", PIN_BASE_PATH)).context("Error pinning the event map")?;
            }
        }
        match self.rules {
            Some(_) => { is_started_already = true; debug!("Rules map is already pinned"); }
            None => if let Some(rule_map) = self.ebpf.map_mut(RULES_MAP_NAME) {
                rule_map.pin(format!("{}/rules", PIN_BASE_PATH)).context("Error pinning the rule map")?;
            }
        }
        if is_started_already { return Err(anyhow!("Firewall already started")); }
        Ok(())
    }

    fn stop(self) -> anyhow::Result<()> {
        for path in ["rules", "events", "xdp"] {
            let _ = std::fs::remove_file(format!("{}/{}", PIN_BASE_PATH, path));
        }
        let _ = std::fs::remove_dir(PIN_BASE_PATH);
        debug!("Maps unpinned from filesystem");
        Ok(())
    }
}

impl EbpfFirewall {
    pub fn new() -> anyhow::Result<Self> {
        let rlim = libc::rlimit { rlim_cur: libc::RLIM_INFINITY, rlim_max: libc::RLIM_INFINITY };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 { debug!("remove limit on locked memory failed, ret is: {ret}"); }
        let ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/zyra")))?;
        Ok(Self { ebpf, events: Self::get_pinned_event_map().ok(), rules: Self::get_pinned_rules_map().ok(), xdp_program: Self::get_pinned_xdp_program().ok() })
    }

    fn get_pinned_rules_map() -> anyhow::Result<HashMap<MapData, zyra_common::RuleKey, Rule>> {
        let path = format!("{}/rules", PIN_BASE_PATH);
        let mapdata = MapData::from_pin(path)?;
        HashMap::try_from(Map::HashMap(mapdata)).map_err(Into::into)
    }

    fn get_pinned_event_map() -> anyhow::Result<RingBuf<MapData>> {
        let mapdata = MapData::from_pin(format!("{}/events", PIN_BASE_PATH))?;
        RingBuf::try_from(Map::RingBuf(mapdata)).map_err(Into::into)
    }

    fn get_pinned_xdp_program() -> anyhow::Result<Xdp> {
        Ok(Xdp::from_pin(format!("{}/xdp", PIN_BASE_PATH), XdpAttachType::Interface)?)
    }
}
