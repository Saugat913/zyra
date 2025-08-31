use anyhow::{Context, Ok, anyhow};
use aya::{
    Ebpf,
    maps::{HashMap, Map, MapData, RingBuf},
    programs::{Xdp, XdpFlags},
};
use aya_obj::programs::XdpAttachType;
use log::{debug, warn};
use std::ops::Deref as _;
use tokio::sync::mpsc;

use tokio::io::unix::AsyncFd;
use super::{Event, Rule};

use crate::firewall::Firewall;

const PIN_BASE_PATH: &str = "/sys/fs/bpf/zyra";
const RULES_MAP_NAME: &str = "RULES";
const EVENT_QUEUE_NAME: &str = "EVENTS";

pub struct EbpfFirewall {
    ebpf: Ebpf,
    rules: Option<HashMap<MapData, u32, Rule>>,
    events: Option<RingBuf<MapData>>,
    xdp_program: Option<Xdp>,
}

impl Firewall for EbpfFirewall {
    fn add_rule(&mut self, rule: Rule) -> anyhow::Result<()> {
        if let Some(rules_map) = self.rules.as_mut() {
            rules_map.insert(rule.ip, rule, 0)?;
            Ok(())
        } else {
            return Err(anyhow!("Firewall is not started"));
        }
    }
    fn list_rules(&mut self) -> anyhow::Result<Vec<Rule>> {
        if let Some(rules_map) = self.rules.as_mut() {
            let mut rules = Vec::new();

            // Iterate through all rules in the map
            for key in rules_map.keys() {
                if let std::result::Result::Ok(key) = key {
                    if let std::result::Result::Ok(rule) = rules_map.get(&key, 0) {
                        rules.push(rule);
                    }
                }
            }
            return Ok(rules);
        } else {
            return Err(anyhow!("Firewall is not started"));
        }
    }
    fn reload_rule(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn listen_event(&mut self) -> anyhow::Result<mpsc::Receiver<Event>> {
        let (tx, rx) = mpsc::channel::<Event>(60);
        let events = self
            .events
            .take()
            .ok_or_else(|| anyhow!("Firewall is not started"))?;

        tokio::spawn(async move {
            let mut async_fd = match AsyncFd::new(events) {
                std::result::Result::Ok(fd) => fd,
                Err(e) => {
                    eprintln!("Async failed:{e}");
                    return;
                }
            };

            loop {
                let mut gaurd = match async_fd.readable_mut().await {
                    std::result::Result::Ok(g) => g,
                    Err(_) => continue,
                };

                let rb = gaurd.get_inner_mut();

                while let Some(item) = rb.next() {
                    let bytes = item.deref();

                    if bytes.len() == std::mem::size_of::<Event>() {
                        let ev =
                            unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const Event) };

                        if tx.send(ev).await.is_err() {
                            return;
                        }
                    } else if !bytes.is_empty() {
                        eprintln!("Unexpected event size {}", bytes.len());
                    }
                }

                gaurd.clear_ready();
            }
        });

        Ok(rx)
    }

    fn start(&mut self, interface: &str) -> anyhow::Result<()> {
        if let Err(e) = aya_log::EbpfLogger::init(&mut self.ebpf) {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }

        let mut is_started_already = false;
        std::fs::create_dir_all(PIN_BASE_PATH).context("Failed to create the base pin path")?;

        match self.xdp_program {
            Some(_) => {
                is_started_already = true;
                debug!("Xdp program is already pinned");
            }
            None => {
                let program: &mut Xdp = { self.ebpf.program_mut("zyra_xdp").unwrap().try_into()? };
                program.load()?;

                program.attach(interface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
                let program_pin_path = format!("{}/xdp", PIN_BASE_PATH);
                program
                    .pin(program_pin_path)
                    .context("Cannot pin the program")?;
            }
        }

        match self.events {
            Some(_) => {
                is_started_already = true;
                debug!("Events map is already pinned");
            }
            None => {
                if let Some(event_map) = self.ebpf.map_mut(EVENT_QUEUE_NAME) {
                    let event_map_pin_path = format!("{}/events", PIN_BASE_PATH);
                    event_map
                        .pin(&event_map_pin_path)
                        .context("Error pinning the event map")?;
                    debug!("Pined the event map at :{}", event_map_pin_path);
                }
            }
        }

        match self.rules {
            Some(_) => {
                is_started_already = true;
                debug!("Rules map is already pinned");
            }
            None => {
                if let Some(rule_map) = self.ebpf.map_mut(RULES_MAP_NAME) {
                    let rule_map_pin_path = format!("{}/rules", PIN_BASE_PATH);
                    println!("Rule Pin path:{}", &rule_map_pin_path);
                    rule_map
                        .pin(&rule_map_pin_path)
                        .context("Error pinning the rule map")?;

                    debug!("Pined the rule map at :{}", rule_map_pin_path);
                }
            }
        }

        if is_started_already {
            return Err(anyhow!("Firewall already started"));
        }
        Ok(())
    }
    fn stop(self) -> anyhow::Result<()> {
        let rules_pin_path = format!("{}/rules", PIN_BASE_PATH);
        let events_pin_path = format!("{}/events", PIN_BASE_PATH);
        let program_pin_path = format!("{}/xdp", PIN_BASE_PATH);

        let _ = std::fs::remove_file(&rules_pin_path);
        let _ = std::fs::remove_file(&events_pin_path);
        let _ = std::fs::remove_file(program_pin_path);
        let _ = std::fs::remove_dir(PIN_BASE_PATH);

        debug!("Maps unpinned from filesystem");
        Ok(())
    }
}

impl EbpfFirewall {
    pub fn new() -> anyhow::Result<Self> {
        // Bump the memlock rlimit. This is needed for older kernels that don't use the
        // new memcg based accounting, see https://lwn.net/Articles/837122/
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            debug!("remove limit on locked memory failed, ret is: {ret}");
        }

        // This will include your eBPF object file as raw bytes at compile-time and load it at
        // runtime. This approach is recommended for most real-world use cases. If you would
        // like to specify the eBPF program at runtime rather than at compile-time, you can
        // reach for `Bpf::load_file` instead.
        let ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/zyra"
        )))?;

        Ok(Self {
            ebpf: ebpf,
            events: Self::get_pinned_event_map().ok(),
            rules: Self::get_pinned_rules_map().ok(),
            xdp_program: Self::get_pinned_xdp_program().ok(),
        })
    }

    fn get_pinned_rules_map() -> anyhow::Result<HashMap<MapData, u32, Rule>> {
        let path = format!("{}/rules", PIN_BASE_PATH);
        let mapdata = MapData::from_pin(path)?;
        let map = Map::HashMap(mapdata);
        let rules_map: HashMap<MapData, u32, Rule> = HashMap::try_from(map)?;
        return anyhow::Ok(rules_map);
    }

    fn get_pinned_event_map() -> anyhow::Result<RingBuf<MapData>> {
        let path = format!("{}/events", PIN_BASE_PATH);
        let mapdata = MapData::from_pin(path)?;
        let map = Map::RingBuf(mapdata);
        let event_map: RingBuf<MapData> = RingBuf::try_from(map)?;
        return anyhow::Ok(event_map);
    }

    fn get_pinned_xdp_program() -> anyhow::Result<Xdp> {
        let program_pin_path = format!("{}/xdp", PIN_BASE_PATH);
        let xdp_program = Xdp::from_pin(program_pin_path, XdpAttachType::Interface)?;
        Ok(xdp_program)
    }
}
