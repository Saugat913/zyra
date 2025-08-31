use tokio::sync::mpsc;

use anyhow::Result;

/// This trait represent the firwall main api usages to be implemented
pub trait Firewall {
    /// Represent the start of the firewall service
    fn start(&mut self, interface: &str) -> Result<()>;

    /// Represent the end of firewall service
    fn stop(self) -> Result<()>;

    /// Represent the addition of rules
    fn add_rule(&mut self, rule: Rule) -> Result<()>;

    /// Represent the listing of rules
    fn list_rules(&mut self) -> Result<Vec<Rule>>;

    /// Represent the reloading/refreshing the rule
    fn reload_rule(&mut self) -> Result<()>;

    /// Listen to the event produced
    async fn listen_event(&mut self) -> Result<mpsc::Receiver<Event>>;
}

mod ebpf_firewall;
pub use ebpf_firewall::EbpfFirewall;
use zyra_common::{self, Event};

// reimport for common
pub use zyra_common::{FlowDirection, Rule, RuleAction};
