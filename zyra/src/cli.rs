use crate::firewall::{FlowDirection, RuleAction};
use clap::{Parser, ValueEnum};

#[derive(Debug, Parser)]
#[command(name = "zyra", version, about = "eBPF Firewall CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum FlowDirectionArg {
    INBOUND,
    OUTBOUND,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum RuleActionArg {
    Allow,
    Block,
}

impl From<FlowDirectionArg> for FlowDirection {
    fn from(arg: FlowDirectionArg) -> Self {
        match arg {
            FlowDirectionArg::INBOUND => FlowDirection::INGRESS,
            FlowDirectionArg::OUTBOUND => FlowDirection::EGRESS,
        }
    }
}

impl From<RuleActionArg> for RuleAction {
    fn from(arg: RuleActionArg) -> Self {
        match arg {
            RuleActionArg::Allow => RuleAction::ALLOW,
            RuleActionArg::Block => RuleAction::BLOCK,
        }
    }
}
#[derive(Debug, clap::Subcommand, Clone)]
pub enum Commands {
    /// Start the firewall on the given interface
    Start { interface: String },
    /// Stop the firewall
    Stop,
    /// Add a firewall rule
    AddRule {
        #[arg(long)]
        ip: u32,
        #[arg(long, default_value_t = 0)]
        port: u16,
        #[arg(long, value_enum,default_value_t=FlowDirectionArg::INBOUND)]
        direction: FlowDirectionArg,
        #[arg(long, value_enum,default_value_t=RuleActionArg::Block)]
        action: RuleActionArg,
    },
    /// List firewall rules
    ListRules,

    /// Listen events
    Listen,
}
