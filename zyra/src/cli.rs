use crate::firewall::{FlowDirection, RuleAction};
use clap::{Parser, ValueEnum};
use std::net::Ipv4Addr;

#[derive(Debug, Parser)]
#[command(name = "zyra", version, about = "eBPF Firewall CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum FlowDirectionArg { Inbound, Outbound }

#[derive(Debug, Clone, ValueEnum)]
pub enum RuleActionArg { Allow, Block }

#[derive(Debug, Clone, ValueEnum)]
pub enum ProtocolArg { Tcp, Udp, Any }

impl From<FlowDirectionArg> for FlowDirection {
    fn from(arg: FlowDirectionArg) -> Self {
        match arg { FlowDirectionArg::Inbound => FlowDirection::INGRESS, FlowDirectionArg::Outbound => FlowDirection::EGRESS }
    }
}

impl From<RuleActionArg> for RuleAction {
    fn from(arg: RuleActionArg) -> Self {
        match arg { RuleActionArg::Allow => RuleAction::ALLOW, RuleActionArg::Block => RuleAction::BLOCK }
    }
}

impl From<ProtocolArg> for u8 {
    fn from(arg: ProtocolArg) -> Self {
        match arg { ProtocolArg::Tcp => 6, ProtocolArg::Udp => 17, ProtocolArg::Any => 0 }
    }
}

#[derive(Debug, clap::Subcommand, Clone)]
pub enum Commands {
    Start { interface: String },
    Stop,
    AddRule {
        #[arg(long)]
        id: u32,
        #[arg(long, default_value_t = 100)]
        priority: u16,
        #[arg(long, default_value = "0.0.0.0")]
        ip: Ipv4Addr,
        #[arg(long, default_value_t = 0)]
        port: u16,
        #[arg(long, value_enum, default_value_t = FlowDirectionArg::Inbound)]
        direction: FlowDirectionArg,
        #[arg(long, value_enum, default_value_t = ProtocolArg::Any)]
        protocol: ProtocolArg,
        #[arg(long, value_enum, default_value_t = RuleActionArg::Block)]
        action: RuleActionArg,
    },
    ListRules,
    Listen,
}
