mod analyzer;
mod cli;
mod firewall;
mod api;
mod rule_engine;

use clap::Parser;
use firewall::Rule;
use crate::{cli::Cli, firewall::Firewall, rule_engine::RuleEngine};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    env_logger::init();

    match cli.command {
        cli::Commands::Start { interface } => {
            let mut firewall = firewall::EbpfFirewall::new()?;
            firewall.start(&interface)?;
            println!("Firewall started!");
        }
        cli::Commands::Stop => {
            let firewall = firewall::EbpfFirewall::new()?;
            firewall.stop()?;
            println!("Firewall stopped!");
        }
        cli::Commands::AddRule { id, priority, ip, port, direction, protocol, action } => {
            let mut firewall = firewall::EbpfFirewall::new()?;
            let parsed_rule = Rule::new(
                id,
                priority,
                u32::from(ip),
                port,
                protocol.into(),
                direction.into(),
                action.into(),
            );
            RuleEngine::validate(&parsed_rule)?;
            firewall.add_rule(parsed_rule)?;
            println!("Rule {} installed with priority {}", id, priority);
        }
        cli::Commands::ListRules => {
            let mut firewall = firewall::EbpfFirewall::new()?;
            let rules = firewall.list_rules()?;
            println!("Current rules:");
            for rule in rules { println!("{:?}", rule); }
        }
        cli::Commands::Listen => {
            let mut firewall = firewall::EbpfFirewall::new()?;
            let mut channel = firewall.listen_event().await?;
            while let Some(data) = channel.recv().await { println!("Received event {:?}", data); }
        }
    }
    Ok(())
}
