mod analyzer;
mod cli;
mod firewall;
mod api;

use clap::Parser;
use firewall::Rule;

use crate::{cli::Cli, firewall::Firewall};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    env_logger::init();

    match cli.command {
        cli::Commands::Start { interface } => {
            let mut firewall = firewall::EbpfFirewall::new()?;

            // let ctrl_c = tokio::signal::ctrl_c();
            firewall.start(&interface)?;
            // ctrl_c.await?;
            println!("Firewall started!");
        }
        cli::Commands::Stop => {
            let firewall = firewall::EbpfFirewall::new()?;
            firewall.stop()?;
            println!("Firewall Stopped!");
        }
        cli::Commands::AddRule {
            ip,
            port,
            direction,
            action,
        } => {
            let mut firewall = firewall::EbpfFirewall::new()?;
            let parsed_rule: Rule = Rule::new(ip, port, direction.into(), action.into());
            firewall.add_rule(parsed_rule)?;
            println!("✅ Rule added: {:?}", parsed_rule);
        }
        cli::Commands::ListRules => {
            let mut firewall = firewall::EbpfFirewall::new()?;
            let rules = firewall.list_rules()?; // <-- we’ll add this method

            println!("Current rules:");
            for r in rules {
                println!("{:?}", r);
            }
        }
        cli::Commands::Listen => {
            let mut firewall = firewall::EbpfFirewall::new()?;
            let mut channel = firewall.listen_event().await?;

            while let Some(data) = channel.recv().await {
                println!("Received event {:?}", data);
            }
        }
    }

    Ok(())
}
