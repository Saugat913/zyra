use std::collections::HashMap;

use anyhow::{bail, Result};
use crate::firewall::{Rule, RuleAction};

/// Userspace policy validator and deterministic ordering layer.
#[derive(Debug, Default)]
pub struct RuleEngine {
    rules: HashMap<u32, Rule>,
}

impl RuleEngine {
    pub fn new() -> Self { Self::default() }

    pub fn validate(rule: &Rule) -> Result<()> {
        if rule.id == 0 { bail!("rule id must be non-zero"); }
        if rule.key.protocol > 0 && !matches!(rule.key.protocol, 6 | 17) {
            bail!("unsupported protocol {}; currently only TCP (6) and UDP (17) are supported", rule.key.protocol);
        }
        if rule.priority == u16::MAX { bail!("priority {} is reserved", u16::MAX); }
        Ok(())
    }

    pub fn insert(&mut self, rule: Rule) -> Result<()> {
        Self::validate(&rule)?;
        if self.rules.contains_key(&rule.id) { bail!("rule {} already exists", rule.id); }
        if self.rules.values().any(|r| r.key == rule.key) { bail!("a rule with the same match key already exists"); }
        self.rules.insert(rule.id, rule);
        Ok(())
    }

    pub fn remove(&mut self, id: u32) -> Option<Rule> { self.rules.remove(&id) }

    pub fn ordered(&self) -> Vec<Rule> {
        let mut rules: Vec<_> = self.rules.values().copied().collect();
        rules.sort_by_key(|r| (r.priority, r.id));
        rules
    }

    pub fn action_name(action: RuleAction) -> &'static str {
        match action { RuleAction::ALLOW => "allow", RuleAction::BLOCK => "block" }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::FlowDirection;

    fn rule(id: u32, priority: u16) -> Rule {
        Rule::new(id, priority, 0x0100007f, 443, 6, FlowDirection::INGRESS, RuleAction::ALLOW)
    }

    #[test]
    fn rejects_zero_id() { assert!(RuleEngine::validate(&rule(0, 10)).is_err()); }

    #[test]
    fn rejects_duplicate_ids() {
        let mut engine = RuleEngine::new();
        engine.insert(rule(1, 10)).unwrap();
        assert!(engine.insert(rule(1, 20)).is_err());
    }

    #[test]
    fn orders_by_priority_then_id() {
        let mut engine = RuleEngine::new();
        engine.insert(rule(2, 20)).unwrap();
        engine.insert(rule(1, 10)).unwrap();
        engine.insert(rule(3, 10)).unwrap();
        let ids: Vec<_> = engine.ordered().into_iter().map(|r| r.id).collect();
        assert_eq!(ids, vec![1, 3, 2]);
    }
}
