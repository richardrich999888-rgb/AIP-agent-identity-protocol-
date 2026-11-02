use aip_types::{Action, CapabilityScope, ScopeAction};
use serde::Deserialize;

pub fn parse_action_str(s: &str) -> ScopeAction {
    match s.trim().to_ascii_lowercase().as_str() {
        "read" => ScopeAction::Standard(Action::Read),
        "write" => ScopeAction::Standard(Action::Write),
        "delete" => ScopeAction::Standard(Action::Delete),
        "admin" => ScopeAction::Standard(Action::Admin),
        "execute" => ScopeAction::Standard(Action::Execute),
        "delegate" => ScopeAction::Standard(Action::Delegate),
        other => ScopeAction::Custom(other.to_string()),
    }
}

pub fn parse_action_loose(action_json: &str) -> Result<ScopeAction, String> {
    if let Ok(act) = serde_json::from_str::<ScopeAction>(action_json) {
        return Ok(act);
    }
    if let Ok(act) = serde_json::from_str::<Action>(action_json) {
        return Ok(ScopeAction::Standard(act));
    }
    if let Ok(s) = serde_json::from_str::<String>(action_json) {
        return Ok(parse_action_str(&s));
    }
    let trimmed = action_json.trim().trim_matches('"');
    if !trimmed.is_empty() {
        return Ok(parse_action_str(trimmed));
    }
    Err("Invalid ScopeAction JSON".into())
}

#[derive(Deserialize)]
struct LooseScope {
    #[serde(default)]
    allowed: Vec<serde_json::Value>,
    #[serde(default)]
    denied: Vec<serde_json::Value>,
}

fn parse_value_to_action(v: serde_json::Value) -> Option<ScopeAction> {
    if let Ok(act) = serde_json::from_value::<ScopeAction>(v.clone()) {
        Some(act)
    } else if let Ok(act) = serde_json::from_value::<Action>(v.clone()) {
        Some(ScopeAction::Standard(act))
    } else if let Some(s) = v.as_str() {
        Some(parse_action_str(s))
    } else {
        None
    }
}

pub fn parse_scope_loose(json_str: &str) -> Result<CapabilityScope, String> {
    if let Ok(scope) = serde_json::from_str::<CapabilityScope>(json_str) {
        return Ok(scope);
    }
    if let Ok(loose) = serde_json::from_str::<LooseScope>(json_str) {
        let allowed = loose.allowed.into_iter().filter_map(parse_value_to_action).collect();
        let denied = loose.denied.into_iter().filter_map(parse_value_to_action).collect();
        return Ok(CapabilityScope { allowed, denied });
    }
    Err("Invalid CapabilityScope JSON".into())
}
