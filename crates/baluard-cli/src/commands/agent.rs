//! D80 `baluard run`: request a human-approved grant, then ask the daemon to
//! execute the child with approved environment injections.

use crate::client;
use zeroize::Zeroize;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Injection {
    name: String,
    item_id: String,
    field: String,
}

pub fn handle_run(
    direct: bool,
    socket: Option<&str>,
    injection_args: &[String],
    need: &str,
    argv: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    if direct {
        deny("agent run requires daemon mode; drop --direct");
    }
    if socket.is_some() {
        deny("agent run uses the default daemon socket; drop --socket");
    }
    if argv.is_empty() {
        deny("missing command after --");
    }
    let injections = match parse_injections(injection_args) {
        Ok(injections) => injections,
        Err(e) => deny(&e),
    };
    let item_ids: Vec<String> = injections
        .iter()
        .map(|injection| injection.item_id.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let claimed_name = std::env::var("BALUARD_AGENT_NAME").unwrap_or_else(|_| "local agent".into());
    let requested = match agent_call(
        "agents.request",
        serde_json::json!({
            "claimed_name": claimed_name,
            "need": need,
            "item_ids": item_ids,
        }),
        "",
    ) {
        Ok(value) => value,
        Err(e) => deny(&e),
    };
    let Some(request_id) = requested["request_id"].as_str().map(str::to_string) else {
        deny("daemon returned no agent request id");
    };

    let mut agent_token = zeroize::Zeroizing::new(String::new());
    for _ in 0..120 {
        let polled = match agent_call(
            "agents.poll",
            serde_json::json!({"request_id": request_id}),
            "",
        ) {
            Ok(value) => value,
            Err(e) => deny(&e),
        };
        match polled["status"].as_str().unwrap_or("unknown") {
            "pending" => std::thread::sleep(std::time::Duration::from_secs(1)),
            "approved" => {
                agent_token = zeroize::Zeroizing::new(
                    polled["token"].as_str().unwrap_or_default().to_string(),
                );
                break;
            }
            "denied" => deny("agent credential request was denied"),
            _ => deny("agent credential request expired"),
        }
    }
    if agent_token.is_empty() {
        deny("agent credential request timed out waiting for approval");
    }

    let result = match agent_call(
        "agents.run",
        serde_json::json!({
            "argv": argv,
            "inject": injections.iter().map(|injection| {
                serde_json::json!({
                    "name": injection.name,
                    "item_id": injection.item_id,
                    "field": injection.field,
                })
            }).collect::<Vec<_>>(),
        }),
        &agent_token,
    ) {
        Ok(value) => value,
        Err(e) => {
            agent_token.zeroize();
            deny(&e)
        }
    };
    use std::io::Write;
    print!("{}", result["stdout"].as_str().unwrap_or_default());
    std::io::stdout().flush().ok();
    eprint!("{}", result["stderr"].as_str().unwrap_or_default());
    std::io::stderr().flush().ok();
    let status = result["status"].as_i64().unwrap_or(1) as i32;
    if status != 0 {
        agent_token.zeroize();
        std::process::exit(status);
    }
    Ok(())
}

fn agent_call(
    action: &str,
    payload: serde_json::Value,
    token: &str,
) -> Result<serde_json::Value, String> {
    let response = client::request_agent(action, &payload.to_string(), token)
        .map_err(|e| format!("agent daemon request failed: {e}"))?;
    if !response.success {
        return Err(response.error_message);
    }
    serde_json::from_str(&response.payload)
        .map_err(|e| format!("invalid agent daemon response: {e}"))
}

pub fn handle_agent_action(
    action: crate::AgentAction,
    socket: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (route, payload) = match action {
        crate::AgentAction::Pending => ("agents.pending", serde_json::json!({})),
        crate::AgentAction::Approve { request_id } => (
            "agents.approve",
            serde_json::json!({"request_id": request_id}),
        ),
        crate::AgentAction::Deny { request_id } => {
            ("agents.deny", serde_json::json!({"request_id": request_id}))
        }
        crate::AgentAction::List => ("agents.list", serde_json::json!({})),
        crate::AgentAction::Revoke => ("agents.revoke", serde_json::json!({})),
    };
    let response = client::request_to(route, &payload.to_string(), socket)?;
    if !response.success {
        return Err(response.error_message.into());
    }
    println!("{}", response.payload);
    Ok(())
}

fn deny(reason: &str) -> ! {
    eprintln!("{}", serde_json::json!({"error": reason}));
    std::process::exit(1)
}

fn parse_injections(args: &[String]) -> Result<Vec<Injection>, String> {
    if args.is_empty() {
        return Err("at least one --inject NAME=ITEM_ID:FIELD is required".into());
    }
    args.iter()
        .map(|arg| {
            let (name, target) = arg
                .split_once('=')
                .ok_or_else(|| format!("invalid injection '{arg}': expected NAME=ITEM_ID:FIELD"))?;
            let (item_id, field) = target
                .split_once(':')
                .ok_or_else(|| format!("invalid injection '{arg}': missing field"))?;
            if !valid_env_name(name) || name.to_ascii_uppercase().starts_with("BALUARD_") {
                return Err(format!("invalid environment name '{name}'"));
            }
            uuid::Uuid::parse_str(item_id).map_err(|_| format!("invalid item id '{item_id}'"))?;
            let is_custom = field
                .strip_prefix("custom:")
                .is_some_and(|name| !name.is_empty());
            if !matches!(field, "username" | "password" | "totp") && !is_custom {
                return Err(format!("field '{field}' is not allowed"));
            }
            Ok(Injection {
                name: name.to_string(),
                item_id: item_id.to_string(),
                field: field.to_string(),
            })
        })
        .collect()
}

fn valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_login_and_custom_field_injections() {
        let id = uuid::Uuid::new_v4();
        let parsed = parse_injections(&[
            format!("LOGIN_USER={id}:username"),
            format!("LOGIN_PASS={id}:password"),
            format!("API_KEY={id}:custom:api-key"),
            format!("OTP={id}:totp"),
        ])
        .unwrap();
        assert_eq!(parsed.len(), 4);
        assert_eq!(parsed[1].name, "LOGIN_PASS");
        assert_eq!(parsed[2].field, "custom:api-key");
    }

    #[test]
    fn rejects_malformed_or_forbidden_injections() {
        let id = uuid::Uuid::new_v4();
        for bad in [
            "MISSING_DELIMITERS".to_string(),
            format!("1BAD={id}:password"),
            format!("BALUARD_TOKEN={id}:password"),
            format!("TOKEN=not-a-uuid:password"),
            format!("TOKEN={id}:notes"),
            format!("TOKEN={id}:custom:"),
        ] {
            assert!(parse_injections(&[bad]).is_err());
        }
        assert!(parse_injections(&[]).is_err());
    }
}
