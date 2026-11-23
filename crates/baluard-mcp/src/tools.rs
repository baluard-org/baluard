//! Tool registry, request-to-capability mapping, and the JSON schemas the
//! transports advertise over `tools/list`. Pure data; both front-ends serve
//! the same definitions so CLI and desktop never drift.

pub const TOOL_SEARCH: &str = "search_items";
pub const TOOL_GET_LOGIN: &str = "get_login";
pub const TOOL_GET_TOTP: &str = "get_totp";

/// The capability a tool call maps to. Everything else is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpAction {
    Search,
    GetLogin,
    GetTotp,
}

pub fn mcp_action_for_tool(name: &str) -> Option<McpAction> {
    match name {
        TOOL_SEARCH => Some(McpAction::Search),
        TOOL_GET_LOGIN => Some(McpAction::GetLogin),
        TOOL_GET_TOTP => Some(McpAction::GetTotp),
        _ => None,
    }
}

/// One tool definition, transport-neutral. Front-ends convert this into
/// their SDK's tool type.
#[derive(Debug, Clone)]
pub struct ToolDesc {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: serde_json::Value,
}

fn object_schema(properties: serde_json::Value, required: &[&str]) -> serde_json::Value {
    let required: Vec<serde_json::Value> = required
        .iter()
        .map(|s| serde_json::Value::String((*s).to_string()))
        .collect();
    serde_json::json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false,
    })
}

/// The v1 read-only surface. Order is the advertised order.
pub fn tool_definitions() -> Vec<ToolDesc> {
    vec![
        ToolDesc {
            name: TOOL_SEARCH,
            description: "Search vault entries by name or username. Returns ids, names, \
                          usernames, and site URIs. Never returns passwords or secrets. \
                          Requires a non-empty query; at most 20 results.",
            input_schema: object_schema(
                serde_json::json!({
                    "query": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 200,
                        "description": "Text to match against entry names and usernames",
                    }
                }),
                &["query"],
            ),
        },
        ToolDesc {
            name: TOOL_GET_LOGIN,
            description: "Read one login entry's username, password, and custom fields by id. \
                          Requires the user's approval per read. Use search_items first to \
                          find the id. Never returns TOTP seeds.",
            input_schema: object_schema(
                serde_json::json!({
                    "item_id": {
                        "type": "string",
                        "description": "Entry id from search_items",
                    }
                }),
                &["item_id"],
            ),
        },
        ToolDesc {
            name: TOOL_GET_TOTP,
            description: "Read one entry's current two-factor code by id. Requires the user's \
                          approval per read. Fails cleanly when the entry has no TOTP.",
            input_schema: object_schema(
                serde_json::json!({
                    "item_id": {
                        "type": "string",
                        "description": "Entry id from search_items",
                    }
                }),
                &["item_id"],
            ),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_tools_map_to_actions_and_everything_else_is_refused() {
        assert_eq!(mcp_action_for_tool(TOOL_SEARCH), Some(McpAction::Search));
        assert_eq!(
            mcp_action_for_tool(TOOL_GET_LOGIN),
            Some(McpAction::GetLogin)
        );
        assert_eq!(mcp_action_for_tool(TOOL_GET_TOTP), Some(McpAction::GetTotp));
        assert_eq!(mcp_action_for_tool("list_folders"), None);
        assert_eq!(mcp_action_for_tool("write_item"), None);
        assert_eq!(mcp_action_for_tool(""), None);
    }

    #[test]
    fn definitions_carry_valid_schemas_and_required_fields() {
        let defs = tool_definitions();
        assert_eq!(defs.len(), 3);
        for def in &defs {
            assert_eq!(def.input_schema["type"], "object");
            assert!(def.input_schema["required"].is_array());
            assert!(!def.description.is_empty());
            assert!(mcp_action_for_tool(def.name).is_some());
        }
        // search requires query; gets require item_id.
        assert_eq!(defs[0].input_schema["required"][0], "query");
        assert_eq!(defs[1].input_schema["required"][0], "item_id");
        assert_eq!(defs[2].input_schema["required"][0], "item_id");
    }
}
