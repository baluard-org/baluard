//! `baluard mcp serve` — the CLI stdio transport (ADR 0116). The MCP
//! client spawns this process, so its parent is the coding agent; the
//! daemon resolves that parent chain itself (SO_PEERCRED + process walk)
//! and binds the volatile session to it. Every tool call proxies to the
//! daemon over IPC with the same policy stack the desktop transport uses.

use crate::client::request_agent;
use baluard_mcp::{mcp_action_for_tool, tool_definitions};
use baluard_proto::GatewayResponse;
use rmcp::handler::server::ServerHandler;
use rmcp::model::ErrorData as McpError;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, Content, Implementation, ListToolsResult,
    ProtocolVersion, ServerCapabilities, ServerInfo, Tool, ToolAnnotations,
};
use rmcp::service::{RequestContext, RoleServer, serve_server};
use rmcp::transport::io::stdio;
use std::borrow::Cow;
use std::sync::RwLock;

/// Runs the stdio server until the client disconnects.
pub fn run(vault_slug: Option<String>) -> anyhow::Result<()> {
    // 0083 hardening set: every inherited BALUARD_* variable is scrubbed
    // BEFORE any request, which also pins the daemon socket to its default
    // path (no BALUARD_SOCKET redirect), and stored CLI session tokens are
    // never loaded — request_agent presents nothing of the user's.
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("BALUARD_") {
            // SAFETY: runs before any thread or the tokio runtime exists,
            // so no concurrent reader can observe a torn environment.
            unsafe { std::env::remove_var(key) };
        }
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let service = StdioMcpServer::new(vault_slug);
        let running = serve_server(service, stdio())
            .await
            .map_err(|e| anyhow::anyhow!("mcp server failed to start: {e}"))?;
        let _ = running.waiting().await;
        anyhow::Ok(())
    })
}

#[derive(Clone)]
struct StdioMcpServer {
    vault_slug: Option<String>,
    session: std::sync::Arc<RwLock<Option<String>>>,
}

impl StdioMcpServer {
    fn new(vault_slug: Option<String>) -> Self {
        Self {
            vault_slug,
            session: std::sync::Arc::new(RwLock::new(None)),
        }
    }

    /// Establishes the volatile daemon session. Blocks while the human
    /// decides; the daemon bounds the wait at 60 seconds.
    fn establish_session_blocking(&self) -> Result<String, String> {
        let payload = serde_json::json!({ "slug": self.vault_slug });
        let resp = request_agent("agents.mcp_start", &payload.to_string(), "")
            .map_err(|e| e.to_string())?;
        if !resp.success {
            return Err(resp.error_message);
        }
        let value: serde_json::Value =
            serde_json::from_str(&resp.payload).map_err(|e| e.to_string())?;
        value
            .get("session_token")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| "daemon returned no session token".to_string())
    }

    fn ensure_session(&self) -> Result<String, String> {
        if let Some(token) = self.session.read().unwrap().clone() {
            return Ok(token);
        }
        let token = self.establish_session_blocking()?;
        *self.session.write().unwrap() = Some(token.clone());
        Ok(token)
    }

    fn shape(resp: GatewayResponse) -> CallToolResult {
        if resp.success {
            let structured = serde_json::from_str(&resp.payload).ok();
            CallToolResult {
                content: vec![Content::text(resp.payload)],
                structured_content: structured,
                is_error: Some(false),
                meta: None,
            }
        } else {
            tool_error(resp.error_message)
        }
    }

    /// One proxied tool call. Blocking IPC runs inside spawn_blocking at
    /// the call site; session loss (daemon restart) re-establishes once,
    /// which needs fresh human approval — fail closed, never re-minted
    /// silently.
    fn forward(&self, name: &str, args: &serde_json::Value) -> Result<CallToolResult, String> {
        if mcp_action_for_tool(name).is_none() {
            return Ok(tool_error("denied"));
        }
        let token = self.ensure_session()?;
        let payload = serde_json::json!({ "tool": name, "args": args });
        let resp = request_agent("agents.mcp_call", &payload.to_string(), &token)
            .map_err(|e| e.to_string())?;
        if !resp.success && resp.error_message.contains("no active MCP session") {
            *self.session.write().unwrap() = None;
            let token = self.ensure_session()?;
            let resp = request_agent("agents.mcp_call", &payload.to_string(), &token)
                .map_err(|e| e.to_string())?;
            return Ok(Self::shape(resp));
        }
        Ok(Self::shape(resp))
    }
}

fn tool_error(message: impl Into<String>) -> CallToolResult {
    // Machine-readable outcomes ride tool-level error results, not
    // protocol errors, so the agent sees the verdict text verbatim.
    CallToolResult::error(vec![Content::text(message.into())])
}

impl ServerHandler for StdioMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::default(),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation {
                name: "baluard".to_string(),
                title: Some("Baluard".to_string()),
                version: env!("CARGO_PKG_VERSION").to_string(),
                description: Some("Baluard password manager MCP endpoint (stdio)".to_string()),
                ..Default::default()
            },
            instructions: Some(
                "Read-only access to one vault. search_items returns metadata only; \
                 get_login and get_totp require the user's approval per read."
                    .to_string(),
            ),
        }
    }

    fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, McpError>> + Send + '_ {
        let tools: Vec<Tool> = tool_definitions()
            .into_iter()
            .map(|d| {
                let Ok(schema) = serde_json::from_value::<rmcp::model::JsonObject>(d.input_schema)
                else {
                    unreachable!("tool schemas are static and valid");
                };
                Tool {
                    name: Cow::Borrowed(d.name),
                    title: None,
                    description: Some(Cow::Borrowed(d.description)),
                    input_schema: std::sync::Arc::new(schema),
                    output_schema: None,
                    annotations: Some(ToolAnnotations {
                        title: None,
                        read_only_hint: Some(true),
                        destructive_hint: Some(false),
                        idempotent_hint: Some(true),
                        open_world_hint: Some(false),
                    }),
                    execution: None,
                    icons: None,
                    meta: None,
                }
            })
            .collect();
        std::future::ready(Ok(ListToolsResult::with_all_items(tools)))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let name = request.name.to_string();
        let args = serde_json::Value::Object(request.arguments.unwrap_or_default());
        // The blocking IPC hop runs off the async reactor. Client
        // cancellation is bounded by the daemon's 30-second approval
        // window; a vanished client just leaves the outcome unread.
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.forward(&name, &args))
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .map_err(|e| McpError::internal_error(e, None))
    }
}
