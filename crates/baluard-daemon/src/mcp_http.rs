//! The desktop HTTP transport: rmcp Streamable HTTP on a fixed loopback
//! port, guarded by Host validation and browser-Origin rejection (ADR
//! 0116). Pairing tokens arrive on the Authorization header and are
//! verified constant-time against the hashed registry before any policy
//! runs. Bind failure fails closed and surfaces in Settings.

use crate::host::SharedVaultHost;
use crate::mcp::MCP_REGISTRY;
use baluard_mcp::tool_definitions;
use rmcp::handler::server::ServerHandler;
use rmcp::model::ErrorData as McpError;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, Content, Implementation, ListToolsResult,
    ProtocolVersion, ServerCapabilities, ServerInfo, Tool, ToolAnnotations,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use std::borrow::Cow;
use std::sync::Mutex;

pub(crate) const MCP_DEFAULT_PORT: u16 = 17990;

#[derive(Debug, Clone)]
struct ServerStatus {
    running: bool,
    port: u16,
    error: Option<String>,
}

static SERVER_STATUS: Mutex<Option<ServerStatus>> = Mutex::new(None);

/// What `mcp.status` reports: bound port, or the fail-closed bind error.
pub(crate) fn server_status_json() -> serde_json::Value {
    let guard = SERVER_STATUS.lock().unwrap();
    match guard.as_ref() {
        Some(status) => serde_json::json!({
            "running": status.running,
            "port": status.port,
            "error": status.error,
        }),
        None => serde_json::json!({ "running": false, "port": null, "error": "not started" }),
    }
}

fn set_status(status: ServerStatus) {
    *SERVER_STATUS.lock().unwrap() = Some(status);
}

/// Spawns the loopback HTTP server. A bind failure returns Err (the daemon
/// logs it and `mcp.status` reports it) instead of silently serving on a
/// mismatched port. `BALUARD_MCP_PORT` overrides the fixed default for
/// hermetic tests.
pub async fn spawn_server(host: SharedVaultHost) -> Result<u16, String> {
    let port: u16 = std::env::var("BALUARD_MCP_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(MCP_DEFAULT_PORT);
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .map_err(|e| format!("cannot bind mcp endpoint on 127.0.0.1:{port}: {e}"))?;
    let session_manager = std::sync::Arc::new(LocalSessionManager::default());
    let service: StreamableHttpService<McpHttpHandler, LocalSessionManager> =
        StreamableHttpService::new(
            move || Ok(McpHttpHandler { host: host.clone() }),
            session_manager,
            StreamableHttpServerConfig {
                stateful_mode: true,
                ..Default::default()
            },
        );
    let app = axum::Router::new()
        .route_service("/mcp", service)
        .layer(axum::middleware::from_fn(host_origin_guard));
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            log::warn!("[mcp] http server stopped: {e}");
            set_status(ServerStatus {
                running: false,
                port,
                error: Some(format!("server stopped: {e}")),
            });
        }
    });
    set_status(ServerStatus {
        running: true,
        port,
        error: None,
    });
    Ok(port)
}

/// DNS-rebinding defense: only loopback Host values pass, and browser
/// Origins are rejected outright — MCP clients never send Origin.
async fn host_origin_guard(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::{StatusCode, header};
    use axum::response::IntoResponse;
    let host_ok = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(|h| {
            let h = h.to_ascii_lowercase();
            h.starts_with("127.0.0.1:") || h.starts_with("localhost:")
        })
        .unwrap_or(false);
    if !host_ok {
        return (StatusCode::FORBIDDEN, "invalid host").into_response();
    }
    if req.headers().contains_key(header::ORIGIN) {
        return (StatusCode::FORBIDDEN, "browser origins are rejected").into_response();
    }
    next.run(req).await
}

struct McpHttpHandler {
    host: SharedVaultHost,
}

fn tool_error(message: impl Into<String>) -> CallToolResult {
    // Machine-readable outcomes ride tool-level error results, not
    // protocol errors, so the agent sees the verdict text verbatim.
    CallToolResult::error(vec![Content::text(message.into())])
}

fn extract_pairing_token(ctx: &RequestContext<RoleServer>) -> Option<String> {
    let parts = ctx.extensions.get::<http::request::Parts>()?;
    let value = parts
        .headers
        .get(http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "));
    Some(token?.trim().to_string())
}

impl ServerHandler for McpHttpHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::default(),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation {
                name: "baluard".to_string(),
                title: Some("Baluard".to_string()),
                version: env!("CARGO_PKG_VERSION").to_string(),
                description: Some("Baluard password manager MCP endpoint".to_string()),
                ..Default::default()
            },
            instructions: Some(
                "Read-only access to one vault. search_items returns metadata only; \
                 get_login and get_totp require the user's approval per read."
                    .to_string(),
            ),
        }
    }

    async fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
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
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let Some(token) = extract_pairing_token(&context) else {
            return Ok(tool_error("denied: missing pairing token"));
        };
        let pairing = match MCP_REGISTRY.verify_pairing(&token) {
            Ok(p) => p,
            Err(e) => return Ok(tool_error(format!("denied: {e}"))),
        };
        let args = serde_json::Value::Object(request.arguments.clone().unwrap_or_default());
        let resp = crate::mcp::http_tool_call(&self.host, pairing, &request.name, &args).await;
        if resp.success {
            let structured = serde_json::from_str(&resp.payload).ok();
            Ok(CallToolResult {
                content: vec![Content::text(resp.payload)],
                structured_content: structured,
                is_error: Some(false),
                meta: None,
            })
        } else {
            Ok(tool_error(resp.error_message))
        }
    }
}
