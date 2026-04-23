use crate::ast;
use crate::ast::GoalFailureType;
use crate::runtime::{AgentError, Context};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot, Mutex};

/// Basic JSON-RPC 2.0 structures for MCP
#[derive(Serialize)]
struct JsonRpcRequest {
    jsonrpc: &'static str,
    id: u64,
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<JsonValue>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: Option<u64>,
    result: Option<JsonValue>,
    error: Option<JsonValue>,
}

#[derive(Serialize)]
struct JsonRpcNotification {
    jsonrpc: &'static str,
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<JsonValue>,
}

/// A generic async JSON-RPC client over Stdio
pub struct McpClient {
    next_id: Arc<std::sync::atomic::AtomicU64>,
    sender: mpsc::Sender<String>,
    pending_requests: Arc<Mutex<HashMap<u64, oneshot::Sender<Result<JsonValue>>>>>,
}

impl McpClient {
    pub async fn spawn(command: &str, args: &[String]) -> Result<Arc<Self>> {
        let mut child = Command::new(command)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| anyhow!("Failed to spawn MCP server: {}", e))?;

        let mut stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();

        let (tx, mut rx) = mpsc::channel::<String>(32);
        let pending_requests = Arc::new(Mutex::new(HashMap::<u64, oneshot::Sender<Result<JsonValue>>>::new()));

        // Writer task
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                let msg = format!("{}\n", msg);
                if stdin.write_all(msg.as_bytes()).await.is_err() {
                    break;
                }
            }
        });

        // Reader task
        let pending = pending_requests.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                if let Ok(res) = serde_json::from_str::<JsonRpcResponse>(&line)
                    && let Some(id) = res.id
                {
                    let mut p = pending.lock().await;
                    if let Some(sender) = p.remove(&id) {
                        if let Some(err) = res.error {
                            let _ = sender.send(Err(anyhow!("JSON-RPC Error: {:?}", err)));
                        } else if let Some(result) = res.result {
                            let _ = sender.send(Ok(result));
                        } else {
                            let _ = sender.send(Err(anyhow!("Missing result and error in JSON-RPC response")));
                        }
                    }
                }
                line.clear();
            }
        });

        Ok(Arc::new(Self {
            next_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            sender: tx,
            pending_requests,
        }))
    }

    pub async fn request(&self, method: &str, params: Option<JsonValue>) -> Result<JsonValue> {
        let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            id,
            method: method.to_string(),
            params,
        };

        let msg = serde_json::to_string(&req)?;
        let (tx, rx) = oneshot::channel();
        self.pending_requests.lock().await.insert(id, tx);
        
        self.sender.send(msg).await.map_err(|_| anyhow!("MCP Client writer dropped"))?;
        
        rx.await.map_err(|_| anyhow!("MCP Request timed out or dropped"))?
    }

    pub async fn notify(&self, method: &str, params: Option<JsonValue>) -> Result<()> {
        let notif = JsonRpcNotification {
            jsonrpc: "2.0",
            method: method.to_string(),
            params,
        };
        let msg = serde_json::to_string(&notif)?;
        self.sender.send(msg).await.map_err(|_| anyhow!("MCP Client writer dropped"))?;
        Ok(())
    }
}

pub async fn load_mcp_servers(ctx: Arc<Context>, command: String, args: Vec<String>) -> Result<()> {
    // 1. Setup transport & client
    let client = McpClient::spawn(&command, &args).await?;
    
    // 2. Initialize
    let init_params = serde_json::json!({
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {
            "name": "AgentLang",
            "version": "0.1.0"
        }
    });
    
    let _init_res = client.request("initialize", Some(init_params)).await?;
    client.notify("notifications/initialized", None).await?;

    // 3. List Tools
    let tools_res = client.request("tools/list", None).await?;
    
    let mut tool_defs = ctx.tools.lock().unwrap();
    let mut tool_handlers = ctx.tool_handlers.lock().unwrap();

    let tools_array = tools_res.get("tools")
        .and_then(|t| t.as_array())
        .ok_or_else(|| anyhow!("Expected 'tools' array in tools/list response"))?;

    for tool in tools_array {
        let name = tool.get("name").and_then(|n| n.as_str()).unwrap_or_default().to_string();
        let description = tool.get("description").and_then(|d| d.as_str()).unwrap_or_default().to_string();
        let input_schema = tool.get("inputSchema").cloned().unwrap_or(serde_json::json!({}));

        let mut inputs = Vec::new();
        if let Some(props) = input_schema.get("properties").and_then(|p| p.as_object()) {
            let required_fields = input_schema.get("required")
                .and_then(|r| r.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<&str>>())
                .unwrap_or_default();

            for (key, prop) in props {
                let type_str = prop.get("type").and_then(|t| t.as_str()).unwrap_or("string");
                let type_hint = match type_str {
                    "number" | "integer" => "number",
                    "boolean" => "boolean",
                    _ => "text",
                }.to_string();

                inputs.push(ast::ToolField {
                    name: key.clone(),
                    type_hint,
                    required: required_fields.contains(&key.as_str()),
                    annotations: vec![],
                });
            }
        }

        let def = ast::ToolDefinition {
            name: name.clone(),
            description: Some(description),
            category: Some(ast::ToolCategory::Read), // Default for now
            version: Some("1.0.0".to_string()),
            inputs,
            outputs: vec![],
            reversible: false,
            side_effect: true,
            rate_limit: None,
            timeout: Some(30.0),
        };
        
        println!("  [MCP] Loaded tool: {}", def.name);

        let tool_name = name.clone();
        let mcp_client = client.clone();

        // 4. Create handler closure
        let handler = Arc::new(move |args: HashMap<String, ast::AnnotatedValue>| {
            let tool_name = tool_name.clone();
            let mcp_client = mcp_client.clone();
            
            let res: Result<ast::AnnotatedValue> = tokio::task::block_in_place(move || {
                tokio::runtime::Handle::current().block_on(async move {
                    let mut json_args = serde_json::Map::new();
                    for (k, v) in args {
                        json_args.insert(k, value_to_json(&v.value));
                    }

                    let call_params = serde_json::json!({
                        "name": tool_name,
                        "arguments": json_args
                    });

                    let call_res = mcp_client.request("tools/call", Some(call_params))
                        .await
                        .map_err(|e| anyhow!(AgentError {
                            failure_type: GoalFailureType::ToolFail,
                            message: format!("MCP Request failed: {:?}", e),
                        }))?;

                    let content_array = call_res.get("content")
                        .and_then(|c| c.as_array())
                        .ok_or_else(|| anyhow!(AgentError {
                            failure_type: GoalFailureType::ToolFail,
                            message: "Missing 'content' in MCP tools/call response".to_string(),
                        }))?;

                    let mut contents = Vec::new();
                    for content in content_array {
                        if let Some(text) = content.get("text").and_then(|t| t.as_str()) {
                            contents.push(ast::AnnotatedValue::from(ast::Value::Text(text.to_string())));
                        } else if let Some(data) = content.get("data").and_then(|t| t.as_str()) {
                            contents.push(ast::AnnotatedValue::from(ast::Value::Text(data.to_string())));
                        }
                    }

                    if contents.len() == 1 {
                        Ok(contents.pop().unwrap())
                    } else {
                        Ok(ast::AnnotatedValue::from(ast::Value::List(contents)))
                    }
                })
            });

            res
        });

        tool_defs.insert(name.clone(), def);
        tool_handlers.insert(name.clone(), handler);
    }

    Ok(())
}

fn value_to_json(val: &ast::Value) -> JsonValue {
    match val {
        ast::Value::Number(n) => JsonValue::Number(serde_json::Number::from_f64(*n).unwrap()),
        ast::Value::Text(t) => JsonValue::String(t.clone()),
        ast::Value::Boolean(b) => JsonValue::Bool(*b),
        ast::Value::List(l) => JsonValue::Array(l.iter().map(|v| value_to_json(&v.value)).collect()),
        ast::Value::Object(o) => {
            let mut map = serde_json::Map::new();
            for (k, v) in o {
                map.insert(k.clone(), value_to_json(&v.value));
            }
            JsonValue::Object(map)
        }
        ast::Value::Null => JsonValue::Null,
    }
}