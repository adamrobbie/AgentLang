import re

with open('src/runtime/mcp.rs', 'r') as f:
    text = f.read()

text = text.replace(
"""                if let Ok(res) = serde_json::from_str::<JsonRpcResponse>(&line) {
                    if let Some(id) = res.id {""",
"""                if let Ok(res) = serde_json::from_str::<JsonRpcResponse>(&line)
                    && let Some(id) = res.id
                {"""
)

with open('src/runtime/mcp.rs', 'w') as f:
    f.write(text)

