**Title:** Migrate AST evaluation functions to `async` to prevent Bastion thread-pool exhaustion during heavy MCP I/O

**Labels:** `technical-debt`, `enhancement`, `mcp`, `runtime`

### Description

Currently, the AgentLang AST execution evaluates tool calls synchronously. This was originally designed because simple, in-memory tool closures didn't need to block on I/O. However, with the introduction of the new asynchronous MCP (Model Context Protocol) integration in `src/runtime/mcp.rs`, our dynamically generated tool closures must wait for JSON-RPC 2.0 requests to travel over `stdio` to an external process.

Because the closures stored in `ctx.tool_handlers` are synchronous (`Arc<dyn Fn(HashMap<String, ast::AnnotatedValue>) -> Result<ast::AnnotatedValue>>`), we are currently bridging the sync-async divide by spawning a blocking Tokio task inside the Bastion actor execution pool:

```rust
let res: Result<ast::AnnotatedValue> = tokio::task::block_in_place(move || {
    tokio::runtime::Handle::current().block_on(async move {
        // ... Await MCP tools/call JSON-RPC ...
    })
});
```

### The Problem

`tokio::task::block_in_place` yields the current Tokio worker thread to another async task (avoiding classic async starvation), but it still inherently blocks the Bastion supervisor's computation pool while waiting for the MCP server to respond. If an AgentLang program attempts to run a large number of concurrent `USE tool` statements (e.g., inside a `PARALLEL` or `RACE` block), and the target MCP servers are slow (e.g., querying an LLM or waiting on network I/O), we will rapidly exhaust the Bastion thread pool, causing the entire runtime to bottleneck or deadlock.

### Proposed Solution

We need to make the entire AST evaluation chain properly asynchronous. 

1. **Update `ToolHandler` Signature:**
   Change the `tool_handlers` definition in `Context` to return a `BoxFuture` (or simply an `async fn` if using a trait).
   ```rust
   // Current:
   type ToolHandler = Arc<dyn Fn(HashMap<String, ast::AnnotatedValue>) -> Result<ast::AnnotatedValue> + Send + Sync>;
   
   // Target:
   type ToolHandler = Arc<dyn Fn(HashMap<String, ast::AnnotatedValue>) -> BoxFuture<'static, Result<ast::AnnotatedValue>> + Send + Sync>;
   ```

2. **Rewrite `eval` Functions in `src/runtime/eval.rs`:**
   Almost all evaluation functions inside `eval.rs` that touch expressions (and subsequently tools) must become `async fn`.
   - `eval_expression` needs to `await` the tool handler if the expression resolves to a tool call.
   - Any AST node evaluating arguments (like `IF`, `SET`, `USE`, `PARALLEL`) will need to safely `await` the child expressions.
   
3. **Remove `block_in_place` from `src/runtime/mcp.rs`:**
   Once the AST natively supports async evaluation, we can remove the `block_in_place` hack and simply return the `async move { ... }` block directly from the MCP tool registry closure.

### Impact

This is a highly invasive refactor touching the core execution loop (`eval.rs`, `call.rs`, `goal.rs`), but it is critical for productionizing AgentLang's orchestration capabilities. Natively awaiting I/O will let the runtime scale to thousands of concurrent MCP tool invocations without locking up the Bastion actor model.