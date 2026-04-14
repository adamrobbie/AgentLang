## Summary
Upgrade inter-agent communication on top of the merged `main` baseline by introducing structured remote call envelopes for `CALL` / `AWAIT` and aligning the gRPC service with JSON-backed `AnnotatedValue` argument transport.

## Context
The current branch already had the core expression, goal, and annotation groundwork from the merged Phase 1 work, but remote agent calls still had an inconsistent result contract. The runtime mixed raw remote results with pending call state, and the gRPC service still relied on heuristic string parsing for incoming arguments. This PR makes remote-call behavior consistent and easier to consume from AgentLang programs.

## Changes
- add structured pending/completed/failed remote call envelopes in the runtime
- store pending call receivers consistently and resolve them through `AWAIT`
- persist a `{call_id}.result` alias alongside the full envelope for convenient nested access
- switch service-side call argument decoding to prefer JSON `AnnotatedValue` payloads with backward-compatible fallback parsing
- update gRPC integration assertions and add focused runtime tests for envelope lifecycle helpers

## Key Implementation Details
### Runtime
- `CALL` now immediately stores a pending envelope with metadata and `result: null`
- the spawned remote task resolves to a completed or failed envelope instead of a bare payload
- `AWAIT` stores the completed envelope back into working memory and persists the `.result` alias

### Service
- request arguments are decoded with `serde_json` into `AnnotatedValue` first
- existing primitive/text fallback parsing is preserved when JSON decoding fails

### Test coverage added
- pending envelope shape
- completed envelope persistence plus `.result` alias
- `AWAIT` storing a completed envelope
- gRPC inter-agent call returning the structured envelope contract

## Use Cases
- inspect remote call lifecycle via fields like `status`, `agent_id`, `goal_name`, and `result`
- access the remote payload directly through `{remote_res.result}`
- send structured/annotated argument values over RPC without degrading them to debug strings

## Testing
Passed locally:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features
cargo test --all
```
