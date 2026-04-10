# AgentLang Implementation Roadmap

**Date:** 2026-04-10  
**Basis:** Comparison of the draft language spec against the current Rust implementation  
**Goal:** Turn the verified feature-gap analysis into an execution roadmap with concrete tasks, dependency order, and implementation risk.

---

## 1. Current baseline

The current codebase already has a stable prototype foundation:

- parser and AST for a subset of the language in `src/ast.rs` and `src/parser.rs`
- runtime execution for goals, control flow, memory, events, proofs, WASM, and inter-agent calls in `src/runtime.rs`
- gRPC registry and agent service scaffolding in `src/main.rs`, `proto/agent.proto`, and `proto/registry.proto`
- clean quality baseline from prior work: build, clippy, fmt, and tests passing

However, the implementation is still materially narrower than the spec in areas such as structured values, outputs, tool declarations, versioning, trust/federation semantics, memory backends, and semantic proof behavior.

---

## 2. Sequencing principles

Implement in this order:

1. **Strengthen the language core first**
   - AST, values, expressions, and parser coverage must be improved before higher-level features can be implemented cleanly.
2. **Add execution semantics second**
   - goal outputs, failure categories, annotations, and tool semantics should sit on top of a richer core model.
3. **Deepen platform features third**
   - communication, contracts, trust, federation, and registry lifecycle can be expanded after the language model stabilizes.
4. **Swap prototype infrastructure last**
   - database/vector backends and semantic proof workflows should come after the public language/runtime behavior is settled.

---

## 3. Phase-by-phase roadmap

## Phase 0 — Protect the working baseline

**Objective:** Keep the current project stable while larger refactors land.

**Primary code areas:**
- `src/parser.rs`
- `src/runtime.rs`
- `src/main.rs`

**Tasks:**
1. Preserve the current quality gates in local workflow and CI.
2. Add focused regression tests before refactoring parser and runtime hotspots.
3. Keep feature work behind small, reviewable commits.
4. Re-run `cargo check`, `cargo clippy --all-targets --all-features`, `cargo fmt --all --check`, and `cargo test --all` after each phase.

**Difficulty:** Low  
**Risk:** Low

**Why this phase matters:**
The parser/runtime coupling is tight, and later phases will touch central execution paths. A stable baseline reduces rework and regression risk.

**Exit criteria:**
- existing tests still pass
- new parser/runtime tests added before structural refactors
- no phase merges with failing lint/build/test results

---

## Phase 1 — Upgrade the core value and expression model

**Objective:** Make the language capable of representing structured results and nested references from the spec.

**Primary code areas:**
- `src/ast.rs`
- `src/parser.rs`
- `src/runtime.rs`

**Tasks:**
1. Extend `Value` beyond `Text`, `Number`, `Boolean`, and `List`.
2. Introduce structured/object values to support named goal outputs and event payloads.
3. Replace flat `VariableRef(String)` handling with path-aware access.
4. Add parser support for:
   - `{foo.bar}`
   - `{items[0]}`
   - nested access chains
5. Update expression evaluation to resolve dot/index paths.
6. Add parser/runtime tests for nested reads and invalid path behavior.

**Suggested design moves:**
- add `Value::Object(...)`
- optionally add `Value::Null`
- model path segments explicitly in the AST

**Difficulty:** High  
**Risk:** Medium-High

**Why this phase matters:**
This phase unlocks confidence access, output objects, event payload access, and better inter-agent/tool result handling.

**Exit criteria:**
- nested field access works end-to-end
- list indexing works end-to-end
- structured values can be stored and retrieved through runtime memory
- parser and runtime tests cover path resolution behavior

---

## Phase 2 — Implement structured goal results and outputs

**Objective:** Bring `GOAL` result behavior closer to the spec.

**Primary code areas:**
- `src/ast.rs`
- `src/parser.rs`
- `src/runtime.rs`

**Tasks:**
1. Extend goal AST representation to include output/result metadata.
2. Parse `OUTPUT ... END` blocks.
3. Parse richer `RESULT INTO {var}` semantics where appropriate.
4. Define a stable runtime convention for goal result storage.
5. Store named goal outputs as structured values.
6. Add tests for downstream access such as `{goal_name.output_field}`.

**Suggested design moves:**
- represent goal outputs as a structured object value
- standardize where goal results are written into working memory
- align result naming so later parallel and call aggregation can reuse the same model

**Difficulty:** High  
**Risk:** Medium

**Why this phase matters:**
The spec assumes goals produce usable structured outputs. Without that, confidence-driven flow and compositional orchestration remain awkward.

**Exit criteria:**
- `OUTPUT` blocks parse correctly
- goal execution stores structured output data
- downstream expressions can read named outputs reliably

---

## Phase 3 — Complete annotation and type semantics

**Objective:** Turn annotation flags into actual language behavior.

**Primary code areas:**
- `src/ast.rs`
- `src/parser.rs`
- `src/runtime.rs`

**Tasks:**
1. Define propagation rules for confidence-bearing values.
2. Support confidence access patterns enabled by Phase 1/2.
3. Enforce stricter rules for `AS uncertain` before irreversible actions.
4. Tighten `AS sensitive` handling so raw value materialization follows explicit policy.
5. Add a coercion layer for safe/conditional conversions where the spec requires them.
6. Add tests covering approximate comparisons, uncertain actions, and sensitive-access behavior.

**Difficulty:** Medium-High  
**Risk:** Medium-High

**Why this phase matters:**
The project already stores annotation metadata, but the spec promises semantic behavior, not just flags.

**Exit criteria:**
- confidence metadata is observable and usable in conditions
- uncertain values cannot silently flow into irreversible operations
- sensitive-value handling is consistent across memory, emit, call, and reveal paths

---

## Phase 4 — Expand goal directives and failure handling

**Objective:** Replace ad hoc failure routing with spec-aligned execution semantics.

**Primary code areas:**
- `src/ast.rs`
- `src/parser.rs`
- `src/runtime.rs`

**Tasks:**
1. Introduce an internal failure-category model instead of string-matching errors.
2. Expand goal directive parsing for missing options such as:
   - `WAIT`
   - `AUDIT_TRAIL`
   - `CONFIRM_WITH`
   - `TIMEOUT_CONFIRMATION`
3. Support typed `ON_FAIL[...]` handling more robustly.
4. Define a confirmation workflow for irreversible actions.
5. Improve audit behavior for goal execution and sensitive operations.
6. Add tests for timeout, permission, and tool-failure routing.

**Difficulty:** Medium-High  
**Risk:** Medium

**Why this phase matters:**
Current failure handling is workable for a prototype, but it is too coarse for the language model promised by the spec.

**Exit criteria:**
- failures are classified using an internal model
- goal directives parse and execute consistently
- `ON_FAIL[type]` behavior is test-covered and deterministic

---

## Phase 5 — Build the real tool system

**Objective:** Replace the current mock `USE` behavior with actual tool declarations and policy-aware execution.

**Primary code areas:**
- `src/ast.rs`
- `src/parser.rs`
- `src/runtime.rs`

**Tasks:**
1. Add AST support for `TOOL` declarations.
2. Parse tool metadata such as input/output schema, category, version, reversibility, and timeout.
3. Add a runtime tool registry or tool catalog.
4. Validate tool arguments against declared schemas.
5. Replace mock results with real execution adapters.
6. Enforce confirmation, timeout, and side-effect policies.
7. Add tests for declared-tool parsing and runtime policy enforcement.

**Optional extension in this phase:**
- start a simple built-in standard library adapter model before tackling broader external adapters

**Difficulty:** High  
**Risk:** High

**Why this phase matters:**
This is one of the largest gaps between the spec and the current implementation.

**Exit criteria:**
- `TOOL` declarations parse and register successfully
- `USE` resolves declared tool metadata
- runtime validates tool inputs/outputs and enforces policy

---

## Phase 6 — Improve parallel semantics and aggregation

**Objective:** Make parallel blocks return meaningful results instead of only a success flag.

**Primary code areas:**
- `src/ast.rs`
- `src/parser.rs`
- `src/runtime.rs`

**Tasks:**
1. Redesign parallel result collection to return structured branch outcomes.
2. Implement better semantics for:
   - `GATHER`
   - `GATHER_ALL`
   - `GATHER_MIN`
   - `RACE` / `FIRST_INTO`
3. Add support for `ON_PARTIAL_FAIL` and `ON_ALL_FAIL`.
4. Add support for `TRUST_INHERIT` semantics if retained from the spec.
5. Add tests for partial success/failure and collected outputs.

**Difficulty:** Medium-High  
**Risk:** Medium

**Why this phase matters:**
Once outputs are structured, parallel orchestration becomes much more useful and much closer to the spec.

**Exit criteria:**
- parallel blocks can store aggregated results
- failure policies are explicit and testable
- race/gather behavior is no longer boolean-only

---

## Phase 7 — Expand communication semantics

**Objective:** Move beyond basic `CALL`/`AWAIT` toward the fuller agent-communication model.

**Primary code areas:**
- `src/ast.rs`
- `src/parser.rs`
- `src/runtime.rs`
- `src/main.rs`
- `proto/agent.proto`

**Tasks:**
1. Add `DELEGATE` support in the AST, parser, and runtime.
2. Extend `CALL` handling with richer metadata such as timeout and trust/verification settings.
3. Improve event payload modeling so handlers can access structured event data.
4. Add correlation IDs or stronger call tracking semantics.
5. Update agent RPC payloads if needed to support richer call metadata.
6. Add tests for request/response, delegate-and-forget, and event subscription paths.

**Difficulty:** High  
**Risk:** High

**Why this phase matters:**
The current communication layer proves the concept, but it does not yet match the communication surface described in the spec.

**Exit criteria:**
- `DELEGATE` exists and works
- richer call metadata is parsed and honored
- event payloads can be consumed structurally by handlers

---

## Phase 8 — Deepen contracts, trust, and registry lifecycle

**Objective:** Expand the trust model from simple permission checks to a more complete agent-platform policy layer.

**Primary code areas:**
- `src/ast.rs`
- `src/parser.rs`
- `src/runtime.rs`
- `src/main.rs`
- `proto/registry.proto`

**Tasks:**
1. Extend contract parsing beyond simple `CAN USE` / `CANNOT USE` rules.
2. Add stronger trust-level enforcement in runtime execution paths.
3. Add registry lifecycle operations such as verify, revoke, renew, and federate if they remain in scope.
4. Model richer registry state and contract validation behavior.
5. Add tests for trust restrictions and contract edge cases.

**Difficulty:** High  
**Risk:** High

**Why this phase matters:**
The spec positions trust and registry behavior as first-class concerns, but the current implementation is still minimal.

**Exit criteria:**
- trust levels affect runtime behavior in meaningful ways
- registry API surface supports more than registration and lookup
- contract structure is rich enough to encode real policy

---

## Phase 9 — Replace prototype memory backends with spec-aligned storage

**Objective:** Move from JSON files and mutex maps toward the backend architecture implied by the spec.

**Primary code areas:**
- `src/runtime.rs`
- `src/main.rs`
- `Cargo.toml`

**Tasks:**
1. Introduce a storage abstraction layer for working, session, long-term, and shared memory.
2. Replace session storage with a higher-concurrency structure.
3. Replace JSON-file long-term memory with database-backed persistence.
4. Replace substring fuzzy recall with vector-backed retrieval.
5. Add expiry enforcement and threshold-aware fuzzy retrieval.
6. Add migration/test strategy for persistence-backed memory behavior.

**Likely dependency additions:**
- `dashmap`
- `sqlx`
- a pgvector integration crate or equivalent stack

**Difficulty:** High  
**Risk:** Very High

**Why this phase matters:**
This phase aligns implementation architecture with the spec, but it is invasive and should be deferred until the language model is more stable.

**Exit criteria:**
- long-term/shared memory no longer rely on local JSON files
- fuzzy recall is no longer simple substring matching
- expiry behavior is enforced in storage and retrieval logic

---

## Phase 10 — Make proof semantics meaningful

**Objective:** Move from proof plumbing to spec-level proof semantics.

**Primary code areas:**
- `src/ast.rs`
- `src/parser.rs`
- `src/runtime.rs`
- `src/crypto.rs`

**Tasks:**
1. Add claim-oriented proof syntax and AST coverage.
2. Bind proofs to actual claims, permissions, or selective-disclosure policies.
3. Define what `REVEAL` unlocks and under what conditions.
4. Integrate proof checks with trust, contracts, and sensitive-value workflows.
5. Add tests that verify proof semantics, not only proof generation/verification.

**Difficulty:** Very High  
**Risk:** Very High

**Why this phase matters:**
The cryptographic engine exists, but the language-level semantics are still placeholder-grade.

**Exit criteria:**
- proofs represent meaningful claims
- reveal behavior is policy-driven and test-covered
- proof workflows integrate with contracts and sensitive access rules

---

## 4. Recommended milestone grouping

### Milestone A — Language core parity
Complete:
- Phase 1
- Phase 2
- Phase 3
- Phase 4

**Outcome:**
The language becomes much more expressive and internally consistent. This is the most important milestone.

### Milestone B — Agent platform parity
Complete:
- Phase 5
- Phase 6
- Phase 7
- Phase 8

**Outcome:**
Tools, communication, trust, and registry behavior start to resemble the draft spec in a meaningful way.

### Milestone C — Architecture parity
Complete:
- Phase 9
- Phase 10

**Outcome:**
The runtime/storage/proof layers move from prototype implementations toward spec-aligned infrastructure.

---

## 5. Recommended first implementation slice

If execution starts immediately, the best initial slice is:

1. **Phase 1 — Core value/expression model**
2. **Phase 2 — Structured goal results and outputs**
3. **Phase 4 — Goal directives and failure model**

This slice has the best payoff because it unlocks most of the later work while keeping architectural churn manageable.

Follow that with:

4. **Phase 3 — Annotation/type semantics**
5. **Phase 5 — Tool system**

---

## 6. Overall risk summary

### Lowest risk
- Phase 0
- selected parts of Phase 4

### Moderate risk
- Phase 2
- Phase 3
- Phase 6

### Highest risk
- Phase 1
- Phase 5
- Phase 7
- Phase 8
- Phase 9
- Phase 10

### Main risk drivers
- AST/parser/runtime coupling
- protocol changes affecting RPC surfaces
- storage backend migration complexity
- semantic ambiguity in the draft spec
- cryptographic correctness and policy enforcement interactions

---

## 7. Final recommendation

Do **not** start with storage or proof sophistication.

Start by making the language core and execution model match the spec more closely:
- richer expressions
- structured outputs
- stronger failure semantics
- then annotations and tool declarations

That order gives the best chance of reaching spec parity without repeatedly rewriting the same core abstractions.
