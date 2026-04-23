# AgentLang Language Specification

**Version:** 1.0 — Draft  
**Date:** April 2026  
**Status:** Draft Proposal  
**License:** Apache 2.0  
**Repository:** github.com/agentlang/spec

---

> **A purpose-built language for LLM-powered agents.**  
> *Written by agents. Executed by runtimes. Trusted by design.*

---

## Abstract

AgentLang is a programming language designed to be written and executed by large language model (LLM) powered agents. Unlike general-purpose languages designed for human authorship, AgentLang optimises for token efficiency, unambiguous machine generation, and agent-native semantics. It introduces goal-oriented control flow, first-class uncertainty and confidence types, privacy-preserving Zero Knowledge Proof integration, cryptographically signed agent identity, four-scope memory with fuzzy recall, and a hybrid Elixir/BEAM and Rust/Tokio runtime architecture.

This document is the primary reference for the AgentLang language. It is intended for language implementors, runtime authors, tool builders, and researchers working on agent systems.

> **NOTE** This is a draft specification. Sections marked `[OPEN]` contain unresolved design questions. Feedback is welcome via the repository issue tracker.

---

## Table of Contents

- [Part I — Introduction](#part-i--introduction)
  - [1. Introduction](#1-introduction)
- [Part II — Lexical Structure & Syntax](#part-ii--lexical-structure--syntax)
  - [2. Lexical Structure](#2-lexical-structure)
  - [3. Syntax](#3-syntax)
- [Part III — Core Language](#part-iii--core-language)
  - [4. Goals](#4-goals)
  - [5. Control Flow](#5-control-flow)
  - [6. Type System](#6-type-system)
  - [7. Variables and Memory](#7-variables-and-memory)
- [Part IV — Agent Systems](#part-iv--agent-systems)
  - [8. Parallelism](#8-parallelism)
  - [9. Agent Communication](#9-agent-communication)
  - [10. Trust and Identity](#10-trust-and-identity)
  - [11. Tools](#11-tools)
  - [12. Agent Registry](#12-agent-registry)
- [Part V — Runtime & Implementation](#part-v--runtime--implementation)
  - [13. Runtime Architecture](#13-runtime-architecture)
- [Part VI — Complete Example](#part-vi--complete-example)
  - [14. Complete Example Program](#14-complete-example-program)
- [Appendix A — Keyword Reference](#appendix-a--keyword-reference)
- [Appendix B — Glossary](#appendix-b--glossary)
- [Appendix C — Design Influences](#appendix-c--design-influences)
- [Appendix D — Change Log](#appendix-d--change-log)
- [Appendix E — Open Questions](#appendix-e--open-questions)

---

# Part I — Introduction

## 1. Introduction

### 1.1 Motivation

Modern LLM agents typically write code in Python or call tools via JSON-formatted API requests. Neither approach was designed with agents in mind. Python is optimised for human readability and has no built-in concepts for agent-specific concerns such as uncertainty, trust, idempotency, or goal-oriented execution. JSON tool calls are untyped, verbose, and provide no language-level guarantees about behaviour.

AgentLang addresses this gap by providing a language where agents are the primary authors and consumers. Every design decision prioritises what makes agents succeed: compact syntax, goal-based reasoning, native error recovery, and trust-aware communication.

### 1.2 Design Goals

- **Token efficiency** — minimal syntax overhead, no unnecessary punctuation
- **Agent-native control flow** — goals, retries, and fallbacks instead of loops and exceptions
- **First-class uncertainty** — confidence scores and uncertain values as language primitives
- **Privacy by default** — sensitive values encrypted and ZK-proof protected automatically
- **Trust-aware communication** — every inter-agent message is signed and verifiable
- **Idempotency as a primitive** — side effects guaranteed not to double-execute
- **Composable parallelism** — fan-out, race, and gather patterns built into the language

### 1.3 Non-Goals

- AgentLang is **not** designed for human authorship — readability is secondary to generability
- AgentLang is **not** a general-purpose language — it does not replace Python or TypeScript
- AgentLang does **not** require a blockchain or decentralised infrastructure
- AgentLang does **not** mandate a specific LLM or model provider

### 1.4 Relationship to Existing Work

AgentLang draws inspiration from several existing systems. The goal-oriented control flow is influenced by BDI (Belief-Desire-Intention) agent architectures and AgentSpeak. The actor model runtime is inspired by Erlang/OTP. The trust and ZK proof layer is informed by work in privacy-preserving cryptography. The MCP tool compatibility layer aligns with the Model Context Protocol standard.

Unlike **QUASAR** (Mell et al., 2025), which transpiles from Python, AgentLang is designed as a first-class language agents write natively.

### 1.5 Document Conventions

| Convention | Meaning |
|---|---|
| `KEYWORD` | An AgentLang reserved keyword — shown in uppercase monospace |
| `{variable}` | A variable reference — braces enclose the variable name |
| `// comment` | An inline comment — not part of the program |
| `[OPEN]` | An unresolved design question — marked for future resolution |
| `[NORMATIVE]` | A requirement that conforming implementations must satisfy |
| `[INFORMATIVE]` | Explanatory text — not a conformance requirement |

---

# Part II — Lexical Structure & Syntax

## 2. Lexical Structure

### 2.1 Source Encoding

AgentLang source files are encoded in UTF-8. The file extension is `.al`. Non-ASCII characters are permitted only in string literals and comments.

### 2.2 Whitespace and Line Endings

Whitespace is significant for indentation within blocks. Indentation uses **two spaces per level**. Tabs are normalised to two spaces. Line endings may be LF or CRLF.

### 2.3 Comments

Single-line comments begin with `//` and extend to the end of the line.

```
// This is a comment
GOAL book_flight   // inline comment
```

### 2.4 Keywords

| Category | Keywords |
|---|---|
| Control flow | `GOAL` `IF` `ELSE` `END` `REPEAT` `UNTIL` `FOREACH` `IN` |
| Execution | `RETRY` `ON_FAIL` `DEADLINE` `WAIT` `FALLBACK` `IDEMPOTENT` |
| Parallelism | `PARALLEL` `RACE` `GATHER` `GATHER_MIN` `GATHER_ALL` `FIRST_INTO` `NAMESPACE` |
| Memory | `REMEMBER` `RECALL` `FORGET` `SCOPE` `FUZZY` `INTO` `ON_MISSING` |
| Variables | `SET` `DECLARE` `AS` `REVEAL` |
| Trust | `AGENT` `CONTRACT` `PROVE` `CLAIM` `WITHOUT` `REVEALING` `SIGNED_BY` `VERIFY_KEY` |
| Tools | `TOOL` `USE` `CONFIRM_WITH` `REVERSIBLE` `SIDE_EFFECT` `DEPRECATED` |
| Agents | `CALL` `DELEGATE` `EMIT` `ON` `AWAIT` `TRUST_LEVEL` `TRUST_INHERIT` |
| Results | `RESULT` `OUTPUT` `NAMESPACE` `ERROR` |
| Registry | `REGISTRY` `FEDERATE` `REVOKE` `RENEW` `SUSPEND` |
| Versioning | `VERSION` `MINIMUM_VERSION` `FALLBACK` `MAP` `SUNSET` `UPGRADE_TO` |

### 2.5 Literals

```ebnf
text_literal     ::= '"' character* '"'
number_literal   ::= digit+ ('.' digit+)?
boolean_literal  ::= 'true' | 'false'
date_literal     ::= digit{4} '-' digit{2} '-' digit{2}
duration_literal ::= number ('s' | 'm' | 'h' | 'd')
list_literal     ::= '[' value (',' value)* ']'
variable_ref     ::= '{' identifier ('.' identifier)* '}'
agent_ref        ::= 'agent:' identifier
event_ref        ::= 'event:' identifier
registry_ref     ::= 'registry:' identifier
```

### 2.6 Identifiers

```ebnf
identifier ::= (letter | '_') (letter | digit | '_')*
letter     ::= [a-zA-Z]
digit      ::= [0-9]
```

Identifiers are case-sensitive. Reserved keywords may not be used as identifiers.

---

## 3. Syntax

### 3.1 Program Structure

```ebnf
program      ::= declaration* goal_block+
declaration  ::= agent_decl | contract_decl | tool_decl | set_stmt
goal_block   ::= 'GOAL' identifier param* directive* statement* 'END'
param        ::= identifier value
directive    ::= retry_dir | deadline_dir | on_fail_dir | idempotent_dir
               | output_dir | result_dir | audit_dir | confirm_dir
statement    ::= set_stmt | if_stmt | loop_stmt | parallel_stmt
               | remember_stmt | recall_stmt | use_stmt | call_stmt
               | delegate_stmt | emit_stmt | on_stmt | reveal_stmt
               | goal_block
```

### 3.2 Block Notation

Blocks are delimited by keywords and `END`. Nested blocks are indented by two spaces per level. No semicolons or commas are required between statements.

```
GOAL outer_goal
  PARAM value

  GOAL inner_goal     // nested block
    PARAM other
  END

  IF condition
    GOAL another
    END
  END

END
```

### 3.3 Variable References

```
SET name = "Alice"
GOAL greet
  MESSAGE {name}                  // simple reference
  PRICE {trip.flight.cost}        // dot notation
  FIRST {results[0]}              // bracket notation
  TOTAL {price * quantity}        // expression
END
```

---

# Part III — Core Language

## 4. Goals

### 4.1 The GOAL Block

The `GOAL` is the primary unit of computation in AgentLang. A GOAL represents a discrete piece of work the agent intends to accomplish.

```
GOAL book_flight
  FROM London
  TO "New York"
  DATE 2026-06-01
  BUDGET 500
  RETRY 3
  DEADLINE 30s
  ON_FAIL GOAL notify_booking_failed
  IDEMPOTENT
  AUDIT_TRAIL true
END
```

### 4.2 Goal Directives

| Directive | Type | Description |
|---|---|---|
| `RETRY n` | number | Retry up to n times on failure before invoking ON_FAIL |
| `ON_FAIL GOAL x` | goal ref | Execute goal x if this goal fails after all retries |
| `FALLBACK value` | any | Return a default value on failure instead of erroring |
| `DEADLINE duration` | duration | Abort execution if not complete within duration |
| `IDEMPOTENT` | flag | Guarantee the goal executes at most once per parameter set |
| `WAIT duration` | duration | Pause before executing the goal body |
| `AUDIT_TRAIL bool` | boolean | Log this goal's execution to the immutable audit trail |
| `CONFIRM_WITH x` | human\|agent | Require confirmation before executing irreversible actions |
| `TIMEOUT_CONFIRMATION d` | duration | Abort confirmation wait after duration |

### 4.3 Goal Results

GOALs return results via named `OUTPUT` blocks (standard form) or `RESULT INTO` shorthand (simple single-value form).

```
// Standard form — named outputs
GOAL search_flights
  FROM {origin}
  TO {destination}
  OUTPUT
    flights     list
    cheapest    number AS approximate
    confidence  float  AS confidence
  END
END

// Shorthand — single value
GOAL get_exchange_rate
  FROM GBP TO USD
  RESULT INTO {rate}
END

// Accessing named outputs via dot notation
IF {search_flights.confidence} > 0.85
  GOAL book_flight
    FLIGHT {search_flights.flights[0]}
  END
END
```

---

## 5. Control Flow

### 5.1 Conditional Execution

```
IF {city.confidence} > 0.9
  GOAL book_flight
    TO {city}
  END
ELSE IF {city.confidence} > 0.6
  GOAL confirm_with_user
    MESSAGE "Did you mean {city}?"
  END
ELSE
  GOAL ask_for_clarification
  END
END
```

### 5.2 Goal Chaining

Goals chain via `ON_FAIL`, forming declarative execution trees. This is the **preferred** control flow mechanism in AgentLang.

```
GOAL book_preferred_flight
  AIRLINE british_airways
  ON_FAIL GOAL book_any_flight
    ON_FAIL GOAL notify_no_flights_available
  END
END
```

### 5.3 Iteration

`REPEAT UNTIL` and `FOREACH IN` provide iteration. These are intentionally less prominent than goal chaining — most agent iteration should be expressed as retries, not loops.

```
// Retry-based — preferred for agents
GOAL find_available_flight
  RETRY 5
  WAIT 10s
END

// Explicit iteration — use sparingly
FOREACH city IN [London, Paris, Berlin]
  GOAL search_flights
    FROM {city}
    TO New York
  END
END

REPEAT UNTIL flight_booked
  GOAL search_flights
  WAIT 30s
END
```

### 5.4 Error Handling

AgentLang defines five agent-specific failure modes:

| Failure Type | Meaning | Typical Response |
|---|---|---|
| `TOOL_FAIL` | An external tool or API call failed | RETRY or use fallback tool |
| `TIMEOUT` | Execution exceeded DEADLINE | Escalate or notify human |
| `HALLUCINATION` | Output failed validation check | RETRY with different approach |
| `AMBIGUOUS` | Agent could not determine how to proceed | CONFIRM_WITH human |
| `PERMISSION` | Agent lacked required trust level | Request elevated CONTRACT |

```
GOAL fetch_flight_prices
  SOURCE skyscanner_api
  ON_FAIL[TOOL_FAIL]     GOAL fetch_flight_prices
    SOURCE kayak_api
  END
  ON_FAIL[TIMEOUT]       GOAL notify_user
    MESSAGE "Search is taking too long"
  END
  ON_FAIL[HALLUCINATION] GOAL fetch_flight_prices
    SOURCE google_flights
    RETRY 1
  END
  RETRY 2
  DEADLINE 30s
END
```

---

## 6. Type System

### 6.1 Inferred Base Types

AgentLang uses structural type inference — the runtime determines types from value syntax. No declarations are required.

| Type | Example | Notes |
|---|---|---|
| `text` | `"hello world"` | Double-quoted string literal |
| `number` | `42` | Integer value |
| `float` | `3.14` | Decimal value |
| `boolean` | `true` / `false` | Lowercase literals only |
| `date` | `2026-06-01` | ISO 8601 format required |
| `duration` | `10s` / `30m` / `2h` / `7d` | Used in DEADLINE, WAIT, EXPIRES |
| `url` | `https://example.com` | Must include protocol scheme |
| `agent_ref` | `agent:flight_specialist` | Reference to a registered agent |
| `event_ref` | `event:booking_confirmed` | Reference to an event type |
| `list` | `[London, Paris, Berlin]` | Comma-separated in brackets |

### 6.2 Agent-Specific Type Annotations

Four annotations extend the base type system using the `AS` keyword:

| Annotation | Range | Runtime Behaviour |
|---|---|---|
| `AS confidence` | 0.0 – 1.0 | Enables confidence-driven control flow and human escalation |
| `AS sensitive` | any | Auto-encrypts in memory, requires ZK proof to share, redacted in audit logs |
| `AS uncertain` | any | Triggers verification step before use in irreversible actions |
| `AS approximate` | number | Uses tolerance-aware comparisons in IF conditions |

### 6.3 Confidence-Driven Control Flow

Confidence scores are first-class control flow primitives — unique to AgentLang.

```
GOAL identify_city
  RESULT INTO {city} AS confidence

  IF {city.confidence} > 0.9
    GOAL proceed_with_booking
  ELSE IF {city.confidence} > 0.6
    GOAL confirm_with_user
      MESSAGE "Did you mean {city}?"
  ELSE
    GOAL ask_for_clarification
  END
END
```

### 6.4 Sensitive Values and REVEAL

Sensitive values are encrypted at rest and require explicit ZK proof unlocking via `REVEAL`.

```
SET passport = "AB123456" AS sensitive

// Passing to another agent — ZK proof auto-generated:
CALL agent:verification_agent
  DATA {passport}
  TRUST_LEVEL verified
END

// Accessing raw value — explicit proof required:
REVEAL passport
  PROVE identity
    CLAIM authorised_verification_agent
  END
  INTO {raw_passport}
END
```

### 6.5 Type Coercion

| From | To | Safe? | Notes |
|---|---|---|---|
| `number` | `text` | Yes | Always succeeds |
| `date` | `text` | Yes | Produces ISO 8601 string |
| `text` | `number` | Conditional | Fails if not parseable |
| `text` | `date` | Conditional | Fails if not valid ISO 8601 |
| `sensitive` | any | **No** | Requires REVEAL with ZK proof |
| `uncertain` | any | Conditional | Triggers verification step |
| `approximate` | `number` | Yes | Comparisons use tolerance window |

---

## 7. Variables and Memory

### 7.1 Working Variables

Declared with `SET`, scoped to the current GOAL, discarded when the GOAL ends.

```
GOAL calculate_total
  SET subtotal = 450
  SET tax      = 50
  SET total    = {subtotal + tax}
END
```

### 7.2 Memory Scopes

| Scope | Lifetime | Visibility | Backend |
|---|---|---|---|
| `working` | Current GOAL only | This agent | BEAM process heap |
| `session` | Current session | This agent | ETS (in-memory) |
| `long_term` | Until FORGET or expiry | This agent | Embedded Vector DB (LanceDB) |
| `shared` | Until FORGET or expiry | All trusted agents | Embedded Vector DB (LanceDB) |

### 7.3 Memory Operations

```
// Store
REMEMBER flight_preference
  SCOPE long_term
  VALUE {preferred_airline}
  EXPIRES 30d
END

// Retrieve
RECALL flight_preference
  SCOPE long_term
  INTO {pref}
  ON_MISSING USE default_airline
END

// Fuzzy recall — natural language query against vector index
RECALL "user flight preferences from last month"
  SCOPE long_term
  FUZZY true
  LIMIT 3
  INTO {past_prefs}
END

// Delete
FORGET flight_preference
  SCOPE long_term
END
```

### 7.4 Shared Memory and Trust

Shared memory writes are signed by the writing agent. Reads can require a minimum trust level.

```
REMEMBER booking_status
  SCOPE shared
  KEY booking_{id}
  VALUE confirmed
  SIGNED_BY {this_agent_key}
  READABLE_BY TRUST_LEVEL verified
  EXPIRES 7d
END
```

---

# Part IV — Agent Systems

## 8. Parallelism

### 8.1 Parallel Patterns

| Pattern | Keyword | Behaviour | Web Equivalent |
|---|---|---|---|
| Fan-out | `PARALLEL ... GATHER` | Run all, wait for all | `Promise.all()` |
| Race | `RACE ... FIRST_INTO` | Run all, take first winner | `Promise.race()` |
| Partial | `PARALLEL ... GATHER_MIN n` | Continue when n complete | `Promise.any()` |
| Settled | `PARALLEL ... GATHER_ALL` | Collect all outcomes | `Promise.allSettled()` |

### 8.2 Fan-Out Example

```
PARALLEL
  GOAL search_flights
    FROM {origin} TO {destination}
    RESULT INTO {travel.flight}
  END
  GOAL search_hotels
    IN {destination}
    RESULT INTO {travel.hotel}
  END
  GOAL search_car_hire
    IN {destination}
    RESULT INTO {travel.car}
  END
GATHER INTO {travel}
DEADLINE 15s
ON_PARTIAL_FAIL CONTINUE
ON_ALL_FAIL GOAL notify_search_failed
END
```

### 8.3 Race Example

```
RACE
  GOAL search_skyscanner END
  GOAL search_kayak END
  GOAL search_expedia END
FIRST_INTO {flight_results}
DEADLINE 10s
END
```

### 8.4 Trust in Parallel Blocks

```
PARALLEL TRUST_INHERIT
  GOAL search_verified_source END
  GOAL search_unverified_source
    TRUST_LEVEL sandboxed
  END
GATHER_ALL INTO {all_results}
END
```

---

## 9. Agent Communication

### 9.1 Communication Patterns

| Pattern | Keyword | Direction | Analogy |
|---|---|---|---|
| Request/Response | `CALL ... AWAIT` | Bidirectional | REST API call |
| Delegate & Forget | `DELEGATE` | Outbound only | Message queue publish |
| Broadcast | `EMIT` | Outbound to all | Webhook / pub-sub |
| Subscribe | `ON event:` | Inbound trigger | Event listener |

### 9.2 Request / Response

```
CALL agent:flight_specialist
  SIGNED_BY {this_agent_key}
  VERIFY_KEY registry:flight_specialist
  ASK find_cheapest_flight
  FROM {origin}
  TO {destination}
  AWAIT result
  TIMEOUT 10s
  ON_FAIL GOAL handle_specialist_unavailable
END
```

### 9.3 Broadcast and Subscribe

```
// Agent A emits an event
EMIT event:booking_confirmed
  DATA {booking_details}
  SIGNED_BY {this_agent_key}
END

// Agent B subscribes and reacts
ON event:booking_confirmed
  VERIFY_FROM agent:booking_agent
  GOAL send_confirmation_email
    DATA {event.payload}
  END
END
```

---

## 10. Trust and Identity

### 10.1 Agent Identity

```
AGENT travel_booking_agent
  ID 0x4a3f9c2e...
  REGISTRY acme.agentregistry.io
  SIGNED_BY acme.agentregistry.io
  TRUST_LEVEL verified
  VERSION 1.0
END
```

### 10.2 Contracts

CONTRACT blocks declare an agent's capabilities. They are signed by the issuing registry and verifiable by any agent via ZK proof.

```
CONTRACT travel_agent_permissions
  ISSUED_BY registry:acme.agentregistry.io
  SIGNED_BY {agent_key}

  CAN USE search_flights
  CAN USE book_flight
    BUDGET_LIMIT 1000
    REQUIRES_CONFIRMATION true
  CAN USE send_email
    DOMAIN example.com
  CANNOT USE charge_card_directly
  CANNOT USE impersonate_human

  EXPIRES 24h
  ON_EXPIRY_WARNING 1h
    GOAL renew_contract
    END
  END
  ON_EXPIRED SUSPEND
  AUDIT_TRAIL true
END
```

### 10.3 Trust Levels

| Level | Meaning | Permitted Operations |
|---|---|---|
| `VERIFIED` | Registry-signed identity confirmed | Read, write, call, delegate, emit |
| `TRUSTED` | Known agent, prior interaction | Read, write, call, delegate |
| `SANDBOXED` | Unknown or unverified agent | Read only — no side effects |
| `BLOCKED` | Explicitly denied | All calls rejected immediately |

### 10.4 Zero Knowledge Proofs

ZK proofs use the **winterfell** library (zk-STARKs). Chosen over zk-SNARKs because zk-STARKs require no trusted setup ceremony — critical for autonomous multi-agent systems — and are post-quantum secure.

```
GOAL access_payment_system
  PROVE permission
    CLAIM can_charge_up_to 1000
    WITHOUT REVEALING full_contract
  END
END

EMIT event:task_complete
  PROVE completion
    CLAIM booked_flight
    WITHOUT REVEALING passenger_details
  END
END
```

---

## 11. Tools

### 11.1 Tool Declaration

```
TOOL search_flights
  DESCRIPTION "Search for available flights between two cities"
  CATEGORY read
  VERSION 2.1.0
  INPUT
    from       text   REQUIRED
    to         text   REQUIRED
    date       date   REQUIRED
    max_price  number OPTIONAL
  END
  OUTPUT
    flights    list
    best_price number AS approximate
    confidence float  AS confidence
  END
  REVERSIBLE true
  SIDE_EFFECT false
  RATE_LIMIT 10/min
  TIMEOUT 15s
END
```

### 11.2 Tool Categories

| Category | Side Effects | Reversible | Requires Confirmation |
|---|---|---|---|
| `read` | None | Always | Never |
| `write` | Yes | May not be | If `REVERSIBLE false` |
| `agent` | Via called agent | Depends | Depends on contract |

### 11.3 Calling a Tool

```
USE search_flights
  from {origin}
  to {destination}
  date {travel_date}
  RESULT INTO {flights}
  RETRY 3
  DEADLINE 10s
  ON_FAIL GOAL handle_search_failure
END

// Irreversible tool — requires confirmation
USE book_flight
  flight_id   {selected_flight.id}
  passenger   {passenger_name}
  card_number {card}         // sensitive — ZK proof auto-generated
  CONFIRM_WITH human
  TIMEOUT_CONFIRMATION 30m
  ON_TIMEOUT GOAL cancel_booking_attempt
  IDEMPOTENT
  AUDIT_TRAIL true
  RESULT INTO {booking}
END
```

### 11.4 Tool Versioning

```
TOOL search_flights
  VERSION 3.0.0
  INPUT
    origin       text REQUIRED
    destination  text REQUIRED
  END

  FALLBACK VERSION 2.x
    MAP origin      → from
    MAP destination → to
    MAP results     ← flights
  END

  FALLBACK VERSION 1.x
    MAP origin      → departure_city
    MAP destination → arrival_city
  END
END
```

Field mapping uses `→` for input remapping (new name → old name) and `←` for output remapping (new name ← old name).

### 11.5 Standard Tool Library

| Tool | Category | Description |
|---|---|---|
| `web_search` | read | Search the web for current information |
| `http_request` | write | Make an HTTP request to any external API |
| `send_email` | write | Send an email to one or more recipients |
| `notify_human` | write | Escalate a decision or alert to a human operator |
| `log` | read | Write a message to the immutable audit trail |
| `verify_proof` | read | Verify a ZK proof from another agent |
| `read_memory` | read | Read from any memory scope |
| `write_memory` | write | Write to any memory scope |
| `get_time` | read | Get the current date and time |
| `validate` | read | Validate a value against a schema or contract |

### 11.6 MCP Compatibility

Any MCP-compatible tool can be wrapped using the `SOURCE` directive:

```
TOOL github_create_pr
  SOURCE mcp:github
  CATEGORY write
  REVERSIBLE false
  REQUIRES_CONFIRMATION true
  AUDIT_TRAIL true
END
```

---

## 12. Agent Registry

### 12.1 Registry Model

AgentLang uses a **federated registry model** inspired by email and ActivityPub. Organisations run their own registries. Registries cross-verify via a federation protocol. A reference centralised registry is provided for bootstrapping.

### 12.2 Registry Operations

| Operation | Description | Auth Required |
|---|---|---|
| `REGISTER agent` | Create a new agent identity | Human operator + signing key |
| `LOOKUP agent:id` | Resolve agent ID to public key and contract | None — public |
| `VERIFY agent:id` | Confirm identity via ZK proof | Proof from agent |
| `REVOKE agent:id` | Invalidate a compromised agent | Registry admin + original key |
| `RENEW contract` | Extend or update an agent's CONTRACT | Agent signing key |
| `FEDERATE registry:x` | Establish cross-registry trust | Both registry admins |

### 12.3 Cross-Registry Trust

```
CONTRACT cross_registry_trust
  TRUST registry:openregistry.io
    LEVEL verified
    VERIFY_VIA ZK_PROOF
  END
  TRUST registry:partnerorg.agentregistry.io
    LEVEL sandboxed
    UPGRADE_ON human_approval
  END
END
```

---

# Part V — Runtime & Implementation

## 13. Runtime Architecture

### 13.1 Pure Rust Runtime Model

AgentLang 1.0 utilizes a **Pure Rust** architecture optimized for maximum throughput, memory safety, and deterministic execution. The runtime is built on the **Tokio** asynchronous executor and the **Bastion** highly-available supervisor framework, providing OTP-like resilience without the overhead of a virtual machine.

```
AgentLang Source (.al)
         |
   Rust Parser / Lexer (nom)
         |
   AST / Bytecode
         |
   Orchestration Layer (Tokio / Bastion)
   |-- Goal Supervisor (Bastion)
   |-- Parallel Task Scheduler (Tokio)
   |-- Event Bus (Internal MPMC Channels)
   |-- Agent Registry Client (Tonic / gRPC)
   |-- Session Store (DashMap / In-memory)
         |
   Performance & Security Layer
   |-- ZK Proof Engine (winterfell / zk-STARKs)
   |-- Crypto Signing (Ed25519)
   |-- Memory Encryption (AES-256-GCM)
   |-- Audit Hash Chain (SHA-256)
   |-- Contract Validator
         |
   Memory Layer
   |-- Working   (Tokio Local Storage)
   |-- Session   (DashMap)
   |-- Long-term (Embedded Vector DB / LanceDB)
   |-- Shared    (Embedded Vector DB / LanceDB)
         |
   Tool Executor
   |-- Standard Library (Rust Built-ins)
   |-- MCP Adapter
   |-- HTTP Client (reqwest)
         |
   External World
```

### 13.2 Goal Orchestration via Bastion

Every `GOAL` maps to a supervised **Bastion Child**. This provides fault isolation and hierarchical recovery identical to the Erlang/OTP model.

| AgentLang Concept | Rust / Bastion Equivalent |
|---|---|
| `GOAL` | Bastion Child (Lightweight Task) |
| `PARALLEL` block | Bastion Group with custom restart strategy |
| `RACE` block | `tokio::select!` with early cancellation |
| `RETRY n` | Bastion `restart_policy` with max_restarts |
| `DEADLINE duration` | `tokio::time::timeout` |
| `EMIT / ON` | Internal MPMC broadcast channels |
| Hot update | WASM-based logic hot-swapping |

### 13.3 Performance Characteristics

| Component | Technology | Reason |
|---|---|---|
| Async Runtime | Tokio | Industry standard for high-performance async I/O |
| Supervision | Bastion | Fault-tolerant actor model with low overhead |
| Persistence | sqlx | Compile-time verified SQL queries |
| ZK Engine | winterfell | High-performance STARK generation in Rust |
| Communication | Tonic | High-performance gRPC for inter-agent calls |

### 13.4 Implementation Roadmap

| Phase | Deliverable |
|---|---|
| 1 — Foundation | Rust Parser (nom) + Tokio-based execution loop |
| 2 — Orchestration | Integrate Bastion for GOAL supervision and retries |
| 3 — Crypto | Integrate winterfell for ZK proofs and Ed25519 for identity |
| 4 — Distribution | Implement Tonic (gRPC) for inter-agent communication |
| 5 — Hardening | Security audits, performance benchmarking, and WASM integration |

---

# Part VI — Complete Example

## 14. Complete Example Program

A complete AgentLang program exercising identity, contracts, memory, parallel search, confidence-driven decisions, trust-aware tool use, and audit logging.

```
// ── Identity ───────────────────────────────────────────────
AGENT travel_booking_agent
  ID 0x4a3f9c2e...
  REGISTRY acme.agentregistry.io
  SIGNED_BY acme.agentregistry.io
  TRUST_LEVEL verified
END

// ── Permissions ────────────────────────────────────────────
CONTRACT travel_agent_permissions
  ISSUED_BY registry:acme.agentregistry.io
  CAN USE search_flights
  CAN USE book_flight
    BUDGET_LIMIT 1000
    REQUIRES_CONFIRMATION true
  CAN USE send_email
  EXPIRES 24h
END

// ── Variables ──────────────────────────────────────────────
SET origin      = London
SET destination = "New York"
SET budget      = 600
SET travel_date = 2026-06-01
SET card        = "4111111111111111" AS sensitive

// ── Recall user preferences ────────────────────────────────
RECALL "user flight preferences"
  SCOPE long_term
  FUZZY true
  INTO {past_prefs}
END

// ── Main goal ──────────────────────────────────────────────
GOAL plan_trip
  ON_FAIL GOAL notify_failure
  DEADLINE 120s
  AUDIT_TRAIL true

  // Parallel search
  PARALLEL
    GOAL search_flights
      FROM {origin} TO {destination}
      DATE {travel_date}
      OUTPUT
        flights    list
        best_price number AS approximate
        confidence float  AS confidence
      END
      RETRY 3
    END
    GOAL search_hotels
      IN {destination}
      DATE {travel_date}
      OUTPUT
        hotels    list
        best_rate number AS approximate
      END
    END
  GATHER INTO {search}
  ON_ALL_FAIL GOAL notify_no_availability
  END

  // Confidence-driven booking decision
  IF {search.flights.confidence} > 0.85
    IF {search.flights.best_price} < {budget}

      USE book_flight
        flight_id   {search.flights.flights[0].id}
        passenger   "Alice Smith"
        card_number {card}       // sensitive — ZK proof auto-generated
        CONFIRM_WITH human
        TIMEOUT_CONFIRMATION 30m
        ON_TIMEOUT GOAL cancel_and_notify
        IDEMPOTENT
        AUDIT_TRAIL true
        RESULT INTO {booking}
      END

      REMEMBER last_booking
        SCOPE long_term
        VALUE {booking}
        EXPIRES 90d
      END

      GOAL send_confirmation_email
        TO user@example.com
        DATA {booking}
        IDEMPOTENT
      END

      EMIT event:booking_confirmed
        DATA {booking}
        SIGNED_BY {this_agent_key}
      END

    ELSE
      GOAL find_budget_alternatives
        BUDGET {budget}
        ON_FAIL GOAL notify_no_budget_options
      END
    END
  ELSE
    GOAL confirm_with_user
      MESSAGE "I found flights but I'm not confident — shall I proceed?"
    END
  END

END  // plan_trip
```

---

# Appendix A — Keyword Reference

Complete alphabetical listing of all AgentLang reserved keywords.

| Keyword | Section | Description |
|---|---|---|
| `AS` | §6.2 | Apply a type annotation to a value |
| `AUDIT_TRAIL` | §4.2 | Log goal execution to the immutable audit trail |
| `AWAIT` | §9.2 | Wait for a response from a CALL |
| `BLOCKED` | §10.3 | Trust level — all calls rejected |
| `CALL` | §9.2 | Send a request to another agent and await response |
| `CLAIM` | §10.4 | Assert a condition in a ZK proof |
| `CONFIRM_WITH` | §4.2, §11.3 | Require human or agent confirmation |
| `CONTRACT` | §10.2 | Declare agent capabilities and permissions |
| `DEADLINE` | §4.2 | Abort execution after a duration |
| `DECLARE` | §6 | Explicitly declare a typed variable |
| `DELEGATE` | §9 | Hand off a task — fire and forget |
| `DEPRECATED` | §11.4 | Mark a tool version as deprecated |
| `EMIT` | §9.3 | Broadcast an event to all subscribers |
| `END` | §3.2 | Close a block |
| `ERROR` | §4.3 | An error result type |
| `EXPIRES` | §7.3 | Set expiry on a memory entry or contract |
| `FALLBACK` | §4.2, §11.4 | Default value or version fallback |
| `FEDERATE` | §12.3 | Establish cross-registry trust |
| `FIRST_INTO` | §8.1 | Store the first winner of a RACE |
| `FOREACH` | §5.3 | Iterate over a list |
| `FORGET` | §7.3 | Delete a memory entry |
| `FUZZY` | §7.3 | Enable semantic fuzzy recall |
| `GATHER` | §8.1 | Collect all parallel results |
| `GATHER_ALL` | §8.1 | Collect all results including failures |
| `GATHER_MIN` | §8.1 | Continue when minimum n results available |
| `GOAL` | §4.1 | Declare a unit of agent work |
| `IDEMPOTENT` | §4.2 | Guarantee at-most-once execution |
| `IF` / `ELSE` | §5.1 | Conditional branching |
| `IN` | §5.3 | Used in FOREACH iteration |
| `INTO` | §7.3, §4.3 | Store a result into a variable |
| `MAP` | §11.4 | Field mapping in tool version fallback |
| `MINIMUM_VERSION` | §11.4 | Minimum acceptable tool version |
| `NAMESPACE` | §8.4 | Scope parallel branch results |
| `ON` | §9.3 | Subscribe to an event |
| `ON_ALL_FAIL` | §8 | Handle failure of all parallel branches |
| `ON_EXPIRED` | §10.2 | Handle contract expiry |
| `ON_EXPIRY_WARNING` | §10.2 | Trigger renewal before contract expires |
| `ON_FAIL` | §4.2, §5.2 | Handle goal failure |
| `ON_MISSING` | §7.3 | Default when memory key not found |
| `ON_PARTIAL_FAIL` | §8 | Handle partial failure in parallel block |
| `ON_TIMEOUT` | §4.2 | Handle confirmation timeout |
| `OUTPUT` | §4.3 | Declare named output values from a goal |
| `PARALLEL` | §8 | Execute multiple goals simultaneously |
| `PROVE` | §10.4 | Generate a Zero Knowledge Proof |
| `RACE` | §8.1 | Execute multiple goals, take first winner |
| `READABLE_BY` | §7.4 | Set trust level required to read shared memory |
| `RECALL` | §7.3 | Read from memory |
| `REGISTRY` | §12 | Reference an agent registry |
| `REMEMBER` | §7.3 | Write to memory |
| `RENEW` | §12.2 | Renew an agent contract |
| `REPEAT` | §5.3 | Loop until a condition is met |
| `RESULT` | §4.3 | Store a single goal result |
| `RETRY` | §4.2 | Retry on failure |
| `REVEAL` | §6.4 | Unlock a sensitive value with ZK proof |
| `REVERSIBLE` | §11.1 | Declare whether a tool action can be undone |
| `REVOKE` | §12.2 | Invalidate an agent identity |
| `SANDBOXED` | §10.3 | Trust level — read only |
| `SET` | §7.1 | Assign a working variable |
| `SIDE_EFFECT` | §11.1 | Declare whether a tool has side effects |
| `SIGNED_BY` | §10.1 | Cryptographic signature assertion |
| `SOURCE` | §11.6 | Specify an MCP source for a tool |
| `SUNSET` | §11.4 | Date after which a deprecated version is removed |
| `SUSPEND` | §10.2 | Halt agent execution |
| `TOOL` | §11.1 | Declare an external tool |
| `TRUST_INHERIT` | §8.4 | Inherit parent trust level in parallel block |
| `TRUST_LEVEL` | §10.3 | Set or assert a trust level |
| `TRUSTED` | §10.3 | Trust level — full access |
| `UNTIL` | §5.3 | Termination condition for REPEAT |
| `USE` | §11.3 | Call a declared tool |
| `VERIFIED` | §10.3 | Trust level — registry-confirmed identity |
| `VERSION` | §11.1, §11.4 | Declare or require a tool version |
| `WAIT` | §4.2 | Pause before executing |
| `WITHOUT REVEALING` | §10.4 | ZK proof privacy constraint |

---

# Appendix B — Glossary

| Term | Definition |
|---|---|
| **Actor** | A lightweight concurrent process in the BEAM runtime with its own state and message mailbox. Every AgentLang GOAL maps to a BEAM actor. |
| **Agent** | An LLM-powered autonomous entity that writes and executes AgentLang programs to accomplish goals. |
| **Audit Trail** | An append-only, tamper-evident hash chain of agent actions. Implemented as a SHA-256 chain in the Rust performance layer. |
| **BEAM** | The Erlang virtual machine. Provides the actor model, OTP supervision trees, and hot code reloading for the AgentLang orchestration layer. |
| **BDI** | Belief-Desire-Intention — an agent architecture model that influenced AgentLang's goal-based control flow. |
| **Confidence** | A float annotation (0.0–1.0) expressing the agent's certainty about a value. A first-class type in AgentLang. |
| **Contract** | A signed, verifiable declaration of an agent's capabilities and permission boundaries. |
| **ETS** | Erlang Term Storage — an in-memory key-value store used for session-scope memory in the AgentLang runtime. |
| **Fuzzy Recall** | Memory retrieval using semantic similarity rather than exact key lookup. Backed by pgvector embeddings. |
| **Goal** | The primary unit of work in AgentLang. Declarative, typed, and supervisable. |
| **Idempotent** | A GOAL or tool call that produces the same result regardless of how many times it is executed. |
| **MCP** | Model Context Protocol — an industry standard for tool and data access in agent systems. AgentLang tools are MCP-compatible. |
| **NIF** | Native Implemented Function — the mechanism for calling Rust code from the Elixir/BEAM orchestration layer. |
| **pgvector** | A PostgreSQL extension for vector similarity search. Replaced by LanceDB embedded vector storage in the AgentLang reference implementation. |
| **Registry** | A federated service that stores and verifies agent identities and contracts. |
| **Sensitive** | A type annotation marking a value as PII or secret. Auto-encrypted, ZK-proof-protected, and redacted in audit logs. |
| **Supervision Tree** | An OTP pattern where processes are supervised by parent processes that apply restart strategies on failure. |
| **Trust Level** | A categorical declaration of how much an agent trusts another: VERIFIED, TRUSTED, SANDBOXED, or BLOCKED. |
| **winterfell** | A Rust library for zk-STARK proof generation and verification. The ZK proof backend for AgentLang. |
| **ZK Proof** | Zero Knowledge Proof — a cryptographic technique for proving a claim without revealing the underlying data. |
| **zk-STARK** | Zero Knowledge Scalable Transparent Argument of Knowledge — requires no trusted setup and is post-quantum secure. |

---

# Appendix C — Design Influences

| Influence | Concept Borrowed |
|---|---|
| Bastion / Tokio | Fault-tolerant actor model, supervision trees, high-performance async |
| AgentSpeak / Jason | BDI agent architecture, goal-oriented control flow primitives |
| QUASAR (Mell et al., 2025) | Uncertainty quantification, agent code actions |
| Rust | Memory safety, performance, ZK proof and cryptographic library ecosystem |
| Tonic / gRPC | High-performance, typed inter-agent communication |
| SQL | Declarative intent over imperative procedure — write *what*, not *how* |
| GraphQL | Typed, inspectable, composable query structures — inspiration for OUTPUT blocks |
| MCP | Tool and data access standard — AgentLang tools are MCP-compatible by design |
| Zcash / bellman | ZK proof concepts — AgentLang chose winterfell (zk-STARKs) |
| ActivityPub / Email | Federated identity model — inspiration for the federated Agent Registry |
| Go language spec | Spec structure — minimal, precise, example-driven |
| Rust reference | Spec conventions — normative/informative distinction, grammar blocks |

---

# Appendix D — Change Log

| Version | Date | Changes |
|---|---|---|
| v0.1 | Apr 2026 | Initial draft — core syntax, GOAL blocks, control flow, error handling, idempotency, variables |
| v0.2 | Apr 2026 | Added agent-to-agent communication (CALL, DELEGATE, EMIT, ON) |
| v0.3 | Apr 2026 | Added trust layer, ZK proofs, contracts, agent identity, audit trail |
| v0.4 | Apr 2026 | Added memory system — four scopes, REMEMBER/RECALL/FORGET, fuzzy recall |
| v0.5 | Apr 2026 | Added type system — inferred types and agent-specific annotations |
| v0.6 | Apr 2026 | Added parallelism — PARALLEL/RACE/GATHER patterns, trust scoping |
| v0.7 | Apr 2026 | Added tools — declaration, USE, versioning, MCP compatibility |
| v0.8 | Apr 2026 | Added runtime architecture — hybrid Elixir/BEAM + Rust/Tokio |
| v0.9 | Apr 2026 | Resolved four open questions: GOAL result composition, ZK library (winterfell), Agent Registry (federated), tool versioning (semver + fallback) |
| v1.0 | Apr 2026 | Full restructure as publishable specification modelled on Go and Rust reference docs. Added: Abstract, formal grammar, lexical structure, keyword reference, glossary, design influences, change log, cover page. Added Actix Web guidance for Registry API. |

---

# Appendix E — Open Questions

The following questions remain unresolved and are marked `[OPEN]` for future specification versions:

1. `[OPEN]` How are memory conflicts resolved when two agents write the same shared key simultaneously — last-write-wins, or a conflict resolution protocol?
2. `[OPEN]` Should confidence thresholds be configurable at the runtime level, language level, or both?
3. `[OPEN]` How does the `uncertain` type interact with agent self-correction and hallucination-recovery loops?
4. `[OPEN]` Should `PARALLEL` blocks support dynamic branching — spawning goals from a list computed at runtime?
5. `[OPEN]` How should tool rate limits be enforced across parallel branches sharing the same tool?
6. `[OPEN]` Should there be a public tool registry beyond the standard library — and if so, who operates it?
7. `[OPEN]` What is the measured NIF communication overhead between the Elixir and Rust runtime layers in practice?
8. `[OPEN]` How does the runtime handle agent upgrades mid-execution during very long-running tasks?

---

*AgentLang Language Specification v1.0 · April 2026 · Apache 2.0 · github.com/agentlang/spec*
