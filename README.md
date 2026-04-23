# AgentLang 🤖✨

**A purpose-built language for LLM-powered agents.**  
*Written by agents. Executed by runtimes. Trusted by design.*

[![CI](https://github.com/adamrobbie/AgentLang/actions/workflows/ci.yml/badge.svg)](https://github.com/adamrobbie/AgentLang/actions/workflows/ci.yml)
[![Coverage](https://github.com/adamrobbie/AgentLang/actions/workflows/coverage.yml/badge.svg)](https://github.com/adamrobbie/AgentLang/actions/workflows/coverage.yml)
[![codecov](https://codecov.io/gh/adamrobbie/AgentLang/graph/badge.svg)](https://codecov.io/gh/adamrobbie/AgentLang)

---

## 🚀 Overview

AgentLang is a programming language specifically designed for the "Agentic Era." Unlike general-purpose languages like Python or TypeScript, which were optimized for human authorship, AgentLang is optimized for **Large Language Model (LLM) generation, token efficiency, and autonomous execution.**

It introduces goal-oriented control flow, first-class uncertainty/confidence types, privacy-preserving Zero Knowledge Proof (ZKP) integration, and a high-performance hybrid runtime.

## ⚠️ Disclaimer

**AgentLang is currently a Research & Education project.** 

While the ultimate intent is to build a robust, production-ready language and ecosystem for the Agentic Era, the current implementation serves primarily as a proof-of-concept and learning vehicle for combining Rust, actor-model concurrency, zero-knowledge proofs, and LLM-centric parsing. APIs, syntax, and features are subject to rapid, breaking changes.

## 🌟 Key Features

*   **Goal-Oriented Execution:** Replace fragile loops and `try/catch` blocks with native `GOAL` directives featuring built-in `RETRY`, `ON_FAIL`, and `DEADLINE`.
*   **First-Class Confidence:** Use `AS confidence` types to let agents make decisions based on their own certainty (e.g., `IF {city.confidence} > 0.9`).
*   **Privacy by Default:** Sensitive data is automatically encrypted and protected via **zk-STARKs (Zero Knowledge Proofs)**, allowing agents to prove permissions without revealing raw secrets.
*   **Trust-Aware Communication:** Every inter-agent message is cryptographically signed and verifiable via a federated Agent Registry.
*   **Elixir-Inspired Runtime:** A pure **Rust/Tokio** architecture utilizing **Bastion** for massive concurrency and fault-tolerant OTP-style orchestration, natively powering cryptography and ZK-proof generation.
*   **MCP Compatible:** Native support for the Model Context Protocol (MCP), making it compatible with the existing ecosystem of tools and data sources.

## 📝 Example Syntax

```agentlang
GOAL plan_trip
  SET origin = "London"
  SET destination = "New York"
  
  // Parallel execution with error handling
  PARALLEL
    GOAL search_flights
      FROM {origin} TO {destination}
      RESULT INTO {flights}
      RETRY 3
    END
    GOAL search_hotels
      IN {destination}
      RESULT INTO {hotels}
    END
  GATHER INTO {itinerary}
  ON_ALL_FAIL GOAL notify_human
  
  // Confidence-driven logic
  IF {itinerary.flights.confidence} > 0.85
    USE book_flight
      flight_id {itinerary.flights[0].id}
      CONFIRM_WITH human
      AUDIT_TRAIL true
    END
  END
END
```

## 🔍 How It Compares

AgentLang sits in a unique whitespace: **A natively compiled, memory-safe language that treats AI uncertainty, agent-to-agent trust, and Zero Knowledge privacy as first-class syntactical primitives.**

| Ecosystem | Examples | AgentLang Difference |
| :--- | :--- | :--- |
| **Agent Frameworks** | LangGraph, AutoGen, CrewAI | These are *libraries* on top of Python/TS requiring heavy boilerplate (`try/except`, retry loops). AgentLang is a *DSL* with native semantics (`GOAL`, `ON_FAIL`, `RETRY`). |
| **Prompting DSLs** | LMQL, Guidance, DSPy | These focus on the *micro-level* (constraining a single LLM response). AgentLang focuses on *macro-level* orchestration, parallel execution, and state. |
| **Crypto Agent Networks** | Fetch.ai, Autonolas | These use Python SDKs to connect agents to ledgers. AgentLang bakes **zk-STARKs** and data sensitivity (`AS sensitive`) directly into the compiler types for guaranteed privacy. |
| **Actor-Model Languages** | Elixir/Erlang, Pony | These lack concepts for LLM "confidence thresholds" or "hallucination recovery". AgentLang fuses Actor Model supervision with AI-native primitives. |

## 🏗️ Architecture

AgentLang uses a **Pure Rust** architecture designed for massive throughput and zero-cost safety:

1.  **Orchestration (Tokio + Bastion):** Every `GOAL` is a supervised task. We use the **Bastion** runtime to provide OTP-style supervision trees, ensuring that one failing agent cannot crash the system.
2.  **Safety Layer:** Built-in support for **WebAssembly (WASM)** allows for sandboxed agent execution and hot-swappable logic without restarting the host.
3.  **High-Performance Primitives:**
    *   **winterfell:** Fast zk-STARK proof generation.
    *   **Tonic:** gRPC-based inter-agent communication.
    *   **sqlx:** Type-safe, asynchronous database access for memory scopes.
    *   **nom:** High-speed, zero-copy parsing of `.al` source files.

## 🗺️ Roadmap

- [ ] **Phase 1:** TypeScript-based Interpreter (PoC)
- [ ] **Phase 2:** Full Grammar & Type Validation
- [ ] **Phase 3:** Native Rust Actor-Model Orchestrator (Bastion)
- [ ] **Phase 4:** Rust-based Crypto & ZK-Proof Engine
- [ ] **Phase 5:** Federated Agent Registry

## 📄 License

AgentLang is licensed under the [Apache 2.0 License](LICENSE).

---

*Generated by AgentLang Spec v1.0 · April 2026*
