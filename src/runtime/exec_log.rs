//! Execution log for ZKP Phase 1.
//!
//! Append-only record of every Statement evaluated inside a Prove block,
//! used as the trace input for per-statement AIRs in Phase 2+.
//! See docs/zkp/01-per-statement-airs.md.

use crate::ast::MemoryScope;
use crate::runtime::memory_commit::MemoryCommit;
use ring::digest;
use serde::{Deserialize, Serialize};

pub type Hash32 = [u8; 32];

/// SHA-256 of `bytes`, sized for the `Hash32` operand fields. Phase 2's
/// memory-Merkle gadget assumes 256-bit leaves; matching that here means
/// the eventual constraint check has nothing to coerce.
pub fn hash(bytes: &[u8]) -> Hash32 {
    let h = digest::digest(&digest::SHA256, bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_ref());
    out
}

/// Folds the first 16 bytes of `bytes` (big-endian) into a `u128`.
/// Used by the AIR's memory-row columns (`CFA_PATH_COL`, `CFA_VALUE_COL`)
/// where the trace cell only has ~128 bits of headroom in the BaseElement
/// field. Lossy by ~64 bits vs. the source 256-bit hash; the lookup
/// argument's α/β randomization in sub-phase 3e folds the residual entropy
/// back in via the `(α·path + β·value)` linear combination, restoring the
/// soundness margin per the prototype's degree-budget analysis.
///
/// The leading 16 bytes are deliberate: SHA-256's avalanche distributes
/// pre-image entropy across all 32 output bytes, so the prefix is as
/// good as any other slice for collision-resistance purposes, and using
/// the prefix keeps the fold trivially auditable.
pub fn fold_to_u128(bytes: &[u8]) -> u128 {
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&bytes[..16]);
    u128::from_be_bytes(arr)
}

/// Maps `MemoryScope` to the 0-based byte the AIR's scope column
/// expects (`CFA_SCOPE_COL`). Aligned with `memory_commit::scope_byte`
/// — i.e. the encoding the SMT keys leaves under — so trace rows and
/// SMT addresses share one namespace.
///
/// Deliberately distinct from [`scope_byte`] (1-based) which is used
/// only for the canonical-bytes digest binding. The two namespaces
/// must not be merged: lookup-argument soundness in 3e requires the
/// trace `(scope, path, value)` factor to collide with the table side
/// derived from the SMT, and the SMT side uses 0-based.
fn mem_scope_byte(scope: MemoryScope) -> u8 {
    match scope {
        MemoryScope::Working => 0,
        MemoryScope::Session => 1,
        MemoryScope::LongTerm => 2,
        MemoryScope::Shared => 3,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Opcode {
    Nop = 0x00,
    GoalEnter = 0x01,
    GoalExit = 0x02,
    Set = 0x10,
    If = 0x11,
    Remember = 0x20,
    Recall = 0x21,
    Forget = 0x22,
    Call = 0x30,
    Delegate = 0x31,
    UseWasm = 0x40,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum GoalStatus {
    Success = 0x01,
    Failure = 0x02,
    Timeout = 0x03,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operands {
    GoalEnter {
        name_hash: Hash32,
        audit_root: Hash32,
    },
    GoalExit {
        name_hash: Hash32,
        status: GoalStatus,
        audit_root: Hash32,
    },
    Set {
        name_hash: Hash32,
        value_hash: Hash32,
    },
    If {
        cond_hash: Hash32,
        branch_taken: bool,
    },
    Remember {
        scope: MemoryScope,
        path_hash: Hash32,
        value_hash: Hash32,
        ttl: Option<u64>,
    },
    Recall {
        scope: MemoryScope,
        path_hash: Hash32,
        value_hash: Hash32,
    },
    Forget {
        scope: MemoryScope,
        path_hash: Hash32,
    },
    Call {
        callee_hash: Hash32,
        goal_hash: Hash32,
        args_hash: Hash32,
        result_hash: Hash32,
    },
    Delegate {
        callee_hash: Hash32,
        goal_hash: Hash32,
        args_hash: Hash32,
        result_hash: Hash32,
    },
    UseWasm {
        module_hash: Hash32,
        function_hash: Hash32,
        input_hash: Hash32,
        output_hash: Hash32,
        fuel_consumed: u64,
    },
    Nop,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    pub operands: Operands,
}

impl LogEntry {
    pub fn opcode(&self) -> Opcode {
        match self.operands {
            Operands::Nop => Opcode::Nop,
            Operands::GoalEnter { .. } => Opcode::GoalEnter,
            Operands::GoalExit { .. } => Opcode::GoalExit,
            Operands::Set { .. } => Opcode::Set,
            Operands::If { .. } => Opcode::If,
            Operands::Remember { .. } => Opcode::Remember,
            Operands::Recall { .. } => Opcode::Recall,
            Operands::Forget { .. } => Opcode::Forget,
            Operands::Call { .. } => Opcode::Call,
            Operands::Delegate { .. } => Opcode::Delegate,
            Operands::UseWasm { .. } => Opcode::UseWasm,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionLog {
    entries: Vec<LogEntry>,
}

impl ExecutionLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, entry: LogEntry) {
        self.entries.push(entry);
    }

    pub fn entries(&self) -> &[LogEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Deterministic, fixed-width-per-opcode encoding consumed by the
    /// Phase 2 AIR. The byte stream is the concatenation of
    /// `[opcode_byte][operands...]` for each entry in record order.
    /// Operand widths are pinned by tests in this module — changing them
    /// invalidates every existing proof.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for entry in &self.entries {
            entry.write_canonical(&mut out);
        }
        out
    }
}

/// One row of the Phase 2 AIR trace. The AIR consumes one row per
/// `LogEntry`; constraints fire selector-style based on `opcode`.
///
/// `branch_taken` and `goal_status` surface the two control-flow witnesses
/// the constraint families need without parsing the canonical-byte stream.
/// Every other operand stays bound through the polynomial digest recurrence.
///
/// Default = Nop row with zero witnesses, used for trace padding to a
/// power-of-two length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogTraceRow {
    pub opcode: u8,
    pub branch_taken: u8,
    pub goal_status: u8,
    /// Goal-stack depth BEFORE this row's opcode is processed. Row 0 is
    /// always 0; each `GoalEnter` increments depth on the *next* row,
    /// each `GoalExit` decrements. Phase 2 Slice 6 uses this column as
    /// witness for the AIR's pairing constraint.
    pub depth: u32,

    // -- Phase 3c-AIR: memory-row witness columns ---------------------
    // Populated for `Set`, `Remember`, `Recall`, `Forget` rows; zero on
    // every other opcode. The AIR's main segment carries one column per
    // field (`CFA_SCOPE_COL`/`PATH_COL`/`VALUE_COL`/`MROOT_COL`).
    //
    // Encoding (must match what the table-side prover will use in 3e):
    //   - `scope` — 0=Working, 1=Session, 2=LongTerm, 3=Shared. Aligned
    //     with `memory_commit::scope_byte` (the 0-based encoding the
    //     SMT keys leaves with), *not* `exec_log::scope_byte` (1-based,
    //     used only for canonical-bytes digest binding). The two are
    //     deliberately distinct namespaces — the AIR consumes the
    //     SMT-aligned form so `(scope, path, value)` lookup factors
    //     line up across trace and table.
    //   - `path` — first 16 bytes of `Operands::*.path_hash` (or
    //     `Set.name_hash`) folded to `u128`. Lossy (~64-bit collision
    //     resistance after BaseElement reduction); the lookup
    //     argument's α/β randomization in 3e adds back the soundness
    //     margin per the prototype's degree-budget analysis.
    //   - `value` — same fold over `value_hash`. `Forget` rows use
    //     0 since `EMPTY_LEAF` folds to 0.
    //   - `mroot` — running memory root after this row's update,
    //     folded to `u128`. **Zero in 3c-AIR**; 3d wires the running
    //     SMT root through the prover into this column.
    pub scope: u8,
    pub path: u128,
    pub value: u128,
    pub mroot: u128,
}

impl Default for LogTraceRow {
    /// Padding row used to extend a trace to power-of-two length. All
    /// fields are zero except the Nop opcode. Column variation across
    /// the trace is driven by the anti-pad sequence in
    /// `ControlFlowProver::build_trace` (one Nop, GoalEnter, If,
    /// GoalExit row); padding need not contribute. Pinning
    /// branch_taken/goal_status to 0 keeps the Slice 7 binding
    /// constraint `branch_taken * (opcode - IF) = 0` trivially
    /// satisfied on padding rows.
    fn default() -> Self {
        Self {
            opcode: Opcode::Nop as u8,
            branch_taken: 0,
            goal_status: 0,
            depth: 0,
            scope: 0,
            path: 0,
            value: 0,
            mroot: 0,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogTrace {
    pub rows: Vec<LogTraceRow>,
}

/// Per-entry witness fields the trace consumes regardless of `mroot`
/// strategy. Returned in column order:
/// `(opcode, branch_taken, goal_status, scope, path, value)`.
fn entry_witnesses(entry: &LogEntry) -> (u8, u8, u8, u8, u128, u128) {
    let opcode = entry.opcode() as u8;
    let (branch_taken, goal_status) = match &entry.operands {
        Operands::If { branch_taken, .. } => (if *branch_taken { 1 } else { 0 }, 0),
        Operands::GoalExit { status, .. } => (0, *status as u8),
        _ => (0, 0),
    };
    // Phase 3c-AIR memory-row witness columns. Non-memory rows leave
    // (scope, path, value) at zero; SET infers scope=0 (Working) per
    // option (Y); FORGET sets value=0 since EMPTY_LEAF folds to 0.
    let (scope, path, value) = match &entry.operands {
        Operands::Set {
            name_hash,
            value_hash,
        } => (0, fold_to_u128(name_hash), fold_to_u128(value_hash)),
        Operands::Remember {
            scope,
            path_hash,
            value_hash,
            ..
        } => (
            mem_scope_byte(*scope),
            fold_to_u128(path_hash),
            fold_to_u128(value_hash),
        ),
        Operands::Recall {
            scope,
            path_hash,
            value_hash,
        } => (
            mem_scope_byte(*scope),
            fold_to_u128(path_hash),
            fold_to_u128(value_hash),
        ),
        Operands::Forget { scope, path_hash } => {
            (mem_scope_byte(*scope), fold_to_u128(path_hash), 0)
        }
        _ => (0, 0, 0),
    };
    (opcode, branch_taken, goal_status, scope, path, value)
}

/// `+1` for `GoalEnter`, `-1` for `GoalExit`, `0` everywhere else.
/// Drives the depth-column recurrence; we use a signed counter so
/// unbalanced logs surface as either negative-clipped depths or huge
/// u32 values, both of which the AIR's depth boundary at the last row
/// will reject as ≠ 0.
fn entry_depth_delta(entry: &LogEntry) -> i64 {
    match &entry.operands {
        Operands::GoalEnter { .. } => 1,
        Operands::GoalExit { .. } => -1,
        _ => 0,
    }
}

impl From<&ExecutionLog> for LogTrace {
    fn from(log: &ExecutionLog) -> Self {
        // Witness-only constructor: leaves the `mroot` column at zero on
        // every row. Used by hand-built test traces and any caller that
        // doesn't have a starting `MemoryCommit` to replay against. The
        // production path (`Statement::Prove`) goes through
        // [`LogTrace::from_log_and_commit`] which threads the running
        // SMT root through `mroot`.
        let mut depth: i64 = 0;
        let rows = log
            .entries()
            .iter()
            .map(|entry| {
                let (opcode, branch_taken, goal_status, scope, path, value) =
                    entry_witnesses(entry);
                let row = LogTraceRow {
                    opcode,
                    branch_taken,
                    goal_status,
                    depth: depth.max(0) as u32,
                    scope,
                    path,
                    value,
                    mroot: 0,
                };
                depth += entry_depth_delta(entry);
                row
            })
            .collect();
        LogTrace { rows }
    }
}

impl LogTrace {
    /// Replay-driven trace builder (sub-phase 3d). Threads `starting_commit`'s
    /// root through the `mroot` column with **before-row semantics**:
    /// `rows[i].mroot` is the SMT root *entering* row `i` (i.e., the root
    /// before that row's effect is applied). Mutations advance the
    /// running commit so `rows[i+1].mroot` reflects row `i`'s update.
    ///
    /// What that buys 3e:
    /// - `rows[0].mroot == fold_to_u128(memory_root_pre)`. The eventual
    ///   boundary assertion in the AIR can compare this column cell to
    ///   a folded form of `StarkProof.memory_root_pre`.
    /// - The post-execution `commit.root()` (which equals
    ///   `memory_root_post`) is the value carried by every row past the
    ///   last memory-mutating entry. The 3e prover propagates that into
    ///   anti-pad / padding rows so the last-row boundary against
    ///   `memory_root_post` works.
    /// - On non-memory rows, `mroot[i+1] == mroot[i]` — the root-carry
    ///   constraint C8a in the plan is therefore degree 1 outside the
    ///   memory-selector gate.
    ///
    /// Recall is treated as a no-op for the running root: it's a *read*,
    /// not a write. The 3e lookup ties the (scope, path, value) factor
    /// to a table-side row that asserts `mroot_before == mroot_after`
    /// for that read; the column cells on the trace already match that.
    /// Shared scope is also a runtime no-op (`apply_remember`/`apply_forget`
    /// return `None` for Shared per 3a option a), so the fold of the
    /// running root passes through unchanged for those rows too.
    pub fn from_log_and_commit(log: &ExecutionLog, mut commit: MemoryCommit) -> Self {
        let mut depth: i64 = 0;
        let mut prev_root_folded = fold_to_u128(&commit.root());
        let rows = log
            .entries()
            .iter()
            .map(|entry| {
                let (opcode, branch_taken, goal_status, scope, path, value) =
                    entry_witnesses(entry);
                let row = LogTraceRow {
                    opcode,
                    branch_taken,
                    goal_status,
                    depth: depth.max(0) as u32,
                    scope,
                    path,
                    value,
                    mroot: prev_root_folded,
                };
                // Apply this entry's effect to the running commit. Set
                // routes to `apply_remember(Working, ...)` per option
                // (Y); Recall and non-memory ops leave the commit
                // untouched. The witness returned by apply_* is
                // discarded — 3e wires the AIR-side lookup against a
                // separate table builder, not against witnesses
                // captured here.
                match &entry.operands {
                    Operands::Set {
                        name_hash,
                        value_hash,
                    } => {
                        commit.apply_remember(MemoryScope::Working, name_hash, *value_hash);
                    }
                    Operands::Remember {
                        scope,
                        path_hash,
                        value_hash,
                        ..
                    } => {
                        commit.apply_remember(*scope, path_hash, *value_hash);
                    }
                    Operands::Forget { scope, path_hash } => {
                        commit.apply_forget(*scope, path_hash);
                    }
                    _ => {}
                }
                prev_root_folded = fold_to_u128(&commit.root());
                depth += entry_depth_delta(entry);
                row
            })
            .collect();
        LogTrace { rows }
    }
}

fn scope_byte(scope: MemoryScope) -> u8 {
    // Stable scope-byte assignment. Pinned by tests; bump proof_version
    // before reordering. See docs/zkp/01-per-statement-airs.md.
    match scope {
        MemoryScope::Working => 0x01,
        MemoryScope::Session => 0x02,
        MemoryScope::LongTerm => 0x03,
        MemoryScope::Shared => 0x04,
    }
}

impl LogEntry {
    fn write_canonical(&self, out: &mut Vec<u8>) {
        out.push(self.opcode() as u8);
        match &self.operands {
            Operands::Nop => {}
            Operands::GoalEnter {
                name_hash,
                audit_root,
            } => {
                out.extend_from_slice(name_hash);
                out.extend_from_slice(audit_root);
            }
            Operands::GoalExit {
                name_hash,
                status,
                audit_root,
            } => {
                out.extend_from_slice(name_hash);
                out.push(*status as u8);
                out.extend_from_slice(audit_root);
            }
            Operands::Set {
                name_hash,
                value_hash,
            } => {
                out.extend_from_slice(name_hash);
                out.extend_from_slice(value_hash);
            }
            Operands::If {
                cond_hash,
                branch_taken,
            } => {
                out.extend_from_slice(cond_hash);
                out.push(if *branch_taken { 0x01 } else { 0x00 });
            }
            Operands::Remember {
                scope,
                path_hash,
                value_hash,
                ttl,
            } => {
                out.push(scope_byte(*scope));
                out.extend_from_slice(path_hash);
                out.extend_from_slice(value_hash);
                // Fixed width: 1-byte present marker + 8-byte BE u64. Both
                // halves are written even when ttl is None so the AIR can
                // step row-aligned without parsing.
                match ttl {
                    Some(t) => {
                        out.push(0x01);
                        out.extend_from_slice(&t.to_be_bytes());
                    }
                    None => {
                        out.push(0x00);
                        out.extend_from_slice(&[0u8; 8]);
                    }
                }
            }
            Operands::Recall {
                scope,
                path_hash,
                value_hash,
            } => {
                out.push(scope_byte(*scope));
                out.extend_from_slice(path_hash);
                out.extend_from_slice(value_hash);
            }
            Operands::Forget { scope, path_hash } => {
                out.push(scope_byte(*scope));
                out.extend_from_slice(path_hash);
            }
            Operands::Call {
                callee_hash,
                goal_hash,
                args_hash,
                result_hash,
            }
            | Operands::Delegate {
                callee_hash,
                goal_hash,
                args_hash,
                result_hash,
            } => {
                out.extend_from_slice(callee_hash);
                out.extend_from_slice(goal_hash);
                out.extend_from_slice(args_hash);
                out.extend_from_slice(result_hash);
            }
            Operands::UseWasm {
                module_hash,
                function_hash,
                input_hash,
                output_hash,
                fuel_consumed,
            } => {
                out.extend_from_slice(module_hash);
                out.extend_from_slice(function_hash);
                out.extend_from_slice(input_hash);
                out.extend_from_slice(output_hash);
                out.extend_from_slice(&fuel_consumed.to_be_bytes());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(b: u8) -> Hash32 {
        [b; 32]
    }

    fn set_entry(name: u8, val: u8) -> LogEntry {
        LogEntry {
            operands: Operands::Set {
                name_hash: h(name),
                value_hash: h(val),
            },
        }
    }

    #[test]
    fn new_log_is_empty() {
        let log = ExecutionLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
        assert!(log.entries().is_empty());
    }

    #[test]
    fn record_appends_in_order() {
        let mut log = ExecutionLog::new();
        log.record(set_entry(1, 2));
        log.record(set_entry(3, 4));
        log.record(set_entry(5, 6));

        assert_eq!(log.len(), 3);
        assert!(!log.is_empty());

        let names: Vec<Hash32> = log
            .entries()
            .iter()
            .map(|e| match e.operands {
                Operands::Set { name_hash, .. } => name_hash,
                _ => panic!("unexpected variant"),
            })
            .collect();
        assert_eq!(names, vec![h(1), h(3), h(5)]);
    }

    #[test]
    fn opcode_byte_values_are_stable() {
        // These bytes feed the AIR's opcode column. Changing them invalidates
        // every existing proof; bump StarkProof.proof_version if you must.
        // See docs/zkp/01-per-statement-airs.md "Open questions" #5.
        assert_eq!(Opcode::Nop as u8, 0x00);
        assert_eq!(Opcode::GoalEnter as u8, 0x01);
        assert_eq!(Opcode::GoalExit as u8, 0x02);
        assert_eq!(Opcode::Set as u8, 0x10);
        assert_eq!(Opcode::If as u8, 0x11);
        assert_eq!(Opcode::Remember as u8, 0x20);
        assert_eq!(Opcode::Recall as u8, 0x21);
        assert_eq!(Opcode::Forget as u8, 0x22);
        assert_eq!(Opcode::Call as u8, 0x30);
        assert_eq!(Opcode::Delegate as u8, 0x31);
        assert_eq!(Opcode::UseWasm as u8, 0x40);
    }

    #[test]
    fn goal_status_byte_values_are_stable() {
        assert_eq!(GoalStatus::Success as u8, 0x01);
        assert_eq!(GoalStatus::Failure as u8, 0x02);
        assert_eq!(GoalStatus::Timeout as u8, 0x03);
    }

    #[test]
    fn opcode_matches_goal_enter() {
        let entry = LogEntry {
            operands: Operands::GoalEnter {
                name_hash: h(1),
                audit_root: h(2),
            },
        };
        assert_eq!(entry.opcode(), Opcode::GoalEnter);
    }

    #[test]
    fn opcode_matches_goal_exit() {
        let entry = LogEntry {
            operands: Operands::GoalExit {
                name_hash: h(1),
                status: GoalStatus::Success,
                audit_root: h(2),
            },
        };
        assert_eq!(entry.opcode(), Opcode::GoalExit);
    }

    #[test]
    fn opcode_matches_set() {
        assert_eq!(set_entry(1, 2).opcode(), Opcode::Set);
    }

    #[test]
    fn opcode_matches_if() {
        let entry = LogEntry {
            operands: Operands::If {
                cond_hash: h(1),
                branch_taken: true,
            },
        };
        assert_eq!(entry.opcode(), Opcode::If);
    }

    #[test]
    fn opcode_matches_remember() {
        let entry = LogEntry {
            operands: Operands::Remember {
                scope: MemoryScope::LongTerm,
                path_hash: h(1),
                value_hash: h(2),
                ttl: None,
            },
        };
        assert_eq!(entry.opcode(), Opcode::Remember);
    }

    #[test]
    fn opcode_matches_recall() {
        let entry = LogEntry {
            operands: Operands::Recall {
                scope: MemoryScope::LongTerm,
                path_hash: h(1),
                value_hash: h(2),
            },
        };
        assert_eq!(entry.opcode(), Opcode::Recall);
    }

    #[test]
    fn opcode_matches_forget() {
        let entry = LogEntry {
            operands: Operands::Forget {
                scope: MemoryScope::LongTerm,
                path_hash: h(1),
            },
        };
        assert_eq!(entry.opcode(), Opcode::Forget);
    }

    #[test]
    fn opcode_matches_call() {
        let entry = LogEntry {
            operands: Operands::Call {
                callee_hash: h(1),
                goal_hash: h(2),
                args_hash: h(3),
                result_hash: h(4),
            },
        };
        assert_eq!(entry.opcode(), Opcode::Call);
    }

    #[test]
    fn opcode_matches_delegate() {
        let entry = LogEntry {
            operands: Operands::Delegate {
                callee_hash: h(1),
                goal_hash: h(2),
                args_hash: h(3),
                result_hash: h(4),
            },
        };
        assert_eq!(entry.opcode(), Opcode::Delegate);
    }

    #[test]
    fn opcode_matches_use_wasm() {
        let entry = LogEntry {
            operands: Operands::UseWasm {
                module_hash: h(1),
                function_hash: h(2),
                input_hash: h(3),
                output_hash: h(4),
                fuel_consumed: 100,
            },
        };
        assert_eq!(entry.opcode(), Opcode::UseWasm);
    }

    #[test]
    fn opcode_matches_nop() {
        let entry = LogEntry {
            operands: Operands::Nop,
        };
        assert_eq!(entry.opcode(), Opcode::Nop);
    }

    #[test]
    fn call_and_delegate_have_distinct_opcodes() {
        let same_operands = (h(1), h(2), h(3), h(4));
        let call = LogEntry {
            operands: Operands::Call {
                callee_hash: same_operands.0,
                goal_hash: same_operands.1,
                args_hash: same_operands.2,
                result_hash: same_operands.3,
            },
        };
        let delegate = LogEntry {
            operands: Operands::Delegate {
                callee_hash: same_operands.0,
                goal_hash: same_operands.1,
                args_hash: same_operands.2,
                result_hash: same_operands.3,
            },
        };
        assert_ne!(call.opcode(), delegate.opcode());
        assert_ne!(call, delegate);
    }

    #[test]
    fn entries_serialize_roundtrip_json() {
        let mut log = ExecutionLog::new();
        log.record(LogEntry {
            operands: Operands::GoalEnter {
                name_hash: h(1),
                audit_root: h(2),
            },
        });
        log.record(set_entry(3, 4));
        log.record(LogEntry {
            operands: Operands::If {
                cond_hash: h(5),
                branch_taken: true,
            },
        });
        log.record(LogEntry {
            operands: Operands::Remember {
                scope: MemoryScope::LongTerm,
                path_hash: h(6),
                value_hash: h(7),
                ttl: Some(60),
            },
        });
        log.record(LogEntry {
            operands: Operands::GoalExit {
                name_hash: h(1),
                status: GoalStatus::Success,
                audit_root: h(8),
            },
        });

        let json = serde_json::to_string(&log).expect("serialize");
        let restored: ExecutionLog = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored, log);
    }

    #[test]
    fn memory_scopes_produce_distinct_entries() {
        // The AIR's memory commitment lookup keys off scope; entries that
        // differ only in scope must remain non-equal.
        let mk = |s| LogEntry {
            operands: Operands::Remember {
                scope: s,
                path_hash: h(1),
                value_hash: h(2),
                ttl: None,
            },
        };
        let working = mk(MemoryScope::Working);
        let session = mk(MemoryScope::Session);
        let long_term = mk(MemoryScope::LongTerm);
        let shared = mk(MemoryScope::Shared);
        assert_ne!(working, session);
        assert_ne!(session, long_term);
        assert_ne!(long_term, shared);
        assert_ne!(working, shared);
    }

    #[test]
    fn goal_statuses_produce_distinct_entries() {
        let mk = |st| LogEntry {
            operands: Operands::GoalExit {
                name_hash: h(1),
                status: st,
                audit_root: h(2),
            },
        };
        assert_ne!(mk(GoalStatus::Success), mk(GoalStatus::Failure));
        assert_ne!(mk(GoalStatus::Failure), mk(GoalStatus::Timeout));
        assert_ne!(mk(GoalStatus::Success), mk(GoalStatus::Timeout));
    }

    #[test]
    fn if_branch_selector_is_recorded_faithfully() {
        // Phase 2 control-flow constraints witness `branch_taken`; the log
        // must surface both polarities byte-for-byte.
        let mut log = ExecutionLog::new();
        log.record(LogEntry {
            operands: Operands::If {
                cond_hash: h(1),
                branch_taken: true,
            },
        });
        log.record(LogEntry {
            operands: Operands::If {
                cond_hash: h(2),
                branch_taken: false,
            },
        });
        let taken: Vec<bool> = log
            .entries()
            .iter()
            .map(|e| match e.operands {
                Operands::If { branch_taken, .. } => branch_taken,
                _ => panic!("unexpected variant"),
            })
            .collect();
        assert_eq!(taken, vec![true, false]);
    }

    #[test]
    fn remember_ttl_optional_round_trip() {
        let mut log = ExecutionLog::new();
        log.record(LogEntry {
            operands: Operands::Remember {
                scope: MemoryScope::LongTerm,
                path_hash: h(1),
                value_hash: h(2),
                ttl: None,
            },
        });
        log.record(LogEntry {
            operands: Operands::Remember {
                scope: MemoryScope::LongTerm,
                path_hash: h(1),
                value_hash: h(2),
                ttl: Some(60),
            },
        });
        let ttls: Vec<Option<u64>> = log
            .entries()
            .iter()
            .map(|e| match e.operands {
                Operands::Remember { ttl, .. } => ttl,
                _ => panic!("unexpected variant"),
            })
            .collect();
        assert_eq!(ttls, vec![None, Some(60)]);
    }

    #[test]
    fn wasm_fuel_is_recorded() {
        let mut log = ExecutionLog::new();
        log.record(LogEntry {
            operands: Operands::UseWasm {
                module_hash: h(1),
                function_hash: h(2),
                input_hash: h(3),
                output_hash: h(4),
                fuel_consumed: 12_345,
            },
        });
        match log.entries()[0].operands {
            Operands::UseWasm { fuel_consumed, .. } => assert_eq!(fuel_consumed, 12_345),
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn equal_logs_compare_equal() {
        // Property used by differential tests in Phase 5: the same Prove
        // block re-executed must produce a log equal to the original.
        let mut a = ExecutionLog::new();
        let mut b = ExecutionLog::new();
        for i in 0..5 {
            a.record(set_entry(i, i + 1));
            b.record(set_entry(i, i + 1));
        }
        assert_eq!(a, b);
    }

    #[test]
    fn divergent_logs_compare_unequal() {
        let mut a = ExecutionLog::new();
        let mut b = ExecutionLog::new();
        a.record(set_entry(1, 2));
        b.record(set_entry(1, 3));
        assert_ne!(a, b);
    }

    #[test]
    fn hash_field_size_is_thirty_two_bytes() {
        // Phase 2's memory-Merkle gadget assumes 256-bit hashes. If we
        // ever change Hash32, this test forces the change to be deliberate.
        let _: Hash32 = [0u8; 32];
        assert_eq!(std::mem::size_of::<Hash32>(), 32);
    }

    // ----------------------------------------------------------------------
    // Phase 2 — canonical_bytes encoding
    //
    // The AIR's polynomial digest consumes the log byte-by-byte, so the
    // mapping from `ExecutionLog` to bytes must be deterministic, fixed-width
    // per opcode, and faithful to every operand. These tests pin the wire
    // format. Changing them invalidates every existing proof.
    // ----------------------------------------------------------------------

    #[test]
    fn canonical_bytes_empty_log_is_empty() {
        let log = ExecutionLog::new();
        assert!(log.canonical_bytes().is_empty());
    }

    #[test]
    fn canonical_bytes_starts_with_opcode_byte() {
        let mut log = ExecutionLog::new();
        log.record(set_entry(1, 2));
        let bytes = log.canonical_bytes();
        assert_eq!(bytes[0], Opcode::Set as u8);
    }

    #[test]
    fn canonical_bytes_set_layout_is_opcode_then_name_then_value() {
        let mut log = ExecutionLog::new();
        log.record(set_entry(0xAA, 0xBB));
        let bytes = log.canonical_bytes();
        // 1 byte opcode + 32 name + 32 value
        assert_eq!(bytes.len(), 1 + 32 + 32);
        assert_eq!(bytes[0], Opcode::Set as u8);
        assert_eq!(&bytes[1..33], &[0xAA; 32]);
        assert_eq!(&bytes[33..65], &[0xBB; 32]);
    }

    #[test]
    fn canonical_bytes_concatenates_entries_in_order() {
        let mut log = ExecutionLog::new();
        log.record(set_entry(1, 2));
        log.record(set_entry(3, 4));
        let bytes = log.canonical_bytes();
        assert_eq!(bytes.len(), 2 * (1 + 32 + 32));

        let mut a = ExecutionLog::new();
        a.record(set_entry(1, 2));
        let mut b = ExecutionLog::new();
        b.record(set_entry(3, 4));
        let mut concat = a.canonical_bytes();
        concat.extend(b.canonical_bytes());
        assert_eq!(bytes, concat);
    }

    #[test]
    fn canonical_bytes_is_deterministic() {
        let build = || {
            let mut log = ExecutionLog::new();
            log.record(LogEntry {
                operands: Operands::GoalEnter {
                    name_hash: h(1),
                    audit_root: h(2),
                },
            });
            log.record(set_entry(3, 4));
            log.record(LogEntry {
                operands: Operands::GoalExit {
                    name_hash: h(1),
                    status: GoalStatus::Success,
                    audit_root: h(5),
                },
            });
            log
        };
        assert_eq!(build().canonical_bytes(), build().canonical_bytes());
    }

    #[test]
    fn canonical_bytes_extends_on_record_preserving_prefix() {
        let mut log = ExecutionLog::new();
        log.record(set_entry(1, 2));
        let prefix = log.canonical_bytes();
        log.record(set_entry(3, 4));
        let extended = log.canonical_bytes();
        assert!(extended.len() > prefix.len());
        assert_eq!(&extended[..prefix.len()], prefix.as_slice());
    }

    #[test]
    fn canonical_bytes_distinguishes_branch_taken() {
        let mk = |taken: bool| {
            let mut log = ExecutionLog::new();
            log.record(LogEntry {
                operands: Operands::If {
                    cond_hash: h(1),
                    branch_taken: taken,
                },
            });
            log.canonical_bytes()
        };
        assert_ne!(mk(true), mk(false));
    }

    #[test]
    fn canonical_bytes_distinguishes_memory_scopes() {
        let mk = |scope: MemoryScope| {
            let mut log = ExecutionLog::new();
            log.record(LogEntry {
                operands: Operands::Remember {
                    scope,
                    path_hash: h(1),
                    value_hash: h(2),
                    ttl: None,
                },
            });
            log.canonical_bytes()
        };
        let working = mk(MemoryScope::Working);
        let session = mk(MemoryScope::Session);
        let long_term = mk(MemoryScope::LongTerm);
        let shared = mk(MemoryScope::Shared);
        // All four must be pairwise distinct.
        let all = [&working, &session, &long_term, &shared];
        for i in 0..4 {
            for j in (i + 1)..4 {
                assert_ne!(all[i], all[j], "scopes {i} and {j} must encode differently");
            }
        }
    }

    #[test]
    fn canonical_bytes_distinguishes_ttl_present_vs_absent() {
        let mk = |ttl| {
            let mut log = ExecutionLog::new();
            log.record(LogEntry {
                operands: Operands::Remember {
                    scope: MemoryScope::LongTerm,
                    path_hash: h(1),
                    value_hash: h(2),
                    ttl,
                },
            });
            log.canonical_bytes()
        };
        // None and Some(0) must remain distinguishable in the byte stream.
        assert_ne!(mk(None), mk(Some(0)));
        assert_ne!(mk(Some(60)), mk(Some(120)));
    }

    #[test]
    fn canonical_bytes_distinguishes_call_from_delegate() {
        // Identical operand hashes, different opcode → different bytes.
        let envelope = (h(1), h(2), h(3), h(4));
        let mk_call = || {
            let mut log = ExecutionLog::new();
            log.record(LogEntry {
                operands: Operands::Call {
                    callee_hash: envelope.0,
                    goal_hash: envelope.1,
                    args_hash: envelope.2,
                    result_hash: envelope.3,
                },
            });
            log.canonical_bytes()
        };
        let mk_del = || {
            let mut log = ExecutionLog::new();
            log.record(LogEntry {
                operands: Operands::Delegate {
                    callee_hash: envelope.0,
                    goal_hash: envelope.1,
                    args_hash: envelope.2,
                    result_hash: envelope.3,
                },
            });
            log.canonical_bytes()
        };
        let call_bytes = mk_call();
        let del_bytes = mk_del();
        assert_eq!(call_bytes.len(), del_bytes.len());
        // Differ in exactly the opcode byte.
        assert_ne!(call_bytes[0], del_bytes[0]);
        assert_eq!(call_bytes[1..], del_bytes[1..]);
    }

    #[test]
    fn canonical_bytes_use_wasm_fuel_is_big_endian() {
        let mut log = ExecutionLog::new();
        log.record(LogEntry {
            operands: Operands::UseWasm {
                module_hash: h(1),
                function_hash: h(2),
                input_hash: h(3),
                output_hash: h(4),
                fuel_consumed: 0x0102_0304_0506_0708,
            },
        });
        let bytes = log.canonical_bytes();
        // The last 8 bytes are the fuel; big-endian keeps lex-order monotone
        // with numeric order, which matters when we range-check fuel in AIR.
        assert_eq!(
            &bytes[bytes.len() - 8..],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn canonical_bytes_nop_is_single_opcode_byte() {
        let mut log = ExecutionLog::new();
        log.record(LogEntry {
            operands: Operands::Nop,
        });
        assert_eq!(log.canonical_bytes(), vec![Opcode::Nop as u8]);
    }

    // ----------------------------------------------------------------------
    // Phase 2 Slice 3 — LogTrace (opcode-row trace + control-flow witnesses)
    //
    // The Phase 2 AIR consumes one row per LogEntry. Beyond the opcode
    // column, two witness columns surface control-flow facts that the AIR
    // constrains directly:
    //   - branch_taken: 0/1 on If rows, 0 elsewhere
    //   - goal_status: GoalStatus byte on GoalExit rows, 0 elsewhere
    // Operand hashes stay bound through the canonical-byte digest recurrence;
    // no need to surface them as columns yet.
    // ----------------------------------------------------------------------

    #[test]
    fn log_trace_from_empty_log_has_no_rows() {
        let log = ExecutionLog::new();
        let trace = LogTrace::from(&log);
        assert!(trace.rows.is_empty());
    }

    #[test]
    fn log_trace_has_one_row_per_entry() {
        let mut log = ExecutionLog::new();
        log.record(set_entry(1, 2));
        log.record(set_entry(3, 4));
        log.record(LogEntry {
            operands: Operands::Nop,
        });
        let trace = LogTrace::from(&log);
        assert_eq!(trace.rows.len(), 3);
    }

    #[test]
    fn log_trace_opcode_column_matches_entry_opcode() {
        let mut log = ExecutionLog::new();
        log.record(LogEntry {
            operands: Operands::GoalEnter {
                name_hash: h(1),
                audit_root: h(2),
            },
        });
        log.record(set_entry(3, 4));
        log.record(LogEntry {
            operands: Operands::GoalExit {
                name_hash: h(1),
                status: GoalStatus::Success,
                audit_root: h(5),
            },
        });
        let trace = LogTrace::from(&log);
        assert_eq!(trace.rows[0].opcode, Opcode::GoalEnter as u8);
        assert_eq!(trace.rows[1].opcode, Opcode::Set as u8);
        assert_eq!(trace.rows[2].opcode, Opcode::GoalExit as u8);
    }

    #[test]
    fn log_trace_if_row_carries_branch_taken_witness() {
        let mut log = ExecutionLog::new();
        log.record(LogEntry {
            operands: Operands::If {
                cond_hash: h(1),
                branch_taken: true,
            },
        });
        log.record(LogEntry {
            operands: Operands::If {
                cond_hash: h(2),
                branch_taken: false,
            },
        });
        let trace = LogTrace::from(&log);
        assert_eq!(trace.rows[0].branch_taken, 1);
        assert_eq!(trace.rows[1].branch_taken, 0);
    }

    #[test]
    fn log_trace_branch_taken_is_zero_for_non_if_rows() {
        let mut log = ExecutionLog::new();
        log.record(set_entry(1, 2));
        log.record(LogEntry {
            operands: Operands::Recall {
                scope: MemoryScope::LongTerm,
                path_hash: h(3),
                value_hash: h(4),
            },
        });
        log.record(LogEntry {
            operands: Operands::Nop,
        });
        let trace = LogTrace::from(&log);
        for row in &trace.rows {
            assert_eq!(row.branch_taken, 0, "branch_taken nonzero on non-If row");
        }
    }

    #[test]
    fn log_trace_goal_exit_row_carries_status_witness() {
        let mk = |st| LogEntry {
            operands: Operands::GoalExit {
                name_hash: h(1),
                status: st,
                audit_root: h(2),
            },
        };
        let mut log = ExecutionLog::new();
        log.record(mk(GoalStatus::Success));
        log.record(mk(GoalStatus::Failure));
        log.record(mk(GoalStatus::Timeout));
        let trace = LogTrace::from(&log);
        assert_eq!(trace.rows[0].goal_status, GoalStatus::Success as u8);
        assert_eq!(trace.rows[1].goal_status, GoalStatus::Failure as u8);
        assert_eq!(trace.rows[2].goal_status, GoalStatus::Timeout as u8);
    }

    #[test]
    fn log_trace_goal_status_is_zero_outside_goal_exit() {
        let mut log = ExecutionLog::new();
        log.record(LogEntry {
            operands: Operands::GoalEnter {
                name_hash: h(1),
                audit_root: h(2),
            },
        });
        log.record(set_entry(3, 4));
        log.record(LogEntry {
            operands: Operands::If {
                cond_hash: h(5),
                branch_taken: true,
            },
        });
        let trace = LogTrace::from(&log);
        for row in &trace.rows {
            assert_eq!(
                row.goal_status, 0,
                "goal_status nonzero on non-GoalExit row (opcode={:#04x})",
                row.opcode
            );
        }
    }

    #[test]
    fn log_trace_preserves_record_order() {
        let mut log = ExecutionLog::new();
        for i in 0..5 {
            log.record(set_entry(i, i + 100));
        }
        let trace = LogTrace::from(&log);
        for row in &trace.rows {
            assert_eq!(row.opcode, Opcode::Set as u8);
        }
        assert_eq!(trace.rows.len(), 5);
    }

    #[test]
    fn log_trace_row_default_is_zero_nop() {
        // Padding rows are all-zero with a Nop opcode. Column variation
        // is provided by the AIR's anti-pad sequence, not by padding
        // defaults — see `Default for LogTraceRow` and Slice 7.
        let row = LogTraceRow::default();
        assert_eq!(row.opcode, Opcode::Nop as u8);
        assert_eq!(row.branch_taken, 0);
        assert_eq!(row.goal_status, 0);
        assert_eq!(row.depth, 0);
        // Phase 3c-AIR memory columns must default to zero so padding
        // rows don't accidentally drive the future memory-row selector
        // off Nop.
        assert_eq!(row.scope, 0);
        assert_eq!(row.path, 0);
        assert_eq!(row.value, 0);
        assert_eq!(row.mroot, 0);
    }

    // ----------------------------------------------------------------------
    // Phase 3c-AIR — memory-row trace columns
    //
    // The AIR will gate a `(scope, path, value)` lookup against the table
    // side derived from the SMT (sub-phase 3e). For now we only assert
    // that LogTrace::from populates the four new columns deterministically
    // from operand fields. `mroot` stays 0 throughout 3c-AIR; 3d wires
    // the running root.
    // ----------------------------------------------------------------------

    #[test]
    fn fold_to_u128_takes_first_sixteen_bytes_big_endian() {
        let bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, // ^^ first 16 bytes feed the fold
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, // tail must not influence output
        ];
        assert_eq!(
            fold_to_u128(&bytes),
            0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10
        );
    }

    #[test]
    fn fold_to_u128_distinguishes_distinct_prefixes() {
        let a: Hash32 = [0xaa; 32];
        let b: Hash32 = [0xbb; 32];
        assert_ne!(fold_to_u128(&a), fold_to_u128(&b));
    }

    #[test]
    fn log_trace_set_row_populates_scope_path_value() {
        // Option (Y): SET joins the memory selector. The AIR sees scope=0
        // (Working) and the (folded) name/value hashes.
        let mut log = ExecutionLog::new();
        log.record(set_entry(0xAA, 0xBB));
        let trace = LogTrace::from(&log);
        let row = trace.rows[0];
        assert_eq!(row.opcode, Opcode::Set as u8);
        assert_eq!(row.scope, 0, "SET implicitly attests to Working");
        assert_eq!(row.path, fold_to_u128(&h(0xAA)));
        assert_eq!(row.value, fold_to_u128(&h(0xBB)));
        assert_eq!(row.mroot, 0, "mroot stays zero in 3c-AIR");
    }

    #[test]
    fn log_trace_remember_row_populates_scope_from_operand() {
        let mk = |scope| LogEntry {
            operands: Operands::Remember {
                scope,
                path_hash: h(1),
                value_hash: h(2),
                ttl: None,
            },
        };
        let mut log = ExecutionLog::new();
        log.record(mk(MemoryScope::Working));
        log.record(mk(MemoryScope::Session));
        log.record(mk(MemoryScope::LongTerm));
        log.record(mk(MemoryScope::Shared));
        let trace = LogTrace::from(&log);
        // Encoding aligned with `memory_commit::scope_byte` (0-based).
        // The 1-based `exec_log::scope_byte` namespace stays separate.
        assert_eq!(trace.rows[0].scope, 0);
        assert_eq!(trace.rows[1].scope, 1);
        assert_eq!(trace.rows[2].scope, 2);
        assert_eq!(trace.rows[3].scope, 3);
        // Path/value identical across all four — only the scope column
        // separates them on the AIR side.
        let path = fold_to_u128(&h(1));
        let value = fold_to_u128(&h(2));
        for row in &trace.rows {
            assert_eq!(row.path, path);
            assert_eq!(row.value, value);
        }
    }

    #[test]
    fn log_trace_recall_row_populates_columns_like_remember() {
        let mut log = ExecutionLog::new();
        log.record(LogEntry {
            operands: Operands::Recall {
                scope: MemoryScope::LongTerm,
                path_hash: h(0x33),
                value_hash: h(0x44),
            },
        });
        let row = LogTrace::from(&log).rows[0];
        assert_eq!(row.opcode, Opcode::Recall as u8);
        assert_eq!(row.scope, 2);
        assert_eq!(row.path, fold_to_u128(&h(0x33)));
        assert_eq!(row.value, fold_to_u128(&h(0x44)));
    }

    #[test]
    fn log_trace_forget_row_zeroes_value_column() {
        // FORGET writes EMPTY_LEAF at the SMT side; EMPTY_LEAF folds
        // to 0, so the AIR's value column for a FORGET row must be 0
        // too — otherwise the `(scope,path,value)` lookup factor would
        // miss the table side in 3e.
        let mut log = ExecutionLog::new();
        log.record(LogEntry {
            operands: Operands::Forget {
                scope: MemoryScope::Session,
                path_hash: h(0x55),
            },
        });
        let row = LogTrace::from(&log).rows[0];
        assert_eq!(row.opcode, Opcode::Forget as u8);
        assert_eq!(row.scope, 1);
        assert_eq!(row.path, fold_to_u128(&h(0x55)));
        assert_eq!(row.value, 0);
    }

    // ----------------------------------------------------------------------
    // Phase 3d — running mroot column populated by from_log_and_commit
    //
    // These tests pin the replay semantics: row N's mroot is the SMT
    // root *entering* row N (before row N's effect is applied). The
    // running root advances only for memory-mutating opcodes. Recall,
    // non-memory ops, and Shared-scope mutations leave the root
    // unchanged so subsequent rows carry the same value.
    // ----------------------------------------------------------------------

    #[test]
    fn from_log_and_commit_empty_log_yields_no_rows() {
        use crate::runtime::memory_commit::MemoryCommit;
        let trace = LogTrace::from_log_and_commit(&ExecutionLog::new(), MemoryCommit::new());
        assert!(trace.rows.is_empty());
    }

    #[test]
    fn from_log_and_commit_single_set_row_carries_pre_root() {
        // Sub-phase 3d boundary semantics: rows[0].mroot is the running
        // root *entering* row 0, i.e., starting_commit.root() folded.
        // The replay updates the commit after recording the row, so a
        // hypothetical row 1 would see the post-SET root.
        use crate::runtime::memory_commit::MemoryCommit;
        let starting = MemoryCommit::new();
        let pre_root_folded = fold_to_u128(&starting.root());

        let mut log = ExecutionLog::new();
        log.record(set_entry(0xAA, 0xBB));
        let trace = LogTrace::from_log_and_commit(&log, starting);
        assert_eq!(trace.rows[0].mroot, pre_root_folded);
        // Sanity: the empty-tree root is non-zero, so we're actually
        // testing that replay grabs *something* — a regression against
        // accidentally going back to mroot=0 on row 0 would still pass
        // a `mroot == 0` assertion if pre-root happened to fold to 0.
        assert_ne!(pre_root_folded, 0, "empty SMT root must not fold to 0");
    }

    #[test]
    fn from_log_and_commit_advances_root_across_memory_ops() {
        // Two SETs in a row — row 1's mroot must reflect the SMT after
        // row 0's SET applied. The replay is the only place that
        // information lives in the trace.
        use crate::runtime::memory_commit::MemoryCommit;
        let starting = MemoryCommit::new();
        let pre_root_folded = fold_to_u128(&starting.root());

        let mut log = ExecutionLog::new();
        log.record(set_entry(0xAA, 0xBB));
        log.record(set_entry(0xCC, 0xDD));
        let trace = LogTrace::from_log_and_commit(&log, starting.clone());

        // Hand-rebuild the expected post-row-0 root by applying the SET
        // to a fresh commit, then folding.
        let mut probe = starting.clone();
        probe.apply_remember(MemoryScope::Working, &h(0xAA), h(0xBB));
        let expected_after_row0 = fold_to_u128(&probe.root());

        assert_eq!(trace.rows[0].mroot, pre_root_folded);
        assert_eq!(trace.rows[1].mroot, expected_after_row0);
        assert_ne!(
            trace.rows[0].mroot, trace.rows[1].mroot,
            "consecutive SETs must change the running root"
        );
    }

    #[test]
    fn from_log_and_commit_recall_does_not_advance_root() {
        // RECALL is a read; the running root must pass through unchanged
        // so the row after a RECALL sees the same mroot the RECALL did.
        use crate::runtime::memory_commit::MemoryCommit;
        let starting = MemoryCommit::new();

        let mut log = ExecutionLog::new();
        log.record(LogEntry {
            operands: Operands::Recall {
                scope: MemoryScope::LongTerm,
                path_hash: h(0x11),
                value_hash: h(0x22),
            },
        });
        log.record(LogEntry {
            operands: Operands::Recall {
                scope: MemoryScope::Working,
                path_hash: h(0x33),
                value_hash: h(0x44),
            },
        });
        let trace = LogTrace::from_log_and_commit(&log, starting);
        assert_eq!(
            trace.rows[0].mroot, trace.rows[1].mroot,
            "RECALL is a read — running root must not change"
        );
    }

    #[test]
    fn from_log_and_commit_shared_scope_does_not_advance_root() {
        // Shared writes are RPC-routed and excluded from the SMT (3a
        // option a). REMEMBER{Shared} and FORGET{Shared} must therefore
        // pass the running root through unchanged on the trace side too,
        // matching `apply_remember`/`apply_forget` returning None.
        use crate::runtime::memory_commit::MemoryCommit;
        let starting = MemoryCommit::new();

        let mut log = ExecutionLog::new();
        log.record(LogEntry {
            operands: Operands::Remember {
                scope: MemoryScope::Shared,
                path_hash: h(0x55),
                value_hash: h(0x66),
                ttl: None,
            },
        });
        log.record(LogEntry {
            operands: Operands::Forget {
                scope: MemoryScope::Shared,
                path_hash: h(0x77),
            },
        });
        let trace = LogTrace::from_log_and_commit(&log, starting);
        assert_eq!(trace.rows[0].mroot, trace.rows[1].mroot);
    }

    #[test]
    fn from_log_and_commit_non_memory_ops_carry_root_unchanged() {
        // GoalEnter, If, Set, GoalExit — the SET advances the root, the
        // surrounding control-flow ops carry it unchanged. We assert the
        // pattern: rows[0..2] share one root, rows[2..] share a different
        // one (post-SET). This is the C8a "non-memory rows are root-
        // carry" behaviour the 3e plan calls for.
        use crate::runtime::memory_commit::MemoryCommit;
        let starting = MemoryCommit::new();

        let mut log = ExecutionLog::new();
        log.record(LogEntry {
            operands: Operands::GoalEnter {
                name_hash: h(1),
                audit_root: h(2),
            },
        });
        log.record(LogEntry {
            operands: Operands::If {
                cond_hash: h(3),
                branch_taken: true,
            },
        });
        log.record(set_entry(0xAA, 0xBB));
        log.record(LogEntry {
            operands: Operands::GoalExit {
                name_hash: h(1),
                status: GoalStatus::Success,
                audit_root: h(4),
            },
        });
        let trace = LogTrace::from_log_and_commit(&log, starting);
        // Pre-SET span: rows 0, 1, 2 all see the pre-root entering them.
        // (Row 2 is the SET itself; its mroot is "entering", so equals
        // the pre-root. The post-SET root only appears on row 3.)
        assert_eq!(trace.rows[0].mroot, trace.rows[1].mroot);
        assert_eq!(trace.rows[1].mroot, trace.rows[2].mroot);
        // Post-SET span: row 3 (GoalExit) carries the post-SET root.
        assert_ne!(
            trace.rows[2].mroot, trace.rows[3].mroot,
            "GoalExit after SET must carry the post-SET root"
        );
    }

    #[test]
    fn from_log_default_keeps_mroot_at_zero() {
        // The single-arg `From<&ExecutionLog>` constructor stays
        // witness-only on `mroot` — it has no commit to replay against.
        // Hand-built test traces and the fuzz harness rely on this.
        let mut log = ExecutionLog::new();
        log.record(set_entry(0xAA, 0xBB));
        let trace = LogTrace::from(&log);
        assert_eq!(trace.rows[0].mroot, 0);
    }

    #[test]
    fn log_trace_non_memory_rows_leave_memory_columns_zero() {
        // The sub-phase 3e selector `is_mem(opcode) = I_SET + I_REM
        // + I_RECALL + I_FORGET` gates the lookup, but a defence-in-
        // depth check is that non-memory rows carry zeros so an
        // off-by-one in the selector still doesn't leak garbage into
        // the lookup factor.
        let mut log = ExecutionLog::new();
        log.record(LogEntry {
            operands: Operands::GoalEnter {
                name_hash: h(1),
                audit_root: h(2),
            },
        });
        log.record(LogEntry {
            operands: Operands::If {
                cond_hash: h(3),
                branch_taken: true,
            },
        });
        log.record(LogEntry {
            operands: Operands::GoalExit {
                name_hash: h(1),
                status: GoalStatus::Success,
                audit_root: h(4),
            },
        });
        log.record(LogEntry {
            operands: Operands::Nop,
        });
        for row in &LogTrace::from(&log).rows {
            assert_eq!(row.scope, 0);
            assert_eq!(row.path, 0);
            assert_eq!(row.value, 0);
            assert_eq!(row.mroot, 0);
        }
    }
}
