//! Execution log for ZKP Phase 1.
//!
//! Append-only record of every Statement evaluated inside a Prove block,
//! used as the trace input for per-statement AIRs in Phase 2+.
//! See docs/zkp/01-per-statement-airs.md.

use crate::ast::MemoryScope;
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
}
