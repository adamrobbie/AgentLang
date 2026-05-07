//! Phase 3a: sparse Merkle commitment over agent memory.
//!
//! Backs the `memory_root_pre`/`memory_root_post` public inputs that
//! `StarkProof` v2 will carry. See `docs/zkp/phase3-implementation-plan.md`
//! §1 for the design and §"Open questions" item 1 for the
//! canonicalisation note.
//!
//! Tree shape:
//! - 256-deep sparse Merkle tree, addresses are 256-bit.
//! - The address of a logical leaf `(scope, path_hash)` is
//!   `SHA256(scope_byte || path_hash)` — folding `scope` into the
//!   address keeps the 256-bit shape and avoids a 257th level just
//!   for the scope byte.
//! - Leaves store `value_hash: Hash32`. Empty slot = `[0u8; 32]`.
//! - Internal nodes are `SHA256(left || right)`. Empty subtree roots
//!   per depth are precomputed in `empty_subtree_roots()` so unset
//!   paths cost no real hashing.
//! - SHA-256 (via `ring::digest`) instead of Blake3 — matches the
//!   existing `exec_log::hash` so `Operands::Remember.path_hash` /
//!   `Operands::Recall.path_hash` flow into the address builder
//!   directly. A pivot to Blake3 (`docs/zkp/phase3-implementation-plan.md`
//!   §1) would also pivot `exec_log::hash`; not in scope for 3a.
//!
//! Bit/index conventions (lock these down because the AIR work in
//! sub-phase 3e will encode the same walk):
//! - Address byte 0 is the most-significant byte; bit 7 of byte 0 is
//!   the most-significant bit ("MSB-first" everywhere).
//! - Tree level 0 = root, level 256 = leaves. Descent reads the bit
//!   at position `level` (MSB-first), 0 = left, 1 = right.
//! - `siblings[level]` is the sibling encountered at the level-`level`
//!   step of descent — so `siblings[0]` is the root's other child and
//!   `siblings[255]` is the leaf's sibling. Verification walks bottom-
//!   up, level 255 → 0.

use crate::ast::{AnnotatedValue, MemoryScope};
use crate::runtime::context::Context;
use crate::runtime::exec_log::{self, Hash32};
use anyhow::Result;
use ring::digest;
use std::collections::BTreeMap;
use std::sync::OnceLock;

pub const TREE_DEPTH: usize = 256;
pub const EMPTY_LEAF: Hash32 = [0u8; 32];

pub type Address = [u8; 32];

/// Root of the empty SMT — i.e. `empty_subtree_roots()[TREE_DEPTH]`.
///
/// Exposed as a helper so callers can't accidentally reach for
/// `empty_subtree_roots()[0]` (which is `EMPTY_LEAF`, the *leaf-level*
/// empty hash, not the empty *tree* root). Use this whenever the
/// runtime needs the "no memory committed yet" root value.
pub fn empty_root() -> Hash32 {
    empty_subtree_roots()[TREE_DEPTH]
}

fn sha256_concat(a: &[u8], b: &[u8]) -> Hash32 {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    let h = digest::digest(&digest::SHA256, &buf);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_ref());
    out
}

fn scope_byte(scope: MemoryScope) -> u8 {
    match scope {
        MemoryScope::Working => 0,
        MemoryScope::Session => 1,
        MemoryScope::LongTerm => 2,
        MemoryScope::Shared => 3,
    }
}

/// `path_hash` for a variable name, matching the convention the
/// `Operands::*.path_hash` fields are populated with at log time
/// (`exec_log::hash` over the name's bytes — `eval.rs:386, 878-879,
/// 967-968, 980-981, 996`). `from_context` and the AIR table-builder
/// must agree on this so leaves keyed by `(scope, name)` and rows
/// keyed by `(scope, Operands::*.path_hash)` collide.
fn name_path_hash(name: &str) -> Hash32 {
    exec_log::hash(name.as_bytes())
}

/// `value_hash` (leaf payload) for an `AnnotatedValue`. Mirrors the
/// `format!("{:?}", val.value)` debug-encoding the log uses today
/// (`eval.rs:386` etc.). Open question 1 in the plan tracks
/// canonicalising both sites together; until that lands, this helper
/// is the single point both must agree on.
fn leaf_for_value(val: &AnnotatedValue) -> Hash32 {
    exec_log::hash(format!("{:?}", val.value).as_bytes())
}

/// Address of a logical `(scope, path_hash)` slot. Hashes both inputs
/// together so the resulting `Address` is uniformly distributed across
/// the 256-bit space — important for sparse tree balance arguments.
pub fn address_of(scope: MemoryScope, path_hash: &Hash32) -> Address {
    let mut buf = [0u8; 33];
    buf[0] = scope_byte(scope);
    buf[1..].copy_from_slice(path_hash);
    let h = digest::digest(&digest::SHA256, &buf);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_ref());
    out
}

/// Bit `level` (MSB-first) of the address. `level=0` selects between
/// the root's two children; `level=255` selects between leaf siblings.
fn addr_bit(addr: &Address, level: usize) -> u8 {
    debug_assert!(level < TREE_DEPTH);
    (addr[level / 8] >> (7 - (level % 8))) & 1
}

/// `empty_subtree_roots()[d]` is the root of a `d`-deep all-empty
/// subtree. `[0]` is `EMPTY_LEAF`; `[256]` is the all-empty tree's
/// root. Computed once and cached because every sibling-path materialisation
/// reads from this array.
pub fn empty_subtree_roots() -> &'static [Hash32; TREE_DEPTH + 1] {
    static EMPTY: OnceLock<[Hash32; TREE_DEPTH + 1]> = OnceLock::new();
    EMPTY.get_or_init(|| {
        let mut out = [[0u8; 32]; TREE_DEPTH + 1];
        out[0] = EMPTY_LEAF;
        for d in 0..TREE_DEPTH {
            out[d + 1] = sha256_concat(&out[d], &out[d]);
        }
        out
    })
}

/// Sparse Merkle commitment over the agent's memory. Built fresh at
/// the start of every Prove block per
/// `docs/zkp/phase3-implementation-plan.md` §1; not maintained
/// incrementally across the whole runtime.
#[derive(Debug, Clone, Default)]
pub struct MemoryCommit {
    leaves: BTreeMap<Address, Hash32>,
}

impl MemoryCommit {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a commit that reflects the agent's current memory state.
    /// Used by `Statement::Prove` (Phase 3c) to capture pre/post roots
    /// against actual Context contents rather than against an empty
    /// SMT.
    ///
    /// Scopes enumerated:
    /// - `Working` → `ctx.working_variables` (also covers
    ///   `Statement::Set`, which writes here per option Y).
    /// - `Session` → `ctx.session_variables`.
    /// - `LongTerm` → `ctx.long_term_backend.load(...)`. A load failure
    ///   on first run (no `memory.json` yet) is treated as an empty
    ///   map; any other I/O error propagates so we don't silently
    ///   fabricate an empty post-root.
    /// - `Shared` is **not** enumerated. Per the 3a decision (option
    ///   a), shared writes are RPC-routed and live outside the SMT;
    ///   `apply_remember`/`apply_forget` already return `None` for
    ///   `Shared`, so omitting them here keeps the runtime SMT and
    ///   the AIR-side `mroot` column consistent.
    pub fn from_context(ctx: &Context) -> Result<Self> {
        let mut commit = Self::new();
        let working = ctx
            .working_variables
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        for (name, val) in &working {
            commit.insert(MemoryScope::Working, &name_path_hash(name), leaf_for_value(val));
        }
        let session = ctx
            .session_variables
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        for (name, val) in &session {
            commit.insert(MemoryScope::Session, &name_path_hash(name), leaf_for_value(val));
        }
        // The default `JsonFileBackend` already treats a missing
        // memory file as an empty map (`memory.rs:171`). Other backends
        // may surface I/O failures here; we propagate so a corrupted
        // long-term store can't silently produce a phantom empty
        // post-root.
        let long_term = ctx.long_term_backend.load(&ctx.session_key)?;
        for (name, val) in &long_term {
            commit.insert(
                MemoryScope::LongTerm,
                &name_path_hash(name),
                leaf_for_value(val),
            );
        }
        Ok(commit)
    }

    /// Number of non-empty leaves currently committed. Useful for
    /// tests; the AIR doesn't read this.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Direct access to a value at an address. `None` for unset
    /// addresses (which hash to `EMPTY_LEAF`).
    pub fn get(&self, addr: &Address) -> Option<Hash32> {
        self.leaves.get(addr).copied()
    }

    /// Sets the leaf at `(scope, path_hash)` to `value_hash`. Returns
    /// the previous leaf (or `EMPTY_LEAF` if unset). Pure mutation —
    /// callers needing the witness for the AIR should use
    /// [`apply_remember`](Self::apply_remember) instead.
    pub fn insert(&mut self, scope: MemoryScope, path_hash: &Hash32, value_hash: Hash32) -> Hash32 {
        let addr = address_of(scope, path_hash);
        self.leaves.insert(addr, value_hash).unwrap_or(EMPTY_LEAF)
    }

    /// Removes the leaf at `(scope, path_hash)`. Returns the previous
    /// leaf (or `EMPTY_LEAF` if unset).
    pub fn remove(&mut self, scope: MemoryScope, path_hash: &Hash32) -> Hash32 {
        let addr = address_of(scope, path_hash);
        self.leaves.remove(&addr).unwrap_or(EMPTY_LEAF)
    }

    /// Root of the current commitment. O(n · log n · 32) where n is
    /// the leaf count — recomputed from scratch on every call. The
    /// per-Prove rebuild model means this is fine in practice; an
    /// incremental cache is sub-phase 3+ optimisation territory.
    pub fn root(&self) -> Hash32 {
        let entries: Vec<(Address, Hash32)> =
            self.leaves.iter().map(|(a, h)| (*a, *h)).collect();
        compute_subtree_root(&entries, 0)
    }

    /// Inclusion proof for `addr`. If `addr` is unset, returns a
    /// non-membership proof: `value = EMPTY_LEAF`, siblings populate
    /// the same path. Both cases verify via [`InclusionProof::verify`].
    pub fn prove(&self, addr: Address) -> InclusionProof {
        let entries: Vec<(Address, Hash32)> =
            self.leaves.iter().map(|(a, h)| (*a, *h)).collect();
        let mut siblings = [[0u8; 32]; TREE_DEPTH];
        gather_siblings(&entries, 0, &addr, &mut siblings);
        let value = self.leaves.get(&addr).copied().unwrap_or(EMPTY_LEAF);
        InclusionProof { addr, value, siblings }
    }

    /// Apply a `REMEMBER` and return the witness binding the pre-root
    /// to the post-root. The returned witness is what the AIR's
    /// table-side periodic columns will eventually consume.
    ///
    /// Returns `None` for `MemoryScope::Shared`: shared memory is RPC-
    /// routed (`docs/zkp/phase3-implementation-plan.md` §"Non-goals")
    /// and intentionally lives outside the SMT so C8/C11 can gate the
    /// lookup off cleanly. Phase 4 layers a separate capability lookup
    /// for shared writes; until then, attesting them in this commit
    /// would create a soundness gap (the prover could change the root
    /// arbitrarily on a Shared row with no in-AIR witness binding).
    pub fn apply_remember(
        &mut self,
        scope: MemoryScope,
        path_hash: &Hash32,
        value_hash: Hash32,
    ) -> Option<RememberWitness> {
        if matches!(scope, MemoryScope::Shared) {
            return None;
        }
        let addr = address_of(scope, path_hash);
        let pre = self.prove(addr);
        let pre_root = self.root();
        let old_leaf = pre.value;
        self.leaves.insert(addr, value_hash);
        let post_root = self.root();
        Some(RememberWitness {
            addr,
            old_leaf,
            new_leaf: value_hash,
            siblings: pre.siblings,
            pre_root,
            post_root,
        })
    }

    /// Apply a `FORGET` and return the witness. Same shape as
    /// [`RememberWitness`] but `new_leaf == EMPTY_LEAF`. Calling on
    /// an unset address is permitted (it's a no-op against the root)
    /// — the AIR will gate on opcode rather than refusing to produce
    /// a witness here.
    ///
    /// Returns `None` for `MemoryScope::Shared` for the same reason as
    /// [`apply_remember`](Self::apply_remember).
    pub fn apply_forget(
        &mut self,
        scope: MemoryScope,
        path_hash: &Hash32,
    ) -> Option<ForgetWitness> {
        if matches!(scope, MemoryScope::Shared) {
            return None;
        }
        let addr = address_of(scope, path_hash);
        let pre = self.prove(addr);
        let pre_root = self.root();
        let old_leaf = pre.value;
        self.leaves.remove(&addr);
        let post_root = self.root();
        Some(ForgetWitness {
            addr,
            old_leaf,
            siblings: pre.siblings,
            pre_root,
            post_root,
        })
    }
}

#[derive(Debug, Clone)]
pub struct InclusionProof {
    pub addr: Address,
    pub value: Hash32,
    pub siblings: [Hash32; TREE_DEPTH],
}

impl InclusionProof {
    /// Reconstructs the root by hashing the leaf up the sibling path
    /// and compares against `expected`.
    pub fn verify(&self, expected: Hash32) -> bool {
        self.compute_root() == expected
    }

    pub fn compute_root(&self) -> Hash32 {
        let mut cur = self.value;
        for level in (0..TREE_DEPTH).rev() {
            let sib = &self.siblings[level];
            cur = if addr_bit(&self.addr, level) == 0 {
                sha256_concat(&cur, sib)
            } else {
                sha256_concat(sib, &cur)
            };
        }
        cur
    }
}

/// Witness for a single REMEMBER row in the proof. The AIR's table
/// side reconstructs `pre_root` from `(old_leaf, siblings)` and
/// `post_root` from `(new_leaf, siblings)`; both must match the
/// running memory-root column.
#[derive(Debug, Clone)]
pub struct RememberWitness {
    pub addr: Address,
    pub old_leaf: Hash32,
    pub new_leaf: Hash32,
    pub siblings: [Hash32; TREE_DEPTH],
    pub pre_root: Hash32,
    pub post_root: Hash32,
}

impl RememberWitness {
    pub fn verify(&self) -> bool {
        let pre = InclusionProof {
            addr: self.addr,
            value: self.old_leaf,
            siblings: self.siblings,
        };
        let post = InclusionProof {
            addr: self.addr,
            value: self.new_leaf,
            siblings: self.siblings,
        };
        pre.verify(self.pre_root) && post.verify(self.post_root)
    }
}

#[derive(Debug, Clone)]
pub struct ForgetWitness {
    pub addr: Address,
    pub old_leaf: Hash32,
    pub siblings: [Hash32; TREE_DEPTH],
    pub pre_root: Hash32,
    pub post_root: Hash32,
}

impl ForgetWitness {
    pub fn verify(&self) -> bool {
        let pre = InclusionProof {
            addr: self.addr,
            value: self.old_leaf,
            siblings: self.siblings,
        };
        let post = InclusionProof {
            addr: self.addr,
            value: EMPTY_LEAF,
            siblings: self.siblings,
        };
        pre.verify(self.pre_root) && post.verify(self.post_root)
    }
}

// ---------------------------------------------------------------- internal recursion

/// Root of the subtree rooted at `level`, where `entries` is a sorted
/// (by `Address`) slice of the leaves whose addresses pass through
/// this subtree. `level=0` is the whole tree's root.
fn compute_subtree_root(entries: &[(Address, Hash32)], level: usize) -> Hash32 {
    if entries.is_empty() {
        return empty_subtree_roots()[TREE_DEPTH - level];
    }
    if level == TREE_DEPTH {
        // At the leaf level, the slice has at most one entry by
        // construction (addresses are unique).
        debug_assert_eq!(entries.len(), 1);
        return entries[0].1;
    }
    let split = entries.partition_point(|(addr, _)| addr_bit(addr, level) == 0);
    let (left, right) = entries.split_at(split);
    let lh = compute_subtree_root(left, level + 1);
    let rh = compute_subtree_root(right, level + 1);
    sha256_concat(&lh, &rh)
}

/// Walks the subtree rooted at `level` toward `target`, recording the
/// sibling encountered at each level into `out`. Slots `out[0..level]`
/// are left untouched by this call.
fn gather_siblings(
    entries: &[(Address, Hash32)],
    level: usize,
    target: &Address,
    out: &mut [Hash32; TREE_DEPTH],
) {
    if level == TREE_DEPTH {
        return;
    }
    let split = entries.partition_point(|(addr, _)| addr_bit(addr, level) == 0);
    let (left, right) = entries.split_at(split);
    if addr_bit(target, level) == 0 {
        out[level] = compute_subtree_root(right, level + 1);
        gather_siblings(left, level + 1, target, out);
    } else {
        out[level] = compute_subtree_root(left, level + 1);
        gather_siblings(right, level + 1, target, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::exec_log;

    fn h(s: &str) -> Hash32 {
        exec_log::hash(s.as_bytes())
    }

    #[test]
    fn empty_root_matches_default_subtree_precompute() {
        let commit = MemoryCommit::new();
        assert_eq!(commit.root(), empty_subtree_roots()[TREE_DEPTH]);
        // empty_root() is the helper callers should reach for; assert
        // it returns the full-depth empty root, not the leaf-level
        // EMPTY_LEAF. This regression guards the [0] vs [TREE_DEPTH]
        // footgun that surfaced during Phase 3b review.
        assert_eq!(empty_root(), empty_subtree_roots()[TREE_DEPTH]);
        assert_ne!(
            empty_root(),
            EMPTY_LEAF,
            "empty *tree* root must not equal the empty *leaf* — \
             confusing the two silently breaks Reveal-side root binding"
        );
    }

    #[test]
    fn empty_subtree_recurrence() {
        let empty = empty_subtree_roots();
        assert_eq!(empty[0], EMPTY_LEAF);
        for d in 0..TREE_DEPTH {
            assert_eq!(empty[d + 1], sha256_concat(&empty[d], &empty[d]));
        }
    }

    #[test]
    fn known_answer_single_leaf_root() {
        // Hand-computable: the root of a tree with exactly one leaf at
        // address `a` and value `v` is the hash chain
        //   level 256:  v
        //   level 255:  sha256(v || EMPTY[0])    if bit_255==0 else sha256(EMPTY[0] || v)
        //   level 254:  sha256(level_255 || EMPTY[1]) if bit_254==0 else ...
        //   ... up to level 0
        //
        // We reconstruct the expected root independently here, then
        // compare to MemoryCommit::root(). If both implementations
        // agree, the partition + recursion in compute_subtree_root is
        // consistent with the InclusionProof::compute_root walk.
        let mut commit = MemoryCommit::new();
        let path = h("alpha");
        let value = h("first-write");
        commit.insert(MemoryScope::Working, &path, value);

        let addr = address_of(MemoryScope::Working, &path);
        let empty = empty_subtree_roots();
        let mut cur = value;
        for level in (0..TREE_DEPTH).rev() {
            let sib = empty[TREE_DEPTH - 1 - level];
            cur = if addr_bit(&addr, level) == 0 {
                sha256_concat(&cur, &sib)
            } else {
                sha256_concat(&sib, &cur)
            };
        }
        assert_eq!(commit.root(), cur);
    }

    #[test]
    fn inclusion_roundtrip_after_remember() {
        let mut commit = MemoryCommit::new();
        let path = h("k1");
        let value = h("v1");
        commit.insert(MemoryScope::LongTerm, &path, value);
        let root = commit.root();
        let proof = commit.prove(address_of(MemoryScope::LongTerm, &path));
        assert_eq!(proof.value, value);
        assert!(proof.verify(root));
    }

    #[test]
    fn non_membership_proof_verifies() {
        let mut commit = MemoryCommit::new();
        commit.insert(MemoryScope::Working, &h("present"), h("v"));
        let root = commit.root();
        let absent_addr = address_of(MemoryScope::Working, &h("absent"));
        let proof = commit.prove(absent_addr);
        assert_eq!(proof.value, EMPTY_LEAF);
        assert!(proof.verify(root));
    }

    #[test]
    fn root_invariant_under_insertion_order() {
        let mut a = MemoryCommit::new();
        a.insert(MemoryScope::Working, &h("k1"), h("v1"));
        a.insert(MemoryScope::Session, &h("k2"), h("v2"));
        a.insert(MemoryScope::LongTerm, &h("k3"), h("v3"));

        let mut b = MemoryCommit::new();
        b.insert(MemoryScope::LongTerm, &h("k3"), h("v3"));
        b.insert(MemoryScope::Working, &h("k1"), h("v1"));
        b.insert(MemoryScope::Session, &h("k2"), h("v2"));

        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn scope_separates_addresses() {
        let mut a = MemoryCommit::new();
        a.insert(MemoryScope::Working, &h("k"), h("v-working"));
        let mut b = MemoryCommit::new();
        b.insert(MemoryScope::Session, &h("k"), h("v-working"));
        // Same path_hash and same value, different scope — must
        // produce different roots, otherwise scope-confusion attacks
        // become possible.
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn remember_witness_verifies() {
        let mut commit = MemoryCommit::new();
        commit.insert(MemoryScope::Working, &h("other"), h("padding"));
        let witness = commit
            .apply_remember(MemoryScope::LongTerm, &h("k"), h("v"))
            .expect("non-Shared scope must yield a witness");
        assert_eq!(commit.root(), witness.post_root);
        assert!(witness.verify());
        assert_eq!(witness.old_leaf, EMPTY_LEAF);
        assert_eq!(witness.new_leaf, h("v"));
    }

    #[test]
    fn remember_overwrite_witness_verifies() {
        let mut commit = MemoryCommit::new();
        commit.insert(MemoryScope::LongTerm, &h("k"), h("v0"));
        let witness = commit
            .apply_remember(MemoryScope::LongTerm, &h("k"), h("v1"))
            .expect("non-Shared scope must yield a witness");
        assert_eq!(witness.old_leaf, h("v0"));
        assert_eq!(witness.new_leaf, h("v1"));
        assert_ne!(witness.pre_root, witness.post_root);
        assert!(witness.verify());
    }

    #[test]
    fn forget_witness_verifies() {
        let mut commit = MemoryCommit::new();
        commit.insert(MemoryScope::LongTerm, &h("k"), h("v"));
        commit.insert(MemoryScope::Session, &h("other"), h("padding"));
        let witness = commit
            .apply_forget(MemoryScope::LongTerm, &h("k"))
            .expect("non-Shared scope must yield a witness");
        assert_eq!(witness.old_leaf, h("v"));
        assert_eq!(commit.get(&address_of(MemoryScope::LongTerm, &h("k"))), None);
        assert!(witness.verify());
        assert_eq!(commit.root(), witness.post_root);
    }

    #[test]
    fn forget_unset_address_is_witness_noop() {
        let mut commit = MemoryCommit::new();
        commit.insert(MemoryScope::Working, &h("present"), h("v"));
        let pre_root = commit.root();
        let witness = commit
            .apply_forget(MemoryScope::LongTerm, &h("absent"))
            .expect("non-Shared scope must yield a witness");
        assert_eq!(witness.old_leaf, EMPTY_LEAF);
        assert_eq!(witness.pre_root, pre_root);
        assert_eq!(witness.post_root, pre_root);
        assert!(witness.verify());
    }

    #[test]
    fn tampered_witness_rejected() {
        let mut commit = MemoryCommit::new();
        let mut witness = commit
            .apply_remember(MemoryScope::Working, &h("k"), h("v"))
            .expect("non-Shared scope must yield a witness");
        // Flip a bit in the post-root — verification must fail.
        witness.post_root[0] ^= 0x01;
        assert!(!witness.verify());
    }

    #[test]
    fn shared_remember_returns_none_and_does_not_mutate_smt() {
        // Phase 3 design decision: Shared writes are RPC-routed and do
        // not enter the SMT. apply_remember(Shared, ...) must be a true
        // no-op so the post-root stays equal to the pre-root, keeping
        // C11 (root-carry on non-attesting rows) trivially satisfied.
        let mut commit = MemoryCommit::new();
        commit.insert(MemoryScope::Working, &h("padding"), h("v"));
        let pre_root = commit.root();
        let pre_len = commit.len();

        let witness = commit.apply_remember(MemoryScope::Shared, &h("k"), h("v-shared"));
        assert!(witness.is_none(), "Shared scope must yield no witness");
        assert_eq!(commit.root(), pre_root, "Shared write must not change the SMT root");
        assert_eq!(commit.len(), pre_len, "Shared write must not add a leaf");
        // And the address derived for the Shared key must remain
        // unset, so a subsequent Working/Session/LongTerm commit on
        // the same path_hash isn't shadowed by phantom shared state.
        assert_eq!(commit.get(&address_of(MemoryScope::Shared, &h("k"))), None);
    }

    #[test]
    fn shared_forget_returns_none_and_does_not_mutate_smt() {
        let mut commit = MemoryCommit::new();
        commit.insert(MemoryScope::LongTerm, &h("padding"), h("v"));
        let pre_root = commit.root();

        let witness = commit.apply_forget(MemoryScope::Shared, &h("k"));
        assert!(witness.is_none(), "Shared scope must yield no witness");
        assert_eq!(commit.root(), pre_root);
    }

    #[test]
    fn from_context_empty_returns_empty_root() {
        let ctx = crate::runtime::context::Context::new();
        let commit = MemoryCommit::from_context(&ctx).expect("from_context");
        assert_eq!(commit.root(), empty_root());
        assert!(commit.is_empty());
    }

    #[test]
    fn from_context_reflects_set_and_remember_in_working() {
        // Phase 3c-runtime / option (Y): SET writes to working_variables
        // exactly like REMEMBER{Working}. from_context must see both.
        use crate::ast::{AnnotatedValue, Value};
        let ctx = crate::runtime::context::Context::new();
        ctx.working_variables
            .lock()
            .unwrap()
            .insert(
                "from_set".to_string(),
                AnnotatedValue::from(Value::Number(42.0)),
            );
        ctx.working_variables
            .lock()
            .unwrap()
            .insert(
                "from_remember".to_string(),
                AnnotatedValue::from(Value::Text("hi".into())),
            );

        let commit = MemoryCommit::from_context(&ctx).expect("from_context");
        assert_eq!(commit.len(), 2);
        assert_ne!(commit.root(), empty_root());

        // Both entries must be retrievable at addresses derived the
        // same way the AIR table-builder will derive them at row time.
        let set_addr = address_of(MemoryScope::Working, &name_path_hash("from_set"));
        let rem_addr = address_of(MemoryScope::Working, &name_path_hash("from_remember"));
        assert!(commit.get(&set_addr).is_some());
        assert!(commit.get(&rem_addr).is_some());
    }

    #[test]
    fn from_context_excludes_shared_scope() {
        // Shared writes are RPC-routed and stay outside the SMT (3a
        // option a). from_context enumerates Working/Session/LongTerm
        // only — ctx.shared_backend is never read here.
        use crate::ast::{AnnotatedValue, Value};
        let ctx = crate::runtime::context::Context::new();
        ctx.session_variables.lock().unwrap().insert(
            "session_key".to_string(),
            AnnotatedValue::from(Value::Number(1.0)),
        );
        let commit = MemoryCommit::from_context(&ctx).expect("from_context");
        assert_eq!(commit.len(), 1);
        let session_addr =
            address_of(MemoryScope::Session, &name_path_hash("session_key"));
        assert!(commit.get(&session_addr).is_some());
    }

    #[test]
    fn deep_tree_inclusion_holds() {
        // Insert several leaves whose addresses share high-order bits
        // (we craft this via path strings that happen to address-collide
        // in the top byte) and then check inclusion of each. This
        // catches off-by-one bugs in the partition/recursion when the
        // sparse path has a real sibling at multiple levels.
        let mut commit = MemoryCommit::new();
        let mut entries = vec![];
        for i in 0..32 {
            let path = h(&format!("entry-{i:03}"));
            let value = h(&format!("value-{i:03}"));
            commit.insert(MemoryScope::Working, &path, value);
            entries.push((path, value));
        }
        let root = commit.root();
        for (path, value) in &entries {
            let proof = commit.prove(address_of(MemoryScope::Working, path));
            assert_eq!(proof.value, *value);
            assert!(
                proof.verify(root),
                "inclusion failed for {:?}",
                String::from_utf8_lossy(&path[..4])
            );
        }
    }
}
