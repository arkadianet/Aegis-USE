//! The monolithic 2-in / 2-out spend circuit — ONE proof binding, behind ONE
//! public accumulator root, all of: depth-32 Merkle membership, `cm` opening,
//! `owner == H(nk)` ownership, `nf == H_NF(nk‖rho)` nullifier reveal, and
//! `Σin == Σout + fee` balance + output range — with a **private** witness
//! shared across the sub-statements (no public `cm`, no leaf index).
//!
//! # Why one proof (not several)
//! Privacy needs `cm` internal: revealing it would name the spent note. So the
//! sub-statements cannot be separate proofs linked by public values — they must
//! share a private witness inside one proof. The whole soundness question is
//! then **binding**: what forces each shared value to be the SAME field element
//! everywhere it is used. That is answered per value below.
//!
//! # Layout — the "wide row"
//! Each trace row carries [`NB`] = 8 always-valid Poseidon2 permutation blocks
//! (`eval_permutation` is ungated, so every block is a real permutation on every
//! row) plus a few extra columns. Because a whole note's hashes (owner = 1 perm,
//! cm = 4, nf = 2) fit in one row's blocks, **every intra-note binding is a
//! same-row column equality** — trivially sound, no bus needed. Only two things
//! cross rows: the `cm → Merkle-leaf` hand-off and the Merkle chain (adjacent
//! next-row links), and the five transfer amounts (a tiny constant "value bus").
//!
//! A fixed *preprocessed* schedule (7 boolean flags, committed and bound into
//! the transcript — trusted, not prover-controlled) marks each row's role. Row
//! plan (`DEPTH = 32`, padded to 128):
//! `hash(in0) · merkle(in0)×32 · hash(in1) · merkle(in1)×32 · output · pad…`.
//!
//! # Per-value binding-soundness (the whole game)
//! - **`nk`** (input i): the SAME columns feed the owner hash (block B0 rate) and
//!   the nullifier hash (block B5 rate) — constraint `B5.in == B0.in` on the rate
//!   lanes. So the key proving ownership is the key deriving the nullifier; a
//!   mismatch is unsatisfiable. *Theft*: only an `nk`-holder opens the note.
//! - **`owner`**: the value absorbed into `cm` (block B2) is constrained to equal
//!   the owner hash output (`B2.in − B1.out == B0.out` on the rate). So the note's
//!   committed `owner` is exactly `H(nk)` — you cannot commit to someone else's
//!   `owner` and still satisfy the ownership hash.
//! - **`rho`**: the value absorbed into `cm` (block B3) and into `nf` (block B6)
//!   are constrained equal (`B3.in − B2.out == B6.in − B5.out`). So the revealed
//!   nullifier is derived from the note's own `rho`; you cannot pair one note's
//!   membership with another note's nullifier.
//! - **`cm`**: the opening's final output (`B4.out`) is handed to the first Merkle
//!   row's `child` (next-row link, gated `cm_to_leaf`). So the note proven in the
//!   tree is exactly the one just opened — no public `cm` leaks which.
//! - **`value`**: `cm`'s value block (`B1.in[0]`) is bound to the value bus, and
//!   the bus feeds conservation. So the amount conserved is the amount committed.
//! - **`root`**: every Merkle chain's last output is bound to the one public root;
//!   both inputs prove membership under the same accumulator.
//! - **`nf0 ≠ nf1`**: an explicit one-hot/inverse gadget forbids the two inputs
//!   from being the same note *inside* one proof (double-spend); cross-tx
//!   double-spend is the consensus nullifier set's job.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::balance_air::compute_carries;
use super::perm::{eval_permutation, fill_permutation, PermCols, PERM_COLS};
use crate::commit::{note_commitment, owner_key, value_limbs, LIMB_BITS, LIMB_BOUND, N_LIMBS};
use crate::merkle::{MerklePath, NoteTree, DEPTH};
use crate::nullifier::nullifier;
use crate::poseidon::{
    sponge_init, Digest, DIGEST_ELEMS, DOMAIN_COMMITMENT, DOMAIN_NULLIFIER, DOMAIN_OWNER, F, WIDTH,
};

/// Permutation blocks per row.
pub const NB: usize = 8;

// --- extra-column offsets (after the NB permutation blocks) ---
const EXTRA: usize = NB * PERM_COLS;
const CHILD: usize = EXTRA; // 8 — Merkle running node entering this row
const SIB: usize = CHILD + DIGEST_ELEMS; // 8 — Merkle sibling
const BIT: usize = SIB + DIGEST_ELEMS; // 1 — Merkle index bit
/// The value bus: 5 amounts × 4 limbs (constant across the trace), in order
/// `in0[0..4] ‖ in1 ‖ out0 ‖ out1 ‖ fee` (canonical LE 16-bit limbs).
const BUS: usize = BIT + 1;
const N_VALUES: usize = 5;
const BUS_W: usize = N_VALUES * N_LIMBS; // 20
const BUS_IN0: usize = 0;
const BUS_IN1: usize = N_LIMBS;
const BUS_OUT0: usize = 2 * N_LIMBS;
const BUS_OUT1: usize = 3 * N_LIMBS;
const BUS_FEE: usize = 4 * N_LIMBS;
/// Range bits: EVERY bus limb gets a 16-bit decomposition (5 × 64 bits).
/// Outputs/fee are created here (range mandatory); ranging the inputs too is
/// defense-in-depth on top of the cm-binding induction (see balance_air).
const RBITS: usize = BUS + BUS_W;
const N_RANGE_BITS: usize = N_VALUES * N_LIMBS * LIMB_BITS; // 320
/// Balance carries c_1..c_3 ∈ {-2..1}, 2 bits each (c_0 = c_4 = 0 built-in).
const CARRYB: usize = RBITS + N_RANGE_BITS;
const N_CARRIES: usize = N_LIMBS - 1;
const ENEQ: usize = CARRYB + 2 * N_CARRIES; // 8 — one-hot limb selector for nf0≠nf1
const INV: usize = ENEQ + DIGEST_ELEMS; // 1 — inverse witness for nf0≠nf1
/// Monolith row width.
pub const ROW_W: usize = INV + 1;

// --- preprocessed schedule flags ---
const P_HASH0: usize = 0;
const P_HASH1: usize = 1;
const P_MERKLE: usize = 2;
const P_MCHAIN: usize = 3;
const P_MLAST: usize = 4;
const P_CM2LEAF: usize = 5;
const P_OUTPUT: usize = 6;
const PRE_W: usize = 7;

// --- public-value offsets (exposed so a settlement verifier can read the
//     journal effects of each spend: root, nullifiers, output commitments) ---
/// Offset of the accumulator root in the public values.
pub const PUB_ROOT: usize = 0;
/// Offset of input 0's revealed nullifier.
pub const PUB_NF0: usize = 8;
/// Offset of input 1's revealed nullifier.
pub const PUB_NF1: usize = 16;
/// Offset of output 0's commitment.
pub const PUB_CMO0: usize = 24;
/// Offset of output 1's commitment.
pub const PUB_CMO1: usize = 32;
/// Offset of the fee (4 canonical 16-bit limbs — full u64).
pub const PUB_FEE: usize = 40;
/// Number of public values: root ‖ nf0 ‖ nf1 ‖ cm_out0 ‖ cm_out1 ‖ fee_limbs(4).
pub const N_PUB: usize = 44;

// --- fixed row schedule ---
const HASH0_ROW: usize = 0;
const MERKLE0_LAST: usize = DEPTH; // rows 1..=DEPTH
const HASH1_ROW: usize = DEPTH + 1;
const MERKLE1_LAST: usize = 2 * DEPTH + 1; // rows DEPTH+2..=2*DEPTH+1
const OUTPUT_ROW: usize = 2 * DEPTH + 2;
/// Trace height (padded to a power of two).
pub const N_ROWS: usize = (2 * (1 + DEPTH) + 1).next_power_of_two();

const DOM_OWNER: u32 = DOMAIN_OWNER;
const DOM_CM: u32 = DOMAIN_COMMITMENT;
const DOM_NF: u32 = DOMAIN_NULLIFIER;

/// One input note being spent.
#[derive(Clone, Debug)]
pub struct InputNote {
    pub value: u64,
    pub nk: Digest,
    pub rho: Digest,
    pub r: Digest,
    pub index: u64,
}

/// One output note being created.
#[derive(Clone, Debug)]
pub struct OutputNote {
    pub value: u64,
    pub owner: Digest,
    pub rho: Digest,
    pub r: Digest,
}

// ------------------------------- the AIR -------------------------------

/// The monolithic spend AIR.
///
/// `Clone`/`Copy`: p3-batch-stark `StarkInstance` borrows the AIR by value into
/// a slice of instances (the recursion-compatible client proof path), which
/// requires the AIR to be `Clone`. It is a zero-sized unit struct.
#[derive(Debug, Default, Clone, Copy)]
pub struct SpendAir;

impl BaseAir<F> for SpendAir {
    fn width(&self) -> usize {
        ROW_W
    }
    fn num_public_values(&self) -> usize {
        N_PUB
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        Some(schedule_trace())
    }
    fn preprocessed_width(&self) -> usize {
        PRE_W
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

impl<AB: AirBuilder<F = BabyBear>> Air<AB> for SpendAir {
    fn eval(&self, builder: &mut AB) {
        // Preprocessed schedule flags (copied out so the borrow releases).
        let (h0, h1, is_m, mchain, mlast, c2l, is_out) = {
            let p = builder.preprocessed();
            let p = p.current_slice();
            (
                p[P_HASH0],
                p[P_HASH1],
                p[P_MERKLE],
                p[P_MCHAIN],
                p[P_MLAST],
                p[P_CM2LEAF],
                p[P_OUTPUT],
            )
        };
        let main = builder.main();
        let cur = main.current_slice();
        let next = main.next_slice();
        let pv = builder.public_values().to_vec();

        // Ungated permutation constraints on every block; collect outputs.
        let out: Vec<[AB::Expr; WIDTH]> = (0..NB)
            .map(|b| {
                let blk: &PermCols<AB::Var> = cur[b * PERM_COLS..(b + 1) * PERM_COLS].borrow();
                eval_permutation(builder, blk)
            })
            .collect();

        // Helper: block b input lane j (inputs are the first WIDTH cols of a block).
        let binp = |b: usize, j: usize| cur[b * PERM_COLS + j];

        let h: AB::Expr = h0.into() + h1.into();

        // ===== hash rows: owner / cm / nf, and all intra-note bindings =====
        {
            let mut b = builder.when(h.clone());
            // B0 owner init(OWNER, len 8); lanes 0..8 = nk (free).
            assert_init(&mut b, |j| binp(0, j), DOM_OWNER, DIGEST_ELEMS as u32);
            // B1 cm block0 = value_block: lanes 0..4 = value limbs (bound to the
            // bus below), lanes 4..8 = 0.
            for j in N_LIMBS..DIGEST_ELEMS {
                b.assert_zero(binp(1, j));
            }
            assert_init(&mut b, |j| binp(1, j), DOM_CM, (4 * DIGEST_ELEMS) as u32);
            // B2 absorbs owner == B0.out (ownership + cm-owner binding).
            for (j, (o1, o0)) in out[1].iter().zip(&out[0]).enumerate().take(DIGEST_ELEMS) {
                b.assert_eq(binp(2, j).into(), o1.clone() + o0.clone());
            }
            for (j, o1) in out[1].iter().enumerate().skip(DIGEST_ELEMS) {
                b.assert_eq(binp(2, j).into(), o1.clone());
            }
            // B3 absorbs rho (capacity carried; rate bound to B6 below).
            for (j, o2) in out[2].iter().enumerate().skip(DIGEST_ELEMS) {
                b.assert_eq(binp(3, j).into(), o2.clone());
            }
            // B4 absorbs r (free); capacity carried. cm = B4.out[0..8].
            for (j, o3) in out[3].iter().enumerate().skip(DIGEST_ELEMS) {
                b.assert_eq(binp(4, j).into(), o3.clone());
            }
            // B5 nf init(NF, 16); nk == B0's nk (key consistency).
            for j in 0..DIGEST_ELEMS {
                b.assert_eq(binp(5, j).into(), binp(0, j).into());
            }
            assert_init(&mut b, |j| binp(5, j), DOM_NF, (2 * DIGEST_ELEMS) as u32);
            // B6 absorbs rho; capacity carried. nf = B6.out[0..8].
            for (j, o5) in out[5].iter().enumerate().skip(DIGEST_ELEMS) {
                b.assert_eq(binp(6, j).into(), o5.clone());
            }
            // rho consistency: (B3.rate − B2.out) == (B6.rate − B5.out).
            for (j, (o2, o5)) in out[2].iter().zip(&out[5]).enumerate().take(DIGEST_ELEMS) {
                b.assert_eq(
                    binp(3, j).into() - o2.clone(),
                    binp(6, j).into() - o5.clone(),
                );
            }
        }
        // nf public reveal + value-bus binding (per input).
        for (j, o6) in out[6].iter().enumerate().take(DIGEST_ELEMS) {
            builder
                .when(h0.into())
                .assert_eq(o6.clone(), pv[PUB_NF0 + j].into());
            builder
                .when(h1.into())
                .assert_eq(o6.clone(), pv[PUB_NF1 + j].into());
        }
        // value-bus binding: the value limbs absorbed into each input's cm are
        // exactly the bus limbs (h0 row = in0, h1 row = in1).
        for j in 0..N_LIMBS {
            builder
                .when(h0.into())
                .assert_eq(cur[BUS + BUS_IN0 + j].into(), binp(1, j).into());
            builder
                .when(h1.into())
                .assert_eq(cur[BUS + BUS_IN1 + j].into(), binp(1, j).into());
        }

        // ===== output row: two cm chains, well-formed, publicly revealed =====
        {
            let mut b = builder.when(is_out.into());
            // out0 cm: B0(value_block) B1(owner) B2(rho) B3(r).
            for j in N_LIMBS..DIGEST_ELEMS {
                b.assert_zero(binp(0, j));
            }
            assert_init(&mut b, |j| binp(0, j), DOM_CM, (4 * DIGEST_ELEMS) as u32);
            for (j, ((o0, o1), o2)) in out[0]
                .iter()
                .zip(&out[1])
                .zip(&out[2])
                .enumerate()
                .skip(DIGEST_ELEMS)
            {
                b.assert_eq(binp(1, j).into(), o0.clone());
                b.assert_eq(binp(2, j).into(), o1.clone());
                b.assert_eq(binp(3, j).into(), o2.clone());
            }
            // out1 cm: B4(value_block) B5(owner) B6(rho) B7(r).
            for j in N_LIMBS..DIGEST_ELEMS {
                b.assert_zero(binp(4, j));
            }
            assert_init(&mut b, |j| binp(4, j), DOM_CM, (4 * DIGEST_ELEMS) as u32);
            for (j, ((o4, o5), o6)) in out[4]
                .iter()
                .zip(&out[5])
                .zip(&out[6])
                .enumerate()
                .skip(DIGEST_ELEMS)
            {
                b.assert_eq(binp(5, j).into(), o4.clone());
                b.assert_eq(binp(6, j).into(), o5.clone());
                b.assert_eq(binp(7, j).into(), o6.clone());
            }
        }
        // output cm reveal + value-bus binding.
        for j in 0..DIGEST_ELEMS {
            builder
                .when(is_out.into())
                .assert_eq(out[3][j].clone(), pv[PUB_CMO0 + j].into());
            builder
                .when(is_out.into())
                .assert_eq(out[7][j].clone(), pv[PUB_CMO1 + j].into());
        }
        // value-bus binding: the output values committed here are the bus limbs.
        for j in 0..N_LIMBS {
            builder
                .when(is_out.into())
                .assert_eq(cur[BUS + BUS_OUT0 + j].into(), binp(0, j).into());
            builder
                .when(is_out.into())
                .assert_eq(cur[BUS + BUS_OUT1 + j].into(), binp(4, j).into());
        }

        // ===== merkle rows: compression with conditional swap =====
        {
            let mut b = builder.when(is_m.into());
            let bit: AB::Expr = cur[BIT].into();
            b.assert_zero(bit.clone() * (bit.clone() - AB::Expr::ONE));
            for j in 0..DIGEST_ELEMS {
                let c: AB::Expr = cur[CHILD + j].into();
                let s: AB::Expr = cur[SIB + j].into();
                b.assert_eq(
                    binp(0, j).into(),
                    c.clone() + bit.clone() * (s.clone() - c.clone()),
                );
                b.assert_eq(
                    binp(0, j + DIGEST_ELEMS).into(),
                    s.clone() + bit.clone() * (c - s),
                );
            }
        }
        // Merkle chain + root anchor.
        for j in 0..DIGEST_ELEMS {
            builder
                .when(mchain.into())
                .assert_eq(out[0][j].clone(), next[CHILD + j].into());
            builder
                .when(mlast.into())
                .assert_eq(out[0][j].clone(), pv[PUB_ROOT + j].into());
            // cm → first-merkle-leaf hand-off (hash row → next row).
            builder
                .when(c2l.into())
                .assert_eq(out[4][j].clone(), next[CHILD + j].into());
        }

        // ===== value bus is constant across the whole trace =====
        for k in 0..BUS_W {
            builder
                .when_transition()
                .assert_eq(next[BUS + k].into(), cur[BUS + k].into());
        }

        // ===== transaction-wide facts (bus is constant ⇒ first row suffices) =====
        {
            let mut b = builder.when_first_row();
            // Range: every bus limb == its 16-bit decomposition. Kills
            // non-canonical limb encodings (a "limb" ≥ 2^16 denotes a different
            // u64 than its field residue — inflation) and makes the balance
            // equations below provably wrap-free (all terms < 2^18 ≪ p).
            for k in 0..BUS_W {
                let base = RBITS + k * LIMB_BITS;
                let mut acc = AB::Expr::ZERO;
                for i in 0..LIMB_BITS {
                    let bitv: AB::Expr = cur[base + i].into();
                    b.assert_zero(bitv.clone() * (bitv.clone() - AB::Expr::ONE));
                    acc += bitv * AB::Expr::from_u64(1u64 << i);
                }
                b.assert_eq(cur[BUS + k].into(), acc);
            }
            // Carries c_1..c_3 ∈ {-2..1} as 2 bits each (an unconstrained carry
            // would be a ±k·2^16 slush fund per limb — inflation).
            for k in 0..(2 * N_CARRIES) {
                let bitv: AB::Expr = cur[CARRYB + k].into();
                b.assert_zero(bitv.clone() * (bitv - AB::Expr::ONE));
            }
            let carry = |cur: &[AB::Var], k: usize| -> AB::Expr {
                let b0: AB::Expr = cur[CARRYB + 2 * k].into();
                let b1: AB::Expr = cur[CARRYB + 2 * k + 1].into();
                b0 + b1.double() - AB::Expr::TWO
            };
            // Limb-wise conservation with the carry chain: telescopes to
            // in0 + in1 == out0 + out1 + fee over the INTEGERS; c_0 = c_4 = 0
            // built-in (a nonzero final carry = inflation by 2^64 quanta).
            for j in 0..N_LIMBS {
                let c_in = if j == 0 {
                    AB::Expr::ZERO
                } else {
                    carry(cur, j - 1)
                };
                let c_out = if j == N_LIMBS - 1 {
                    AB::Expr::ZERO
                } else {
                    carry(cur, j)
                };
                let lhs: AB::Expr =
                    cur[BUS + BUS_IN0 + j].into() + cur[BUS + BUS_IN1 + j].into() + c_in;
                let rhs: AB::Expr = cur[BUS + BUS_OUT0 + j].into()
                    + cur[BUS + BUS_OUT1 + j].into()
                    + cur[BUS + BUS_FEE + j].into()
                    + c_out * AB::Expr::from_u64(LIMB_BOUND);
                b.assert_eq(lhs, rhs);
            }
            // fee public (4 canonical limbs).
            for j in 0..N_LIMBS {
                b.assert_eq(cur[BUS + BUS_FEE + j].into(), pv[PUB_FEE + j].into());
            }
            // nf0 ≠ nf1: one-hot e picks a differing limb, inv proves it nonzero.
            let mut e_sum = AB::Expr::ZERO;
            let mut sel_diff = AB::Expr::ZERO;
            for j in 0..DIGEST_ELEMS {
                let e: AB::Expr = cur[ENEQ + j].into();
                b.assert_zero(e.clone() * (e.clone() - AB::Expr::ONE));
                e_sum += e.clone();
                sel_diff += e * (pv[PUB_NF0 + j].into() - pv[PUB_NF1 + j].into());
            }
            b.assert_one(e_sum);
            b.assert_one(sel_diff * cur[INV].into());
        }
    }
}

/// Assert a block's capacity carries `domain` (lane `DIGEST_ELEMS`), zeros
/// (lanes `DIGEST_ELEMS+1 .. WIDTH-1`), and `len` (lane `WIDTH-1`).
fn assert_init<AB: AirBuilder<F = BabyBear>>(
    builder: &mut AB,
    lane: impl Fn(usize) -> AB::Var,
    domain: u32,
    len: u32,
) {
    builder.assert_eq(lane(DIGEST_ELEMS).into(), AB::Expr::from_u32(domain));
    for j in (DIGEST_ELEMS + 1)..(WIDTH - 1) {
        builder.assert_zero(lane(j));
    }
    builder.assert_eq(lane(WIDTH - 1).into(), AB::Expr::from_u32(len));
}

// ------------------------------ trace gen ------------------------------

/// The fixed preprocessed schedule (7 flags × `N_ROWS`).
pub fn schedule_trace() -> RowMajorMatrix<F> {
    let mut v = vec![F::ZERO; N_ROWS * PRE_W];
    let set = |v: &mut [F], row: usize, col: usize| v[row * PRE_W + col] = F::ONE;
    set(&mut v, HASH0_ROW, P_HASH0);
    set(&mut v, HASH0_ROW, P_CM2LEAF);
    set(&mut v, HASH1_ROW, P_HASH1);
    set(&mut v, HASH1_ROW, P_CM2LEAF);
    for row in (HASH0_ROW + 1)..=MERKLE0_LAST {
        set(&mut v, row, P_MERKLE);
        if row == MERKLE0_LAST {
            set(&mut v, row, P_MLAST);
        } else {
            set(&mut v, row, P_MCHAIN);
        }
    }
    for row in (HASH1_ROW + 1)..=MERKLE1_LAST {
        set(&mut v, row, P_MERKLE);
        if row == MERKLE1_LAST {
            set(&mut v, row, P_MLAST);
        } else {
            set(&mut v, row, P_MCHAIN);
        }
    }
    set(&mut v, OUTPUT_ROW, P_OUTPUT);
    RowMajorMatrix::new(v, PRE_W)
}

/// Fill the `NB` permutation blocks of a row: block `b` gets `inputs[b]`; unused
/// blocks are filled with a valid dummy permutation so the ungated permutation
/// constraints hold on every row. Returns each block's 16-lane output.
fn fill_blocks(row: &mut [F], inputs: &[[F; WIDTH]; NB]) -> [[F; WIDTH]; NB] {
    core::array::from_fn(|b| {
        fill_permutation(&mut row[b * PERM_COLS..(b + 1) * PERM_COLS], inputs[b])
    })
}

fn absorb(prev_out: [F; WIDTH], block: &Digest) -> [F; WIDTH] {
    let mut s = prev_out;
    for j in 0..DIGEST_ELEMS {
        s[j] += block[j];
    }
    s
}

/// Build the full monolith trace + public values for a 2-in/2-out spend, where
/// both input notes have already been appended to `tree`. Convenience wrapper
/// over [`build_spend_trace_with_paths`] for callers holding the whole tree
/// (tests, the in-memory chain).
pub fn build_spend_trace(
    inputs: &[InputNote; 2],
    tree: &NoteTree,
    outputs: &[OutputNote; 2],
    fee: u64,
) -> (RowMajorMatrix<F>, Vec<F>) {
    let paths = [
        tree.authentication_path(inputs[0].index),
        tree.authentication_path(inputs[1].index),
    ];
    build_spend_trace_with_paths(inputs, &paths, tree.root(), outputs, fee)
}

/// Build the trace from EXPLICIT membership paths + anchor `root` — the node
/// boundary a wallet uses (it fetches each input's path via `ChainView`, then
/// proves against the anchor root, without holding the whole tree).
///
/// # Panics
/// If a path does not fold to `root` for its note (a stale/wrong witness).
pub fn build_spend_trace_with_paths(
    inputs: &[InputNote; 2],
    input_paths: &[MerklePath; 2],
    root: Digest,
    outputs: &[OutputNote; 2],
    fee: u64,
) -> (RowMajorMatrix<F>, Vec<F>) {
    let mut owners = [[F::ZERO; DIGEST_ELEMS]; 2];
    let mut cms = [[F::ZERO; DIGEST_ELEMS]; 2];
    let mut nfs = [[F::ZERO; DIGEST_ELEMS]; 2];
    let mut paths: Vec<MerklePath> = Vec::new();
    for (i, n) in inputs.iter().enumerate() {
        owners[i] = owner_key(&n.nk);
        cms[i] = note_commitment(n.value, &owners[i], &n.rho, &n.r);
        nfs[i] = nullifier(&n.nk, &n.rho);
        assert_eq!(
            crate::merkle::root_from_path(&cms[i], &input_paths[i]),
            root,
            "input {i} path must fold to the anchor root"
        );
        paths.push(input_paths[i].clone());
    }

    let amounts = [
        inputs[0].value,
        inputs[1].value,
        outputs[0].value,
        outputs[1].value,
        fee,
    ];
    let carries = compute_carries(amounts).expect("amounts must balance over the integers");
    let mut bus = [F::ZERO; BUS_W];
    for (v, &val) in amounts.iter().enumerate() {
        bus[v * N_LIMBS..(v + 1) * N_LIMBS].copy_from_slice(&value_limbs(val));
    }

    let mut values = vec![F::ZERO; N_ROWS * ROW_W];

    // Fill every row's bus (constant) up front.
    for row in 0..N_ROWS {
        values[row * ROW_W + BUS..row * ROW_W + BUS + BUS_W].copy_from_slice(&bus);
    }

    let dummy = [F::ZERO; WIDTH];

    // Hash rows.
    for (i, n) in inputs.iter().enumerate() {
        use crate::spend::perm::permutation_output16 as p16;
        let row_idx = if i == 0 { HASH0_ROW } else { HASH1_ROW };
        // owner hash: B0 = init ‖ nk.
        let mut b0 = sponge_init(DOM_OWNER, DIGEST_ELEMS);
        for (bj, nj) in b0.iter_mut().zip(n.nk.iter()) {
            *bj += *nj;
        }
        // cm sponge chain: B1(value_block = 4 LE limbs) B2(owner) B3(rho) B4(r).
        let mut b1 = sponge_init(DOM_CM, 4 * DIGEST_ELEMS);
        for (lane, limb) in b1.iter_mut().zip(value_limbs(n.value).iter()) {
            *lane += *limb;
        }
        let b2 = absorb(p16(&b1), &owners[i]);
        let b3 = absorb(p16(&b2), &n.rho);
        let b4 = absorb(p16(&b3), &n.r);
        // nf sponge chain: B5(nk) B6(rho).
        let mut b5 = sponge_init(DOM_NF, 2 * DIGEST_ELEMS);
        for (bj, nj) in b5.iter_mut().zip(n.nk.iter()) {
            *bj += *nj;
        }
        let b6 = absorb(p16(&b5), &n.rho);
        let ins = [b0, b1, b2, b3, b4, b5, b6, dummy];
        let perm_region = &mut values[row_idx * ROW_W..(row_idx * ROW_W) + EXTRA];
        let _ = fill_blocks(perm_region, &ins);
    }

    // Merkle rows.
    for (i, n) in inputs.iter().enumerate() {
        let first = if i == 0 { HASH0_ROW + 1 } else { HASH1_ROW + 1 };
        let mut child = cms[i];
        let mut idx = n.index;
        for t in 0..DEPTH {
            let row_idx = first + t;
            let sib = paths[i].siblings[t];
            let bit = (idx & 1) as u32;
            let mut input = [F::ZERO; WIDTH];
            if bit == 0 {
                input[..DIGEST_ELEMS].copy_from_slice(&child);
                input[DIGEST_ELEMS..].copy_from_slice(&sib);
            } else {
                input[..DIGEST_ELEMS].copy_from_slice(&sib);
                input[DIGEST_ELEMS..].copy_from_slice(&child);
            }
            let ins = [input, dummy, dummy, dummy, dummy, dummy, dummy, dummy];
            let perm_region = &mut values[row_idx * ROW_W..(row_idx * ROW_W) + EXTRA];
            let outs = fill_blocks(perm_region, &ins);
            // extras
            let base = row_idx * ROW_W;
            values[base + CHILD..base + CHILD + DIGEST_ELEMS].copy_from_slice(&child);
            values[base + SIB..base + SIB + DIGEST_ELEMS].copy_from_slice(&sib);
            values[base + BIT] = F::from_u32(bit);
            child = outs[0][..DIGEST_ELEMS].try_into().unwrap();
            idx >>= 1;
        }
        debug_assert_eq!(child, root, "input {i} path must reach the root");
    }

    // Output row.
    {
        let mut ins = [dummy; NB];
        for (j, out) in outputs.iter().enumerate() {
            let base = j * 4;
            let mut b0 = sponge_init(DOM_CM, 4 * DIGEST_ELEMS);
            for (lane, limb) in b0.iter_mut().zip(value_limbs(out.value).iter()) {
                *lane += *limb;
            }
            let o0 = crate::spend::perm::permutation_output16(&b0);
            let b1 = absorb(o0, &out.owner);
            let o1 = crate::spend::perm::permutation_output16(&b1);
            let b2 = absorb(o1, &out.rho);
            let o2 = crate::spend::perm::permutation_output16(&b2);
            let b3 = absorb(o2, &out.r);
            ins[base] = b0;
            ins[base + 1] = b1;
            ins[base + 2] = b2;
            ins[base + 3] = b3;
        }
        let perm_region = &mut values[OUTPUT_ROW * ROW_W..(OUTPUT_ROW * ROW_W) + EXTRA];
        let _ = fill_blocks(perm_region, &ins);
    }

    // Pad rows: dummy permutations everywhere.
    for row in (OUTPUT_ROW + 1)..N_ROWS {
        let ins = [dummy; NB];
        let perm_region = &mut values[row * ROW_W..(row * ROW_W) + EXTRA];
        let _ = fill_blocks(perm_region, &ins);
    }

    // First-row extras: range bits (all 20 bus limbs), balance carries, and
    // the nf0≠nf1 gadget.
    for (v, &val) in amounts.iter().enumerate() {
        for j in 0..N_LIMBS {
            let base = RBITS + (v * N_LIMBS + j) * LIMB_BITS;
            let raw = (val >> (LIMB_BITS * j)) & (LIMB_BOUND - 1);
            for i in 0..LIMB_BITS {
                values[base + i] = F::from_u64((raw >> i) & 1);
            }
        }
    }
    for (k, &c) in carries.iter().enumerate() {
        let cp = (c + 2) as u64; // {-2..1} -> {0..3}
        values[CARRYB + 2 * k] = F::from_u64(cp & 1);
        values[CARRYB + 2 * k + 1] = F::from_u64(cp >> 1);
    }
    // pick the first limb where nf0 differs from nf1.
    let kdiff = nfs[0]
        .iter()
        .zip(nfs[1].iter())
        .position(|(a, b)| a != b)
        .unwrap_or(0);
    values[ENEQ + kdiff] = F::ONE;
    values[INV] = (nfs[0][kdiff] - nfs[1][kdiff])
        .try_inverse()
        .expect("the two inputs must be different notes (nf0 != nf1)");

    // Public values.
    let mut pis = Vec::with_capacity(N_PUB);
    pis.extend_from_slice(&root);
    pis.extend_from_slice(&nfs[0]);
    pis.extend_from_slice(&nfs[1]);
    pis.extend_from_slice(&cms_out(outputs)[0]);
    pis.extend_from_slice(&cms_out(outputs)[1]);
    pis.extend_from_slice(&value_limbs(fee));

    (RowMajorMatrix::new(values, ROW_W), pis)
}

fn cms_out(outputs: &[OutputNote; 2]) -> [[F; DIGEST_ELEMS]; 2] {
    core::array::from_fn(|j| {
        note_commitment(
            outputs[j].value,
            &outputs[j].owner,
            &outputs[j].rho,
            &outputs[j].r,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::make_config;
    use p3_uni_stark::{prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};

    fn digest(base: u32) -> Digest {
        core::array::from_fn(|i| F::from_u32(base + i as u32))
    }

    /// Two spendable input notes in a tree, two outputs, and a valid fee.
    fn scenario() -> (NoteTree, [InputNote; 2], [OutputNote; 2], u64) {
        let in0 = InputNote {
            value: 1_000,
            nk: digest(1),
            rho: digest(50),
            r: digest(90),
            index: 0,
        };
        let in1 = InputNote {
            value: 500,
            nk: digest(200),
            rho: digest(250),
            r: digest(290),
            index: 0,
        };
        let mut tree = NoteTree::new();
        let cm0 = note_commitment(in0.value, &owner_key(&in0.nk), &in0.rho, &in0.r);
        let cm1 = note_commitment(in1.value, &owner_key(&in1.nk), &in1.rho, &in1.r);
        let i0 = tree.append(cm0);
        let i1 = tree.append(cm1);
        let in0 = InputNote { index: i0, ..in0 };
        let in1 = InputNote { index: i1, ..in1 };
        let out0 = OutputNote {
            value: 900,
            owner: digest(400),
            rho: digest(450),
            r: digest(490),
        };
        let out1 = OutputNote {
            value: 590,
            owner: digest(600),
            rho: digest(650),
            r: digest(690),
        };
        (tree, [in0, in1], [out0, out1], 10)
    }

    fn prove_verify(
        tree: &NoteTree,
        inputs: &[InputNote; 2],
        outputs: &[OutputNote; 2],
        fee: u64,
    ) -> (Vec<F>, bool) {
        let config = make_config();
        let air = SpendAir;
        let degree_bits = N_ROWS.trailing_zeros() as usize;
        let (pd, vk) = setup_preprocessed::<_, _>(&config, &air, degree_bits).unwrap();
        let (trace, pis) = build_spend_trace(inputs, tree, outputs, fee);
        let proof = prove_with_preprocessed(&config, &air, trace, &pis, Some(&pd));
        let ok = verify_with_preprocessed(&config, &air, &proof, &pis, Some(&vk)).is_ok();
        (pis, ok)
    }

    #[test]
    fn spend_2in2out_verifies() {
        let (tree, inputs, outputs, fee) = scenario();
        let (_pis, ok) = prove_verify(&tree, &inputs, &outputs, fee);
        assert!(ok, "an honest 2-in/2-out spend must verify");
    }

    // ----- zero-knowledge (hiding) tests -----
    //
    // The plain config above is SOUND but NOT hiding: FRI query openings are pure
    // functions of the witness trace, so a proof + public values leaks witness
    // columns (nk, rho, values, the Merkle path → which note was spent). The
    // hiding config masks this (see crate::config + the leakage model in
    // dev-docs/sidechain/hash-native-spend-circuit.md). These tests demonstrate
    // (a) the hiding proof still verifies, and (b) it is randomized — proving the
    // SAME statement twice yields different proofs and different openings, the
    // observable signature of the masking; the argument that the k openings are
    // independent of the witness is in the design doc.
    use crate::config::{make_hiding_config, HidingEngineConfig};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn hiding_cfg(seed: u64) -> HidingEngineConfig {
        // Distinct mask + salt streams; distinct `seed` ⇒ distinct masks.
        make_hiding_config(
            ChaCha20Rng::seed_from_u64(seed),
            ChaCha20Rng::seed_from_u64(seed ^ 0x5a5a_5a5a),
        )
    }

    fn hiding_prove(seed: u64) -> (Vec<u8>, Vec<F>) {
        let (tree, inputs, outputs, fee) = scenario();
        let air = SpendAir;
        let degree_bits = N_ROWS.trailing_zeros() as usize;
        let config = hiding_cfg(seed);
        let (pd, _vk) =
            setup_preprocessed::<HidingEngineConfig, _>(&config, &air, degree_bits).unwrap();
        let (trace, pis) = build_spend_trace(&inputs, &tree, &outputs, fee);
        let proof = prove_with_preprocessed(&config, &air, trace, &pis, Some(&pd));
        (postcard::to_allocvec(&proof).unwrap(), pis)
    }

    #[test]
    fn hiding_spend_verifies() {
        let (tree, inputs, outputs, fee) = scenario();
        let air = SpendAir;
        let degree_bits = N_ROWS.trailing_zeros() as usize;
        // The preprocessed (pd, vk) are a matched pair from ONE setup — the vk
        // is the published verifying key (a salted commitment to the PUBLIC
        // schedule). The prover masks the MAIN trace with fresh randomness.
        let pcfg = hiding_cfg(1);
        let (pd, vk) =
            setup_preprocessed::<HidingEngineConfig, _>(&pcfg, &air, degree_bits).unwrap();
        let (trace, pis) = build_spend_trace(&inputs, &tree, &outputs, fee);
        let proof = prove_with_preprocessed(&pcfg, &air, trace, &pis, Some(&pd));

        // The verifier draws no randomness (fixed-seed config, e.g. the guest)
        // and checks against the published vk.
        let vcfg = crate::config::hiding_config_for_verify();
        assert!(
            verify_with_preprocessed(&vcfg, &air, &proof, &pis, Some(&vk)).is_ok(),
            "a hiding 2-in/2-out spend must verify"
        );
    }

    #[test]
    fn hiding_is_randomized_same_statement_differs() {
        // Same witness + same public values, different mask seeds ⇒ the proofs
        // (and their openings) must differ. This is the observable signature that
        // the config injects witness-independent randomness — the plain config,
        // by contrast, is deterministic.
        let (p1, pis1) = hiding_prove(1);
        let (p2, pis2) = hiding_prove(2);
        assert_eq!(pis1, pis2, "same public statement");
        assert_ne!(p1, p2, "two hiding proofs of one statement must differ");

        // The non-hiding proof of the same statement IS deterministic (contrast).
        let det = |()| {
            let (tree, inputs, outputs, fee) = scenario();
            let air = SpendAir;
            let db = N_ROWS.trailing_zeros() as usize;
            let cfg = make_config();
            let (pd, _) = setup_preprocessed::<_, _>(&cfg, &air, db).unwrap();
            let (trace, pis) = build_spend_trace(&inputs, &tree, &outputs, fee);
            let proof = prove_with_preprocessed(&cfg, &air, trace, &pis, Some(&pd));
            (postcard::to_allocvec(&proof).unwrap(), pis)
        };
        let (d1, _) = det(());
        let (d2, _) = det(());
        assert_eq!(
            d1, d2,
            "the non-hiding config is deterministic (no masking)"
        );
    }

    // ----- adversarial binding tests -----
    //
    // Each builds a stitched witness — one that satisfies the sub-circuits it
    // touches in isolation but corresponds to no real spend — and asserts the
    // monolith REJECTS it. `expect_rejected` is robust to either rejection path:
    // the debug prover's `check_constraints` panics, or (release, or preprocessed-
    // gated constraints not pre-checked) the produced proof fails verification.

    /// Assert that proving+verifying `trace`/`pis` does not yield a valid proof.
    fn expect_rejected(trace: RowMajorMatrix<F>, pis: Vec<F>, why: &str) {
        let config = make_config();
        let air = SpendAir;
        let degree_bits = N_ROWS.trailing_zeros() as usize;
        let (pd, vk) = setup_preprocessed::<_, _>(&config, &air, degree_bits).unwrap();
        let accepted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let proof = prove_with_preprocessed(&config, &air, trace, &pis, Some(&pd));
            verify_with_preprocessed(&config, &air, &proof, &pis, Some(&vk)).is_ok()
        }))
        .unwrap_or(false); // a panic (debug constraint check) counts as rejection
        assert!(!accepted, "{why}");
    }

    /// Refill one permutation block's columns from a new input (keeping that
    /// block's permutation constraints valid); returns its 16-lane output.
    fn refill(
        trace: &mut RowMajorMatrix<F>,
        row: usize,
        b: usize,
        input: [F; WIDTH],
    ) -> [F; WIDTH] {
        let base = row * ROW_W + b * PERM_COLS;
        crate::spend::perm::fill_permutation(&mut trace.values[base..base + PERM_COLS], input)
    }

    #[test]
    fn honest_verify_baseline_for_negatives() {
        // Sanity: the untampered trace verifies (so rejections below are the
        // tamper's doing, not a broken harness).
        let (tree, inputs, outputs, fee) = scenario();
        let (trace, pis) = build_spend_trace(&inputs, &tree, &outputs, fee);
        let config = make_config();
        let air = SpendAir;
        let degree_bits = N_ROWS.trailing_zeros() as usize;
        let (pd, vk) = setup_preprocessed::<_, _>(&config, &air, degree_bits).unwrap();
        let proof = prove_with_preprocessed(&config, &air, trace, &pis, Some(&pd));
        assert!(verify_with_preprocessed(&config, &air, &proof, &pis, Some(&vk)).is_ok());
    }

    #[test]
    fn rejects_ownership_key_mismatch() {
        // The nk that derives the owner (block B0) differs from the nk that
        // derives the nullifier (block B5): the `nk` binding (B5.in == B0.in)
        // is unsatisfiable. This is the anti-theft guarantee — the key proving
        // ownership must be the key producing the nullifier.
        let (tree, inputs, outputs, fee) = scenario();
        let (mut trace, pis) = build_spend_trace(&inputs, &tree, &outputs, fee);
        let nkp: Digest = core::array::from_fn(|i| inputs[0].nk[i] + F::ONE);
        let mut b0 = sponge_init(DOM_OWNER, DIGEST_ELEMS);
        for (bj, nj) in b0.iter_mut().zip(nkp.iter()) {
            *bj += *nj;
        }
        let _ = refill(&mut trace, HASH0_ROW, 0, b0); // owner now = H(nk'), nf still = H(nk)
        expect_rejected(trace, pis, "owner and nullifier must use the same nk");
    }

    #[test]
    fn rejects_owner_in_commitment_not_derived_from_nk() {
        // The `owner` absorbed into cm is NOT H(nk): the ownership binding
        // (B2.in − B1.out == B0.out) is unsatisfiable. We refill the whole cm
        // chain with a bogus owner so the sponge stays internally valid.
        let (tree, inputs, outputs, fee) = scenario();
        let (mut trace, pis) = build_spend_trace(&inputs, &tree, &outputs, fee);
        let bogus_owner: Digest = core::array::from_fn(|i| F::from_u32(9000 + i as u32));
        // B1 output is unchanged; re-derive B2(owner') B3(rho) B4(r).
        let o1 = crate::spend::perm::permutation_output16(&{
            let mut b1 = sponge_init(DOM_CM, 4 * DIGEST_ELEMS);
            b1[0] += F::from_u64(inputs[0].value);
            b1
        });
        let b2 = absorb(o1, &bogus_owner);
        let o2 = crate::spend::perm::permutation_output16(&b2);
        let b3 = absorb(o2, &inputs[0].rho);
        let o3 = crate::spend::perm::permutation_output16(&b3);
        let b4 = absorb(o3, &inputs[0].r);
        let _ = refill(&mut trace, HASH0_ROW, 2, b2);
        let _ = refill(&mut trace, HASH0_ROW, 3, b3);
        let _ = refill(&mut trace, HASH0_ROW, 4, b4);
        expect_rejected(trace, pis, "the committed owner must equal H(nk)");
    }

    #[test]
    fn rejects_nullifier_from_foreign_rho() {
        // The nullifier absorbs a different rho than the commitment: the `rho`
        // binding (B3.in − B2.out == B6.in − B5.out) is unsatisfiable. You
        // cannot pair one note's membership with a nullifier built from another
        // rho.
        let (tree, inputs, outputs, fee) = scenario();
        let (mut trace, pis) = build_spend_trace(&inputs, &tree, &outputs, fee);
        let rhop: Digest = core::array::from_fn(|i| inputs[0].rho[i] + F::ONE);
        // B5 output (nf after absorbing nk) is unchanged; re-derive B6 with rho'.
        let mut b5 = sponge_init(DOM_NF, 2 * DIGEST_ELEMS);
        for (bj, nj) in b5.iter_mut().zip(inputs[0].nk.iter()) {
            *bj += *nj;
        }
        let o5 = crate::spend::perm::permutation_output16(&b5);
        let b6 = absorb(o5, &rhop);
        let _ = refill(&mut trace, HASH0_ROW, 6, b6);
        expect_rejected(trace, pis, "the nullifier must use the note's own rho");
    }

    #[test]
    fn rejects_membership_of_a_different_leaf() {
        // Witness substitution: open note A but prove membership of a different
        // leaf. Tampering the first Merkle row's `child` breaks the cm→leaf
        // hand-off (out[4] == child) and the swap — the note proven in the tree
        // must be the note just opened.
        let (tree, inputs, outputs, fee) = scenario();
        let (mut trace, pis) = build_spend_trace(&inputs, &tree, &outputs, fee);
        let base = (HASH0_ROW + 1) * ROW_W + CHILD;
        trace.values[base] += F::ONE;
        expect_rejected(
            trace,
            pis,
            "membership leaf must equal the opened commitment",
        );
    }

    #[test]
    #[should_panic(expected = "different notes")]
    fn double_spend_same_note_is_unbuildable() {
        // The two inputs are the SAME note ⇒ nf0 == nf1 ⇒ the nf0≠nf1 gadget's
        // inverse witness does not exist. A same-note double-spend cannot even
        // be assembled (and would be rejected by the consensus nullifier set
        // cross-tx).
        let in0 = InputNote {
            value: 1_000,
            nk: digest(1),
            rho: digest(50),
            r: digest(90),
            index: 0,
        };
        let mut tree = NoteTree::new();
        let cm = note_commitment(in0.value, &owner_key(&in0.nk), &in0.rho, &in0.r);
        let i = tree.append(cm);
        let same = InputNote {
            index: i,
            ..in0.clone()
        };
        let out0 = OutputNote {
            value: 990,
            owner: digest(400),
            rho: digest(450),
            r: digest(490),
        };
        let out1 = OutputNote {
            value: 1_000,
            owner: digest(600),
            rho: digest(650),
            r: digest(690),
        };
        let inputs = [InputNote { index: i, ..in0 }, same];
        let _ = build_spend_trace(&inputs, &tree, &[out0, out1], 10);
    }

    #[test]
    fn rejects_value_inflation() {
        // Outputs encode more value than the inputs: conservation
        // (v_in0 + v_in1 == v_out0 + v_out1 + fee) is unsatisfiable.
        let (tree, inputs, outputs, fee) = scenario();
        // in0 + in1 = 1500; make outputs sum to 2500 (inflation).
        let bad_out = [
            OutputNote {
                value: 1_500,
                owner: digest(400),
                rho: digest(450),
                r: digest(490),
            },
            OutputNote {
                value: 1_000,
                owner: digest(600),
                rho: digest(650),
                r: digest(690),
            },
        ];
        // The builder itself refuses an integer-imbalanced witness...
        let build = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            build_spend_trace(&inputs, &tree, &bad_out, 0)
        }));
        assert!(build.is_err(), "an inflating witness must be unbuildable");

        // ...and a hand-tampered trace (bus + range bits rewritten to encode
        // the inflating outputs, carries left as witness) is rejected by the
        // carry-chain constraints: no carry assignment in {-2..1} reconciles
        // an integer imbalance (the wrap-around/inflation guard).
        let (mut trace, pis) = build_spend_trace(&inputs, &tree, &outputs, fee);
        for row in 0..N_ROWS {
            let base = row * ROW_W;
            trace.values[base + BUS + BUS_OUT0..base + BUS + BUS_OUT0 + N_LIMBS]
                .copy_from_slice(&value_limbs(bad_out[0].value));
        }
        for j in 0..N_LIMBS {
            let base = RBITS + (2 * N_LIMBS + j) * LIMB_BITS; // out0 bit block
            let raw = (bad_out[0].value >> (LIMB_BITS * j)) & (LIMB_BOUND - 1);
            for i in 0..LIMB_BITS {
                trace.values[base + i] = F::from_u64((raw >> i) & 1);
            }
        }
        expect_rejected(trace, pis, "outputs may not create value");
    }

    #[test]
    fn rejects_wrong_root_at_verify() {
        // Verifier-side: a proof for one accumulator root must not verify
        // against another (the membership is anchored to the public root).
        let (tree, inputs, outputs, fee) = scenario();
        let config = make_config();
        let air = SpendAir;
        let degree_bits = N_ROWS.trailing_zeros() as usize;
        let (pd, vk) = setup_preprocessed::<_, _>(&config, &air, degree_bits).unwrap();
        let (trace, pis) = build_spend_trace(&inputs, &tree, &outputs, fee);
        let proof = prove_with_preprocessed(&config, &air, trace, &pis, Some(&pd));
        let mut bad = pis.clone();
        bad[PUB_ROOT] += F::ONE;
        assert!(verify_with_preprocessed(&config, &air, &proof, &bad, Some(&vk)).is_err());
    }

    #[test]
    #[ignore = "measurement, not a correctness check"]
    fn report_hiding_cost() {
        let (tree, inputs, outputs, fee) = scenario();
        let air = SpendAir;
        let degree_bits = N_ROWS.trailing_zeros() as usize;
        let pcfg = crate::config::hiding_config();
        let (pd, vk) =
            setup_preprocessed::<HidingEngineConfig, _>(&pcfg, &air, degree_bits).unwrap();

        let t0 = std::time::Instant::now();
        let (trace, pis) = build_spend_trace(&inputs, &tree, &outputs, fee);
        let proof = prove_with_preprocessed(&pcfg, &air, trace, &pis, Some(&pd));
        let prove_ms = t0.elapsed().as_secs_f64() * 1e3;

        let vcfg = crate::config::hiding_config_for_verify();
        let t1 = std::time::Instant::now();
        verify_with_preprocessed(&vcfg, &air, &proof, &pis, Some(&vk)).unwrap();
        let verify_ms = t1.elapsed().as_secs_f64() * 1e3;

        let bytes = postcard::to_allocvec(&proof).unwrap().len();
        println!(
            "HIDING monolith 2-in/2-out: prove {prove_ms:.1} ms, verify {verify_ms:.1} ms, \
             proof {} bytes ({:.2} MB); log_blowup=2, {NUM_RANDOM_CODEWORDS} random codewords, \
             {SALT_ELEMS}-elem leaf salts",
            bytes,
            bytes as f64 / 1e6,
        );
    }
    use crate::config::{NUM_RANDOM_CODEWORDS, SALT_ELEMS};

    #[test]
    #[ignore = "measurement, not a correctness check"]
    fn report_monolith_cost() {
        let (tree, inputs, outputs, fee) = scenario();
        let config = make_config();
        let air = SpendAir;
        let degree_bits = N_ROWS.trailing_zeros() as usize;
        let (pd, vk) = setup_preprocessed::<_, _>(&config, &air, degree_bits).unwrap();

        let t0 = std::time::Instant::now();
        let (trace, pis) = build_spend_trace(&inputs, &tree, &outputs, fee);
        let proof = prove_with_preprocessed(&config, &air, trace, &pis, Some(&pd));
        let prove_ms = t0.elapsed().as_secs_f64() * 1e3;

        let t1 = std::time::Instant::now();
        verify_with_preprocessed(&config, &air, &proof, &pis, Some(&vk)).unwrap();
        let verify_ms = t1.elapsed().as_secs_f64() * 1e3;

        let bytes = postcard::to_allocvec(&proof).unwrap().len();
        println!(
            "monolith 2-in/2-out (depth 32): prove {prove_ms:.1} ms, verify {verify_ms:.1} ms, \
             proof {} bytes ({:.2} MB); {N_ROWS} rows × {ROW_W} cols, {N_PUB} public values",
            bytes,
            bytes as f64 / 1e6,
        );
    }

    #[test]
    fn membership_hiding_no_spent_note_in_public_values() {
        // The public values must not leak WHICH notes were spent: no input
        // commitment and no leaf index appears among them.
        let (tree, inputs, outputs, fee) = scenario();
        let (_trace, pis) = build_spend_trace(&inputs, &tree, &outputs, fee);
        assert_eq!(pis.len(), N_PUB);
        // The public vector is EXACTLY root ‖ nf0 ‖ nf1 ‖ cm_out0 ‖ cm_out1 ‖
        // fee limbs — nothing else (in particular no input cm, no leaf index).
        let mut expected: Vec<F> = Vec::new();
        expected.extend_from_slice(&tree.root());
        for n in &inputs {
            expected.extend_from_slice(&nullifier(&n.nk, &n.rho));
        }
        for o in &outputs {
            expected.extend_from_slice(&note_commitment(o.value, &o.owner, &o.rho, &o.r));
        }
        expected.extend_from_slice(&value_limbs(fee));
        assert_eq!(pis, expected, "public values carry only the intended data");
        // And explicitly: no input commitment appears anywhere in them.
        for n in &inputs {
            let cm = note_commitment(n.value, &owner_key(&n.nk), &n.rho, &n.r);
            assert!(
                !pis.windows(DIGEST_ELEMS).any(|w| w == cm),
                "an input commitment leaked into the public values"
            );
        }
    }
}
