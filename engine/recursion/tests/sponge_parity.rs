//! Parity: the engine's native `circuit_sponge` reproduces the recursion
//! library's in-circuit `add_hash_slice` (via the `sponge_digest` oracle). This
//! is the load-bearing guest-parity claim — the settlement guest recomputes the
//! withdrawals digest with `circuit_sponge`, never a circuit.
//!
//! `RUSTFLAGS="-Ctarget-cpu=native" cargo test --release --test sponge_parity`

use aegis_engine::poseidon::F;
use aegis_engine::settlement_digest::circuit_sponge;
use aegis_recursion::digest_agg::sponge_digest;
use p3_field::PrimeCharacteristicRing;

fn seq(base: u32, n: usize) -> Vec<F> {
    (0..n).map(|i| F::from_u32(base + i as u32)).collect()
}

#[test]
fn native_circuit_sponge_matches_circuit_oracle() {
    // Cover the exact input widths the settlement digest uses: leaf (32),
    // fold (16), identity preimage (padded to 24/32), toy (4/8).
    for n in [4usize, 8, 16, 24, 32] {
        let x = seq(1000 + n as u32, n);
        assert_eq!(
            circuit_sponge(&x).as_slice(),
            sponge_digest(&x).as_slice(),
            "circuit_sponge != circuit oracle for n={n}"
        );
    }
}
