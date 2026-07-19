#!/usr/bin/env bash
# Build EVERY deployable binary of a testnet cut from THIS checkout, so a
# deploy can never mix binaries built from different commits.
#
# Why this exists: the v5 cut redeployed the node but left a stale v4
# `bridge-tools` running against it — a v4 wallet's spend proofs
# deterministically fail v5 verification, and the mismatch read as a chain
# bug until the binary was traced to the wrong commit. The rule that falls
# out: A CUT REBUILDS EVERYTHING — node + wallet + bridge-tools + settle —
# from one commit, and the deploy replaces all of them together.
#
# Builds (release):
#   hn_node       — the hash-native testnet node        (aegis-node bin)
#   aegis-wallet  — the Curve-Trees wallet CLI          (root workspace)
#   bridge-tools  — hn wallet ops + devnet bridge tools (own workspace; needs
#                   the sibling-ergo layout, see below)
#   settle        — settlement prover HOST-side build   (own workspace)
#
# The GPU prover (`settle-cuda`) is NOT built here: it must be compiled
# inside the risc0-cuda container (~/apps/risc0-cuda/build.sh) with the
# container's WORKTREE pointed at THIS SAME COMMIT, and its image-id
# cross-check against settlement/IMAGE_ID.hex must pass. The container
# mirrors exact host paths for image-id reproducibility — do not skip the
# cross-check line it prints.
#
# Layout requirement (bridge-tools only): its Cargo.toml path-depends on
# `../../../../ergo/*`, i.e. the checkout must sit three levels below the
# directory that contains the `ergo` repo (the `.worktrees/<name>` layout:
# `<dir>/Aegis-USE/.worktrees/<name>` with `<dir>/ergo`). From any other
# location bridge-tools is skipped with a loud warning — do NOT deploy a cut
# with a skipped bridge-tools; move the checkout and rerun.
#
# Usage:
#   scripts/build-all-hn.sh [TARGET_ROOT]
#
# TARGET_ROOT defaults to a PER-COMMIT directory so two cuts can never
# overwrite each other's binaries; the deploy scripts point at one cut dir.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
SHORT="$(git -C "$ROOT" rev-parse --short HEAD)"
TARGET_ROOT="${1:-$HOME/.cache/cargo-target-aegis-cut-$SHORT}"

if [ -n "$(git -C "$ROOT" status --porcelain)" ]; then
    echo "WARNING: working tree is DIRTY — this cut is not reproducible from $SHORT" >&2
fi

echo "== cut $SHORT ($COMMIT)"
echo "== binaries -> $TARGET_ROOT/<crate>/release/"

echo "== hn_node (aegis-node)"
CARGO_TARGET_DIR="$TARGET_ROOT/hn_node" \
    cargo build --release --manifest-path "$ROOT/Cargo.toml" -p aegis-node --bin hn_node

echo "== aegis-wallet"
CARGO_TARGET_DIR="$TARGET_ROOT/aegis-wallet" \
    cargo build --release --manifest-path "$ROOT/Cargo.toml" -p aegis-wallet

if [ -f "$ROOT/../../../ergo/ergo-primitives/Cargo.toml" ]; then
    echo "== bridge-tools"
    CARGO_TARGET_DIR="$TARGET_ROOT/bridge-tools" \
        cargo build --release --manifest-path "$ROOT/bridge-tools/Cargo.toml"
else
    echo "!! SKIPPED bridge-tools: sibling ergo repo not found at $ROOT/../../../ergo" >&2
    echo "!! (checkout must live at <dir>/Aegis-USE/.worktrees/<name> with <dir>/ergo)" >&2
    echo "!! Do NOT deploy this cut without a bridge-tools built from $SHORT." >&2
fi

echo "== settle (host-side build; GPU binary comes from the risc0-cuda container)"
CARGO_TARGET_DIR="$TARGET_ROOT/settle" \
    cargo build --release --manifest-path "$ROOT/settlement/Cargo.toml" -p settle

echo
echo "== cut $SHORT complete. Deploy checklist:"
echo "   1. point ~/apps/aegis-testnet-hn/start.sh HN_NODE_BIN at $TARGET_ROOT/hn_node/release/hn_node"
echo "   2. replace the bridge-tools binary the ops harness uses (campaign BT=...) with this cut's"
echo "   3. rebuild settle-cuda in ~/apps/risc0-cuda with WORKTREE at $SHORT; image-id MUST match settlement/IMAGE_ID.hex"
echo "   4. restart nodes; verify /hn/v1/status on :8750/:8751 and one wallet scan before calling the cut live"
