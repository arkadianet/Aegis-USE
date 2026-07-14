# Vendored: curve-trees (research proving base)

- Upstream: https://github.com/simonkamp/curve-trees.git
- Commit: 969e12a4d6695631fa39edece77aa392276f0c3c ("Update readme.md")
- Vendored: 2026-07-12, `.git` stripped, otherwise byte-identical at import.
- Role: Curve Tree select-and-rerandomize + Bulletproofs circuits (paper
  ePrint 2022/756). Research-quality and unaudited — the pre-TVL external
  review gate in `dev-docs/sidechain/security.md` covers it.
- This directory is `exclude`d from the main workspace: it is built only as
  a path dependency and is NOT held to the workspace clippy/fmt gate.
- Local modifications:
  - `relations/src/curve_tree.rs`: added an **incremental append** to
    `CurveTree` (`fn append`, `fn num_leaves`, and the private
    `insert_into_even`/`insert_into_odd`/`new_singleton_*`/
    `recompute_*_commitment` helpers), plus `#[derive(Clone)]` on the
    `CurveTree` enum. `append` mutates only the root-to-leaf path and
    recomputes each touched node's commitment with the exact expression
    `CurveTreeNode::combine` already uses, so the resulting tree is
    byte-for-byte identical to `from_set(&all_leaves, params, Some(h))`.
    This is oracle-tested against `from_set` in `aegis-crypto::tree`
    (exhaustively at small L and at the real L=256 params). No existing
    behavior changed; the additions are purely new surface.
