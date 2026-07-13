# Vendored: curve-trees (research proving base)

- Upstream: https://github.com/simonkamp/curve-trees.git
- Commit: 969e12a4d6695631fa39edece77aa392276f0c3c ("Update readme.md")
- Vendored: 2026-07-12, `.git` stripped, otherwise byte-identical at import.
- Role: Curve Tree select-and-rerandomize + Bulletproofs circuits (paper
  ePrint 2022/756). Research-quality and unaudited — the pre-TVL external
  review gate in `dev-docs/sidechain/security.md` covers it.
- This directory is `exclude`d from the main workspace: it is built only as
  a path dependency and is NOT held to the workspace clippy/fmt gate.
- Local modifications: none yet. Every future patch must be listed here.
