# Engineering remediation history

This file records the first reliability pass. The next AST/data-flow milestone is implemented in Leo 0.3.0; see [CHANGELOG-0.3.0.md](./CHANGELOG-0.3.0.md) for its exact coverage and limitations.

The initial pass corrected source delivery to Recon, Exploit-to-Audit handoff, explicit context-budget failures, broader source extensions, finding path/line validation, project-scoped memory, safe patch application, per-session backups, snapshot-aware resume, restrictive file permissions, and removal of fabricated precision/coverage scores.

Leo 0.2.0 adds bounded multi-batch analysis, cross-batch deduplication/correlation, OSV dependency lookups, source-to-sink taint heuristics, independent verification, and labeled TP/FP/TN/FN evaluation.


## Leo 0.3.0

Leo 0.3.0 adds TypeScript compiler AST-based taint analysis for JavaScript/JSX/TypeScript/TSX, intra-file function argument/return summaries, selected branch-sensitive allowlist reasoning, source-side evidence locations, and structured independent-verifier proof obligations. See [CHANGELOG-0.3.0.md](./CHANGELOG-0.3.0.md).
