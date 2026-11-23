# Leo 0.6.0 — Bounded Interprocedural Analysis

## Highlights

- Replaced one-pass TypeScript/JavaScript function summaries with a bounded monotone fixed-point iteration.
- Propagates parameter-to-sink and parameter-to-return summaries through local functions and relative named imports, including recursive and multi-hop helper chains where the resolver can identify the target.
- Adds a convergence record (`summary_iterations`, `summary_fixed_point_reached`) to `project_analysis.json`.
- Adds bounded syntactic contradiction checks over recovered enclosing path conditions. Contradictions are surfaced as uncertainty/reachability warnings; they are not treated as formal proofs.
- Adds regression coverage for multi-file, multi-hop propagation and contradictory branch conditions.
- Preserves the 0.5 evidence graph, proof obligations, uncertainty notes, counterexample hypotheses, Python AST adapter, and Java `javac` adapter.

## Verification

- `npm test`: 34/34 tests passed.
- TypeScript build: passed (part of `npm test`).
- CLI version smoke test: `0.6.0`.
- npm package dry-run and ZIP integrity: verified during packaging.

## Important scope boundaries

- Function summaries are context-insensitive; this release does not claim true k-call-string context sensitivity.
- The fixed-point iteration is bounded. If the iteration limit is reached before convergence, the metadata reports that explicitly.
- Call resolution remains limited to local functions and supported relative named imports. Dynamic dispatch, polymorphism, reflection, package exports, path aliases, and arbitrary higher-order calls remain unresolved.
- Path-condition checks recognize only a narrow syntactic subset. They are not SMT solving, symbolic execution, arithmetic reasoning, or proof of reachability/unreachability.
- Heap analysis remains a bounded direct-field alias model, not a general points-to, shape, escape, or ownership analysis.
- Python and Java remain less interprocedurally capable than the TypeScript/JavaScript path.
- Counterexamples remain unexecuted hypotheses. No runtime exploit validation or BenchProctor benchmark was performed as part of this release.
