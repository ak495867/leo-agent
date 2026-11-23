# Leo analysis model and evidence contract

Leo separates static observations, inferred data-flow hypotheses, and runtime validation. A static finding is not a demonstrated exploit.

## TypeScript / JavaScript summary propagation

1. Parse project files with the TypeScript compiler API.
2. Resolve supported relative named imports and local function declarations.
3. Seed each function's parameter-to-sink and parameter-to-return summary from direct AST observations.
4. Revisit call expressions and propagate callee summaries into caller summaries until no summary changes or a bounded iteration limit is reached.
5. Record iteration count and whether the fixed point was reached.

This is a bounded, function-summary analysis. It is not a context-sensitive abstract interpreter. In particular, it does not distinguish two callers of the same function by call string, receiver object, generic instantiation, or runtime dispatch target.

## Path conditions

Leo records enclosing `if` conditions for a candidate sink. A narrow syntactic checker identifies a few obvious contradictory constraints, such as the same variable being required to equal both `true` and `false`. This checker does not understand arbitrary boolean algebra, numeric ranges, alias equivalence, exceptions, loop invariants, or framework routing. `no_contradiction_detected` means only that this limited checker found no contradiction.

## Heap abstraction

The current TypeScript/JavaScript model tracks selected direct object-field aliases. It does not model arbitrary pointers, prototype mutation, reflection, object escape, collection contents, native extensions, or concurrent mutation.

## Evidence and uncertainty

The `project_analysis.json` artifact includes:

- source and sink locations where recovered;
- propagation-path candidates and security-boundary labels;
- proof obligations that still need checking;
- recovered path conditions and bounded feasibility status;
- summary convergence metadata;
- parser availability and known limitations;
- counterexample challenge inputs marked `generated_not_executed`.

A counterexample is a proposed test input, not an exploit. Runtime reachability, authentication state, deployment configuration, framework behavior, and mitigation effectiveness require separate validation.

## Safe interpretation

- `confirmed` must be reserved for evidence that passes Leo's independent verification workflow; it is not a guarantee that every environment is exploitable.
- `needs_review` means the static evidence is incomplete or ambiguous.
- A clean scan is not proof that a project is secure.
- Always inspect parser status, analysis limitations, skipped files, and dependency-query status before interpreting results.

## Leo 1.0 bounded context and heap pass

The 1.0 pass constructs a bounded call-string context graph for local statically named TypeScript/JavaScript functions (default depth `k=2`). Context exploration is capped; truncation is recorded. This graph supplements the existing function-summary taint engine. It does not yet make every taint summary context-sensitive, and it does not resolve arbitrary imported package targets, dynamic dispatch, reflection, or higher-order callbacks.

Heap facts use allocation sites and direct property writes. They are useful evidence about selected object-field relationships, not a complete points-to solution. The artifact records each fact as approximate and includes model limitations.

## SMT-backed path feasibility

When the `z3` executable is present, Leo attempts SMT-LIB checks for a restricted set of simple boolean, equality and numeric comparison expressions. Unsupported syntax, solver absence, solver timeout, and translation failures remain `unknown`. A bounded internal contradiction fallback handles repeated conditions with conflicting polarity and selected equality contradictions. It is not a general symbolic executor, and `unknown` must not be promoted to `sat`, `unsat`, or safe.

## Runtime challenge execution

The ordinary scan never executes generated counterexamples. An operator may explicitly call `runCounterexampleInSandbox` or `leo sandbox` with a fixture directory, pre-pulled container image and argument-vector command. Image pulling is disabled. The Docker/Podman invocation disables networking, uses a read-only root and source mount, drops Linux capabilities, enables no-new-privileges, and constrains memory, CPU, PIDs, time, and fixture size. This is defense-in-depth rather than a perfect isolation boundary; use a disposable hardened host for hostile code. A successful process exit only records that the supplied command ran; it does not prove a vulnerability unless the expected security-relevant observation is independently checked.

## Benchmark contract

`leo benchmark` evaluates a user-supplied labeled corpus. It reports TP/FP/TN/FN, precision, recall and F1 alongside corpus identity and limitations. Metrics are scoped to that corpus, its labels, and the detector configuration. Do not compare results across corpora without documenting label policy, language mix, deduplication, line tolerance, parser coverage, and detector version.
