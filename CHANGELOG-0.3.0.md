# Leo 0.3.0 — AST data-flow and evidence verification

## Added
- JavaScript and TypeScript taint analysis backed by the TypeScript compiler AST.
- Intra-file interprocedural summaries for tainted function arguments and tainted return values.
- Bounded control-flow sensitivity for allowlist branches and rejecting guards that terminate.
- Detection of dynamic code execution, shell execution, tainted SQL construction, unsafe deserialization calls, and tainted DOM HTML writes.
- Evidence paths now include attacker-controlled source expressions and concrete sinks where statically recoverable.
- The independent verifier receives source-side and sink-side excerpts and must assess source, propagation, trust boundary, sink, and mitigations.
- TypeScript is now a runtime dependency because the compiler parser is used by the production CLI.

## Scope and limitations
- AST/data-flow support in this release is for JavaScript, JSX, TypeScript, and TSX.
- Python, Go, Rust, Java, Ruby, PHP, C, C++, C#, and shell continue to use the existing conservative lexical rules. They are not represented as AST-analyzed.
- Function summaries are intra-file. Imported/exported call graphs across files are not yet resolved.
- Control-flow sensitivity covers selected allowlist and early-rejection patterns; it is not a full CFG, SSA, alias, heap, or path-condition engine.
- Sanitization is sink-context-specific. Unknown sanitizer functions are not assumed safe.
- A static finding is a candidate, not a proof of exploitability. The independent verifier may return confirmed, rejected, or needs_review; human review remains necessary for high-impact decisions.

## Validation
- TypeScript compilation passed.
- 20 regression tests passed, including new AST tests for interprocedural parameter flow, tainted returns, rejecting allowlist guards, DOM XSS, and malformed syntax handling.
