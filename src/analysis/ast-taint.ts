import ts from "typescript";
import { AuditFinding } from "../agents/audit.js";

type Origins = Set<string>;
type FlowState = Map<string, Origins>;
interface SinkRule { category: string; severity: AuditFinding["severity"]; kind: "code" | "shell" | "sql" | "deserialize" | "xss"; }
interface FunctionInfo { name: string; node: ts.FunctionLikeDeclaration; params: string[]; }
interface FunctionSummary { taintedParams: Set<number>; returnParams: Set<number>; returnsSource: boolean; returnSources: Set<string>; }
type ParamOriginMap = Map<string, Map<number, Origins>>;
interface SinkHit { line: number; category: string; severity: AuditFinding["severity"]; sink: string; origins: string[]; }

const SINKS: SinkRule[] = [
  { category: "CODE_INJECTION", severity: "CRITICAL", kind: "code" },
  { category: "COMMAND_INJECTION", severity: "HIGH", kind: "shell" },
  { category: "SQL_INJECTION", severity: "HIGH", kind: "sql" },
  { category: "INSECURE_DESERIALIZATION", severity: "HIGH", kind: "deserialize" },
  { category: "XSS", severity: "HIGH", kind: "xss" },
];

function textOf(node: ts.Node): string { return node.getText(); }
function lineOf(node: ts.Node, sf: ts.SourceFile): number { return sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1; }
function propName(node: ts.Expression): string {
  if (ts.isIdentifier(node)) return node.text;
  if (ts.isPropertyAccessExpression(node)) return `${propName(node.expression)}.${node.name.text}`;
  if (ts.isElementAccessExpression(node)) return `${propName(node.expression)}[${node.argumentExpression ? textOf(node.argumentExpression) : ""}]`;
  return textOf(node);
}
function sourceOrigin(node: ts.Expression): string { return `source:${textOf(node)}#L${lineOf(node, node.getSourceFile())}`; }
function isSource(node: ts.Expression): boolean {
  const s = textOf(node);
  return /\b(?:req|request)\.(?:body|query|params|headers|cookies|files)\b/i.test(s)
    || /\b(?:request\.(?:args|form|GET|POST|data|json)|process\.argv)\b/i.test(s)
    || /\b(?:input|readline\.question|URLSearchParams\([^)]*\)\.get)\s*\(/i.test(s)
    || /\b(?:ctx|context)\.request\.(?:body|query|params)\b/i.test(s);
}
function callName(node: ts.CallExpression | ts.NewExpression): string {
  const e = node.expression;
  return ts.isExpression(e) ? propName(e) : textOf(e);
}
function isSanitizer(node: ts.Expression, kind: SinkRule["kind"]): boolean {
  const s = textOf(node);
  if (kind === "xss") return /\b(?:DOMPurify\.sanitize|sanitizeHtml|escapeHtml|validator\.escape)\s*\(/i.test(s);
  return false; // Sanitizers are context-specific; never treat generic encoding as universally safe.
}
function hasParameterizedSql(call: ts.CallExpression): boolean {
  if (!call.arguments.length) return false;
  const first = call.arguments[0];
  // A tainted SQL string is still unsafe. A constant query plus separate bound values is safe.
  return (ts.isStringLiteral(first) || ts.isNoSubstitutionTemplateLiteral(first)) && call.arguments.length > 1;
}
function sinkKind(call: ts.CallExpression | ts.NewExpression): SinkRule["kind"] | null {
  const name = callName(call).toLowerCase();
  if (name === "eval" || name.endsWith(".eval") || name === "function" || name.endsWith(".function")) return "code";
  if (["exec", "execsync", "child_process.exec", "child_process.execsync", "execasync"].includes(name)) return "shell";
  if (["query", "execute", "raw", "rawquery", "sequelize.query", "knex.raw"].includes(name) || /\.(?:query|execute|raw|rawquery)$/.test(name)) return "sql";
  if (["yaml.load", "jsyaml.load", "pickle.loads", "unserialize"].includes(name)) return "deserialize";
  if (["document.write", "document.writeln"].includes(name)) return "xss";
  return null;
}
function cloneState(state: FlowState): FlowState { return new Map([...state].map(([k, v]) => [k, new Set(v)])); }
function mergeState(a: FlowState, b: FlowState): FlowState {
  const out = cloneState(a);
  for (const [k, v] of b) out.set(k, new Set([...(out.get(k) ?? []), ...v]));
  return out;
}
function expressionOrigins(expr: ts.Expression, state: FlowState, summaries: Map<string, FunctionSummary>, current: string, kind: SinkRule["kind"]): Origins {
  if (isSanitizer(expr, kind)) return new Set();
  if (isSource(expr)) return new Set([sourceOrigin(expr)]);
  if (ts.isIdentifier(expr)) return new Set(state.get(expr.text) ?? []);
  if (ts.isCallExpression(expr) || ts.isNewExpression(expr)) {
    const result = new Set<string>();
    const name = callName(expr);
    const summary = summaries.get(name) ?? summaries.get(name.split(".").pop() ?? "");
    if (summary?.returnsSource) for (const origin of summary.returnSources) result.add(origin);
    if (summary) for (const index of summary.returnParams) {
      const arg = expr.arguments?.[index];
      if (arg && ts.isExpression(arg)) for (const origin of expressionOrigins(arg, state, summaries, current, kind)) result.add(origin);
    }
    // Preserve taint through common string/array transformations.
    if (/^(?:String|JSON\.stringify|encodeURI|encodeURIComponent|\.concat|concat|join|replace|trim|toString)$/.test(name) || name.includes(".concat")) {
      for (const arg of expr.arguments ?? []) if (ts.isExpression(arg)) for (const origin of expressionOrigins(arg, state, summaries, current, kind)) result.add(origin);
      if (ts.isPropertyAccessExpression(expr.expression)) for (const origin of expressionOrigins(expr.expression.expression, state, summaries, current, kind)) result.add(origin);
    }
    return result;
  }
  if (ts.isPropertyAccessExpression(expr)) {
    if (isSource(expr)) return new Set([sourceOrigin(expr)]);
    return expressionOrigins(expr.expression, state, summaries, current, kind);
  }
  if (ts.isElementAccessExpression(expr)) {
    if (isSource(expr)) return new Set([sourceOrigin(expr)]);
    return expressionOrigins(expr.expression, state, summaries, current, kind);
  }
  const out = new Set<string>();
  expr.forEachChild(child => { if (ts.isExpression(child)) for (const o of expressionOrigins(child, state, summaries, current, kind)) out.add(o); });
  return out;
}
function localFunctionName(node: ts.Expression): string | null {
  if (ts.isIdentifier(node)) return node.text;
  if (ts.isPropertyAccessExpression(node)) return node.name.text;
  return null;
}
function isTerminating(stmt: ts.Statement): boolean {
  if (ts.isThrowStatement(stmt) || ts.isReturnStatement(stmt)) return true;
  if (ts.isBlock(stmt) && stmt.statements.length) return isTerminating(stmt.statements[stmt.statements.length - 1]);
  return false;
}
function guardedVariable(expr: ts.Expression): { name: string; negated: boolean } | null {
  const s = textOf(expr);
  const m = s.match(/!?\s*(?:[\w$.]+\.(?:includes|contains|has)|(?:allowed|allowlist|valid\w*)\.test)\s*\(\s*([A-Za-z_$][\w$]*)/i);
  return m ? { name: m[1], negated: /^\s*!/.test(s) } : null;
}

function analyzeBody(info: FunctionInfo | null, body: ts.Block | ts.SourceFile, initial: FlowState, summaries: Map<string, FunctionSummary>, rule: SinkRule, collect: boolean, paramOrigins: ParamOriginMap = new Map()): { state: FlowState; hits: SinkHit[]; paramFlows: Map<string, Set<number>>; paramOriginFlows: Map<string, Map<number, Origins>>; returnParams: Set<number>; returnSources: Set<string>; returnsSource: boolean } {
  const hits: SinkHit[] = [];
  const paramFlows = new Map<string, Set<number>>();
  const paramOriginFlows = new Map<string, Map<number, Origins>>();
  const returnParams = new Set<number>();
  const returnSources = new Set<string>();
  let returnsSource = false;
  const paramIndex = new Map((info?.params ?? []).map((p, i) => [p, i]));
  const markCallFlow = (call: ts.CallExpression | ts.NewExpression, state: FlowState) => {
    const target = localFunctionName(call.expression);
    if (!target) return;
    const args = call.arguments ?? [];
    const indexes = new Set<number>();
    args.forEach((arg, i) => {
      if (!ts.isExpression(arg)) return;
      const origins = expressionOrigins(arg, state, summaries, info?.name ?? "<top>", rule.kind);
      if (!origins.size) return;
      indexes.add(i);
      const byIndex = paramOriginFlows.get(target) ?? new Map<number, Origins>();
      byIndex.set(i, new Set([...(byIndex.get(i) ?? []), ...origins]));
      paramOriginFlows.set(target, byIndex);
    });
    if (indexes.size) paramFlows.set(target, new Set([...(paramFlows.get(target) ?? []), ...indexes]));
  };
  const inspectExpressions = (node: ts.Node, state: FlowState) => {
    if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
      markCallFlow(node, state);
      const kind = sinkKind(node);
      if (kind === rule.kind && node.arguments?.length) {
        const args = node.arguments;
        const relevant = kind === "sql" ? args[0] : args[0];
        if (relevant && ts.isExpression(relevant) && !(kind === "sql" && hasParameterizedSql(node as ts.CallExpression))) {
          const origins = expressionOrigins(relevant, state, summaries, info?.name ?? "<top>", rule.kind);
          if (origins.size && collect) hits.push({ line: lineOf(node, body.getSourceFile()), category: rule.category, severity: rule.severity, sink: textOf(node).slice(0, 240), origins: [...origins] });
        }
      }
    }
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isPropertyAccessExpression(node.left) && ["innerHTML", "outerHTML"].includes(node.left.name.text) && rule.kind === "xss") {
      const origins = expressionOrigins(node.right, state, summaries, info?.name ?? "<top>", rule.kind);
      if (origins.size && collect) hits.push({ line: lineOf(node, body.getSourceFile()), category: rule.category, severity: rule.severity, sink: textOf(node).slice(0, 240), origins: [...origins] });
    }
    node.forEachChild(child => inspectExpressions(child, state));
  };
  const walk = (statements: readonly ts.Statement[], input: FlowState): FlowState => {
    let state = cloneState(input);
    for (const stmt of statements) {
      if (ts.isVariableStatement(stmt)) {
        for (const decl of stmt.declarationList.declarations) if (ts.isIdentifier(decl.name) && decl.initializer) {
          const origins = expressionOrigins(decl.initializer, state, summaries, info?.name ?? "<top>", rule.kind);
          if (origins.size) state.set(decl.name.text, origins); else state.delete(decl.name.text);
          inspectExpressions(decl.initializer, state);
        }
      } else if (ts.isExpressionStatement(stmt)) {
        const e = stmt.expression;
        if (ts.isBinaryExpression(e) && e.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(e.left)) {
          const origins = expressionOrigins(e.right, state, summaries, info?.name ?? "<top>", rule.kind);
          if (origins.size) state.set(e.left.text, origins); else state.delete(e.left.text);
        }
        inspectExpressions(e, state);
      } else if (ts.isIfStatement(stmt)) {
        const guard = guardedVariable(stmt.expression);
        const thenState = cloneState(state); const elseState = cloneState(state);
        const terminatingRejectGuard = !!(guard?.negated && stmt.thenStatement && isTerminating(stmt.thenStatement));
        if (guard) {
          // A positive allowlist branch is trusted only inside that branch.
          if (!guard.negated) thenState.delete(guard.name);
          else if (terminatingRejectGuard) elseState.delete(guard.name);
        }
        const thenResult = ts.isBlock(stmt.thenStatement) ? walk(stmt.thenStatement.statements, thenState) : walk([stmt.thenStatement], thenState);
        const elseResult = stmt.elseStatement ? (ts.isBlock(stmt.elseStatement) ? walk(stmt.elseStatement.statements, elseState) : walk([stmt.elseStatement], elseState)) : elseState;
        // A rejecting branch that always throws/returns cannot reach statements after the guard.
        state = terminatingRejectGuard ? elseResult : mergeState(thenResult, elseResult);
      } else if (ts.isBlock(stmt)) {
        state = walk(stmt.statements, state);
      } else if (ts.isReturnStatement(stmt) && stmt.expression) {
        const origins = expressionOrigins(stmt.expression, state, summaries, info?.name ?? "<top>", rule.kind);
        for (const origin of origins) {
          const match = origin.match(/^param:[^:]+:(\d+)$/);
          if (match) returnParams.add(Number(match[1])); else if (origin.startsWith("source:")) { returnsSource = true; returnSources.add(origin); }
        }
        inspectExpressions(stmt.expression, state);
      } else {
        inspectExpressions(stmt, state);
        if (ts.isForStatement(stmt) || ts.isForOfStatement(stmt) || ts.isWhileStatement(stmt) || ts.isDoStatement(stmt)) {
          const loop = ts.isBlock(stmt.statement) ? walk(stmt.statement.statements, cloneState(state)) : walk([stmt.statement], cloneState(state));
          state = mergeState(state, loop);
        }
      }
    }
    return state;
  };
  const state = cloneState(initial);
  if (info) for (const [i, name] of info.params.entries()) if (summaries.get(info.name)?.taintedParams.has(i)) {
    const knownOrigins = paramOrigins.get(info.name)?.get(i) ?? new Set<string>();
    state.set(name, new Set([...knownOrigins, `param:${info.name}:${i}`]));
  }
  const endState = walk(body.statements, state);
  return { state: endState, hits, paramFlows, paramOriginFlows, returnParams, returnSources, returnsSource };
}

export function analyzeJavaScriptAst(file: string, source: string): AuditFinding[] {
  const scriptKind = /\.tsx$/i.test(file) ? ts.ScriptKind.TSX : /\.jsx$/i.test(file) ? ts.ScriptKind.JSX : /\.m?js$|\.cjs$/i.test(file) ? ts.ScriptKind.JS : ts.ScriptKind.TS;
  const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, scriptKind);
  if (((sf as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics ?? []).length) return []; // Do not guess on syntactically invalid or truncated source.
  const functions: FunctionInfo[] = [];
  const seenFunctionNodes = new Set<ts.Node>();
  const addFn = (name: string, node: ts.FunctionLikeDeclaration) => {
    if (seenFunctionNodes.has(node)) return;
    seenFunctionNodes.add(node);
    if (node.body && ts.isBlock(node.body)) functions.push({ name, node, params: node.parameters.map(p => p.name && ts.isIdentifier(p.name) ? p.name.text : "") });
  };
  const collect = (node: ts.Node) => {
    if (ts.isFunctionDeclaration(node) && node.name) addFn(node.name.text, node);
    else if (ts.isMethodDeclaration(node) && node.name) addFn(node.name.getText(sf), node);
    else if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer && (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer))) addFn(node.name.text, node.initializer);
    else if ((ts.isArrowFunction(node) || ts.isFunctionExpression(node)) && node.body && ts.isBlock(node.body)) addFn(`@anonymous_${lineOf(node, sf)}`, node);
    node.forEachChild(collect);
  };
  collect(sf);
  const summaries = new Map<string, FunctionSummary>(functions.map(f => [f.name, { taintedParams: new Set(), returnParams: new Set(), returnsSource: false, returnSources: new Set() }]));
  const paramOrigins: ParamOriginMap = new Map();
  const resolveParamOrigins = (origins: Origins, depth = 0): Origins => {
    if (depth > 8) return new Set(origins);
    const out = new Set<string>();
    for (const origin of origins) {
      const match = origin.match(/^param:(.*):(\d+)$/);
      if (!match) { out.add(origin); continue; }
      const mapped = paramOrigins.get(match[1])?.get(Number(match[2]));
      if (mapped?.size) for (const resolved of resolveParamOrigins(mapped, depth + 1)) out.add(resolved);
      else out.add(origin);
    }
    return out;
  };
  const mergeParamOriginFlows = (flows: Map<string, Map<number, Origins>>): boolean => {
    let changed = false;
    for (const [callee, byIndex] of flows) for (const [index, origins] of byIndex) {
      const resolved = resolveParamOrigins(origins);
      const target = paramOrigins.get(callee) ?? new Map<number, Origins>();
      const existing = target.get(index) ?? new Set<string>();
      for (const origin of resolved) if (!existing.has(origin)) { existing.add(origin); changed = true; }
      target.set(index, existing); paramOrigins.set(callee, target);
    }
    return changed;
  };
  // Interprocedural fixed point: tainted call arguments taint callee parameters;
  // tainted parameters flowing into returns taint callers' corresponding values.
  for (let pass = 0; pass < Math.min(12, functions.length + 2); pass++) {
    let changed = false;
    for (const rule of SINKS) {
      for (const fn of functions) {
        const result = analyzeBody(fn, fn.node.body as ts.Block, new Map(), summaries, rule, false, paramOrigins);
        const summary = summaries.get(fn.name)!;
        for (const [callee, indexes] of result.paramFlows) {
          const target = summaries.get(callee);
          if (target) for (const index of indexes) if (!target.taintedParams.has(index)) { target.taintedParams.add(index); changed = true; }
        }
        if (mergeParamOriginFlows(result.paramOriginFlows)) changed = true;
        for (const index of result.returnParams) if (!summary.returnParams.has(index)) { summary.returnParams.add(index); changed = true; }
        if (result.returnsSource && !summary.returnsSource) { summary.returnsSource = true; changed = true; }
        for (const origin of result.returnSources) if (!summary.returnSources.has(origin)) { summary.returnSources.add(origin); changed = true; }
      }
      const moduleResult = analyzeBody(null, sf, new Map(), summaries, rule, false, paramOrigins);
      for (const [callee, indexes] of moduleResult.paramFlows) {
        const target = summaries.get(callee);
        if (target) for (const index of indexes) if (!target.taintedParams.has(index)) { target.taintedParams.add(index); changed = true; }
      }
      if (mergeParamOriginFlows(moduleResult.paramOriginFlows)) changed = true;
    }
    if (!changed) break;
  }
  const findings: AuditFinding[] = [];
  const seen = new Set<string>();
  for (const rule of SINKS) {
    for (const fn of functions) {
      const result = analyzeBody(fn, fn.node.body as ts.Block, new Map(), summaries, rule, true, paramOrigins);
      for (const hit of result.hits) {
        const key = `${hit.line}:${hit.category}`; if (seen.has(key)) continue; seen.add(key);
        const id = `ast-${rule.category.toLowerCase()}-${file}-${hit.line}`;
        findings.push({ id, severity: hit.severity, file, line: hit.line, category: hit.category, description: `AST data-flow analysis found attacker-controlled data reaching ${hit.sink}. Evidence path: ${[...resolveParamOrigins(new Set(hit.origins))].join(" -> ")} -> ${hit.sink}.`, evidence: JSON.stringify({ source_origins: [...resolveParamOrigins(new Set(hit.origins))], propagation_path: [...resolveParamOrigins(new Set(hit.origins)), hit.sink], security_boundary: rule.kind === "xss" ? "untrusted request data crossing into browser DOM" : "untrusted application input crossing into a privileged operation", sink: hit.sink, analysis: "typescript-compiler-ast", function: fn.name }), recommendation: rule.kind === "sql" ? "Use prepared statements and keep SQL structure separate from untrusted values." : rule.kind === "shell" ? "Avoid shell command strings; use fixed executables and argument arrays with shell disabled." : rule.kind === "xss" ? "Use context-aware output encoding or a vetted HTML sanitizer before writing to the DOM." : rule.kind === "deserialize" ? "Use a safe data-only parser and validate the resulting schema." : "Avoid dynamic code execution; replace it with explicit, constrained operations." });
      }
    }
    const top = analyzeBody(null, sf, new Map(), summaries, rule, true, paramOrigins);
    for (const hit of top.hits) {
      const key = `${hit.line}:${hit.category}`; if (seen.has(key)) continue; seen.add(key);
      findings.push({ id: `ast-${rule.category.toLowerCase()}-${file}-${hit.line}`, severity: hit.severity, file, line: hit.line, category: hit.category, description: `AST data-flow analysis found attacker-controlled data reaching ${hit.sink}. Evidence path: ${[...resolveParamOrigins(new Set(hit.origins))].join(" -> ")} -> ${hit.sink}.`, evidence: JSON.stringify({ source_origins: [...resolveParamOrigins(new Set(hit.origins))], propagation_path: [...resolveParamOrigins(new Set(hit.origins)), hit.sink], security_boundary: rule.kind === "xss" ? "untrusted request data crossing into browser DOM" : "untrusted application input crossing into a privileged operation", sink: hit.sink, analysis: "typescript-compiler-ast", function: "<module>" }), recommendation: "Validate and constrain untrusted input using controls appropriate to the sink." });
    }
  }
  return findings;
}
