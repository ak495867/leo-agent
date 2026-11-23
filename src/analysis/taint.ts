import { AuditFinding, AuditReport } from "../agents/audit.js";
import { analyzeJavaScriptAst } from "./ast-taint.js";
import { analyzeProject, ProjectAnalysisResult } from "./project-analysis.js";

interface TaintRule { id: string; category: string; severity: AuditFinding["severity"]; source: RegExp; sink: RegExp; description: string; recommendation: string; }
const RULES: TaintRule[] = [
  { id: "dynamic-eval", category: "CODE_INJECTION", severity: "CRITICAL", source: /(?:req\.(?:body|query|params)|request\.(?:args|form|GET|POST)|input\s*\(|process\.argv)/i, sink: /\b(?:eval|exec|Function)\s*\(/, description: "Potential untrusted input reaches a dynamic code execution sink.", recommendation: "Avoid dynamic evaluation; use explicit parsers, allowlists, and safe APIs." },
  { id: "shell-command", category: "COMMAND_INJECTION", severity: "HIGH", source: /(?:req\.(?:body|query|params)|request\.(?:args|form|GET|POST)|process\.argv|input\s*\()/i, sink: /\b(?:exec|execSync|spawn|system|popen|shell_exec|passthru)\s*\(/i, description: "Potential untrusted input is used in a process-execution call.", recommendation: "Use argument arrays with shell disabled and validate each argument against an allowlist." },
  { id: "sql-concat", category: "SQL_INJECTION", severity: "HIGH", source: /(?:req\.(?:body|query|params)|request\.(?:args|form|GET|POST)|input\s*\()/i, sink: /\b(?:query|execute|raw|rawQuery)\s*\(/i, description: "Potential untrusted input may flow into a database query. Confirm whether the query is parameterized.", recommendation: "Use prepared statements or parameterized query APIs; never concatenate untrusted values into SQL." },
  { id: "unsafe-deserialization", category: "INSECURE_DESERIALIZATION", severity: "HIGH", source: /(?:req\.(?:body|query)|request\.(?:data|body)|input\s*\()/i, sink: /\b(?:pickle\.loads?|yaml\.load|unserialize|ObjectInputStream)\s*\(/i, description: "Untrusted input may reach an unsafe deserialization API.", recommendation: "Use safe data-only formats/loaders and enforce strict schemas; never deserialize untrusted native objects." },
];

function extractAssignedVariable(line: string): string | null {
  const m = line.match(/(?:^|[;{}\s])(?:const|let|var|final|String|int|auto)?\s*([A-Za-z_$][\w$]*)\s*=\s*[^=]/);
  return m?.[1] ?? null;
}
/**
 * Static taint front-end. JavaScript/TypeScript use project-wide compiler AST
 * analysis, relative import summaries, a structured CFG, bounded field aliases,
 * and explicit SSA-like definition versions. Python uses the stdlib AST; Java
 * uses the JDK javac Tree API when a JDK is available. Remaining languages keep
 * conservative lexical adapters and are labelled as such in evidence.
 */
export function runTaintHeuristics(files: Record<string, string>): AuditReport & { project_analysis: ProjectAnalysisResult } {
  const findings: AuditFinding[] = [];
  const projectAnalysis = analyzeProject(files);
  findings.push(...projectAnalysis.findings);
  for (const [file, source] of Object.entries(files)) {
    if (!/\.(?:ts|tsx|js|jsx|mjs|cjs|py|go|rs|java|rb|php|cs|c|h|cc|hh|cpp|hpp|cxx|hxx|sh|bash|zsh)$/i.test(file)) continue;
    if (/\.(?:ts|tsx|js|jsx|mjs|cjs)$/i.test(file)) {
      findings.push(...analyzeJavaScriptAst(file, source));
      continue;
    }
    if (/\.java$/i.test(file)) continue;
    const lines = source.split(/\r?\n/);
    for (const rule of RULES) {
      const tainted = new Set<string>();
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (rule.source.test(line)) {
          const variable = extractAssignedVariable(line);
          if (variable) tainted.add(variable);
        } else {
          // Propagate simple assignment aliases: derived = original_input.
          const assignment = line.match(/(?:^|[;{}\s])(?:const|let|var|final|String|int|auto)?\s*([A-Za-z_$][\w$]*)\s*=\s*([^;]+)/);
          if (assignment && [...tainted].some(v => new RegExp(`\\b${v.replace(/[$]/g, "\\$")}\\b`).test(assignment[2]))) tainted.add(assignment[1]);
        }
        // A nearby explicit allowlist guard is treated as a sanitizer for that variable.
        if (/\bif\b/.test(line) && /(?:\bin\s*\{|\.includes\s*\(|\.contains\s*\(|allowlist|allowed\w*)/i.test(line)) {
          for (const variable of [...tainted]) if (new RegExp(`\\b${variable.replace(/[$]/g, "\\$")}\\b`).test(line)) tainted.delete(variable);
        }
        if (!rule.sink.test(line)) continue;
        const directFlow = rule.source.test(line);
        const sinkContext = lines.slice(i, Math.min(lines.length, i + 4)).join(" ");
        const referenced = [...tainted].filter(v => new RegExp(`\\b${v.replace(/[$]/g, "\\$")}\\b`).test(sinkContext));
        if (!directFlow && !referenced.length) continue;
        const parameterizedSql = rule.id === "sql-concat" && (/[?]/.test(sinkContext) || /\$\d+/.test(sinkContext) || /:\w+/.test(sinkContext)) && /[,\[]/.test(sinkContext);
        const safeShell = rule.id === "shell-command" && /shell\s*[:=]\s*false/.test(sinkContext);
        if (parameterizedSql || safeShell) continue;
        const sourceLine = directFlow ? i : Math.max(0, lines.findIndex((candidate, index) => index <= i && rule.source.test(candidate)));
        const evidence = lines.slice(Math.max(0, sourceLine - 1), Math.min(lines.length, i + 2)).join("\n").slice(0, 1200);
        findings.push({ id: `taint-${rule.id}-${file}-${i + 1}`, severity: rule.severity, file, line: i + 1, category: rule.category, description: `${rule.description} Static heuristic: ${rule.id}.`, evidence, recommendation: rule.recommendation });
      }
    }
  }
  const unique = new Map<string, AuditFinding>();
  for (const finding of findings) {
    const key = `${finding.file}:${finding.line}:${finding.category}`;
    const previous = unique.get(key);
    if (!previous || ((finding.evidence ?? "").includes("typescript-compiler-ast") && !(previous.evidence ?? "").includes("typescript-compiler-ast")) || ((finding.evidence ?? "").length > (previous.evidence ?? "").length && !(previous.evidence ?? "").includes("typescript-compiler-ast"))) unique.set(key, finding);
  }
  return { findings: [...unique.values()], rejected_findings: [], project_analysis: projectAnalysis };
}

export function runProjectAnalysis(files: Record<string, string>): ProjectAnalysisResult {
  return analyzeProject(files);
}
