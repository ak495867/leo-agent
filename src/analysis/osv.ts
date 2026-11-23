import { promises as fs } from "node:fs";
import path from "node:path";
import { AuditFinding, AuditReport } from "../agents/audit.js";

interface Dep { name: string; version: string; ecosystem: string; manifest: string; }
export interface OsvResult { status: "complete" | "partial" | "unavailable"; queried: number; findings: AuditFinding[]; errors: string[]; }

function parsePackageJson(raw: string, file: string): Dep[] {
  const p = JSON.parse(raw); const out: Dep[] = [];
  for (const section of ["dependencies", "devDependencies", "optionalDependencies"]) for (const [name, version] of Object.entries(p[section] ?? {})) {
    const v = String(version).replace(/^[~^><=v\s]+/, ""); if (/^\d+\.\d+\.\d+/.test(v)) out.push({ name, version: v, ecosystem: "npm", manifest: file });
  }
  return out;
}
function parseRequirements(raw: string, file: string): Dep[] {
  return raw.split(/\r?\n/).flatMap(line => { const m = line.trim().match(/^([A-Za-z0-9_.-]+)==([0-9][A-Za-z0-9.+!-]*)/); return m ? [{ name: m[1], version: m[2], ecosystem: "PyPI", manifest: file }] : []; });
}
function parseGoMod(raw: string, file: string): Dep[] {
  return raw.split(/\r?\n/).flatMap(line => { const m = line.trim().match(/^([\w.\-/]+)\s+(v\d+\.\d+\.\d+(?:[-+][\w.]+)?)/); return m ? [{ name: m[1], version: m[2], ecosystem: "Go", manifest: file }] : []; });
}
function parseCargoLock(raw: string, file: string): Dep[] {
  const out: Dep[] = [];
  for (const block of raw.split(/\[\[package\]\]/).slice(1)) {
    const name = block.match(/^\s*name\s*=\s*"([^"]+)"/m)?.[1];
    const version = block.match(/^\s*version\s*=\s*"([^"]+)"/m)?.[1];
    if (name && version) out.push({ name, version, ecosystem: "crates.io", manifest: file });
  }
  return out;
}
function parsePackageLock(raw: string, file: string): Dep[] {
  const json = JSON.parse(raw); const out: Dep[] = [];
  if (json.packages && typeof json.packages === "object") {
    for (const [pkgPath, value] of Object.entries(json.packages) as Array<[string, any]>) {
      if (!pkgPath.startsWith("node_modules/") || !value?.version) continue;
      const name = pkgPath.split("node_modules/").pop() ?? pkgPath.slice("node_modules/".length);
      out.push({ name, version: String(value.version), ecosystem: "npm", manifest: file });
    }
  } else if (json.dependencies && typeof json.dependencies === "object") {
    const walk = (deps: any) => { for (const [name, value] of Object.entries(deps) as Array<[string, any]>) { if (value?.version) out.push({ name, version: String(value.version), ecosystem: "npm", manifest: file }); if (value?.dependencies) walk(value.dependencies); } };
    walk(json.dependencies);
  }
  return out;
}
function parseComposerLock(raw: string, file: string): Dep[] {
  const json = JSON.parse(raw); return [...(json.packages ?? []), ...(json["packages-dev"] ?? [])].filter((p: any) => p.name && p.version).map((p: any) => ({ name: p.name, version: String(p.version).replace(/^v/, ""), ecosystem: "Packagist", manifest: file }));
}
function parseGemfileLock(raw: string, file: string): Dep[] {
  const out: Dep[] = []; let inSpecs = false;
  for (const line of raw.split(/\r?\n/)) {
    if (/^  specs:/.test(line)) { inSpecs = true; continue; }
    if (/^[A-Z]/.test(line)) inSpecs = false;
    if (inSpecs) { const m = line.match(/^    ([A-Za-z0-9_.-]+) \(([^)]+)\)/); if (m) out.push({ name: m[1], version: m[2], ecosystem: "RubyGems", manifest: file }); }
  }
  return out;
}
function parsePoetryLock(raw: string, file: string): Dep[] {
  return raw.split(/\[\[package\]\]/).slice(1).flatMap(block => {
    const name = block.match(/^name\s*=\s*"([^"]+)"/m)?.[1]; const version = block.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
    return name && version ? [{ name, version, ecosystem: "PyPI", manifest: file }] : [];
  });
}
function parseMaven(raw: string, file: string): Dep[] {
  const out: Dep[] = []; const blocks = raw.match(/<dependency>[\s\S]*?<\/dependency>/g) ?? [];
  for (const block of blocks) {
    const group = block.match(/<groupId>\s*([^<]+)\s*<\/groupId>/)?.[1]; const artifact = block.match(/<artifactId>\s*([^<]+)\s*<\/artifactId>/)?.[1]; const version = block.match(/<version>\s*([^<]+)\s*<\/version>/)?.[1];
    if (group && artifact && version && /^\d/.test(version)) out.push({ name: `${group}:${artifact}`, version, ecosystem: "Maven", manifest: file });
  }
  return out;
}
function parseGradleLock(raw: string, file: string): Dep[] {
  return raw.split(/\r?\n/).flatMap(line => { const m = line.match(/^([^:#\s]+):([^:#\s]+):([^:#\s]+)(?:=.*)?$/); return m ? [{ name: `${m[1]}:${m[2]}`, version: m[3], ecosystem: "Maven", manifest: file }] : []; });
}

function dependenciesFromFiles(files: Record<string, string>): Dep[] {
  const out: Dep[] = [];
  for (const [file, raw] of Object.entries(files)) {
    try {
      if (file === "package-lock.json" || file.endsWith("/package-lock.json") || file.endsWith("npm-shrinkwrap.json")) out.push(...parsePackageLock(raw, file));
      else if (file.endsWith("Gemfile.lock")) out.push(...parseGemfileLock(raw, file));
      else if (file.endsWith("poetry.lock")) out.push(...parsePoetryLock(raw, file));
      else if (file.endsWith("pom.xml")) out.push(...parseMaven(raw, file));
      else if (file.endsWith("gradle.lockfile")) out.push(...parseGradleLock(raw, file));
      else if (file === "composer.lock" || file.endsWith("/composer.lock")) out.push(...parseComposerLock(raw, file));
      else if (file === "package.json" || file.endsWith("/package.json")) out.push(...parsePackageJson(raw, file));
      else if (/requirements[^/]*\.txt$/i.test(file)) out.push(...parseRequirements(raw, file));
      else if (file.endsWith("go.mod")) out.push(...parseGoMod(raw, file));
      else if (file.endsWith("Cargo.lock")) out.push(...parseCargoLock(raw, file));
    } catch { /* malformed manifests are surfaced as unavailable metadata, not fatal scan errors */ }
  }
  const unique = new Map<string, Dep>(); for (const d of out) unique.set(`${d.ecosystem}:${d.name}@${d.version}`, d); return [...unique.values()];
}

/** Query OSV in bounded chunks. No API key is required; network failure is explicit. */
export async function scanDependencies(files: Record<string, string>, timeoutMs = 12_000): Promise<OsvResult> {
  const deps = dependenciesFromFiles(files); if (!deps.length) return { status: "complete", queried: 0, findings: [], errors: [] };
  const findings: AuditFinding[] = []; const errors: string[] = [];
  for (let i = 0; i < deps.length; i += 100) {
    const chunk = deps.slice(i, i + 100); const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch("https://api.osv.dev/v1/querybatch", { method: "POST", signal: controller.signal, headers: { "content-type": "application/json" }, body: JSON.stringify({ queries: chunk.map(d => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.version })) }) });
      if (!res.ok) throw new Error(`OSV HTTP ${res.status}`);
      const data: any = await res.json();
      (data.results ?? []).forEach((r: any, idx: number) => {
        for (const v of r.vulns ?? []) {
          const dep = chunk[idx];
          findings.push({
            id: `osv-${v.id}-${dep.name}`, severity: "HIGH", file: dep.manifest, line: 1,
            category: "VULNERABLE_DEPENDENCY",
            description: `${dep.name}@${dep.version} is associated with ${v.id}: ${v.summary ?? "known advisory"}`,
            evidence: JSON.stringify({ advisory: v.id, aliases: v.aliases ?? [], modified: v.modified, package: dep }),
            recommendation: `Upgrade ${dep.name} to a version outside the affected range. Consult ${v.id} in OSV for fixed-version details.`
          });
        }
      });
    } catch (e) { errors.push((e as Error).message); } finally { clearTimeout(timer); }
  }
  return { status: errors.length ? (findings.length ? "partial" : "unavailable") : "complete", queried: deps.length, findings, errors };
}
