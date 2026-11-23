import { promises as fs } from "node:fs";
import path from "node:path";
import { sync as globSync } from "glob";
import { buildTree } from "../utils/tree.js";

export interface CodebaseSnapshot {
  root: string;
  files: Record<string, string>;
  directory_tree: object;
  file_count: number;
  skipped_files: Array<{ file: string; reason: string }>;
  total_bytes: number;
  snapshot_at: string;
}

const SOURCE_GLOB = "**/*.{ts,tsx,js,jsx,mjs,cjs,py,go,rs,java,rb,php,cs,c,h,cc,hh,cpp,hpp,cxx,hxx,bash,sh,zsh}";
const MANIFEST_GLOB = "**/{package.json,package-lock.json,npm-shrinkwrap.json,requirements*.txt,pyproject.toml,poetry.lock,Pipfile.lock,go.mod,go.sum,Cargo.toml,Cargo.lock,composer.json,composer.lock,Gemfile,Gemfile.lock,pnpm-lock.yaml,yarn.lock,pom.xml,build.gradle,build.gradle.kts,gradle.lockfile,packages.lock.json}";
const IGNORE = [
  "**/node_modules/**", "**/.git/**", "**/.hg/**", "**/.svn/**",
  "**/dist/**", "**/build/**", "**/coverage/**", "**/.next/**",
  "**/.venv/**", "**/venv/**", "**/__pycache__/**", "**/vendor/**",
  "**/*.min.js", "**/*.bundle.js", "**/*.map"
];

/** Snapshot source files deterministically, refusing binary/oversized files rather than silently losing context. */
export async function buildSnapshot(projectRoot: string): Promise<CodebaseSnapshot> {
  const root = await fs.realpath(projectRoot);
  const candidates = [...new Set([
    ...globSync(SOURCE_GLOB, { cwd: root, ignore: IGNORE, nodir: true, dot: true, follow: false }),
    ...globSync(MANIFEST_GLOB, { cwd: root, ignore: IGNORE, nodir: true, dot: true, follow: false }),
  ])].sort((a, b) => a.localeCompare(b));
  const files: Record<string, string> = {};
  const skipped_files: Array<{ file: string; reason: string }> = [];
  let total_bytes = 0;
  const MAX_FILE_BYTES = 200_000;

  for (const rel of candidates) {
    const abs = path.resolve(root, rel);
    if (!abs.startsWith(root + path.sep)) { skipped_files.push({ file: rel, reason: "path escapes project root" }); continue; }
    try {
      const st = await fs.lstat(abs);
      if (!st.isFile() || st.isSymbolicLink()) { skipped_files.push({ file: rel, reason: "not a regular file" }); continue; }
      if (st.size > MAX_FILE_BYTES) { skipped_files.push({ file: rel, reason: `exceeds ${MAX_FILE_BYTES} byte per-file limit` }); continue; }
      const buf = await fs.readFile(abs);
      if (buf.includes(0)) { skipped_files.push({ file: rel, reason: "binary content" }); continue; }
      const content = buf.toString("utf8");
      files[rel.split(path.sep).join("/")] = content;
      total_bytes += buf.byteLength;
    } catch (err) {
      skipped_files.push({ file: rel, reason: `read failed: ${(err as Error).message}` });
    }
  }

  return { root, files, directory_tree: buildTree(Object.keys(files)), file_count: Object.keys(files).length, skipped_files, total_bytes, snapshot_at: new Date().toISOString() };
}
