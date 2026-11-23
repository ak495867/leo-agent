import { createHash } from "node:crypto";
import { buildTree } from "../utils/tree.js";
import { CodebaseSnapshot } from "../core/snapshot.js";

export interface SnapshotBatch {
  id: string;
  index: number;
  total: number;
  files: Record<string, string>;
  byte_count: number;
}

/** Deterministic file-aware batching. A file is never split or silently truncated. */
export function createSnapshotBatches(snapshot: CodebaseSnapshot, maxBytes = 48_000): SnapshotBatch[] {
  if (!Number.isFinite(maxBytes) || maxBytes < 1024) throw new Error("Batch budget must be at least 1024 bytes.");
  const entries = Object.entries(snapshot.files).sort(([a], [b]) => a.localeCompare(b));
  const groups: Array<{ files: Record<string, string>; bytes: number }> = [];
  let current = { files: {} as Record<string, string>, bytes: 0 };
  for (const [file, content] of entries) {
    const bytes = Buffer.byteLength(content, "utf8");
    if (bytes > maxBytes) {
      if (current.bytes) { groups.push(current); current = { files: {}, bytes: 0 }; }
      // Keep a large file intact in a dedicated batch (the snapshot has a separate per-file ceiling).
      groups.push({ files: { [file]: content }, bytes });
      continue;
    }
    if (current.bytes > 0 && current.bytes + bytes > maxBytes) { groups.push(current); current = { files: {}, bytes: 0 }; }
    current.files[file] = content; current.bytes += bytes;
  }
  if (current.bytes || groups.length === 0) groups.push(current);
  return groups.map((g, index) => {
    const paths = Object.keys(g.files);
    const digest = createHash("sha256").update(paths.join("\n")).digest("hex").slice(0, 12);
    return { id: `batch-${String(index + 1).padStart(4, "0")}-${digest}`, index: index + 1, total: groups.length, files: g.files, byte_count: g.bytes };
  });
}

export function snapshotForBatch(snapshot: CodebaseSnapshot, batch: SnapshotBatch): CodebaseSnapshot {
  return { ...snapshot, files: batch.files, file_count: Object.keys(batch.files).length, total_bytes: batch.byte_count, directory_tree: buildTree(Object.keys(batch.files)), skipped_files: [] };
}
