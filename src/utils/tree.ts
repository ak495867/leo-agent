import path from "node:path";

type TreeNode = {
  name: string;
  type: "directory" | "file";
  children?: TreeNode[];
};

/**
 * Convert an array of POSIX‑style file paths (e.g. "src/utils/logger.ts")
 * into a hierarchical tree of directories/files. Used for the ReconReport.
 */
export function buildTree(filePaths: string[]): TreeNode {
  const root: TreeNode = { name: ".", type: "directory", children: [] };

  for (const relPath of filePaths) {
    const parts = relPath.split(path.posix.sep);
    let current = root;
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      const isFile = i === parts.length - 1 && part.includes(".");
      const existing = current.children?.find((c) => c.name === part);
      if (existing) {
        current = existing;
        continue;
      }
      const node: TreeNode = {
        name: part,
        type: isFile ? "file" : "directory",
        children: isFile ? undefined : []
      };
      current.children?.push(node);
      current = node;
    }
  }
  return root;
}
