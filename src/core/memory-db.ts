import Database from "better-sqlite3";
import path from "node:path";
import { promises as fs } from "node:fs";

/**
 * Singleton wrapper around better‑sqlite3 that ensures the DB file exists
 * and the schema is created on first use.
 */
export class MemoryDB {
  private static instance: MemoryDB;
  private db: any;

  private constructor(dbPath: string) {
    this.db = new Database(dbPath);
    this.ensureSchema();
  }

  static async getInstance(): Promise<MemoryDB> {
    if (!MemoryDB.instance) {
      const home = process.env.HOME ?? process.env.USERPROFILE ?? "";
      const dir = path.join(home, ".leo");
      await fs.mkdir(dir, { recursive: true });
      const dbPath = path.join(dir, "memory.db");
      MemoryDB.instance = new MemoryDB(dbPath);
    }
    return MemoryDB.instance;
  }

  private ensureSchema() {
    const sql = `
      CREATE TABLE IF NOT EXISTS vulnerability_patterns (
        id TEXT PRIMARY KEY,
        pattern_name TEXT NOT NULL,
        description TEXT NOT NULL,
        attack_class TEXT NOT NULL,
        code_signatures TEXT NOT NULL,
        languages TEXT NOT NULL,
        confidence_weight REAL DEFAULT 1.0,
        false_positive_count INTEGER DEFAULT 0,
        created_at TEXT,
        last_seen_at TEXT
      );
      CREATE TABLE IF NOT EXISTS patch_templates (
        id TEXT PRIMARY KEY,
        vulnerability_pattern_id TEXT REFERENCES vulnerability_patterns(id),
        language TEXT NOT NULL,
        description TEXT NOT NULL,
        before_pattern TEXT NOT NULL,
        after_pattern TEXT NOT NULL,
        success_count INTEGER DEFAULT 0,
        created_at TEXT
      );
      CREATE TABLE IF NOT EXISTS session_scores (
        session_id TEXT PRIMARY KEY,
        project_hash TEXT NOT NULL,
        coverage_score REAL,
        precision_score REAL,
        patch_success_rate REAL,
        novelty_score REAL,
        composite_score REAL,
        model_used TEXT,
        created_at TEXT
      );
      CREATE TABLE IF NOT EXISTS false_positives (
        id TEXT PRIMARY KEY,
        pattern_id TEXT REFERENCES vulnerability_patterns(id),
        reason TEXT NOT NULL,
        code_context TEXT,
        created_at TEXT
      );
    `;
    this.db.exec(sql);
  }

  // ---------- Pattern helpers ----------
  insertPattern(params: {
    id: string;
    pattern_name: string;
    description: string;
    attack_class: string;
    code_signatures: string; // JSON stringified array
    languages: string; // JSON stringified array
    created_at: string;
  }) {
    const stmt = this.db.prepare(
      `INSERT OR IGNORE INTO vulnerability_patterns
      (id, pattern_name, description, attack_class, code_signatures, languages, created_at, last_seen_at)
      VALUES (@id, @pattern_name, @description, @attack_class, @code_signatures, @languages, @created_at, @created_at)`
    );
    stmt.run(params);
  }

  // Return top‑N patterns ordered by confidence_weight DESC
  getTopPatterns(limit: number = 50) {
    const stmt = this.db.prepare(
      `SELECT * FROM vulnerability_patterns ORDER BY confidence_weight DESC LIMIT ?`
    );
    return stmt.all(limit);
  }

  // ---------- Patch template helpers ----------
  insertPatchTemplate(params: {
    id: string;
    vulnerability_pattern_id: string;
    language: string;
    description: string;
    before_pattern: string;
    after_pattern: string;
    created_at: string;
  }) {
    const stmt = this.db.prepare(
      `INSERT OR IGNORE INTO patch_templates
      (id, vulnerability_pattern_id, language, description, before_pattern, after_pattern, created_at)
      VALUES (@id, @vulnerability_pattern_id, @language, @description, @before_pattern, @after_pattern, @created_at)`
    );
    stmt.run(params);
  }

  // ---------- Session score helpers ----------
  insertSessionScore(params: {
    session_id: string;
    project_hash: string;
    coverage_score: number;
    precision_score: number;
    patch_success_rate: number;
    novelty_score: number;
    composite_score: number;
    model_used: string;
    created_at: string;
  }) {
    const stmt = this.db.prepare(
      `INSERT OR REPLACE INTO session_scores
      (session_id, project_hash, coverage_score, precision_score, patch_success_rate, novelty_score, composite_score, model_used, created_at)
      VALUES (@session_id, @project_hash, @coverage_score, @precision_score, @patch_success_rate, @novelty_score, @composite_score, @model_used, @created_at)`
    );
    stmt.run(params);
  }

  // ---------- False positive helper ----------
  insertFalsePositive(params: {
    id: string;
    pattern_id: string;
    reason: string;
    code_context: string;
    created_at: string;
  }) {
    const stmt = this.db.prepare(
      `INSERT INTO false_positives (id, pattern_id, reason, code_context, created_at)
       VALUES (@id, @pattern_id, @reason, @code_context, @created_at)`
    );
    stmt.run(params);
  }
}
