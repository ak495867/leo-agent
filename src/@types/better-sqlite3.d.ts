declare module "better-sqlite3" {
  import { Database } from "better-sqlite3";
  const db: typeof Database;
  export = db;
}
