import { DatabaseSync, type SQLInputValue } from 'node:sqlite';

/** In-memory D1 test adapter: foreign keys stay enabled and batch is atomic. */
export class SqliteD1 {
  readonly sqlite = new DatabaseSync(':memory:');
  readonly db: D1Database = this as unknown as D1Database;

  constructor() {
    this.sqlite.exec('PRAGMA foreign_keys = ON');
  }

  prepare(sql: string): D1PreparedStatement {
    return new SqliteD1Statement(this, sql) as unknown as D1PreparedStatement;
  }

  async batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]> {
    this.sqlite.exec('BEGIN');
    try {
      const results = statements.map((statement) => (statement as unknown as SqliteD1Statement).execute<T>());
      this.sqlite.exec('COMMIT');
      return results;
    } catch (error) {
      this.sqlite.exec('ROLLBACK');
      throw error;
    }
  }

  async exec(sql: string): Promise<D1ExecResult> {
    this.sqlite.exec(sql);
    return { count: 1, duration: 0 };
  }

  close(): void {
    this.sqlite.close();
  }
}

class SqliteD1Statement {
  constructor(private owner: SqliteD1, private sql: string, private values: SQLInputValue[] = []) {}

  bind(...values: unknown[]): SqliteD1Statement {
    if (values.some((value) => value === undefined)) throw new Error('D1 bind does not accept undefined');
    return new SqliteD1Statement(this.owner, this.sql, values as SQLInputValue[]);
  }

  execute<T>(): D1Result<T> {
    if (/^\s*PRAGMA\s+foreign_keys\s*=\s*(OFF|0)\b/i.test(this.sql)) {
      throw new Error('D1 does not support disabling foreign key enforcement');
    }
    // Prepare at execution time, matching D1 batches that create referenced tables.
    const statement = this.owner.sqlite.prepare(this.sql);
    const rows = statement.all(...this.values).map((row) => ({ ...row })) as T[];
    const changes = this.owner.sqlite.prepare('SELECT changes() AS changes').get()!.changes as number;
    return { results: rows, success: true, meta: { changes, duration: 0 } } as D1Result<T>;
  }

  async all<T>(): Promise<D1Result<T>> {
    return this.execute<T>();
  }

  async run<T>(): Promise<D1Result<T>> {
    return this.execute<T>();
  }

  async first<T>(column?: string): Promise<T | null> {
    const row = this.execute<Record<string, unknown>>().results[0];
    if (!row) return null;
    return (column ? row[column] : row) as T;
  }

  async raw<T>(): Promise<T[]> {
    return this.execute<Record<string, unknown>>().results.map((row) => Object.values(row)) as T[];
  }
}
