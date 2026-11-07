import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { SqliteD1 } from './helpers/sqlite-d1';
import { ensureStorageSchema } from '../src/services/storage-schema';

const INITIAL_SQL = readFileSync(new URL('../migrations/0001_init.sql', import.meta.url), 'utf8');
const DATE = '2025-01-02T03:04:05.000Z';
const OPAQUE = '{"organizationId":"legacy-opaque-id","unknown":{"array":[1,null,"x"]},"name":"2.encrypted"}';

function seedUser(adapter: SqliteD1, id = 'user-a'): void {
  adapter.sqlite.prepare(`INSERT INTO users (id, email, master_password_hash, key, kdf_type, kdf_iterations, security_stamp, role, created_at, updated_at)
    VALUES (?, ?, 'hash', 'encrypted-key', 0, 600000, 'stamp', 'admin', ?, ?)`).run(id, `${id}@example.test`, DATE, DATE);
}

function legacyFixture(): SqliteD1 {
  const adapter = new SqliteD1();
  adapter.sqlite.exec(`
    CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, name TEXT, master_password_hash TEXT NOT NULL,
      key TEXT NOT NULL, private_key TEXT, public_key TEXT, kdf_type INTEGER NOT NULL, kdf_iterations INTEGER NOT NULL,
      kdf_memory INTEGER, kdf_parallelism INTEGER, security_stamp TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user',
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE folders (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE);
    CREATE TABLE ciphers (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, type INTEGER NOT NULL, folder_id TEXT, name TEXT, notes TEXT,
      favorite INTEGER NOT NULL DEFAULT 0, data TEXT NOT NULL, reprompt INTEGER, key TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
      archived_at TEXT, deleted_at TEXT, future_extension TEXT DEFAULT 'future', FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE);
    CREATE TABLE attachments (id TEXT PRIMARY KEY, cipher_id TEXT NOT NULL, file_name TEXT NOT NULL, size INTEGER NOT NULL, size_name TEXT NOT NULL, key TEXT,
      FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE);
  `);
  seedUser(adapter);
  adapter.sqlite.prepare('INSERT INTO folders VALUES (?, ?, ?, ?, ?)').run('folder-a', 'user-a', '2.folder', DATE, DATE);
  adapter.sqlite.prepare(`INSERT INTO ciphers (id, user_id, type, folder_id, data, created_at, updated_at, archived_at, deleted_at, future_extension)
    VALUES ('cipher-a', 'user-a', 1, 'folder-a', ?, ?, ?, ?, ?, 'extension-value')`).run(OPAQUE, DATE, DATE, DATE, DATE);
  adapter.sqlite.exec("INSERT INTO attachments VALUES ('attachment-a', 'cipher-a', '2.filename', 7, '7 B', '2.attachment-key')");
  return adapter;
}

async function currentFixture(): Promise<SqliteD1> {
  const adapter = new SqliteD1();
  await ensureStorageSchema(adapter.db);
  seedUser(adapter);
  seedUser(adapter, 'user-b');
  for (const id of ['org-a', 'org-b']) {
    adapter.sqlite.prepare('INSERT INTO organizations VALUES (?, ?, ?, NULL, NULL, ?, ?)').run(id, id, `${id}@example.test`, DATE, DATE);
    adapter.sqlite.prepare('INSERT INTO collections VALUES (?, ?, ?, NULL)').run(`collection-${id}`, id, '2.collection');
    adapter.sqlite.prepare('INSERT INTO organization_groups VALUES (?, ?, ?, 0, NULL)').run(`group-${id}`, id, 'group');
    adapter.sqlite.prepare(`INSERT INTO organization_members (id, organization_id, user_id, email, type, status, created_at, updated_at)
      VALUES (?, ?, ?, ?, 0, 2, ?, ?)`).run(`member-${id}`, id, id === 'org-a' ? 'user-a' : 'user-b', `${id}@example.test`, DATE, DATE);
  }
  adapter.sqlite.prepare("INSERT INTO ciphers (id, user_id, type, data, created_at, updated_at) VALUES ('cipher-a', 'user-a', 1, ?, ?, ?)").run(OPAQUE, DATE, DATE);
  return adapter;
}

test('legacy ownership migration retains data, attachments, timestamps and unknown fields; rerun is safe', async () => {
  const adapter = legacyFixture();
  try {
    const before = ['users', 'folders', 'ciphers', 'attachments'].map((table) => adapter.sqlite.prepare(`SELECT * FROM ${table}`).all());
    await ensureStorageSchema(adapter.db);
    assert.equal(adapter.sqlite.prepare('PRAGMA foreign_keys').get()!.foreign_keys, 1);
    assert.deepEqual(adapter.sqlite.prepare('PRAGMA foreign_key_check').all(), []);
    assert.equal(adapter.sqlite.prepare('SELECT organization_id FROM ciphers').get()!.organization_id, null);
    const columns = Object.keys(before[2][0]).join(', ');
    assert.deepEqual(adapter.sqlite.prepare(`SELECT ${columns} FROM ciphers`).all(), before[2]);
    for (const [i, table] of ['folders', 'attachments'].entries()) {
      assert.deepEqual(adapter.sqlite.prepare(`SELECT * FROM ${table}`).all(), before[i === 0 ? 1 : 3]);
    }
    const user = adapter.sqlite.prepare('SELECT * FROM users').get()!;
    for (const [key, value] of Object.entries(before[0][0])) assert.equal(user[key], value);
    await ensureStorageSchema(adapter.db);
    assert.deepEqual(adapter.sqlite.prepare(`SELECT ${columns} FROM ciphers`).all(), before[2]);
    assert.equal(adapter.sqlite.prepare('SELECT COUNT(*) AS n FROM attachments').get()!.n, 1);
  } finally { adapter.close(); }
});

test('parallel stale bootstraps cannot rebuild away organization writes after the first migration', async () => {
  const adapter = legacyFixture();
  const originalBatch = adapter.batch.bind(adapter);
  let successfulMigrations = 0;
  adapter.batch = async (statements) => {
    const result = await originalBatch(statements);
    if (++successfulMigrations === 1) {
      adapter.sqlite.prepare("INSERT INTO organizations VALUES ('new-org', 'New', 'new@example.test', NULL, NULL, ?, ?)").run(DATE, DATE);
      adapter.sqlite.prepare("INSERT INTO ciphers (id, user_id, organization_id, type, data, created_at, updated_at) VALUES ('new-org-cipher', NULL, 'new-org', 1, ?, ?, ?)").run(OPAQUE, DATE, DATE);
    }
    return result;
  };
  try {
    await Promise.all([ensureStorageSchema(adapter.db), ensureStorageSchema(adapter.db)]);
    assert.equal(successfulMigrations, 1);
    assert.equal(adapter.sqlite.prepare("SELECT organization_id FROM ciphers WHERE id = 'new-org-cipher'").get()!.organization_id, 'new-org');
    assert.equal(adapter.sqlite.prepare('SELECT COUNT(*) AS n FROM attachments').get()!.n, 1);
    assert.deepEqual(adapter.sqlite.prepare('PRAGMA foreign_key_check').all(), []);
  } finally { adapter.close(); }
});

test('ownership rebuild rolls back without deleting attachment metadata on failure', async () => {
  const adapter = legacyFixture();
  const originalBatch = adapter.batch.bind(adapter);
  adapter.batch = async (statements) => originalBatch([
    ...statements,
    adapter.prepare("INSERT INTO config (key, value) VALUES (NULL, NULL)"),
  ]);
  try {
    await assert.rejects(ensureStorageSchema(adapter.db));
    assert.equal(adapter.sqlite.prepare('SELECT data FROM ciphers').get()!.data, OPAQUE);
    assert.equal(adapter.sqlite.prepare('SELECT COUNT(*) AS n FROM attachments').get()!.n, 1);
    assert.equal(adapter.sqlite.prepare('PRAGMA table_info(ciphers)').all().some((row) => row.name === 'organization_id'), false);
    assert.deepEqual(adapter.sqlite.prepare('PRAGMA foreign_key_check').all(), []);
    assert.equal(adapter.sqlite.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE name LIKE '%ownership_snapshot' OR name = 'ciphers__ownership_new'").get()!.n, 0);
    adapter.batch = originalBatch;
    await ensureStorageSchema(adapter.db);
  } finally { adapter.close(); }
});

test('initial and runtime schemas agree on tables, columns, foreign keys, indexes and triggers', async () => {
  const initial = new SqliteD1();
  const runtime = new SqliteD1();
  try {
    initial.sqlite.exec(INITIAL_SQL);
    await ensureStorageSchema(runtime.db);
    const objects = (adapter: SqliteD1) => adapter.sqlite.prepare("SELECT type, name, tbl_name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name").all();
    assert.deepEqual(objects(runtime), objects(initial));
    const tables = initial.sqlite.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").all();
    for (const { name } of tables) {
      assert.deepEqual(runtime.sqlite.prepare(`PRAGMA table_info(${name})`).all(), initial.sqlite.prepare(`PRAGMA table_info(${name})`).all(), `${name}: columns`);
      assert.deepEqual(runtime.sqlite.prepare(`PRAGMA foreign_key_list(${name})`).all(), initial.sqlite.prepare(`PRAGMA foreign_key_list(${name})`).all(), `${name}: foreign keys`);
    }
  } finally { initial.close(); runtime.close(); }
});

test('SQL rejects cross-organization insert/update and parent reassignment but allows sharing personal ciphers', async () => {
  const adapter = await currentFixture();
  try {
    const sql = adapter.sqlite;
    const invalid = [
      "INSERT INTO organization_group_members VALUES ('group-org-a', 'member-org-b')",
      "INSERT INTO collection_users (collection_id, member_id) VALUES ('collection-org-a', 'member-org-b')",
      "INSERT INTO collection_groups (collection_id, group_id) VALUES ('collection-org-a', 'group-org-b')",
      "INSERT INTO cipher_collections VALUES ('cipher-a', 'collection-org-a')",
      "UPDATE ciphers SET organization_id = 'org-a' WHERE id = 'cipher-a'",
      "UPDATE ciphers SET user_id = NULL WHERE id = 'cipher-a'",
    ];
    for (const statement of invalid) assert.throws(() => sql.exec(statement));
    sql.exec("UPDATE ciphers SET user_id = NULL, organization_id = 'org-a' WHERE id = 'cipher-a'");
    sql.exec("INSERT INTO cipher_collections VALUES ('cipher-a', 'collection-org-a')");
    sql.exec("INSERT INTO organization_group_members VALUES ('group-org-a', 'member-org-a')");
    sql.exec("INSERT INTO collection_users (collection_id, member_id) VALUES ('collection-org-a', 'member-org-a')");
    sql.exec("INSERT INTO collection_groups (collection_id, group_id) VALUES ('collection-org-a', 'group-org-a')");
    for (const statement of [
      "UPDATE cipher_collections SET collection_id = 'collection-org-b'",
      "UPDATE ciphers SET organization_id = 'org-b' WHERE id = 'cipher-a'",
      "UPDATE collections SET organization_id = 'org-b' WHERE id = 'collection-org-a'",
      "UPDATE organization_groups SET organization_id = 'org-b' WHERE id = 'group-org-a'",
      "UPDATE organization_members SET organization_id = 'org-b' WHERE id = 'member-org-a'",
      "UPDATE organization_group_members SET member_id = 'member-org-b'",
      "UPDATE collection_users SET member_id = 'member-org-b'",
      "UPDATE collection_groups SET group_id = 'group-org-b'",
    ]) assert.throws(() => sql.exec(statement), /Cross-organization/);
  } finally { adapter.close(); }
});

test('pending invites are nullable identities and case-insensitive unique; preferences use own folders', async () => {
  const adapter = await currentFixture();
  try {
    const sql = adapter.sqlite;
    sql.prepare("INSERT INTO organization_members (id, organization_id, user_id, email, type, status, created_at, updated_at) VALUES ('pending', 'org-a', NULL, 'Pending@EXAMPLE.test', 2, 0, ?, ?)").run(DATE, DATE);
    assert.throws(() => sql.prepare("INSERT INTO organization_members (id, organization_id, email, type, status, created_at, updated_at) VALUES ('duplicate', 'org-a', 'pending@example.test', 2, 0, ?, ?)").run(DATE, DATE), /UNIQUE/);
    sql.prepare("INSERT INTO folders VALUES ('folder-a', 'user-a', '2.name', ?, ?)").run(DATE, DATE);
    assert.throws(() => sql.exec("INSERT INTO cipher_user_preferences VALUES ('cipher-a', 'user-b', 'folder-a', 1)"), /another user/);
    sql.exec("INSERT INTO cipher_user_preferences VALUES ('cipher-a', 'user-a', 'folder-a', 1)");
    sql.exec("DELETE FROM folders WHERE id = 'folder-a'");
    assert.equal(sql.prepare('SELECT folder_id FROM cipher_user_preferences').get()!.folder_id, null);
    sql.exec("UPDATE ciphers SET user_id = NULL, organization_id = 'org-a' WHERE id = 'cipher-a'");
    sql.exec("INSERT INTO attachments VALUES ('attachment', 'cipher-a', 'name', 1, '1 B', NULL)");
    sql.exec("DELETE FROM organizations WHERE id = 'org-a'");
    assert.equal(sql.prepare('SELECT COUNT(*) AS n FROM ciphers').get()!.n, 0);
    assert.equal(sql.prepare('SELECT COUNT(*) AS n FROM attachments').get()!.n, 0);
    assert.deepEqual(sql.prepare('PRAGMA foreign_key_check').all(), []);
  } finally { adapter.close(); }
});
