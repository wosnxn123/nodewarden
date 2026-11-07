import assert from 'node:assert/strict';
import test from 'node:test';
import { zipSync } from 'fflate';
import { SqliteD1 } from './helpers/sqlite-d1';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { buildBackupArchive, parseBackupArchive, validateBackupPayloadContents, type BackupPayload } from '../src/services/backup-archive';
import { importBackupArchiveBytes, importRemoteBackupArchiveBytes } from '../src/services/backup-import';
import { ORGANIZATION_BACKUP_TABLES, ORGANIZATION_BACKUP_TABLE_COLUMNS } from '../shared/backup-schema';
import type { Env } from '../src/types';

const DATE = '2025-01-02T03:04:05.000Z';
const OPAQUE = '{"organizationId":"opaque-not-sql-ownership","unknown":{"nested":[1,null,"x"]},"name":"2.cipher"}';
const BYTES = new Uint8Array([0, 1, 127, 255]);

function environment(adapter: SqliteD1): { env: Env; blobs: Map<string, Uint8Array> } {
  const blobs = new Map<string, Uint8Array>();
  const env = {
    DB: adapter.db,
    ATTACHMENTS: {
      async put(key: string, value: Uint8Array) { blobs.set(key, new Uint8Array(value)); },
      async delete(key: string) { blobs.delete(key); },
    },
  } as unknown as Env;
  return { env, blobs };
}

async function sourceFixture(): Promise<SqliteD1> {
  const adapter = new SqliteD1();
  await ensureStorageSchema(adapter.db);
  const sql = adapter.sqlite;
  for (const id of ['user-a', 'user-b']) {
    sql.prepare(`INSERT INTO users (id, email, master_password_hash, key, kdf_type, kdf_iterations, security_stamp, role, api_key, created_at, updated_at)
      VALUES (?, ?, 'hash', '2.user-key', 0, 600000, 'stamp', 'admin', 'do-not-export', ?, ?)`).run(id, `${id}@example.test`, DATE, DATE);
  }
  sql.prepare("INSERT INTO folders VALUES ('folder-a', 'user-a', '2.folder', ?, ?)").run(DATE, DATE);
  sql.prepare("INSERT INTO user_revisions VALUES ('user-a', ?)").run(DATE);
  sql.prepare("INSERT INTO domain_settings VALUES ('user-a', '[]', '[]', '[]', ?)").run(DATE);
  sql.prepare("INSERT INTO organizations VALUES ('org-a', 'Organization A', 'billing@example.test', 'public', '2.private', ?, ?)").run(DATE, DATE);
  sql.prepare("INSERT INTO organization_members VALUES ('member-a', 'org-a', 'user-a', 'user-a@example.test', 0, 2, 1, '2.member-key', 'external-member', ?, ?)").run(DATE, DATE);
  sql.prepare("INSERT INTO organization_members VALUES ('member-pending', 'org-a', NULL, 'pending@example.test', 2, 0, 0, NULL, NULL, ?, ?)").run(DATE, DATE);
  sql.exec("INSERT INTO collections VALUES ('collection-a', 'org-a', '2.collection', 'external-collection')");
  sql.exec("INSERT INTO organization_groups VALUES ('group-a', 'org-a', 'Group A', 0, 'external-group')");
  sql.exec("INSERT INTO organization_group_members VALUES ('group-a', 'member-a')");
  sql.exec("INSERT INTO collection_users VALUES ('collection-a', 'member-a', 0, 1, 1)");
  sql.exec("INSERT INTO collection_groups VALUES ('collection-a', 'group-a', 1, 1, 0)");
  sql.prepare("INSERT INTO ciphers (id, user_id, organization_id, type, folder_id, data, created_at, updated_at, archived_at, deleted_at) VALUES ('cipher-personal', 'user-a', NULL, 1, 'folder-a', ?, ?, ?, NULL, NULL)").run(OPAQUE, DATE, DATE);
  sql.prepare("INSERT INTO ciphers (id, user_id, organization_id, type, data, created_at, updated_at, archived_at, deleted_at) VALUES ('cipher-org', NULL, 'org-a', 1, ?, ?, ?, ?, ?)").run(OPAQUE, DATE, DATE, DATE, DATE);
  sql.exec("INSERT INTO cipher_collections VALUES ('cipher-org', 'collection-a')");
  sql.exec("INSERT INTO cipher_user_preferences VALUES ('cipher-org', 'user-a', 'folder-a', 1)");
  sql.exec("INSERT INTO cipher_user_preferences VALUES ('cipher-org', 'user-b', NULL, 0)");
  sql.prepare("INSERT INTO organization_events VALUES ('event-a', 'org-a', 'user-a', 1500, 'cipher-org', ?, ?)").run(DATE, '{"unknown":"event-data"}');
  sql.exec("INSERT INTO attachments VALUES ('attachment-a', 'cipher-org', '2.file-name', 4, '4 B', '2.attachment-key')");
  sql.exec("INSERT INTO config VALUES ('registered', 'true'), ('organization.sync.event-a', 'runtime-only')");
  return adapter;
}

function encodePayload(payload: BackupPayload, files: Record<string, Uint8Array> = {}): Uint8Array {
  const encoder = new TextEncoder();
  return zipSync({
    ...files,
    'manifest.json': encoder.encode(JSON.stringify(payload.manifest)),
    'db.json': encoder.encode(JSON.stringify(payload.db)),
  }, { level: 0 });
}

async function exportedFixture(adapter: SqliteD1): Promise<{ payload: BackupPayload; files: Record<string, Uint8Array>; bytes: Uint8Array }> {
  const { env } = environment(adapter);
  const bundle = await buildBackupArchive(env, new Date(DATE), { includeAttachments: true });
  const parsed = parseBackupArchive(bundle.bytes, { allowExternalAttachmentBlobs: true });
  const files = { ...parsed.files, 'attachments/cipher-org/attachment-a.bin': BYTES };
  return { payload: parsed.payload, files, bytes: encodePayload(parsed.payload, files) };
}

test('new exports are v2 and contain every organization table/count but not runtime outbox or API keys', async () => {
  const source = await sourceFixture();
  try {
    const { payload, files } = await exportedFixture(source);
    assert.equal(payload.manifest.formatVersion, 2);
    for (const table of ORGANIZATION_BACKUP_TABLES) {
      assert.ok(Array.isArray(payload.db[table]), table);
      assert.equal(payload.manifest.tableCounts[table], payload.db[table]!.length, table);
      assert.ok(payload.db[table]!.length > 0, table);
    }
    assert.equal(payload.db.config.some((row) => String(row.key).startsWith('organization.sync.')), false);
    assert.equal(payload.db.users.some((row) => 'api_key' in row), false);
    assert.equal(payload.db.ciphers.find((row) => row.id === 'cipher-org')!.user_id, null);
    assert.equal(payload.db.ciphers.find((row) => row.id === 'cipher-personal')!.organization_id, null);
    validateBackupPayloadContents(payload, files);
    // The previous version only accepts formatVersion 1, so cannot partially restore v2.
    assert.notEqual(payload.manifest.formatVersion, 1);
  } finally { source.close(); }
});

for (const mutation of ['share', 'confirm-new-user'] as const) {
  test(`export captures one atomic all-table snapshot across an interleaved ${mutation} mutation`, async () => {
    const source = await sourceFixture();
    const target = new SqliteD1();
    await ensureStorageSchema(target.db);
    try {
      const beforeOrganizations = Object.fromEntries(ORGANIZATION_BACKUP_TABLES.map((table) => [table,
        source.sqlite.prepare(`SELECT ${ORGANIZATION_BACKUP_TABLE_COLUMNS[table].join(', ')} FROM ${table} ORDER BY ${ORGANIZATION_BACKUP_TABLE_COLUMNS[table].join(', ')}`).all().map((row) => ({ ...row })),
      ]));
      const beforeCiphers = source.sqlite.prepare('SELECT * FROM ciphers ORDER BY created_at ASC').all().map((row) => ({ ...row }));
      let mutated = false;
      let batches = 0;
      const mutateOnce = () => {
        if (mutated) return;
        mutated = true;
        source.sqlite.exec('BEGIN');
        try {
          if (mutation === 'share') {
            source.sqlite.exec("UPDATE ciphers SET user_id = NULL, organization_id = 'org-a', folder_id = NULL, key = '2.rewrapped-key' WHERE id = 'cipher-personal'");
            source.sqlite.exec("INSERT INTO cipher_collections VALUES ('cipher-personal', 'collection-a')");
            source.sqlite.exec("UPDATE organization_members SET status = -1, key = NULL WHERE id = 'member-a'");
          } else {
            source.sqlite.prepare(`INSERT INTO users (id, email, master_password_hash, key, kdf_type, kdf_iterations, security_stamp, role, created_at, updated_at)
              VALUES ('user-new', 'pending@example.test', 'new-hash', '2.new-user-key', 0, 600000, 'new-stamp', 'user', ?, ?)`).run(DATE, DATE);
            source.sqlite.exec("UPDATE organization_members SET user_id = 'user-new', status = 2, key = '2.confirmed-member-key' WHERE id = 'member-pending'");
          }
          source.sqlite.exec('COMMIT');
        } catch (error) { source.sqlite.exec('ROLLBACK'); throw error; }
      };
      const originalPrepare = source.prepare.bind(source);
      const originalBatch = source.batch.bind(source);
      source.prepare = (sql) => {
        const wrap = (statement: D1PreparedStatement): D1PreparedStatement => {
          const bind = statement.bind.bind(statement);
          const all = statement.all.bind(statement);
          statement.bind = (...values) => wrap(bind(...values));
          statement.all = async <T>() => {
            const result = await all<T>();
            // The former exporter finished this final personal-table read before
            // starting organization reads. Reproduce a write exactly at that gap.
            if (/FROM webauthn_credentials\b/.test(sql)) mutateOnce();
            return result;
          };
          return statement;
        };
        return wrap(originalPrepare(sql));
      };
      source.batch = async <T>(statements: D1PreparedStatement[]) => {
        batches++;
        const result = await originalBatch<T>(statements);
        // The replacement commits every exported SELECT before the competing write.
        mutateOnce();
        return result;
      };
      const exported = await exportedFixture(source);
      assert.ok(mutated, 'the competing mutation must actually execute');
      validateBackupPayloadContents(exported.payload, exported.files);
      assert.equal(batches, 1, 'all exported tables must share one D1 transaction');
      assert.deepEqual(exported.payload.db.ciphers, beforeCiphers);
      for (const table of ORGANIZATION_BACKUP_TABLES) assert.deepEqual(exported.payload.db[table], beforeOrganizations[table], table);
      assert.equal(exported.payload.db.users.length, 2);
      const restored = await importBackupArchiveBytes(exported.bytes, environment(target).env, 'user-a', false);
      assert.equal(restored.result.imported.ciphers, 2);
      assert.equal(target.sqlite.prepare("SELECT organization_id FROM ciphers WHERE id = 'cipher-personal'").get()!.organization_id, null);
      assert.equal(target.sqlite.prepare("SELECT user_id FROM organization_members WHERE id = 'member-pending'").get()!.user_id, null);
      assert.deepEqual(target.sqlite.prepare('PRAGMA foreign_key_check').all(), []);
      // A subsequent export sees the complete post-mutation state and also restores.
      source.prepare = originalPrepare;
      source.batch = originalBatch;
      const after = await exportedFixture(source);
      validateBackupPayloadContents(after.payload, after.files);
      await importBackupArchiveBytes(after.bytes, environment(target).env, 'user-a', true);
      if (mutation === 'share') {
        assert.equal(target.sqlite.prepare("SELECT organization_id FROM ciphers WHERE id = 'cipher-personal'").get()!.organization_id, 'org-a');
        assert.equal(target.sqlite.prepare("SELECT COUNT(*) AS n FROM cipher_collections WHERE cipher_id = 'cipher-personal'").get()!.n, 1);
        assert.equal(target.sqlite.prepare("SELECT status FROM organization_members WHERE id = 'member-a'").get()!.status, -1);
      } else {
        assert.equal(target.sqlite.prepare("SELECT user_id FROM organization_members WHERE id = 'member-pending'").get()!.user_id, 'user-new');
        assert.equal(target.sqlite.prepare("SELECT COUNT(*) AS n FROM users WHERE id = 'user-new'").get()!.n, 1);
      }
      assert.deepEqual(target.sqlite.prepare('PRAGMA foreign_key_check').all(), []);
    } finally { source.close(); target.close(); }
  });
}

for (const remote of [false, true]) {
  test(`${remote ? 'remote' : 'local'} organization backup restore preserves ownership, permissions, keys, opaque JSON and attachment object ids`, async () => {
    const source = await sourceFixture();
    const target = new SqliteD1();
    await ensureStorageSchema(target.db);
    try {
      const exported = await exportedFixture(source);
      exported.payload.db.config.push({ key: 'organization.sync.untrusted', value: 'discard' });
      exported.payload.db.users[0].api_key = 'discard';
      const { env, blobs } = environment(target);
      const result = remote
        ? await importRemoteBackupArchiveBytes(encodePayload(exported.payload), env, 'user-a', false, { async loadAttachment(key) { assert.equal(key, 'cipher-org/attachment-a'); return BYTES; } })
        : await importBackupArchiveBytes(encodePayload(exported.payload, exported.files), env, 'user-a', false);
      for (const table of ORGANIZATION_BACKUP_TABLES) {
        const columns = ORGANIZATION_BACKUP_TABLE_COLUMNS[table].join(', ');
        const query = `SELECT ${columns} FROM ${table} ORDER BY ${columns}`;
        assert.deepEqual(target.sqlite.prepare(query).all(), source.sqlite.prepare(query).all(), table);
      }
      for (const table of ['ciphers', 'folders', 'attachments']) {
        assert.deepEqual(target.sqlite.prepare(`SELECT * FROM ${table} ORDER BY id`).all(), source.sqlite.prepare(`SELECT * FROM ${table} ORDER BY id`).all(), table);
      }
      assert.deepEqual(blobs.get('cipher-org/attachment-a'), BYTES);
      assert.equal(result.result.imported.organizations, 1);
      assert.equal(result.result.imported.organizationMembers, 2);
      assert.equal(result.result.imported.cipherUserPreferences, 2);
      assert.equal(result.result.imported.organizationEvents, 1);
      assert.equal(result.result.imported.attachmentFiles, 1);
      assert.equal(target.sqlite.prepare("SELECT COUNT(*) AS n FROM config WHERE key LIKE 'organization.sync.%'").get()!.n, 0);
      assert.equal(target.sqlite.prepare('SELECT COUNT(*) AS n FROM users WHERE api_key IS NOT NULL').get()!.n, 0);
      assert.deepEqual(target.sqlite.prepare('PRAGMA foreign_key_check').all(), []);
      assert.equal(target.sqlite.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE name LIKE '%__restore'").get()!.n, 0);
    } finally { source.close(); target.close(); }
  });
}

test('v1 archives restore only personal ownership and ignore retired runtime tables', async () => {
  const source = await sourceFixture();
  const target = new SqliteD1();
  await ensureStorageSchema(target.db);
  try {
    const { payload } = await exportedFixture(source);
    payload.manifest.formatVersion = 1;
    for (const table of ORGANIZATION_BACKUP_TABLES) delete payload.db[table];
    payload.db.ciphers = payload.db.ciphers.filter((row) => row.user_id !== null).map(({ organization_id, ...row }) => row);
    payload.db.attachments = [];
    (payload.db as unknown as Record<string, unknown>).refresh_tokens = [{ token: 'do-not-restore' }];
    const bytes = encodePayload(payload);
    const parsed = parseBackupArchive(bytes);
    validateBackupPayloadContents(parsed.payload, parsed.files);
    const result = await importBackupArchiveBytes(bytes, environment(target).env, 'user-a', false);
    assert.equal(result.result.imported.organizations, 0);
    assert.equal(result.result.imported.ciphers, 1);
    const cipher = target.sqlite.prepare('SELECT * FROM ciphers').get()!;
    assert.equal(cipher.organization_id, null);
    assert.equal(cipher.data, OPAQUE);
    assert.equal(target.sqlite.prepare('SELECT COUNT(*) AS n FROM refresh_tokens').get()!.n, 0);
  } finally { source.close(); target.close(); }
});

test('missing organization tables, future versions and disguised v1 organization data are rejected', async () => {
  const source = await sourceFixture();
  try {
    const exported = await exportedFixture(source);
    for (const table of ORGANIZATION_BACKUP_TABLES) {
      const payload = structuredClone(exported.payload);
      delete payload.db[table];
      assert.throws(() => parseBackupArchive(encodePayload(payload, exported.files)), /table .* is invalid/);
    }
    const future = structuredClone(exported.payload);
    (future.manifest as { formatVersion: number }).formatVersion = 3;
    assert.throws(() => parseBackupArchive(encodePayload(future, exported.files)), /Unsupported backup format version/);
    const unsupported = structuredClone(exported.payload);
    (unsupported.db as unknown as Record<string, unknown>).future_persistent_table = [];
    assert.throws(() => parseBackupArchive(encodePayload(unsupported, exported.files)), /unsupported table: future_persistent_table/);
    const disguised = structuredClone(exported.payload);
    disguised.manifest.formatVersion = 1;
    assert.throws(() => parseBackupArchive(encodePayload(disguised, exported.files)), /Legacy backup format cannot contain organization data/);
    for (const table of ORGANIZATION_BACKUP_TABLES) delete disguised.db[table];
    assert.throws(() => validateBackupPayloadContents(parseBackupArchive(encodePayload(disguised, exported.files)).payload, exported.files), /Legacy backup format cannot contain organization-owned ciphers/);
  } finally { source.close(); }
});

test('invalid organization references, duplicate identities, cross-org links and mismatched counts fail before live data changes', async () => {
  const source = await sourceFixture();
  const target = new SqliteD1();
  await ensureStorageSchema(target.db);
  target.sqlite.exec("INSERT INTO config VALUES ('keep', 'unchanged')");
  try {
    const exported = await exportedFixture(source);
    const mutations: Array<(payload: BackupPayload) => void> = [
      (payload) => { payload.db.organization_members![0].organization_id = 'missing'; },
      (payload) => { payload.db.organization_members![1].email = 'USER-A@EXAMPLE.TEST'; },
      (payload) => { payload.db.organization_members![1].user_id = 'user-a'; },
      (payload) => { payload.db.cipher_user_preferences![0].user_id = 'user-b'; },
      (payload) => { payload.db.ciphers.find((row) => row.id === 'cipher-org')!.user_id = 'user-a'; },
      (payload) => { payload.manifest.tableCounts.organization_events = 0; },
      (payload) => { payload.db.organization_groups![0].organization_id = 'org-b'; payload.db.organizations!.push({ ...payload.db.organizations![0], id: 'org-b' }); payload.manifest.tableCounts.organizations++; },
    ];
    for (const mutate of mutations) {
      const payload = structuredClone(exported.payload);
      mutate(payload);
      await assert.rejects(importBackupArchiveBytes(encodePayload(payload, exported.files), environment(target).env, 'user-a', true));
      assert.equal(target.sqlite.prepare("SELECT value FROM config WHERE key = 'keep'").get()!.value, 'unchanged');
      assert.equal(target.sqlite.prepare('SELECT COUNT(*) AS n FROM organizations').get()!.n, 0);
    }
  } finally { source.close(); target.close(); }
});

test('fresh-only restore rejects organization data even when the target has no ciphers', async () => {
  const source = await sourceFixture();
  const target = new SqliteD1();
  await ensureStorageSchema(target.db);
  target.sqlite.prepare("INSERT INTO organizations VALUES ('existing', 'Existing', 'existing@example.test', NULL, NULL, ?, ?)").run(DATE, DATE);
  try {
    const exported = await exportedFixture(source);
    await assert.rejects(importBackupArchiveBytes(exported.bytes, environment(target).env, 'user-a', false), /requires a fresh instance/);
    assert.equal(target.sqlite.prepare('SELECT name FROM organizations').get()!.name, 'Existing');
    const restored = await importBackupArchiveBytes(exported.bytes, environment(target).env, 'user-a', true);
    assert.equal(restored.result.imported.organizations, 1);
    assert.equal(target.sqlite.prepare('SELECT id FROM organizations').get()!.id, 'org-a');
  } finally { source.close(); target.close(); }
});
