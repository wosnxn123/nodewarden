import assert from 'node:assert/strict';
import test from 'node:test';
import { SqliteD1 } from './helpers/sqlite-d1';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { getUserById } from '../src/services/storage-user-repo';
import { AuthService } from '../src/services/auth';
import { createPasswordVerifier, verifyPasswordVerifier } from '../src/services/password-verifier';
import { handleChangeKdf, handlePurgeVault, handleDeleteAccount } from '../src/handlers/account-lifecycle';
import { handleAdminDeleteUser } from '../src/handlers/admin';
import { handleGetProfile, handleSetKeys, handleChangePassword } from '../src/handlers/accounts';
import { saveAccountKeysIfUnchanged } from '../src/services/account-key-update';
import { deleteOwnAccount, purgePersonalVault, changeAccountKdf } from '../src/services/account-lifecycle-repo';
import type { Env } from '../src/types';

const DATE = '2025-01-02T03:04:05.000Z';
const PROOF = 'current-client-proof';
const NEXT_PROOF = 'new-client-proof-after-kdf';
const enc = (byte: number) => `2.${btoa(String.fromCharCode(byte).repeat(16))}|${btoa(String.fromCharCode(byte).repeat(80))}|${btoa(String.fromCharCode(byte).repeat(32))}`;
const OLD_KEY = enc(1);
const NEW_KEY = enc(2);
const OPAQUE = '{"organizationId":"not-the-sql-owner","unknown":{"nested":[1,null,"x"]},"name":"2.encrypted"}';

async function fixture() {
  const adapter = new SqliteD1();
  await ensureStorageSchema(adapter.db);
  const sql = adapter.sqlite;
  const verifier = await createPasswordVerifier(PROOF);
  for (const id of ['user-a', 'user-b', 'admin']) {
    sql.prepare(`INSERT INTO users (id, email, master_password_hash, key, private_key, public_key, kdf_type, kdf_iterations, security_stamp, role, created_at, updated_at)
      VALUES (?, ?, ?, ?, '2.unchanged-private', 'unchanged-public', 0, 600000, ?, ?, ?, ?)`)
      .run(id, `${id}@example.test`, verifier, OLD_KEY, `stamp-${id}`, id === 'admin' ? 'admin' : 'user', DATE, DATE);
    AuthService.invalidateUserCache(id);
  }
  sql.prepare("INSERT INTO organizations VALUES ('org', 'Organization', 'billing@example.test', 'org-public', '2.org-private', ?, ?)").run(DATE, DATE);
  for (const id of ['user-a', 'user-b']) {
    sql.prepare('INSERT INTO organization_members VALUES (?, ?, ?, ?, 0, 2, 1, ?, NULL, ?, ?)')
      .run(`member-${id}`, 'org', id, `${id}@example.test`, `2.organization-key-${id}`, DATE, DATE);
  }
  sql.exec("INSERT INTO collections VALUES ('collection', 'org', '2.collection', NULL)");
  sql.exec("INSERT INTO organization_groups VALUES ('group', 'org', 'Group', 1, NULL)");
  sql.exec("INSERT INTO organization_group_members VALUES ('group', 'member-user-a'), ('group', 'member-user-b')");
  sql.exec("INSERT INTO collection_users VALUES ('collection', 'member-user-a', 0, 0, 1)");
  sql.exec("INSERT INTO collection_groups VALUES ('collection', 'group', 0, 0, 1)");
  sql.prepare("INSERT INTO folders VALUES ('folder-a', 'user-a', '2.folder', ?, ?)").run(DATE, DATE);
  for (const [id, userId, organizationId] of [['personal-a', 'user-a', null], ['personal-b', 'user-b', null], ['org-cipher', null, 'org']] as const) {
    sql.prepare('INSERT INTO ciphers (id, user_id, organization_id, type, folder_id, data, key, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?)')
      .run(id, userId, organizationId, id === 'personal-a' ? 'folder-a' : null, OPAQUE, `2.item-key-${id}`, DATE, DATE);
    sql.prepare('INSERT INTO attachments VALUES (?, ?, ?, 4, ?, ?)').run(`attachment-${id}`, id, '2.filename', '4 B', '2.attachment-key');
  }
  sql.exec("INSERT INTO cipher_collections VALUES ('org-cipher', 'collection')");
  sql.exec("INSERT INTO cipher_user_preferences VALUES ('org-cipher', 'user-a', 'folder-a', 1)");
  sql.prepare("INSERT INTO sends (id, user_id, type, name, data, key, created_at, updated_at, deletion_date) VALUES ('send-a', 'user-a', 1, '2.send', ?, '2.send-key', ?, ?, ?)")
    .run('{"id":"send-file-a","fileName":"2.file","unknown":true}', DATE, DATE, '2099-01-01T00:00:00.000Z');
  sql.prepare("INSERT INTO sends (id, user_id, type, name, data, key, created_at, updated_at, deletion_date) VALUES ('send-b', 'user-b', 1, '2.send', ?, '2.send-key', ?, ?, ?)")
    .run('{"id":"send-file-b"}', DATE, DATE, '2099-01-01T00:00:00.000Z');
  sql.exec("INSERT INTO refresh_tokens (token,user_id,expires_at,security_stamp) VALUES ('refresh-a','user-a',9999999999999,'stamp-user-a'), ('refresh-b','user-b',9999999999999,'stamp-user-b')");
  sql.exec("INSERT INTO trusted_two_factor_device_tokens VALUES ('trusted-a','user-a','device-a',9999999999999), ('trusted-b','user-b','device-b',9999999999999)");
  sql.prepare("INSERT INTO devices (user_id,device_identifier,name,type,session_stamp,created_at,updated_at) VALUES ('user-a','device-a','Device',14,'device-stamp',?,?)").run(DATE, DATE);
  sql.prepare("INSERT INTO auth_requests (id,user_id,type,request_device_identifier,request_device_type,access_code,public_key,creation_date) VALUES ('auth-a','user-a',0,'device-a',14,'code','public',?)").run(DATE);
  sql.exec("INSERT INTO webauthn_challenges VALUES ('challenge-a','login','user-a',9999999999999,NULL,1)");
  sql.prepare("INSERT INTO user_revisions VALUES ('user-a', ?)").run(DATE);

  const deleted: string[] = [];
  const notifications: Array<{ userId: string; updateType: number }> = [];
  const blobs = new Map<string, Uint8Array>([
    ['personal-a/attachment-personal-a', new Uint8Array([1])], ['personal-b/attachment-personal-b', new Uint8Array([2])],
    ['org-cipher/attachment-org-cipher', new Uint8Array([3])], ['sends/send-a/send-file-a', new Uint8Array([4])], ['sends/send-b/send-file-b', new Uint8Array([5])],
  ]);
  let failCleanup = false;
  const env = {
    DB: adapter.db, JWT_SECRET: 'long-test-jwt-secret-at-least-32-characters',
    NOTIFICATIONS_HUB: {
      idFromName(id: string) { return id; },
      get(id: string) { return { async fetch(_url: string, init: RequestInit) { notifications.push({ userId: id, updateType: JSON.parse(init.body as string).updateType }); return new Response(null, { status: 204 }); } }; },
    },
    ATTACHMENTS: { async delete(key: string) {
      // Every blob must be removed after its SQL metadata was deleted.
      if (key.startsWith('sends/')) assert.equal(sql.prepare("SELECT COUNT(*) AS n FROM sends WHERE id = 'send-a'").get()!.n, 0);
      else assert.equal(sql.prepare('SELECT COUNT(*) AS n FROM attachments WHERE cipher_id = ? AND id = ?').get(...key.split('/'))!.n, 0);
      deleted.push(key);
      if (failCleanup) throw new Error('mock blob outage');
      blobs.delete(key);
    } },
  } as unknown as Env;
  return { adapter, env, blobs, deleted, notifications, failCleanup() { failCleanup = true; } };
}

function request(path: string, body: unknown): Request {
  return new Request(`https://example.test${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
}
function snapshot(adapter: SqliteD1): unknown {
  return Object.fromEntries(['users','ciphers','folders','attachments','sends','organization_members','organizations','collections','cipher_collections','cipher_user_preferences','organization_groups','organization_group_members','collection_users','collection_groups','refresh_tokens','trusted_two_factor_device_tokens','devices','auth_requests','webauthn_challenges','user_revisions','audit_logs']
    .map((table) => [table, adapter.sqlite.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all()]));
}
const flatKdf = () => ({ masterPasswordHash: PROOF, newMasterPasswordHash: NEXT_PROOF, key: NEW_KEY, kdf: 1, kdfIterations: 3, kdfMemory: 64, kdfParallelism: 4 });
const modernKdf = () => ({ masterPasswordHash: PROOF,
  authenticationData: { salt: 'user-a@example.test', kdf: { kdfType: 0, iterations: 700000 }, masterPasswordAuthenticationHash: NEXT_PROOF },
  unlockData: { salt: 'user-a@example.test', kdf: { kdf: 0, kdfIterations: 700000 }, masterKeyWrappedUserKey: NEW_KEY } });

test('profile includes the public key required to create an organization', async () => {
  const f=await fixture();
  try {
    const response=await handleGetProfile(new Request('https://example.test/api/accounts/profile'),f.env,'user-a');
    assert.equal(response.status,200);
    assert.equal((await response.json() as {publicKey:string}).publicKey,'unchanged-public');
  } finally {f.adapter.close();}
});

test('ordinary key and password updates cannot replace an active organization member RSA identity', async () => {
  const f=await fixture();
  try {
    const before=snapshot(f.adapter);
    const keys=await handleSetKeys(request('/api/accounts/keys',{masterPasswordHash:PROOF,key:NEW_KEY,publicKey:'replacement-public',encryptedPrivateKey:enc(3)}),f.env,'user-a');
    assert.equal(keys.status,409);assert.deepEqual(snapshot(f.adapter),before);
    const password=await handleChangePassword(request('/api/accounts/password',{masterPasswordHash:PROOF,newMasterPasswordHash:NEXT_PROOF,key:NEW_KEY,newPublicKey:'replacement-public'}),f.env,'user-a');
    assert.equal(password.status,409);assert.deepEqual(snapshot(f.adapter),before);
    const allowed=await handleChangePassword(request('/api/accounts/password',{masterPasswordHash:PROOF,newMasterPasswordHash:NEXT_PROOF,key:NEW_KEY}),f.env,'user-a');
    assert.equal(allowed.status,200);
    const after=(await getUserById(f.env.DB,'user-a'))!;
    assert.equal(after.publicKey,'unchanged-public');assert.equal(after.key,NEW_KEY);
    assert.equal(f.adapter.sqlite.prepare("SELECT key FROM organization_members WHERE id='member-user-a'").get()!.key,'2.organization-key-user-a');
  } finally {f.adapter.close();}
});

test('key updates compare the original key state and account verifier in SQL', async () => {
  const f=await fixture();
  try {
    const before=(await getUserById(f.env.DB,'user-a'))!;
    f.adapter.sqlite.prepare("UPDATE users SET key='concurrent-rewrap' WHERE id='user-a'").run();
    assert.equal(await saveAccountKeysIfUnchanged(f.env.DB,before,{...before,key:NEW_KEY}),false);
    assert.equal((await getUserById(f.env.DB,'user-a'))!.key,'concurrent-rewrap');
  } finally {f.adapter.close();}
});

for (const modern of [false, true]) {
  test(`KDF ${modern ? 'modern paired' : 'legacy flat'} update verifies proof, stores salted verifier, rewraps only user key and revokes sessions`, async () => {
    const f = await fixture();
    try {
      const before = await getUserById(f.adapter.db, 'user-a');
      const auth = new AuthService(f.env);
      const access = await auth.generateAccessToken(before!);
      assert.ok(await auth.verifyAccessTokenWithUser(`Bearer ${access}`));
      const materialTables = ['ciphers','folders','attachments','sends','organizations','organization_members','collections','cipher_collections'];
      const material = materialTables.map((table) => f.adapter.sqlite.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all());
      const response = await handleChangeKdf(request('/api/accounts/kdf', modern ? modernKdf() : flatKdf()), f.env, 'user-a');
      assert.equal(response.status, 200);
      const after = await getUserById(f.adapter.db, 'user-a');
      assert.equal(after!.key, NEW_KEY);
      assert.notEqual(after!.securityStamp, before!.securityStamp);
      assert.match(after!.masterPasswordHash, /^\$s2\$100000\$/);
      assert.notEqual(after!.masterPasswordHash, NEXT_PROOF);
      assert.equal(await verifyPasswordVerifier(NEXT_PROOF, after!.masterPasswordHash, after!.email), true);
      assert.equal(await verifyPasswordVerifier(PROOF, after!.masterPasswordHash, after!.email), false);
      assert.equal(after!.kdfType, modern ? 0 : 1);
      assert.equal(after!.kdfIterations, modern ? 700000 : 3);
      assert.equal(after!.privateKey, before!.privateKey);
      assert.equal(after!.publicKey, before!.publicKey);
      assert.equal(after!.createdAt, before!.createdAt);
      for (const [i, table] of materialTables.entries()) assert.deepEqual(f.adapter.sqlite.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all(), material[i], table);
      for (const table of ['refresh_tokens','trusted_two_factor_device_tokens','auth_requests']) assert.equal(f.adapter.sqlite.prepare(`SELECT COUNT(*) AS n FROM ${table} WHERE user_id = 'user-a'`).get()!.n, 0);
      assert.equal(f.adapter.sqlite.prepare("SELECT COUNT(*) AS n FROM refresh_tokens WHERE user_id = 'user-b'").get()!.n, 1);
      assert.equal(await auth.verifyAccessTokenWithUser(`Bearer ${access}`), null);
      assert.ok(f.notifications.some((event) => event.userId === 'user-a' && event.updateType === 11));
      assert.deepEqual(f.deleted, []);
      const audit = f.adapter.sqlite.prepare("SELECT actor_user_id, action, metadata FROM audit_logs WHERE action = 'user.kdf.change'").get()!;
      assert.equal(audit.actor_user_id, 'user-a');
      assert.ok(!JSON.stringify(audit).includes(PROOF));
      assert.ok(!JSON.stringify(audit).includes(NEXT_PROOF));
      assert.ok(!JSON.stringify(audit).includes(NEW_KEY));
    } finally { f.adapter.close(); }
  });
}

test('wrong password proof cannot change KDF, purge a vault, or delete an account', async () => {
  const f = await fixture();
  try {
    const before = snapshot(f.adapter);
    for (const handler of [handleChangeKdf, handlePurgeVault, handleDeleteAccount]) {
      const response = await handler(request('/api/accounts/action', { ...flatKdf(), masterPasswordHash: 'wrong-proof' }), f.env, 'user-a');
      assert.equal(response.status, 400);
      assert.deepEqual(snapshot(f.adapter), before);
      assert.deepEqual(f.deleted, []);
      assert.deepEqual(f.notifications, []);
    }
  } finally { f.adapter.close(); }
});

test('KDF malformed, omitted, noninteger, unsupported and out-of-bounds parameters fail without mutation', async () => {
  const f = await fixture();
  try {
    const before = snapshot(f.adapter);
    const variants = [
      { kdf: 2 }, { kdf: 1.5 }, { kdfIterations: 0 }, { kdfIterations: 1.5 }, { kdfIterations: null }, { kdfMemory: 14 },
      { kdfMemory: 1025 }, { kdfMemory: '64' }, { kdfParallelism: 0 }, { kdfParallelism: 17 }, { key: '2.bad|bad|bad' },
      { newMasterPasswordHash: '' }, { kdf: 0, kdfIterations: 99999, kdfMemory: null, kdfParallelism: null },
      { authenticationData: {}, unlockData: null },
    ];
    for (const patch of variants) {
      assert.equal((await handleChangeKdf(request('/api/accounts/kdf', { ...flatKdf(), ...patch }), f.env, 'user-a')).status, 400, JSON.stringify(patch));
      assert.deepEqual(snapshot(f.adapter), before);
    }
    for (const mutate of [
      (body: ReturnType<typeof modernKdf>) => { body.unlockData.kdf.kdfIterations = 800000; },
      (body: ReturnType<typeof modernKdf>) => { body.unlockData.salt = 'other@example.test'; },
    ]) {
      const body = modernKdf(); mutate(body);
      assert.equal((await handleChangeKdf(request('/api/accounts/kdf', body), f.env, 'user-a')).status, 400);
      assert.deepEqual(snapshot(f.adapter), before);
    }
  } finally { f.adapter.close(); }
});

test('personal purge deletes SQL first, leaves organization ownership, memberships, Sends and keys intact', async () => {
  const f = await fixture();
  try {
    const user = await getUserById(f.adapter.db, 'user-a');
    const orgCipher = f.adapter.sqlite.prepare("SELECT * FROM ciphers WHERE id = 'org-cipher'").get();
    const memberships = f.adapter.sqlite.prepare('SELECT * FROM organization_members ORDER BY id').all();
    assert.equal((await handlePurgeVault(request('/api/ciphers/purge', { masterPasswordHash: PROOF }), f.env, 'user-a')).status, 200);
    assert.equal(f.adapter.sqlite.prepare("SELECT COUNT(*) AS n FROM ciphers WHERE id = 'personal-a'").get()!.n, 0);
    assert.equal(f.adapter.sqlite.prepare("SELECT COUNT(*) AS n FROM folders WHERE user_id = 'user-a'").get()!.n, 0);
    assert.deepEqual(f.adapter.sqlite.prepare("SELECT * FROM ciphers WHERE id = 'org-cipher'").get(), orgCipher);
    assert.deepEqual(f.adapter.sqlite.prepare('SELECT * FROM organization_members ORDER BY id').all(), memberships);
    assert.equal(f.adapter.sqlite.prepare("SELECT COUNT(*) AS n FROM sends WHERE user_id = 'user-a'").get()!.n, 1);
    assert.equal((await getUserById(f.adapter.db, 'user-a'))!.key, user!.key);
    assert.equal((await getUserById(f.adapter.db, 'user-a'))!.securityStamp, user!.securityStamp);
    assert.equal(f.adapter.sqlite.prepare("SELECT folder_id FROM cipher_user_preferences WHERE cipher_id = 'org-cipher'").get()!.folder_id, null);
    assert.equal(f.adapter.sqlite.prepare("SELECT favorite FROM cipher_user_preferences WHERE cipher_id = 'org-cipher'").get()!.favorite, 1);
    assert.deepEqual(f.deleted, ['personal-a/attachment-personal-a']);
    assert.ok(f.blobs.has('org-cipher/attachment-org-cipher'));
    assert.ok(f.blobs.has('sends/send-a/send-file-a'));
    assert.ok(f.notifications.some((event) => event.updateType === 5));
    assert.deepEqual(f.adapter.sqlite.prepare('PRAGMA foreign_key_check').all(), []);
  } finally { f.adapter.close(); }
});

test('account deletion removes own cascaded assets and sessions, preserves organization and other-user blobs', async () => {
  const f = await fixture();
  try {
    assert.equal((await handleDeleteAccount(request('/api/accounts/delete', { masterPasswordHash: PROOF }), f.env, 'user-a')).status, 200);
    assert.equal(await getUserById(f.adapter.db, 'user-a'), null);
    for (const table of ['ciphers','folders','sends','refresh_tokens','trusted_two_factor_device_tokens','devices','auth_requests','webauthn_challenges','organization_members']) {
      assert.equal(f.adapter.sqlite.prepare(`SELECT COUNT(*) AS n FROM ${table} WHERE user_id = 'user-a'`).get()!.n, 0, table);
    }
    assert.equal(f.adapter.sqlite.prepare("SELECT organization_id FROM ciphers WHERE id = 'org-cipher'").get()!.organization_id, 'org');
    assert.equal(f.adapter.sqlite.prepare("SELECT key FROM organization_members WHERE user_id = 'user-b'").get()!.key, '2.organization-key-user-b');
    assert.ok(f.blobs.has('org-cipher/attachment-org-cipher'));
    assert.ok(f.blobs.has('personal-b/attachment-personal-b'));
    assert.ok(f.blobs.has('sends/send-b/send-file-b'));
    assert.deepEqual(f.deleted.sort(), ['personal-a/attachment-personal-a', 'sends/send-a/send-file-a']);
    assert.ok(f.notifications.some((event) => event.userId === 'user-a' && event.updateType === 11));
    const audit = f.adapter.sqlite.prepare("SELECT actor_user_id, target_id FROM audit_logs WHERE action = 'user.account.delete'").get()!;
    assert.equal(audit.actor_user_id, null);
    assert.equal(audit.target_id, 'user-a');
    assert.deepEqual(f.adapter.sqlite.prepare('PRAGMA foreign_key_check').all(), []);
  } finally { f.adapter.close(); }
});

test('delete refuses final confirmed owner, ignoring revoked or invited owner memberships', async () => {
  const f = await fixture();
  try {
    for (const status of [-1, 0, 1]) {
      f.adapter.sqlite.prepare("UPDATE organization_members SET status = ? WHERE user_id = 'user-b'").run(status);
      const before = snapshot(f.adapter);
      const response = await handleDeleteAccount(request('/api/accounts/delete', { masterPasswordHash: PROOF }), f.env, 'user-a');
      assert.equal(response.status, 409);
      assert.match(await response.text(), /last confirmed organization owner/);
      assert.deepEqual(snapshot(f.adapter), before);
      assert.deepEqual(f.deleted, []);
    }
  } finally { f.adapter.close(); }
});

test('concurrent final-owner deletion predicates serialize so one confirmed owner remains', async () => {
  const f = await fixture();
  try {
    const a = await getUserById(f.adapter.db, 'user-a');
    const b = await getUserById(f.adapter.db, 'user-b');
    const results = await Promise.all([deleteOwnAccount(f.adapter.db, a!), deleteOwnAccount(f.adapter.db, b!)]);
    assert.equal(results.filter((result) => result.changed).length, 1);
    assert.equal(results.find((result) => !result.changed)!.reason, 'last-owner');
    assert.equal(f.adapter.sqlite.prepare("SELECT COUNT(*) AS n FROM organization_members WHERE type = 0 AND status = 2").get()!.n, 1);
    assert.equal(f.adapter.sqlite.prepare("SELECT COUNT(*) AS n FROM ciphers WHERE organization_id = 'org'").get()!.n, 1);
    assert.deepEqual(f.adapter.sqlite.prepare('PRAGMA foreign_key_check').all(), []);
  } finally { f.adapter.close(); }
});

test('last active global admin cannot leave remaining accounts unmanaged; ordinary self delete allowed', async () => {
  const f = await fixture();
  try {
    const before = snapshot(f.adapter);
    const response = await handleDeleteAccount(request('/api/accounts/delete', { masterPasswordHash: PROOF }), f.env, 'admin');
    assert.equal(response.status, 409);
    assert.match(await response.text(), /last active administrator/);
    assert.deepEqual(snapshot(f.adapter), before);
    f.adapter.sqlite.exec("UPDATE users SET role = 'admin' WHERE id = 'user-b'");
    assert.equal((await handleDeleteAccount(request('/api/accounts/delete', { masterPasswordHash: PROOF }), f.env, 'admin')).status, 200);
  } finally { f.adapter.close(); }
});

test('proof CAS guards all lifecycle mutations against a credential change after verification', async () => {
  const f = await fixture();
  try {
    const stale = await getUserById(f.adapter.db, 'user-a');
    f.adapter.sqlite.exec("UPDATE users SET security_stamp = 'concurrent-new-stamp' WHERE id = 'user-a'");
    const before = snapshot(f.adapter);
    assert.equal((await purgePersonalVault(f.adapter.db, stale!, new Date().toISOString())).changed, false);
    assert.equal((await deleteOwnAccount(f.adapter.db, stale!)).changed, false);
    assert.equal(await changeAccountKdf(f.adapter.db, stale!, { verifier: 'new-verifier', key: NEW_KEY, type: 0, iterations: 700000, memory: null, parallelism: null, securityStamp: 'fresh-new-stamp', revisionDate: new Date().toISOString() }), false);
    assert.deepEqual(snapshot(f.adapter), before);
  } finally { f.adapter.close(); }
});

test('transaction failure rolls back lifecycle deletions before any external blob cleanup', async () => {
  const f = await fixture();
  const original = f.adapter.batch.bind(f.adapter);
  try {
    const before = snapshot(f.adapter);
    f.adapter.batch = async (statements) => original([...statements, f.adapter.prepare('INSERT INTO config (key,value) VALUES (NULL,NULL)')]);
    for (const handler of [handlePurgeVault, handleDeleteAccount, handleChangeKdf]) {
      await assert.rejects(handler(request('/api/accounts/action', flatKdf()), f.env, 'user-a'));
      assert.deepEqual(snapshot(f.adapter), before);
      assert.deepEqual(f.deleted, []);
      assert.deepEqual(f.notifications, []);
    }
  } finally { f.adapter.close(); }
});

test('admin deletion of an ordinary member preserves shared organization attachments and other users', async () => {
  const f = await fixture();
  try {
    f.adapter.sqlite.exec("UPDATE organization_members SET type = 2 WHERE user_id = 'user-a'");
    const actor = await getUserById(f.adapter.db, 'admin');
    const orgCipher = f.adapter.sqlite.prepare("SELECT * FROM ciphers WHERE id = 'org-cipher'").get();
    const orgAttachment = f.adapter.sqlite.prepare("SELECT * FROM attachments WHERE cipher_id = 'org-cipher'").get();
    const otherUser = await getUserById(f.adapter.db, 'user-b');
    const response = await handleAdminDeleteUser(request('/api/admin/users/user-a', { masterPasswordHash: PROOF }), f.env, actor!, 'user-a');
    assert.equal(response.status, 204, await response.text());
    assert.equal(await getUserById(f.adapter.db, 'user-a'), null);
    assert.deepEqual(f.adapter.sqlite.prepare("SELECT * FROM ciphers WHERE id = 'org-cipher'").get(), orgCipher);
    assert.deepEqual(f.adapter.sqlite.prepare("SELECT * FROM attachments WHERE cipher_id = 'org-cipher'").get(), orgAttachment);
    assert.deepEqual(await getUserById(f.adapter.db, 'user-b'), otherUser);
    assert.equal(f.adapter.sqlite.prepare("SELECT COUNT(*) AS n FROM organization_members WHERE user_id = 'user-b'").get()!.n, 1);
    assert.ok(f.blobs.has('org-cipher/attachment-org-cipher'));
    assert.ok(f.blobs.has('personal-b/attachment-personal-b'));
    assert.ok(f.blobs.has('sends/send-b/send-file-b'));
    assert.deepEqual(f.deleted.sort(), ['personal-a/attachment-personal-a', 'sends/send-a/send-file-a']);
    assert.deepEqual(f.adapter.sqlite.prepare('PRAGMA foreign_key_check').all(), []);
  } finally { f.adapter.close(); }
});

test('admin deletion refuses the final confirmed organization owner without metadata or blob changes', async () => {
  const f = await fixture();
  try {
    f.adapter.sqlite.exec("UPDATE organization_members SET type = 2 WHERE user_id = 'user-b'");
    const actor = await getUserById(f.adapter.db, 'admin');
    const before = snapshot(f.adapter);
    const response = await handleAdminDeleteUser(request('/api/admin/users/user-a', { masterPasswordHash: PROOF }), f.env, actor!, 'user-a');
    assert.equal(response.status, 400);
    assert.match(await response.text(), /last organization owner/);
    assert.deepEqual(snapshot(f.adapter), before);
    assert.deepEqual(f.deleted, []);
  } finally { f.adapter.close(); }
});

test('lifecycle proof always reads the current user even when an access-token user is cached', async () => {
  const f = await fixture();
  try {
    const user = await getUserById(f.adapter.db, 'user-a');
    const auth = new AuthService(f.env);
    const token = await auth.generateAccessToken(user!);
    assert.ok(await auth.verifyAccessTokenWithUser(`Bearer ${token}`));
    const replacement = await createPasswordVerifier(NEXT_PROOF);
    f.adapter.sqlite.prepare("UPDATE users SET master_password_hash = ?, security_stamp = 'fresh-stamp' WHERE id = 'user-a'").run(replacement);
    const before = snapshot(f.adapter);
    for (const handler of [handleChangeKdf, handlePurgeVault, handleDeleteAccount]) {
      assert.equal((await handler(request('/api/accounts/action', flatKdf()), f.env, 'user-a')).status, 400);
      assert.deepEqual(snapshot(f.adapter), before);
    }
    assert.deepEqual(f.deleted, []);
  } finally { f.adapter.close(); }
});

test('handler-level credential races return conflict and never clean up blobs or send notifications', async () => {
  for (const handler of [handleChangeKdf, handlePurgeVault, handleDeleteAccount]) {
    for (const column of ['master_password_hash', 'security_stamp']) {
      const f = await fixture();
      try {
        const original = f.adapter.batch.bind(f.adapter);
        let before: unknown;
        f.adapter.batch = async (statements) => {
          f.adapter.sqlite.prepare(`UPDATE users SET ${column} = ? WHERE id = 'user-a'`).run('concurrently-replaced');
          before = snapshot(f.adapter);
          return original(statements);
        };
        assert.equal((await handler(request('/api/accounts/action', flatKdf()), f.env, 'user-a')).status, 409);
        assert.deepEqual(snapshot(f.adapter), before);
        assert.deepEqual(f.deleted, []);
        assert.deepEqual(f.notifications, []);
      } finally { f.adapter.close(); }
    }
  }
});

test('missing or inactive users and omitted proof cannot mutate account lifecycle state', async () => {
  const f = await fixture();
  try {
    for (const handler of [handleChangeKdf, handlePurgeVault, handleDeleteAccount]) {
      const before = snapshot(f.adapter);
      assert.equal((await handler(request('/api/accounts/action', {}), f.env, 'user-a')).status, 400);
      assert.equal((await handler(request('/api/accounts/action', flatKdf()), f.env, 'missing-user')).status, 401);
      assert.deepEqual(snapshot(f.adapter), before);
    }
    f.adapter.sqlite.exec("UPDATE users SET status = 'banned' WHERE id = 'user-a'");
    const before = snapshot(f.adapter);
    for (const handler of [handleChangeKdf, handlePurgeVault, handleDeleteAccount]) {
      assert.equal((await handler(request('/api/accounts/action', flatKdf()), f.env, 'user-a')).status, 401);
      assert.deepEqual(snapshot(f.adapter), before);
    }
    assert.deepEqual(f.deleted, []);
  } finally { f.adapter.close(); }
});

test('ordinary members may self-delete and inactive administrators do not satisfy final active-admin protection', async () => {
  const f = await fixture();
  try {
    f.adapter.sqlite.exec("UPDATE organization_members SET type = 2 WHERE user_id = 'user-a'");
    f.adapter.sqlite.exec("UPDATE users SET role = 'admin', status = 'banned' WHERE id = 'user-b'");
    const before = snapshot(f.adapter);
    assert.equal((await handleDeleteAccount(request('/api/accounts/delete', { masterPasswordHash: PROOF }), f.env, 'admin')).status, 409);
    assert.deepEqual(snapshot(f.adapter), before);
    assert.equal((await handleDeleteAccount(request('/api/accounts/delete', { masterPasswordHash: PROOF }), f.env, 'user-a')).status, 200);
    assert.ok(f.blobs.has('org-cipher/attachment-org-cipher'));
    assert.equal(f.adapter.sqlite.prepare("SELECT COUNT(*) AS n FROM organization_members WHERE user_id = 'user-b'").get()!.n, 1);
  } finally { f.adapter.close(); }
});

test('concurrent administrator self-deletions leave an active instance administrator while ordinary users remain', async () => {
  const f = await fixture();
  try {
    f.adapter.sqlite.exec("UPDATE users SET role = 'admin' WHERE id = 'user-a'");
    const a = await getUserById(f.adapter.db, 'user-a');
    const admin = await getUserById(f.adapter.db, 'admin');
    const results = await Promise.all([deleteOwnAccount(f.adapter.db, a!), deleteOwnAccount(f.adapter.db, admin!)]);
    assert.equal(results.filter((result) => result.changed).length, 1);
    assert.equal(results.find((result) => !result.changed)!.reason, 'last-admin');
    assert.equal(f.adapter.sqlite.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND status = 'active'").get()!.n, 1);
    assert.ok(await getUserById(f.adapter.db, 'user-b'));
  } finally { f.adapter.close(); }
});

test('sole remaining instance administrator may delete their otherwise empty instance account', async () => {
  const f = await fixture();
  try {
    f.adapter.sqlite.exec("DELETE FROM users WHERE id <> 'admin'");
    assert.equal((await handleDeleteAccount(request('/api/accounts/delete', { masterPasswordHash: PROOF }), f.env, 'admin')).status, 200);
    assert.equal(f.adapter.sqlite.prepare('SELECT COUNT(*) AS n FROM users').get()!.n, 0);
    assert.ok(f.blobs.has('org-cipher/attachment-org-cipher'));
  } finally { f.adapter.close(); }
});

test('blob cleanup failures leave committed data removal intact and never delete organization blobs', async () => {
  const f = await fixture();
  try {
    f.failCleanup();
    assert.equal((await handlePurgeVault(request('/api/ciphers/purge', { masterPasswordHash: PROOF }), f.env, 'user-a')).status, 200);
    assert.equal(f.adapter.sqlite.prepare("SELECT COUNT(*) AS n FROM ciphers WHERE user_id = 'user-a'").get()!.n, 0);
    assert.ok(f.blobs.has('org-cipher/attachment-org-cipher'));
    assert.deepEqual(f.deleted, ['personal-a/attachment-personal-a']);
  } finally { f.adapter.close(); }
});
