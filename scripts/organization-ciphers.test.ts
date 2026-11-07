import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { readFileSync } from 'node:fs';
import { SqliteD1 } from './helpers/sqlite-d1';
import { StorageService } from '../src/services/storage';
import { createAttachmentForUser } from '../src/services/storage-attachment-repo';
import type { Env } from '../src/types';
import { handleAuthenticatedRoute } from '../src/router-authenticated';

const editor = 'editor';
const reader = 'reader';
const owner = 'owner';
const org = 'org';
const sharedId = '00000000-0000-4000-8000-000000000101';
const personalId = '00000000-0000-4000-8000-000000000102';
const revision = '2026-11-01T00:00:00.000Z';
// These tests validate authorization/SQL contracts, not cryptographic decryption.
const encrypted = (label: string) => `2.aXY=|${Buffer.from(label).toString('base64')}|bWFj`;

async function fixture(ctx: TestContext) {
  const sqlite = new SqliteD1();
  sqlite.sqlite.exec(readFileSync(new URL('../migrations/0001_init.sql', import.meta.url), 'utf8'));
  ctx.after(async () => { await new Promise((resolve) => setImmediate(resolve)); sqlite.close(); });
  for (const id of [owner, editor, reader, 'outsider', 'pending']) {
    sqlite.sqlite.prepare(`INSERT INTO users(id,email,master_password_hash,key,kdf_type,kdf_iterations,security_stamp,created_at,updated_at)
      VALUES(?,?,'hash','key',0,600000,'stamp',?,?)`).run(id, `${id}@example.test`, revision, revision);
  }
  for (const organizationId of [org, 'other-org']) {
    sqlite.sqlite.prepare(`INSERT INTO organizations(id,name,billing_email,created_at,updated_at) VALUES(?,'Organization','billing@example.test',?,?)`)
      .run(organizationId, revision, revision);
  }
  for (const [id, type, status, accessAll] of [[owner, 0, 2, 1], [editor, 2, 2, 0], [reader, 2, 2, 0], ['pending', 2, 1, 1]] as const) {
    sqlite.sqlite.prepare(`INSERT INTO organization_members(id,organization_id,user_id,email,type,status,access_all,key,created_at,updated_at)
      VALUES(?,?,?,?,?,?,?,'wrapped-key',?,?)`).run(`member-${id}`, org, id, `${id}@example.test`, type, status, accessAll, revision, revision);
  }
  sqlite.sqlite.prepare(`INSERT INTO organization_members(id,organization_id,user_id,email,type,status,access_all,key,created_at,updated_at)
    VALUES('other-editor','other-org',?,'editor@example.test',2,2,1,'wrapped-key',?,?)`).run(editor, revision, revision);
  for (const [id, organizationId] of [['collection', org], ['collection-two', org], ['other-collection', 'other-org']] as const) {
    sqlite.sqlite.prepare('INSERT INTO collections(id,organization_id,name) VALUES(?,?,?)').run(id, organizationId, encrypted(id));
  }
  for (const collection of ['collection', 'collection-two']) {
    for (const [id, readOnly] of [[editor, 0], [reader, 1]] as const) {
      sqlite.sqlite.prepare('INSERT INTO collection_users(collection_id,member_id,read_only,hide_passwords,manage) VALUES(?,?,?,0,0)')
        .run(collection, `member-${id}`, readOnly);
    }
  }
  for (const id of [editor, reader, owner]) {
    sqlite.sqlite.prepare('INSERT INTO folders(id,user_id,name,created_at,updated_at) VALUES(?,?,?,?,?)')
      .run(`folder-${id}`, id, encrypted('folder'), revision, revision);
  }
  const data = { login: { username: encrypted('username'), password: encrypted('password') },
    futureEncryptedField: encrypted('future'), edit: true, permissions: { delete: true, restore: true } };
  sqlite.sqlite.prepare(`INSERT INTO ciphers(id,user_id,organization_id,type,name,notes,data,key,created_at,updated_at) VALUES(?,NULL,?,1,?,?,?,?,?,?)`)
    .run(sharedId, org, encrypted('Shared'), encrypted('Notes'), JSON.stringify(data), encrypted('item-key'), revision, revision);
  sqlite.sqlite.prepare('INSERT INTO cipher_collections(cipher_id,collection_id) VALUES(?,?)').run(sharedId, 'collection');
  const storage = new StorageService(sqlite.db);
  const base = {
    id: personalId, userId: editor, organizationId: null, type: 1,
    name: encrypted('Personal'), notes: encrypted('Notes'), folderId: `folder-${editor}`, favorite: false,
    reprompt: 0, key: encrypted('personal-item-key'), login: { username: encrypted('username'), password: encrypted('password') },
    futureEncryptedField: encrypted('future'), createdAt: revision, updatedAt: revision, archivedAt: null, deletedAt: null,
  };
  await storage.saveCipher(base);
  await storage.saveCipher({ ...base, id: 'other-personal', userId: owner, folderId: null });
  for (const parent of [personalId, sharedId, 'other-personal']) {
    sqlite.sqlite.prepare('INSERT INTO attachments(id,cipher_id,file_name,size,size_name,key) VALUES(?,?,?,4,?,?)')
      .run(`attachment-${parent}`, parent, encrypted('file'), '4 Bytes', encrypted('attachment-key'));
  }
  const deletedBlobs: string[] = [];
  const env = {
    DB: sqlite.db, JWT_SECRET: 'organization-cipher-test-secret-only',
    NOTIFICATIONS_HUB: { idFromName: (name: string) => name, get: () => ({ fetch: async () => new Response(null, { status: 204 }) }) },
    ATTACHMENTS: { delete: async (key: string) => {
      assert.equal(sqlite.sqlite.prepare('SELECT id FROM attachments WHERE id=?').get(key.split('/')[1]), undefined,
        'cipher metadata cascade must commit before blobs are removed');
      deletedBlobs.push(key);
    } },
  } as unknown as Env;
  ctx.mock.method(StorageService.prototype, 'createAuditLog', async () => {});
  ctx.mock.method(StorageService.prototype, 'getConfigValue', async () => null);
  ctx.mock.method(StorageService.prototype, 'pruneAuditLogs', async () => {});
  const route = async (path: string, method = 'GET', body?: unknown, actor = editor) => {
    const request = new Request(`https://vault.example.test${path}`, {
      method, ...(body === undefined ? {} : { body: JSON.stringify(body), headers: { 'Content-Type': 'application/json' } }),
    });
    const response = await handleAuthenticatedRoute(request, env, actor, { id: actor } as any, path, method);
    assert.ok(response, `${method} ${path} must route`);
    return response;
  };
  const share = (extra: Record<string, unknown> = {}) => ({ cipher: {
    ...base, organizationId: org, key: encrypted('organization-item-key'), name: encrypted('Shared personal'),
    lastKnownRevisionDate: revision, ...extra,
  }, collectionIds: ['collection'], lastKnownRevisionDate: revision });
  const revoke = () => sqlite.sqlite.prepare('UPDATE organization_members SET status=-1 WHERE user_id=? AND organization_id=?').run(editor, org);
  return { sqlite, storage, env, route, share, base, deletedBlobs, revoke };
}

test('organization create accepts wrapped aliases and returns authoritative scoped rights/collections', async (ctx) => {
  const f = await fixture(ctx);
  const response = await f.route('/api/ciphers', 'POST', { Cipher: {
    OrganizationId: org, Type: 1, Name: encrypted('Created'), Key: encrypted('org-item-key'), Login: { Password: null },
    UserId: owner, edit: false, viewPassword: false, permissions: { delete: false, restore: false },
  }, CollectionIds: ['collection'] });
  assert.equal(response.status, 200);
  const cipher = await response.json() as any;
  assert.equal(cipher.organizationId, org);
  assert.deepEqual(cipher.collectionIds, ['collection']);
  assert.equal(cipher.edit, true);
  assert.equal(cipher.viewPassword, true);
  assert.deepEqual(cipher.permissions, { delete: true, restore: true });
  assert.equal(cipher.UserId, undefined);
  assert.equal((await f.storage.getCipherForUser(cipher.id, reader))?.edit, false);
  assert.equal(f.sqlite.sqlite.prepare('SELECT user_id FROM ciphers WHERE id=?').get(cipher.id)!.user_id, null);
});

test('personal creation ignores spoofed server permissions and collections', async (ctx) => {
  const f = await fixture(ctx);
  const response = await f.route('/api/ciphers', 'POST', { ...f.base, organizationId: null,
    collectionIds: ['collection'], userId: owner, UserId: owner, edit: false, Edit: false,
    viewPassword: false, permissions: { delete: false, restore: false }, Permissions: { delete: false } });
  assert.equal(response.status, 200);
  const cipher = await response.json() as any;
  assert.equal(cipher.organizationId, null);
  assert.deepEqual(cipher.collectionIds, []);
  assert.equal(cipher.edit, true);
  assert.equal(cipher.viewPassword, true);
  assert.equal(cipher.Permissions, undefined);
  assert.equal((await f.storage.getCipherForUser(cipher.id, editor))?.userId, editor);
});

test('organization creation rejects readonly, nonmember, pending and foreign-collection destinations', async (ctx) => {
  const f = await fixture(ctx);
  const payload = { name: encrypted('Created'), type: 1, organizationId: org, collectionIds: ['collection'], key: encrypted('key') };
  for (const actor of [reader, 'outsider', 'pending']) assert.equal((await f.route('/api/ciphers', 'POST', payload, actor)).status, 403);
  assert.equal((await f.route('/api/ciphers', 'POST', { ...payload, collectionIds: ['other-collection'] })).status, 403);
});

test('readonly shared ciphers reject full CRUD/state changes but allow scoped reads', async (ctx) => {
  const f = await fixture(ctx);
  assert.equal((await f.route(`/api/ciphers/${sharedId}`, 'GET', undefined, reader)).status, 200);
  for (const [suffix, method, body] of [['', 'PUT', { name: encrypted('Denied') }], ['', 'DELETE', undefined],
    ['/delete', 'POST', undefined], ['/restore', 'PUT', undefined], ['/archive', 'PUT', undefined], ['/unarchive', 'PUT', undefined],
    ['/collections', 'PUT', { collectionIds: ['collection-two'] }]] as const) {
    assert.equal((await f.route(`/api/ciphers/${sharedId}${suffix}`, method, body, reader)).status, 403, suffix);
  }
  assert.equal((await f.storage.getCipherForUser(sharedId, editor))?.updatedAt, revision);
  assert.deepEqual(f.deletedBlobs, []);
});

test('full update cannot spoof ownership, collections or permission flags', async (ctx) => {
  const f = await fixture(ctx);
  assert.equal((await f.route(`/api/ciphers/${personalId}`, 'PUT', { organizationId: org, name: encrypted('Spoof') })).status, 400);
  assert.equal((await f.route(`/api/ciphers/${sharedId}`, 'PUT', { OrganizationId: null, name: encrypted('Unshare') })).status, 400);
  const response = await f.route(`/api/ciphers/${sharedId}`, 'PUT', { name: encrypted('Updated'), organizationId: org,
    collectionIds: ['other-collection'], edit: false, viewPassword: false, permissions: { delete: false, restore: false },
    UserId: owner, Permissions: { delete: false }, lastKnownRevisionDate: revision });
  assert.equal(response.status, 200);
  const cipher = await response.json() as any;
  assert.equal(cipher.organizationId, org);
  assert.deepEqual(cipher.collectionIds, ['collection']);
  assert.equal(cipher.edit, true);
  assert.equal(cipher.viewPassword, true);
  assert.equal(cipher.permissions.delete, true);
  assert.equal(cipher.UserId, undefined);
  assert.equal(cipher.Permissions, undefined);
});

test('partial organization updates change only acting-user preferences even for readonly members', async (ctx) => {
  const f = await fixture(ctx);
  const response = await f.route(`/api/ciphers/${sharedId}/partial`, 'PUT', { favorite: true, folderId: 'folder-reader',
    name: encrypted('Spoofed name'), organizationId: 'other-org', edit: true }, reader);
  assert.equal(response.status, 200);
  const mine = await f.storage.getCipherForUser(sharedId, reader);
  const others = await f.storage.getCipherForUser(sharedId, editor);
  assert.equal(mine?.favorite, true);
  assert.equal(mine?.folderId, 'folder-reader');
  assert.equal(others?.favorite, false);
  assert.equal(others?.folderId, null);
  assert.equal(mine?.name, encrypted('Shared'));
  assert.equal(mine?.updatedAt, revision, 'personal preferences do not alter shared cipher revision');
  assert.equal(mine?.edit, false);
  assert.equal((await f.route(`/api/ciphers/${sharedId}/partial`, 'PUT', { folderId: 'folder-editor' }, reader)).status, 404);
});

test('full update commits ciphertext and attachment metadata atomically, ignoring claimed blob sizes', async (ctx) => {
  const f = await fixture(ctx);
  const response = await f.route(`/api/ciphers/${sharedId}`, 'PUT', { name: encrypted('Updated'), lastKnownRevisionDate: revision,
    attachments2: { [`attachment-${sharedId}`]: { fileName: encrypted('Renamed'), key: encrypted('Rewrapped'), size: 999 } } });
  assert.equal(response.status, 200);
  const attachment = await f.storage.getAttachment(`attachment-${sharedId}`);
  assert.equal(attachment?.fileName, encrypted('Renamed'));
  assert.equal(attachment?.key, encrypted('Rewrapped'));
  assert.equal(attachment?.size, 4);
  const cipher = await response.json() as any;
  assert.equal(cipher.attachments[0].size, '4');
  const old = (await f.storage.getCipherForUser(sharedId, editor))!.updatedAt;
  f.sqlite.sqlite.exec("CREATE TRIGGER reject_metadata BEFORE UPDATE ON attachments BEGIN SELECT RAISE(ABORT, 'metadata failure'); END");
  await assert.rejects(f.route(`/api/ciphers/${sharedId}`, 'PUT', { name: encrypted('Rollback'), lastKnownRevisionDate: old,
    attachments2: { [`attachment-${sharedId}`]: { fileName: encrypted('Rollback') } } }), /metadata failure/);
  assert.equal((await f.storage.getCipherForUser(sharedId, editor))?.name, encrypted('Updated'));
});

test('membership revocation during CAS denies ciphertext, metadata and blobs', async (ctx) => {
  const f = await fixture(ctx);
  const batch = f.sqlite.batch.bind(f.sqlite);
  ctx.mock.method(f.sqlite, 'batch', async (statements: D1PreparedStatement[]) => { f.revoke(); return batch(statements); });
  const response = await f.route(`/api/ciphers/${sharedId}`, 'PUT', { name: encrypted('Revoked'), lastKnownRevisionDate: revision,
    attachments2: { [`attachment-${sharedId}`]: { fileName: encrypted('Revoked') } } });
  assert.equal(response.status, 400);
  assert.equal((await f.storage.getCipher(sharedId))?.name, encrypted('Shared'));
  assert.equal((await f.storage.getAttachment(`attachment-${sharedId}`))?.fileName, encrypted('file'));
  assert.deepEqual(f.deletedBlobs, []);
});

test('personal-to-organization share preserves ID/date and item-key attachment ciphertext', async (ctx) => {
  const f = await fixture(ctx);
  const response = await f.route(`/api/ciphers/${personalId}/share`, 'PUT', f.share());
  assert.equal(response.status, 200);
  const cipher = await response.json() as any;
  assert.equal(cipher.id, personalId);
  assert.equal(cipher.organizationId, org);
  assert.equal(cipher.key, encrypted('organization-item-key'));
  assert.equal(cipher.creationDate, revision);
  assert.deepEqual(cipher.collectionIds, ['collection']);
  assert.equal(cipher.futureEncryptedField, encrypted('future'));
  assert.equal((await f.storage.getAttachment(`attachment-${personalId}`))?.key, encrypted('attachment-key'));
  assert.equal((await f.storage.getCipherForUser(personalId, reader))?.userId, null);
  assert.equal((await f.route(`/api/ciphers/${personalId}/share`, 'PUT', f.share())).status, 400, 'cannot reshare or unshare an org item');
});

test('share accepts inner revision and rejects stale/missing revision, foreign IDs, incomplete keys and cleartext', async (ctx) => {
  const f = await fixture(ctx);
  const noRevision = f.share() as any;
  delete noRevision.lastKnownRevisionDate;
  delete noRevision.cipher.lastKnownRevisionDate;
  assert.equal((await f.route(`/api/ciphers/${personalId}/share`, 'PUT', noRevision)).status, 400);
  assert.equal((await f.route(`/api/ciphers/${personalId}/share`, 'PUT', { ...f.share(), lastKnownRevisionDate: '2020-01-01T00:00:00Z' })).status, 400);
  assert.equal((await f.route(`/api/ciphers/${personalId}/share`, 'PUT', f.share({ id: 'other-personal' }))).status, 400);
  assert.equal((await f.route(`/api/ciphers/${personalId}/share`, 'PUT', f.share({ key: null }))).status, 400);
  assert.equal((await f.route(`/api/ciphers/${personalId}/share`, 'PUT', f.share({ login: { password: 'cleartext' } }))).status, 400);
  const inner = f.share() as any;
  delete inner.lastKnownRevisionDate;
  assert.equal((await f.route(`/api/ciphers/${personalId}/share`, 'PUT', inner)).status, 200);
});

test('legacy no-item-key share requires rewrapped metadata for every original attachment', async (ctx) => {
  const f = await fixture(ctx);
  f.sqlite.sqlite.prepare('UPDATE ciphers SET key=NULL WHERE id=?').run(personalId);
  assert.equal((await f.route(`/api/ciphers/${personalId}/share`, 'PUT', f.share())).status, 400);
  assert.equal((await f.route(`/api/ciphers/${personalId}/share`, 'PUT', f.share({ attachments2: {
    [`attachment-${personalId}`]: { key: encrypted('new-key') },
  } }))).status, 400);
  const response = await f.route(`/api/ciphers/${personalId}/share`, 'PUT', f.share({ attachments2: {
    [`attachment-${personalId}`]: { key: encrypted('new-key'), fileName: encrypted('new-filename'), size: 999 },
  } }));
  assert.equal(response.status, 200);
  assert.equal((await f.storage.getAttachment(`attachment-${personalId}`))?.key, encrypted('new-key'));
  assert.equal((await f.storage.getAttachment(`attachment-${personalId}`))?.fileName, encrypted('new-filename'));
  assert.equal((await f.storage.getAttachment(`attachment-${personalId}`))?.size, 4);
});

test('concurrent attachment additions make sharing fail without ownership or key changes', async (ctx) => {
  const f = await fixture(ctx);
  f.sqlite.sqlite.prepare('UPDATE ciphers SET key=NULL WHERE id=?').run(personalId);
  const batch = f.sqlite.batch.bind(f.sqlite);
  ctx.mock.method(f.sqlite, 'batch', async (statements: D1PreparedStatement[]) => {
    f.sqlite.sqlite.prepare('INSERT INTO attachments(id,cipher_id,file_name,size,size_name,key) VALUES(?,?,?,4,?,?)')
      .run('racing-attachment', personalId, encrypted('new'), '4 Bytes', encrypted('new-key'));
    return batch(statements);
  });
  const response = await f.route(`/api/ciphers/${personalId}/share`, 'PUT', f.share({ attachments2: {
    [`attachment-${personalId}`]: { key: encrypted('rewrapped'), fileName: encrypted('rewrapped-file') },
  } }));
  assert.equal(response.status, 400);
  assert.equal((await f.storage.getCipherForUser(personalId, editor))?.organizationId, null);
  assert.equal((await f.storage.getAttachment(`attachment-${personalId}`))?.key, encrypted('attachment-key'));
});

test('collections reassignment validates same-org write access and current revision', async (ctx) => {
  const f = await fixture(ctx);
  assert.equal((await f.route(`/api/ciphers/${personalId}/collections`, 'PUT', { collectionIds: ['collection'] })).status, 400);
  assert.equal((await f.route(`/api/ciphers/${sharedId}/collections`, 'PUT', { collectionIds: ['other-collection'], lastKnownRevisionDate: revision })).status, 400);
  assert.equal((await f.route(`/api/ciphers/${sharedId}/collections`, 'PUT', { collectionIds: ['collection-two'], lastKnownRevisionDate: '2020-01-01' })).status, 400);
  const response = await f.route(`/api/ciphers/${sharedId}/collections`, 'PUT', { collectionIds: ['collection-two'], lastKnownRevisionDate: revision });
  assert.equal(response.status, 200);
  assert.deepEqual((await response.json() as any).collectionIds, ['collection-two']);
  assert.equal((await f.storage.getCipherForUser(sharedId, editor))?.organizationId, org);
});

test('bulk share returns actual shared list and rejects unsupported body shapes', async (ctx) => {
  const f = await fixture(ctx);
  assert.equal((await f.route('/api/ciphers/share', 'PUT', { ids: [personalId], collectionIds: ['collection'] })).status, 400);
  const response = await f.route('/api/ciphers/share', 'PUT', { ciphers: [f.share().cipher], collectionIds: ['collection'] });
  assert.equal(response.status, 200);
  const body = await response.json() as any;
  assert.equal(body.object, 'list');
  assert.deepEqual(body.data.map((cipher: any) => cipher.id), [personalId]);
  assert.equal(body.data[0].organizationId, org);
});

test('bulk share exposes earlier success and later stale failure so clients can retry only failed IDs', async (ctx) => {
  const f = await fixture(ctx);
  const secondId = '00000000-0000-4000-8000-000000000111';
  await f.storage.saveCipher({ ...f.base, id: secondId });
  const first = f.share().cipher;
  const stale = f.share({ id: secondId, lastKnownRevisionDate: '2020-01-01T00:00:00.000Z' }).cipher;
  const response = await f.route('/api/ciphers/share', 'PUT', { ciphers: [first, stale], collectionIds: ['collection'] });
  assert.equal(response.status, 207);
  const body = await response.json() as any;
  assert.equal(body.object, 'list');
  assert.equal(body.partial, true);
  assert.deepEqual(body.data.map((cipher: any) => cipher.id), [personalId]);
  assert.deepEqual(body.errors.map((error: any) => error.id), [secondId]);
  assert.equal(body.errors[0].index, 1);
  assert.equal(body.errors[0].status, 400);
  assert.match(body.errors[0].message, /out of date/);
  assert.equal((await f.storage.getCipherForUser(personalId, editor))?.organizationId, org);
  assert.equal((await f.storage.getCipherForUser(secondId, editor))?.organizationId, null);
  const retry = await f.route('/api/ciphers/share', 'PUT', {
    ciphers: body.errors.map((error: any) => f.share({ id: error.id }).cipher), collectionIds: ['collection'],
  });
  assert.equal(retry.status, 200);
  const retried = await retry.json() as any;
  assert.deepEqual(retried.data.map((cipher: any) => cipher.id), [secondId]);
  assert.equal(retried.errors, undefined, 'all-success retains the normal cipher-list contract');
});

test('bulk share reports an invalid per-item ID after a committed success instead of a plain error', async (ctx) => {
  const f = await fixture(ctx);
  const invalid = { ...f.share().cipher } as any;
  delete invalid.id;
  const response = await f.route('/api/ciphers/share', 'PUT', { ciphers: [f.share().cipher, invalid], collectionIds: ['collection'] });
  assert.equal(response.status, 207);
  const body = await response.json() as any;
  assert.deepEqual(body.data.map((cipher: any) => cipher.id), [personalId]);
  assert.deepEqual(body.errors, [{ id: null, index: 1, status: 400, message: 'Cipher ID is required' }]);
  assert.equal(body.partial, true);
});

test('state mutations use monotonic CAS and never resurrect a concurrently deleted cipher', async (ctx) => {
  const f = await fixture(ctx);
  const future = '2099-01-01T00:00:00.000Z';
  f.sqlite.sqlite.prepare('UPDATE ciphers SET updated_at=? WHERE id=?').run(future, sharedId);
  assert.equal((await f.route(`/api/ciphers/${sharedId}/archive`, 'PUT')).status, 200);
  assert.equal((await f.storage.getCipherForUser(sharedId, editor))?.updatedAt, '2099-01-01T00:00:00.001Z');
  const update = StorageService.prototype.updateCipherIfUnchanged;
  ctx.mock.method(StorageService.prototype, 'updateCipherIfUnchanged', async function (this: StorageService, cipher: any, expected: string, actor?: string, attachments: any[] = []) {
    f.sqlite.sqlite.prepare('DELETE FROM ciphers WHERE id=?').run(cipher.id);
    return update.call(this, cipher, expected, actor, attachments);
  });
  assert.equal((await f.route(`/api/ciphers/${sharedId}/restore`, 'PUT')).status, 400);
  assert.equal(await f.storage.getCipher(sharedId), null);
  assert.deepEqual(f.deletedBlobs, []);
});

test('permanent single and bulk deletion remove blobs only after authorized metadata deletion', async (ctx) => {
  const f = await fixture(ctx);
  assert.equal((await f.route(`/api/ciphers/${sharedId}/delete`, 'POST')).status, 204);
  assert.equal(await f.storage.getCipher(sharedId), null);
  assert.deepEqual(f.deletedBlobs, [`${sharedId}/attachment-${sharedId}`]);
  assert.equal((await f.route('/api/ciphers/delete-permanent', 'POST', { ids: [personalId, 'other-personal', personalId] })).status, 204);
  assert.equal(await f.storage.getCipher(personalId), null);
  assert.ok(await f.storage.getCipher('other-personal'));
  assert.deepEqual(f.deletedBlobs, [`${sharedId}/attachment-${sharedId}`, `${personalId}/attachment-${personalId}`]);
});

test('a new attachment after the deletion snapshot invalidates the expected cipher revision and preserves every blob', async (ctx) => {
  const f = await fixture(ctx);
  const list = StorageService.prototype.getAttachmentsByCipher;
  ctx.mock.method(StorageService.prototype, 'getAttachmentsByCipher', async function (this: StorageService, id: string) {
    const snapshot = await list.call(this, id);
    await createAttachmentForUser(f.sqlite.db, { id: 'new-upload', cipherId: id, fileName: encrypted('new-file'),
      key: encrypted('new-file-key'), size: 4, sizeName: '4 Bytes' }, editor);
    return snapshot;
  });
  assert.equal((await f.route(`/api/ciphers/${sharedId}/delete`, 'POST')).status, 404);
  assert.ok(await f.storage.getCipher(sharedId));
  assert.ok(await f.storage.getAttachment(`attachment-${sharedId}`));
  assert.ok(await f.storage.getAttachment('new-upload'));
  assert.deepEqual(f.deletedBlobs, []);
});

test('revocation immediately after an authorized CAS yields no stale scoped response', async (ctx) => {
  const f = await fixture(ctx);
  const update = StorageService.prototype.updateCipherIfUnchanged;
  ctx.mock.method(StorageService.prototype, 'updateCipherIfUnchanged', async function (this: StorageService, cipher: any, expected: string, actor?: string, attachments: any[] = []) {
    const changed = await update.call(this, cipher, expected, actor, attachments);
    f.revoke();
    return changed;
  });
  assert.equal((await f.route(`/api/ciphers/${sharedId}`, 'PUT', { name: encrypted('Authorized before revocation'), lastKnownRevisionDate: revision })).status, 404);
  assert.equal((await f.storage.getCipher(sharedId))?.name, encrypted('Authorized before revocation'));
});

test('revocation between permanent-delete snapshot and SQL leaves cipher and all blobs untouched', async (ctx) => {
  const f = await fixture(ctx);
  const remove = StorageService.prototype.deleteCipher;
  ctx.mock.method(StorageService.prototype, 'deleteCipher', async function (this: StorageService, id: string, actor: string) {
    f.revoke();
    return remove.call(this, id, actor);
  });
  assert.equal((await f.route(`/api/ciphers/${sharedId}/delete`, 'POST')).status, 404);
  assert.ok(await f.storage.getCipher(sharedId));
  assert.ok(await f.storage.getAttachment(`attachment-${sharedId}`));
  assert.deepEqual(f.deletedBlobs, []);
});
