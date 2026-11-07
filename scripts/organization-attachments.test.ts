import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { readFileSync } from 'node:fs';
import { SqliteD1 } from './helpers/sqlite-d1';
import type { Attachment, Env } from '../src/types';
import { StorageService } from '../src/services/storage';
import { sharePersonalCipher } from '../src/services/cipher-sharing';
import {
  addAttachmentToCipherForUser,
  createAttachmentForUser,
  deleteAttachmentForUser,
  getAttachment,
  getAttachmentForUser,
  getAttachmentsByUserId,
  saveAttachment,
  updateAttachmentForUser,
  updateCipherRevisionDate,
} from '../src/services/storage-attachment-repo';
import { consumeAttachmentDownloadToken } from '../src/services/storage-attachment-token-repo';
import {
  deleteAttachmentBlobs,
  handleCreateAttachment,
  handleDeleteAttachment,
  handleGetAttachment,
  handlePublicDownloadAttachment,
  handlePublicUploadAttachment,
  handleUpdateAttachmentMetadata,
  handleUploadAttachment,
} from '../src/handlers/attachments';
import { createAttachmentUploadToken, createFileDownloadToken, verifyFileDownloadToken } from '../src/utils/jwt';

const secret = 'organization-attachment-test-secret-only';
const date = '2026-11-01T00:00:00.000Z';
const owner = 'owner';
const editor = 'editor';
const reader = 'reader';
const outsider = 'outsider';
const organizationId = 'org';
const cipherId = 'shared-cipher';
const attachmentId = 'shared-attachment';
const safeBind = (statement: D1PreparedStatement, ...values: unknown[]) => statement.bind(...values);

function fixture(ctx: TestContext) {
  const sqlite = new SqliteD1();
  sqlite.sqlite.exec(readFileSync(new URL('../migrations/0001_init.sql', import.meta.url), 'utf8'));
  ctx.after(async () => { await new Promise((resolve) => setImmediate(resolve)); sqlite.close(); });
  for (const id of [owner, editor, reader, outsider, 'pending', 'revoked', 'group-reader']) {
    sqlite.sqlite.prepare(`INSERT INTO users(id,email,master_password_hash,key,kdf_type,kdf_iterations,security_stamp,created_at,updated_at)
      VALUES(?,?, 'hash','key',0,600000,'stamp',?,?)`).run(id, `${id}@example.test`, date, date);
  }
  sqlite.sqlite.prepare(`INSERT INTO organizations(id,name,billing_email,created_at,updated_at) VALUES(?, 'Organization','billing@example.test',?,?)`)
    .run(organizationId, date, date);
  for (const [id, type, status, accessAll] of [[owner, 0, 2, 1], [editor, 2, 2, 0], [reader, 2, 2, 0],
    ['pending', 2, 1, 1], ['revoked', 2, -1, 1], ['group-reader', 2, 2, 0]] as const) {
    sqlite.sqlite.prepare(`INSERT INTO organization_members(id,organization_id,user_id,email,type,status,access_all,key,created_at,updated_at)
      VALUES(?,?,?,?,?,?,?,'wrapped-key',?,?)`).run(`member-${id}`, organizationId, id, `${id}@example.test`, type, status, accessAll, date, date);
  }
  sqlite.sqlite.prepare('INSERT INTO collections(id,organization_id,name) VALUES(?,?,?)').run('collection', organizationId, 'Encrypted collection');
  for (const [id, readOnly] of [[editor, 0], [reader, 1]] as const) {
    sqlite.sqlite.prepare('INSERT INTO collection_users(collection_id,member_id,read_only,hide_passwords,manage) VALUES(?,?,?,0,0)')
      .run('collection', `member-${id}`, readOnly);
  }
  sqlite.sqlite.prepare('INSERT INTO organization_groups(id,organization_id,name) VALUES(?,?,?)').run('group', organizationId, 'Encrypted group');
  sqlite.sqlite.prepare('INSERT INTO organization_group_members(group_id,member_id) VALUES(?,?)').run('group', 'member-group-reader');
  sqlite.sqlite.prepare('INSERT INTO collection_groups(collection_id,group_id,read_only,hide_passwords,manage) VALUES(?,?,1,0,0)').run('collection', 'group');
  for (const [id, userId, orgId] of [[cipherId, null, organizationId], ['personal-cipher', owner, null], ['other-personal', outsider, null]] as const) {
    sqlite.sqlite.prepare(`INSERT INTO ciphers(id,user_id,organization_id,type,data,created_at,updated_at) VALUES(?,?,?,1,'{}',?,?)`)
      .run(id, userId, orgId, date, date);
  }
  sqlite.sqlite.prepare('INSERT INTO cipher_collections(cipher_id,collection_id) VALUES(?,?)').run(cipherId, 'collection');
  for (const [id, parent] of [[attachmentId, cipherId], ['personal-attachment', 'personal-cipher'], ['other-attachment', 'other-personal']] as const) {
    sqlite.sqlite.prepare(`INSERT INTO attachments(id,cipher_id,file_name,size,size_name,key) VALUES(?,?,'Encrypted filename',4,'4 Bytes','Encrypted key')`)
      .run(id, parent);
  }
  const blobReads: string[] = [];
  const blobWrites: string[] = [];
  const blobDeletes: string[] = [];
  const env = {
    DB: sqlite.db,
    JWT_SECRET: secret,
    NOTIFICATIONS_HUB: {
      idFromName: (name: string) => name,
      get: () => ({ fetch: async () => new Response(null, { status: 204 }) }),
    },
    ATTACHMENTS: {
      get: async (key: string) => {
        blobReads.push(key);
        return { body: new Response('data').body, size: 4, httpMetadata: { contentType: 'application/octet-stream' } };
      },
      put: async (key: string) => { blobWrites.push(key); },
      delete: async (key: string) => {
        assert.equal(sqlite.sqlite.prepare('SELECT id FROM attachments WHERE id = ?').get(key.split('/')[1]), undefined,
          'blob deletion must follow committed metadata deletion');
        blobDeletes.push(key);
      },
    },
  } as unknown as Env;
  ctx.mock.method(StorageService.prototype, 'createAuditLog', async () => {});
  ctx.mock.method(StorageService.prototype, 'getConfigValue', async () => null);
  ctx.mock.method(StorageService.prototype, 'pruneAuditLogs', async () => {});
  const attachment: Attachment = { id: attachmentId, cipherId, fileName: 'Encrypted filename', size: 4, sizeName: '4 Bytes', key: 'Encrypted key' };
  const revoke = (userId = editor) => sqlite.sqlite.prepare('UPDATE organization_members SET status = -1 WHERE user_id = ?').run(userId);
  const request = (method = 'GET', body?: unknown) => new Request(`https://vault.example.test/api/ciphers/${cipherId}/attachment/${attachmentId}`, {
    method,
    ...(body === undefined ? {} : { body: JSON.stringify(body), headers: { 'Content-Type': 'application/json' } }),
  });
  const download = (token: string, parent = cipherId, id = attachmentId) => handlePublicDownloadAttachment(
    new Request(`https://vault.example.test/api/attachments/${parent}/${id}?token=${token}`), env, parent, id);
  return { sqlite, env, attachment, revoke, request, download, blobReads, blobWrites, blobDeletes };
}

test('attachment reads and bulk sync include confirmed organization collection/group readers only', async (ctx) => {
  const f = fixture(ctx);
  for (const actor of [owner, editor, reader, 'group-reader']) {
    assert.equal((await getAttachmentForUser(f.sqlite.db, attachmentId, actor))?.id, attachmentId);
  }
  for (const actor of [outsider, 'pending', 'revoked']) {
    assert.equal(await getAttachmentForUser(f.sqlite.db, attachmentId, actor), null);
  }
  assert.deepEqual([...await getAttachmentsByUserId(f.sqlite.db, owner)].map(([id]) => id).sort(), ['personal-cipher', cipherId].sort());
  assert.deepEqual([...await getAttachmentsByUserId(f.sqlite.db, reader)].map(([id]) => id), [cipherId]);
  assert.equal(await getAttachmentForUser(f.sqlite.db, 'other-attachment', owner), null);
});

test('create/update require writes and atomically fan out organization revisions and events', async (ctx) => {
  const f = fixture(ctx);
  const added = { ...f.attachment, id: 'new-attachment' };
  assert.equal(await createAttachmentForUser(f.sqlite.db, added, reader), false);
  assert.equal(await createAttachmentForUser(f.sqlite.db, added, editor), true);
  assert.equal(await createAttachmentForUser(f.sqlite.db, added, editor), false, 'IDs cannot overwrite existing records');
  assert.equal(await updateAttachmentForUser(f.sqlite.db, { ...added, fileName: 'Reader edit' }, reader, added), false);
  assert.equal(await updateAttachmentForUser(f.sqlite.db, { ...added, fileName: 'Editor edit', key: null }, editor, added), true);
  assert.equal((await getAttachment(f.sqlite.db, added.id))?.key, null);
  assert.equal(await updateAttachmentForUser(f.sqlite.db, { ...added, cipherId: 'personal-cipher' }, owner, added), false, 'metadata update cannot move records');
  assert.equal(f.sqlite.sqlite.prepare('SELECT COUNT(*) AS count FROM organization_events').get()!.count, 2);
  const recipients = f.sqlite.sqlite.prepare('SELECT user_id FROM user_revisions ORDER BY user_id').all().map((row) => row.user_id);
  // Organization mutation outbox also snapshots non-confirmed recipients so a
  // membership revocation can invalidate their previously cached vault state.
  assert.deepEqual(recipients, [editor, 'group-reader', owner, 'pending', reader, 'revoked'].sort());
  const outboxes = f.sqlite.sqlite.prepare("SELECT value FROM config WHERE key LIKE 'organization.sync.%'").all();
  assert.equal(outboxes.length, 2);
  assert.ok(outboxes.every((row) => JSON.parse(String(row.value)).organizationId === organizationId));
});

test('organization batch failure rolls back attachment metadata, cipher revision, event and outbox', async (ctx) => {
  const f = fixture(ctx);
  f.sqlite.sqlite.exec("CREATE TRIGGER reject_attachment_event BEFORE INSERT ON organization_events BEGIN SELECT RAISE(ABORT, 'test failure'); END");
  await assert.rejects(createAttachmentForUser(f.sqlite.db, { ...f.attachment, id: 'rolled-back' }, editor), /test failure/);
  assert.equal(await getAttachment(f.sqlite.db, 'rolled-back'), null);
  assert.equal(f.sqlite.sqlite.prepare('SELECT updated_at FROM ciphers WHERE id = ?').get(cipherId)!.updated_at, date);
  assert.equal(f.sqlite.sqlite.prepare('SELECT COUNT(*) AS count FROM user_revisions').get()!.count, 0);
});

test('revocation after the preflight lookup denies SQL metadata mutation without changes', async (ctx) => {
  const f = fixture(ctx);
  const batch = f.sqlite.batch.bind(f.sqlite);
  ctx.mock.method(f.sqlite, 'batch', async (statements: D1PreparedStatement[]) => {
    f.revoke();
    return batch(statements);
  });
  assert.equal(await updateAttachmentForUser(f.sqlite.db, { ...f.attachment, fileName: 'Revoked edit' }, editor, f.attachment), false);
  assert.equal((await getAttachment(f.sqlite.db, attachmentId))?.fileName, f.attachment.fileName);
  assert.equal(await createAttachmentForUser(f.sqlite.db, { ...f.attachment, id: 'revoked-create' }, editor), false);
  assert.equal(await deleteAttachmentForUser(f.sqlite.db, attachmentId, editor), false);
  assert.equal(f.sqlite.sqlite.prepare('SELECT COUNT(*) AS count FROM organization_events').get()!.count, 0);
});

test('metadata handler reauthorizes after request-body parsing', async (ctx) => {
  const f = fixture(ctx);
  const request = f.request('PUT', { fileName: 'Revoked edit' });
  ctx.mock.method(request, 'json', async () => { f.revoke(); return { fileName: 'Revoked edit' }; });
  assert.equal((await handleUpdateAttachmentMetadata(request, f.env, editor, cipherId, attachmentId)).status, 404);
  assert.equal((await getAttachment(f.sqlite.db, attachmentId))?.fileName, f.attachment.fileName);
});

test('filename-only metadata request cannot undo a same-ID key repair during body parsing', async (ctx) => {
  const f = fixture(ctx);
  const storage = new StorageService(f.sqlite.db);
  const request = f.request('PUT', { fileName: 'New filename' });
  ctx.mock.method(request, 'json', async () => {
    const cipher = (await storage.getCipherForUser(cipherId, editor))!;
    assert.equal(await storage.updateCipherIfUnchanged(cipher, cipher.updatedAt, editor,
      [{ ...f.attachment, key: 'Repaired wrapping key' }]), true);
    return { fileName: 'New filename' };
  });
  assert.equal((await handleUpdateAttachmentMetadata(request, f.env, editor, cipherId, attachmentId)).status, 404);
  const saved = (await getAttachment(f.sqlite.db, attachmentId))!;
  assert.equal(saved.key, 'Repaired wrapping key');
  assert.equal(saved.fileName, f.attachment.fileName);
  assert.equal((await storage.getCipherForUser(cipherId, editor))?.edit, true, 'the actor still has write access; this is a metadata CAS conflict');
});

test('filename-only personal request cannot undo attachment wrapping after an authorized organization share', async (ctx) => {
  const f = fixture(ctx);
  const storage = new StorageService(f.sqlite.db);
  const request = f.request('PUT', { fileName: 'Personal filename edit' });
  ctx.mock.method(request, 'json', async () => {
    const source = (await storage.getCipherForUser('personal-cipher', owner))!;
    const originals = await storage.getAttachmentsByCipher(source.id);
    const transferred = originals.map((attachment) => ({ ...attachment, key: '2.a|organization-file-key|m', fileName: '2.a|organization-file-name|m' }));
    const cipher = { ...source, userId: null, organizationId, name: '2.a|organization-name|m', key: '2.a|organization-item-key|m',
      updatedAt: new Date(Math.max(Date.now(), Date.parse(source.updatedAt) + 1)).toISOString() };
    assert.equal(await sharePersonalCipher(f.sqlite.db, cipher, owner, source.updatedAt, ['collection'], transferred,
      { cipher: source, attachments: originals }), true);
    return { fileName: 'Personal filename edit' };
  });
  assert.equal((await handleUpdateAttachmentMetadata(request, f.env, owner, 'personal-cipher', 'personal-attachment')).status, 404);
  const saved = (await getAttachment(f.sqlite.db, 'personal-attachment'))!;
  assert.equal(saved.key, '2.a|organization-file-key|m');
  assert.equal(saved.fileName, '2.a|organization-file-name|m');
  assert.equal((await storage.getCipherForUser('personal-cipher', owner))?.edit, true);
});

for (const mode of ['authenticated', 'token'] as const) {
  test(`${mode} upload cannot overwrite a repaired key after parsing its original metadata snapshot`, async (ctx) => {
    const f = fixture(ctx);
    ctx.mock.method(f.env.ATTACHMENTS!, 'get', async () => null);
    const token = await createAttachmentUploadToken(editor, cipherId, attachmentId, secret);
    const request = new Request(`https://vault.example.test/upload?token=${token}`, {
      method: 'POST', body: 'data', headers: { 'Content-Type': 'multipart/form-data; boundary=test' },
    });
    ctx.mock.method(request, 'formData', async () => {
      f.sqlite.sqlite.prepare('UPDATE attachments SET key=? WHERE id=?').run('Repaired upload wrapping key', attachmentId);
      const form = new FormData();
      form.set('data', new File(['data'], 'upload.bin'));
      return form;
    });
    const response = mode === 'authenticated'
      ? await handleUploadAttachment(request, f.env, editor, cipherId, attachmentId)
      : await handlePublicUploadAttachment(request, f.env, cipherId, attachmentId);
    assert.equal(response.status, 404);
    assert.equal((await getAttachment(f.sqlite.db, attachmentId))?.key, 'Repaired upload wrapping key');
    assert.deepEqual(f.blobWrites, []);
    assert.deepEqual(f.blobDeletes, []);
  });
}

test('read-only actors may download but cannot create, update, delete or use cached upload URLs', async (ctx) => {
  const f = fixture(ctx);
  assert.equal((await handleCreateAttachment(f.request('POST', { fileName: 'name', key: 'key', fileSize: 4 }), f.env, reader, cipherId)).status, 403);
  assert.equal((await handleUpdateAttachmentMetadata(f.request('PUT', { fileName: 'name' }), f.env, reader, cipherId, attachmentId)).status, 403);
  assert.equal((await handleDeleteAttachment(f.request('DELETE'), f.env, reader, cipherId, attachmentId)).status, 403);
  const uploadToken = await createAttachmentUploadToken(reader, cipherId, attachmentId, secret);
  const uploadRequest = new Request(`https://vault.example.test/upload?token=${uploadToken}`, { method: 'POST', body: 'data' });
  assert.equal((await handlePublicUploadAttachment(uploadRequest, f.env, cipherId, attachmentId)).status, 403);
  assert.deepEqual(f.blobWrites, []);
  assert.deepEqual(f.blobDeletes, []);
  const response = await handleGetAttachment(f.request(), f.env, reader, cipherId, attachmentId);
  assert.equal(response.status, 200);
  const info = await response.json() as { url: string };
  const token = new URL(info.url).searchParams.get('token')!;
  assert.equal((await verifyFileDownloadToken(token, secret))?.userId, reader);
  const download = await f.download(token);
  assert.equal(download.status, 200);
  assert.equal(download.headers.get('Cache-Control'), 'private, no-store');
  assert.equal(await download.text(), 'data');
  assert.equal((await f.download(token)).status, 401, 'download tokens are single use');
});

test('cached download URLs are denied after membership revocation without opening blobs', async (ctx) => {
  const f = fixture(ctx);
  const response = await handleGetAttachment(f.request(), f.env, editor, cipherId, attachmentId);
  const info = await response.json() as { url: string };
  const token = new URL(info.url).searchParams.get('token')!;
  assert.equal((await verifyFileDownloadToken(token, secret))?.userId, editor);
  f.revoke();
  assert.equal((await f.download(token)).status, 404);
  assert.deepEqual(f.blobReads, []);
  assert.equal((await f.download(token)).status, 401, 'denied attempts still consume the URL');
});

test('revocation during token consumption is caught by fresh post-consume authorization', async (ctx) => {
  const f = fixture(ctx);
  const token = await createFileDownloadToken(cipherId, attachmentId, secret, editor);
  const consume = StorageService.prototype.consumeAttachmentDownloadToken;
  ctx.mock.method(StorageService.prototype, 'consumeAttachmentDownloadToken', async function (this: StorageService, jti: string, exp: number) {
    const used = await consume.call(this, jti, exp);
    f.revoke();
    return used;
  });
  assert.equal((await f.download(token)).status, 404);
  assert.deepEqual(f.blobReads, []);
});

test('collection grant removal revokes previously cached URLs; forged actors and legacy unbound tokens fail closed', async (ctx) => {
  const f = fixture(ctx);
  const token = await createFileDownloadToken(cipherId, attachmentId, secret, editor);
  f.sqlite.sqlite.prepare('DELETE FROM collection_users WHERE member_id = ?').run('member-editor');
  assert.equal((await f.download(token)).status, 404);
  assert.equal((await f.download(await createFileDownloadToken(cipherId, attachmentId, secret, outsider))).status, 404);
  const legacy = await createFileDownloadToken(cipherId, attachmentId, secret, undefined as unknown as string);
  assert.equal(await verifyFileDownloadToken(legacy, secret), null);
  assert.equal((await f.download(legacy)).status, 401);
  assert.deepEqual(f.blobReads, []);
});

test('public upload reauthorizes after multipart parsing and cannot write bytes after revocation', async (ctx) => {
  const f = fixture(ctx);
  ctx.mock.method(f.env.ATTACHMENTS!, 'get', async () => null);
  const token = await createAttachmentUploadToken(editor, cipherId, attachmentId, secret);
  const request = new Request(`https://vault.example.test/upload?token=${token}`, {
    method: 'POST', body: 'data', headers: { 'Content-Type': 'multipart/form-data; boundary=test' },
  });
  ctx.mock.method(request, 'formData', async () => {
    f.revoke();
    const form = new FormData();
    form.set('data', new File(['data'], 'upload.bin'));
    return form;
  });
  assert.equal((await handlePublicUploadAttachment(request, f.env, cipherId, attachmentId)).status, 404);
  assert.deepEqual(f.blobWrites, []);
  assert.deepEqual(f.blobDeletes, []);
  assert.equal((await getAttachment(f.sqlite.db, attachmentId))?.fileName, f.attachment.fileName);
});

test('authorized create and metadata handlers support organization-owned nullable-user ciphers', async (ctx) => {
  const f = fixture(ctx);
  const create = await handleCreateAttachment(f.request('POST', { fileName: 'New encrypted filename', key: 'New encrypted key', fileSize: 4 }), f.env, editor, cipherId);
  assert.equal(create.status, 200);
  const info = await create.json() as { attachmentId: string; url: string };
  assert.ok(info.attachmentId);
  const upload = new URL(info.url);
  assert.ok(upload.searchParams.get('token'));
  assert.equal((await getAttachmentForUser(f.sqlite.db, info.attachmentId, reader))?.fileName, 'New encrypted filename');
  const update = await handleUpdateAttachmentMetadata(f.request('PUT', { fileName: 'Updated encrypted filename', key: null }), f.env, editor, cipherId, info.attachmentId);
  assert.equal(update.status, 200);
  assert.equal((await getAttachment(f.sqlite.db, info.attachmentId))?.fileName, 'Updated encrypted filename');
  assert.equal((await getAttachment(f.sqlite.db, info.attachmentId))?.key, null);
});

test('cached download URLs remain readable after a write-only grant downgrade but cached uploads do not', async (ctx) => {
  const f = fixture(ctx);
  const downloadToken = await createFileDownloadToken(cipherId, attachmentId, secret, editor);
  const uploadToken = await createAttachmentUploadToken(editor, cipherId, attachmentId, secret);
  f.sqlite.sqlite.prepare('UPDATE collection_users SET read_only = 1 WHERE member_id = ?').run('member-editor');
  const upload = new Request(`https://vault.example.test/upload?token=${uploadToken}`, { method: 'POST', body: 'data' });
  assert.equal((await handlePublicUploadAttachment(upload, f.env, cipherId, attachmentId)).status, 403);
  assert.equal((await f.download(downloadToken)).status, 200);
  assert.deepEqual(f.blobWrites, []);
});

test('removing group collection access invalidates cached reader URLs', async (ctx) => {
  const f = fixture(ctx);
  const token = await createFileDownloadToken(cipherId, attachmentId, secret, 'group-reader');
  f.sqlite.sqlite.prepare('DELETE FROM organization_group_members WHERE member_id = ?').run('member-group-reader');
  assert.equal((await f.download(token)).status, 404);
  assert.deepEqual(f.blobReads, []);
});

test('personal metadata mutations authorize only their owner and update only that vault revision', async (ctx) => {
  const f = fixture(ctx);
  const attachment = { ...f.attachment, id: 'new-personal', cipherId: 'personal-cipher' };
  assert.equal(await createAttachmentForUser(f.sqlite.db, attachment, outsider), false);
  assert.equal(await createAttachmentForUser(f.sqlite.db, attachment, owner), true);
  assert.equal(await updateAttachmentForUser(f.sqlite.db, { ...attachment, key: null }, owner, attachment), true);
  assert.equal(await deleteAttachmentForUser(f.sqlite.db, attachment.id, outsider), false);
  assert.equal(await deleteAttachmentForUser(f.sqlite.db, attachment.id, owner), true);
  assert.deepEqual(f.sqlite.sqlite.prepare('SELECT user_id FROM user_revisions').all().map((row) => row.user_id), [owner]);
  assert.equal(f.sqlite.sqlite.prepare('SELECT COUNT(*) AS count FROM organization_events').get()!.count, 0);
});

test('personal download URLs are invalid once cipher ownership changes', async (ctx) => {
  const f = fixture(ctx);
  const token = await createFileDownloadToken('personal-cipher', 'personal-attachment', secret, owner);
  f.sqlite.sqlite.prepare('UPDATE ciphers SET user_id = ? WHERE id = ?').run(outsider, 'personal-cipher');
  assert.equal((await f.download(token, 'personal-cipher', 'personal-attachment')).status, 404);
  assert.deepEqual(f.blobReads, []);
});

test('delete commits authorized metadata before blob removal and SQL-race denial cannot remove blobs', async (ctx) => {
  const f = fixture(ctx);
  assert.equal((await handleDeleteAttachment(f.request('DELETE'), f.env, editor, cipherId, attachmentId)).status, 200);
  assert.equal(await getAttachment(f.sqlite.db, attachmentId), null);
  assert.deepEqual(f.blobDeletes, [`${cipherId}/${attachmentId}`]);
  f.sqlite.sqlite.prepare(`INSERT INTO attachments(id,cipher_id,file_name,size,size_name) VALUES(?,?,'name',4,'4 Bytes')`).run(attachmentId, cipherId);
  const batch = f.sqlite.batch.bind(f.sqlite);
  ctx.mock.method(f.sqlite, 'batch', async (statements: D1PreparedStatement[]) => { f.revoke(); return batch(statements); });
  assert.equal((await handleDeleteAttachment(f.request('DELETE'), f.env, editor, cipherId, attachmentId)).status, 404);
  assert.ok(await getAttachment(f.sqlite.db, attachmentId));
  assert.deepEqual(f.blobDeletes, [`${cipherId}/${attachmentId}`]);
});

test('blob-only cipher cleanup uses supplied snapshot after cascade deletes metadata', async (ctx) => {
  const f = fixture(ctx);
  f.sqlite.sqlite.prepare('DELETE FROM ciphers WHERE id = ?').run(cipherId);
  await deleteAttachmentBlobs(f.env, [f.attachment]);
  assert.deepEqual(f.blobDeletes, [`${cipherId}/${attachmentId}`]);
});

test('trusted save supports nullable organizational owners but cannot cross ownership scopes', async (ctx) => {
  const f = fixture(ctx);
  await saveAttachment(f.sqlite.db, safeBind, { ...f.attachment, fileName: 'Trusted update' });
  assert.equal((await getAttachment(f.sqlite.db, attachmentId))?.fileName, 'Trusted update');
  await saveAttachment(f.sqlite.db, safeBind, { ...f.attachment, cipherId: 'personal-cipher', fileName: 'Wrong scope' });
  assert.equal((await getAttachment(f.sqlite.db, attachmentId))?.cipherId, cipherId);
  await addAttachmentToCipherForUser(f.sqlite.db, 'personal-cipher', attachmentId, owner);
  assert.equal((await getAttachment(f.sqlite.db, attachmentId))?.cipherId, cipherId);
});

test('revision updates authorize writes and fan out to confirmed organization members, never null owner', async (ctx) => {
  const f = fixture(ctx);
  assert.equal(await updateCipherRevisionDate(f.sqlite.db, cipherId, reader), null);
  const result = await updateCipherRevisionDate(f.sqlite.db, cipherId, editor);
  assert.equal(result?.userId, editor);
  assert.deepEqual(result?.userIds.sort(), [editor, 'group-reader', owner, reader].sort());
  const personal = await updateCipherRevisionDate(f.sqlite.db, 'personal-cipher', owner);
  assert.deepEqual(personal?.userIds, [owner]);
  f.revoke();
  assert.equal(await updateCipherRevisionDate(f.sqlite.db, cipherId, editor), null);
});

test('attachment metadata revisions are monotonic even when the stored timestamp is ahead of wall time', async (ctx) => {
  const f = fixture(ctx);
  const future = '2099-01-01T00:00:00.000Z';
  f.sqlite.sqlite.prepare('UPDATE ciphers SET updated_at=? WHERE id=?').run(future, cipherId);
  assert.equal(await updateAttachmentForUser(f.sqlite.db, { ...f.attachment, fileName: 'New encrypted filename' }, editor, f.attachment), true);
  assert.equal(f.sqlite.sqlite.prepare('SELECT updated_at FROM ciphers WHERE id=?').get(cipherId)!.updated_at, '2099-01-01T00:00:00.001Z');
  const result = await updateCipherRevisionDate(f.sqlite.db, cipherId, editor);
  assert.equal(result?.revisionDate, '2099-01-01T00:00:00.002Z');
  assert.equal(f.sqlite.sqlite.prepare('SELECT revision_date FROM user_revisions WHERE user_id=?').get(editor)!.revision_date, result?.revisionDate);
  f.sqlite.sqlite.prepare('UPDATE ciphers SET updated_at=? WHERE id=?').run(future, 'personal-cipher');
  const personal = (await getAttachment(f.sqlite.db, 'personal-attachment'))!;
  assert.equal(await updateAttachmentForUser(f.sqlite.db, personal, owner, { ...personal }), true);
  assert.equal(f.sqlite.sqlite.prepare('SELECT updated_at FROM ciphers WHERE id=?').get('personal-cipher')!.updated_at, '2099-01-01T00:00:00.001Z');
  assert.equal(f.sqlite.sqlite.prepare('SELECT revision_date FROM user_revisions WHERE user_id=?').get(owner)!.revision_date, '2099-01-01T00:00:00.003Z', 'a personal mutation cannot regress the later organization vault revision');
});

test('revision fanout advances beyond every prior vault revision despite cipher clock skew and mutation ordering', async (ctx) => {
  const f = fixture(ctx);
  const prior = '2050-01-01T00:00:00.000Z';
  for (const [id, value] of [[owner, '2040-01-01T00:00:00.000Z'], [editor, '2045-01-01T00:00:00.000Z'], [reader, prior]]) {
    f.sqlite.sqlite.prepare('INSERT INTO user_revisions(user_id,revision_date) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET revision_date=excluded.revision_date')
      .run(id, value);
  }
  const first = await updateCipherRevisionDate(f.sqlite.db, cipherId, editor);
  assert.equal(first?.revisionDate, '2050-01-01T00:00:00.001Z');
  for (const id of first!.userIds) {
    assert.equal(f.sqlite.sqlite.prepare('SELECT revision_date FROM user_revisions WHERE user_id=?').get(id)!.revision_date, first?.revisionDate);
  }
  // Model a later organization mutation whose vault timestamp is newer than
  // this cipher's clock; a subsequent attachment fanout cannot lower it.
  f.sqlite.sqlite.prepare('UPDATE user_revisions SET revision_date=? WHERE user_id=?').run('2051-01-01T00:00:00.000Z', editor);
  const second = await updateCipherRevisionDate(f.sqlite.db, cipherId, editor);
  assert.equal(second?.revisionDate, '2051-01-01T00:00:00.001Z');
  const personal = (await getAttachment(f.sqlite.db, 'personal-attachment'))!;
  assert.equal(await updateAttachmentForUser(f.sqlite.db, personal, owner, { ...personal }), true);
  assert.equal(f.sqlite.sqlite.prepare('SELECT revision_date FROM user_revisions WHERE user_id=?').get(owner)!.revision_date, '2051-01-01T00:00:00.002Z');
  const personalFanout = await updateCipherRevisionDate(f.sqlite.db, 'personal-cipher', owner);
  assert.equal(personalFanout?.revisionDate, '2051-01-01T00:00:00.003Z');
  assert.deepEqual(personalFanout?.userIds, [owner]);
  assert.equal(f.sqlite.sqlite.prepare('SELECT revision_date FROM user_revisions WHERE user_id=?').get(editor)!.revision_date, second?.revisionDate);
});

test('token consumption rejects expired and malformed expirations without persisting rows', async (ctx) => {
  const f = fixture(ctx);
  const consume = (id: string, exp: number) => consumeAttachmentDownloadToken(f.sqlite.db, () => false, 0, 0, id, exp);
  assert.equal((await consume('expired', Math.floor(Date.now() / 1000) - 1)).consumed, false);
  assert.equal((await consume('invalid', NaN)).consumed, false);
  const exp = Math.floor(Date.now() / 1000) + 60;
  assert.equal((await consume('valid', exp)).consumed, true);
  assert.equal((await consume('valid', exp)).consumed, false);
});
