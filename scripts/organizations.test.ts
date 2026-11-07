import assert from 'node:assert/strict';
import test from 'node:test';
import type { Env, User } from '../src/types';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { SqliteD1 } from './helpers/sqlite-d1';
import { handleOrganizationRoute } from '../src/handlers/organizations';
import { cipherAccessSql, cipherHidePasswordsSql, cipherCollectionIdsSql, getCipherPermissions,
  getProfileOrganizations, listAccessibleCollections } from '../src/services/organization-access';
import { createOrganization, commitOrganizationMutation } from '../src/services/organization-repo';
import { flushOrganizationNotifications, drainOrganizationNotifications } from '../src/services/organization-notifications';

const initial = '2020-01-01T00:00:00.000Z';
async function fixture() {
  const adapter = new SqliteD1();
  await ensureStorageSchema(adapter.db);
  function user(id: string, email = `${id}@example.test`): User {
    adapter.sqlite.prepare(`INSERT INTO users(id,email,master_password_hash,key,public_key,kdf_type,kdf_iterations,security_stamp,created_at,updated_at)
      VALUES(?,?,'hash','encrypted-user-key','rsa-public',0,600000,'stamp',?,?)`).run(id, email, initial, initial);
    return {id, email, status: 'active', publicKey: 'rsa-public'} as User;
  }
  const owner = user('owner'); const admin = user('admin'); const reader = user('reader'); const outsider = user('outsider');
  const org = await createOrganization(adapter.db, owner.id, {name: 'Team', billingEmail: owner.email,
    key: 'rsa-encrypted-owner-key', publicKey: 'org-public', privateKey: 'org-encrypted-private', collectionName: 'encrypted-collection'});
  const orgId = org.id;
  function membership(person: User, type = 2, status = 2, accessAll = false, id = `member-${person.id}`) {
    adapter.sqlite.prepare(`INSERT INTO organization_members(id,organization_id,user_id,email,type,status,access_all,key,created_at,updated_at)
      VALUES(?,?,?,?,?,?,?,'rsa-encrypted-member-key',?,?)`).run(id, orgId, person.id, person.email, type, status, +accessAll, initial, initial);
    return id;
  }
  const adminId = membership(admin, 1); const readerId = membership(reader);
  const collection = adapter.sqlite.prepare('SELECT id FROM collections WHERE organization_id = ?').get(orgId)!.id as string;
  const ownerId = adapter.sqlite.prepare('SELECT id FROM organization_members WHERE user_id = ? AND organization_id = ?').get(owner.id, orgId)!.id as string;
  function cipher(id = 'shared', collectionId: string | null = collection, data = '{}') {
    adapter.sqlite.prepare(`INSERT INTO ciphers(id,organization_id,type,data,created_at,updated_at) VALUES(?,?,1,?,?,?)`)
      .run(id, orgId, data, initial, initial);
    if (collectionId) adapter.sqlite.prepare('INSERT INTO cipher_collections(cipher_id,collection_id) VALUES(?,?)').run(id, collectionId);
    return id;
  }
  function direct(readOnly = true, hidePasswords = true, manage = false, col = collection) {
    adapter.sqlite.prepare('INSERT OR REPLACE INTO collection_users(collection_id,member_id,read_only,hide_passwords,manage) VALUES(?,?,?,?,?)')
      .run(col, readerId, +readOnly, +hidePasswords, +manage);
  }
  function group(accessAll = false, readOnly = false, hidePasswords = false, manage = false) {
    const id = `group-${Math.random()}`;
    adapter.sqlite.prepare('INSERT INTO organization_groups(id,organization_id,name,access_all) VALUES(?,?,?,?)').run(id, orgId, 'Group', +accessAll);
    adapter.sqlite.prepare('INSERT INTO organization_group_members(group_id,member_id) VALUES(?,?)').run(id, readerId);
    adapter.sqlite.prepare('INSERT INTO collection_groups(collection_id,group_id,read_only,hide_passwords,manage) VALUES(?,?,?,?,?)')
      .run(collection, id, +readOnly, +hidePasswords, +manage);
    return id;
  }
  const env = {DB: adapter.db} as Env;
  async function route(person: User, path: string, method = 'GET', body?: unknown): Promise<Response> {
    const response = await handleOrganizationRoute(new Request(`https://vault.example.test${path}`, {method,
      ...(body === undefined ? {} : {body: JSON.stringify(body), headers: {'Content-Type': 'application/json'}})}), env, person, path.split('?')[0], method);
    assert.ok(response); return response;
  }
  return {adapter, env, user, owner, ownerId, admin, adminId, reader, readerId, outsider, orgId, collection, membership, cipher, direct, group, route};
}

test('organization creation protocol initializes a confirmed owner and encrypted collection with honest flags', async () => {
  const f = await fixture();
  try {
    const response = await f.route(f.outsider, '/api/organizations', 'POST', {Name: 'Second team', BillingEmail: f.outsider.email,
      Key: 'encrypted-rsa-owner', CollectionName: 'encrypted-initial', Keys: {PublicKey: 'public', EncryptedPrivateKey: 'encrypted-private'}});
    assert.equal(response.status, 200);
    const org = await response.json() as Record<string, unknown>;
    assert.equal(org.usePolicies, false); assert.equal(org.useScim, false); assert.equal(org.useResetPassword, false);
    assert.equal(org.useEvents, true); assert.equal(org.useGroups, true); assert.equal(org.object, 'organization');
    const profile = await getProfileOrganizations(f.adapter.db, f.outsider.id);
    assert.equal(profile[0].key, 'encrypted-rsa-owner'); assert.equal(profile[0].privateKey, 'encrypted-private');
    assert.equal(f.adapter.sqlite.prepare('SELECT COUNT(*) AS n FROM collections WHERE organization_id = ?').get(org.id as string)!.n, 1);
  } finally { f.adapter.close(); }
});

test('cipher authorization rejects opaque data flags and non-confirmed or foreign members', async () => {
  const f = await fixture();
  try {
    f.cipher('shared', f.collection, JSON.stringify({organizationId: f.orgId, edit: true, viewPassword: true, permissions: {manage: true}}));
    assert.equal((await getCipherPermissions(f.adapter.db, f.reader.id, 'shared')).read, false);
    assert.equal((await getCipherPermissions(f.adapter.db, f.outsider.id, 'shared')).read, false);
    assert.equal((await getCipherPermissions(f.adapter.db, f.owner.id, 'shared')).write, true);
    assert.equal((await getCipherPermissions(f.adapter.db, f.admin.id, 'shared')).hidePasswords, false);
    f.direct(false, false);
    for (const status of [0, 1, -1]) {
      f.adapter.sqlite.prepare('UPDATE organization_members SET status = ? WHERE id = ?').run(status, f.readerId);
      assert.equal((await getCipherPermissions(f.adapter.db, f.reader.id, 'shared')).read, false);
    }
  } finally { f.adapter.close(); }
});

test('collection direct and group grants union to the least restrictive permission', async () => {
  const f = await fixture();
  try {
    f.cipher(); f.direct();
    assert.deepEqual(await getCipherPermissions(f.adapter.db, f.reader.id, 'shared'), {read: true, write: false, hidePasswords: true,
      organizationId: f.orgId, collectionIds: [f.collection]});
    const projection = f.adapter.sqlite.prepare(`WITH actor AS (SELECT ? AS user_id) SELECT ${cipherHidePasswordsSql()} AS hidden,
      ${cipherCollectionIdsSql()} AS ids FROM ciphers c WHERE id = 'shared'`).get(f.reader.id)!;
    assert.equal(projection.hidden, 1); assert.deepEqual(JSON.parse(projection.ids as string), [f.collection]);
    f.group(false, false, false);
    const permissions = await getCipherPermissions(f.adapter.db, f.reader.id, 'shared');
    assert.equal(permissions.write, true); assert.equal(permissions.hidePasswords, false);
    const collections = await listAccessibleCollections(f.adapter.db, f.reader.id);
    assert.equal(collections[0].readOnly, false); assert.equal(collections[0].hidePasswords, false);
  } finally { f.adapter.close(); }
});

test('manage overrides read-only/hide-password flags; group access-all reaches uncollected items', async () => {
  const f = await fixture();
  try {
    f.cipher(); f.cipher('uncollected', null); f.direct(true, true, true);
    let permission = await getCipherPermissions(f.adapter.db, f.reader.id, 'shared');
    assert.equal(permission.write, true); assert.equal(permission.hidePasswords, false);
    assert.equal((await getCipherPermissions(f.adapter.db, f.reader.id, 'uncollected')).read, false);
    f.group(true, true, true);
    permission = await getCipherPermissions(f.adapter.db, f.reader.id, 'uncollected');
    assert.equal(permission.write, true); assert.equal(permission.hidePasswords, false);
  } finally { f.adapter.close(); }
});

test('mutation WHERE permissions are re-evaluated after revoke, and personal ownership stays scoped', async () => {
  const f = await fixture();
  try {
    f.cipher(); f.direct(false, false);
    assert.equal((await getCipherPermissions(f.adapter.db, f.reader.id, 'shared')).write, true);
    f.adapter.sqlite.prepare('UPDATE organization_members SET status = -1 WHERE id = ?').run(f.readerId);
    const result = f.adapter.sqlite.prepare(`WITH actor AS (SELECT ? AS user_id) UPDATE ciphers AS c SET data = 'modified'
      WHERE id = 'shared' AND ${cipherAccessSql('write')}`).run(f.reader.id);
    assert.equal(result.changes, 0);
    f.adapter.sqlite.prepare(`INSERT INTO ciphers(id,user_id,type,data,created_at,updated_at) VALUES('personal',?,1,'{}',?,?)`).run(f.reader.id, initial, initial);
    assert.equal((await getCipherPermissions(f.adapter.db, f.reader.id, 'personal')).write, true);
    assert.equal((await getCipherPermissions(f.adapter.db, f.owner.id, 'personal')).read, false);
    assert.throws(() => cipherAccessSql('read', 'c; DROP TABLE users'), /Invalid SQL alias/);
  } finally { f.adapter.close(); }
});

test('in-app invitation acceptance is email-bound and key confirmation is admin-only', async () => {
  const f = await fixture();
  try {
    const invited = f.user('invited', 'MixedCase@example.test');
    let response = await f.route(f.admin, `/api/organizations/${f.orgId}/users/invite`, 'POST', {emails: ['mixedcase@example.test'], type: 2, groups: [], collections: [{id: f.collection, readOnly: true, hidePasswords: true, manage: false}]});
    assert.equal(response.status, 200);
    const invite = await response.json() as {data: Array<{id: string}>; mailSent: boolean; mailDeliverySupported: boolean};
    assert.equal(invite.mailSent, false); assert.equal(invite.mailDeliverySupported, false);
    const id = invite.data[0].id;
    const pending = await getProfileOrganizations(f.adapter.db, invited.id);
    assert.equal(pending[0].key, null); assert.equal(pending[0].status, 0);
    assert.equal((await (await f.route(invited, '/api/organizations/invitations')).json() as {data: unknown[]}).data.length, 1);
    assert.equal((await f.route(f.outsider, `/api/organizations/${f.orgId}/users/${id}/accept`, 'POST', {})).status, 409);
    assert.equal((await f.route(invited, `/api/organizations/${f.orgId}/users/${id}/accept`, 'POST', {key: 'attacker-key'})).status, 400);
    assert.equal((await f.route(invited, `/api/organizations/${f.orgId}/users/${id}/accept`, 'POST', {})).status, 200);
    assert.equal((await getProfileOrganizations(f.adapter.db, invited.id))[0].key, null);
    assert.equal((await f.route(invited, `/api/organizations/${f.orgId}/users/${id}/confirm`, 'POST', {key: 'encrypted-key'})).status, 403);
    assert.equal((await f.route(f.admin, `/api/organizations/${f.orgId}/users/${id}/confirm`, 'POST', {key: 'encrypted-key'})).status, 204);
    assert.equal((await getProfileOrganizations(f.adapter.db, invited.id))[0].key, 'encrypted-key');
    response = await f.route(f.owner, `/api/organizations/${f.orgId}/users/${id}`);
    const detail = await response.json() as Record<string, unknown>;
    assert.equal(detail.publicKey, 'rsa-public'); assert.equal('key' in detail, false);
    assert.equal(f.adapter.sqlite.prepare(`SELECT COUNT(*) AS n FROM organization_events WHERE data LIKE '%encrypted-key%'`).get()!.n, 0);
  } finally { f.adapter.close(); }
});

test('stale token email and repeated acceptance cannot bind invitations', async () => {
  const f = await fixture();
  try {
    const invitee = f.user('new-member');
    const invited = await (await f.route(f.owner, `/api/organizations/${f.orgId}/users/invite`, 'POST', {emails: [invitee.email], type: 2})).json() as {data: {id: string}[]};
    const path = `/api/organizations/${f.orgId}/users/${invited.data[0].id}/accept`;
    f.adapter.sqlite.prepare('UPDATE users SET email = ? WHERE id = ?').run('changed@example.test', invitee.id);
    assert.equal((await f.route(invitee, path, 'POST', {})).status, 409);
    f.adapter.sqlite.prepare('UPDATE users SET email = ? WHERE id = ?').run(invitee.email, invitee.id);
    assert.equal((await f.route(invitee, path, 'POST', {})).status, 200);
    assert.equal((await f.route(invitee, path, 'POST', {})).status, 409);
  } finally { f.adapter.close(); }
});

test('owner promotions/demotions are owner-only and last confirmed owner is protected', async () => {
  const f = await fixture();
  try {
    assert.equal((await f.route(f.admin, `/api/organizations/${f.orgId}/users/${f.adminId}`, 'PUT', {type: 0})).status, 409);
    assert.equal((await f.route(f.admin, `/api/organizations/${f.orgId}/users/${f.ownerId}`, 'DELETE')).status, 409);
    assert.equal((await f.route(f.owner, `/api/organizations/${f.orgId}/users/${f.ownerId}`, 'PUT', {type: 2})).status, 409);
    assert.equal((await f.route(f.owner, `/api/organizations/${f.orgId}/users/${f.ownerId}/revoke`, 'PUT', {})).status, 409);
    assert.equal((await f.route(f.owner, `/api/organizations/${f.orgId}/leave`, 'POST', {})).status, 409);
    assert.equal((await f.route(f.owner, `/api/organizations/${f.orgId}/users/${f.adminId}`, 'PUT', {type: 0})).status, 200);
    assert.equal((await f.route(f.owner, `/api/organizations/${f.orgId}/users/${f.ownerId}`, 'PUT', {type: 2})).status, 200);
  } finally { f.adapter.close(); }
});

test('simultaneous owner removals cannot remove both owners', async () => {
  const f = await fixture();
  try {
    f.adapter.sqlite.prepare('UPDATE organization_members SET type = 0 WHERE id = ?').run(f.adminId);
    const responses = await Promise.all([
      f.route(f.owner, `/api/organizations/${f.orgId}/users/${f.ownerId}`, 'DELETE'),
      f.route(f.admin, `/api/organizations/${f.orgId}/users/${f.adminId}`, 'DELETE'),
    ]);
    assert.deepEqual(responses.map((response) => response.status).sort(), [204, 409]);
    assert.equal(f.adapter.sqlite.prepare('SELECT COUNT(*) AS n FROM organization_members WHERE organization_id = ? AND type = 0 AND status = 2').get(f.orgId)!.n, 1);
  } finally { f.adapter.close(); }
});

test('revocation invalidates removed and remaining users and restore requires new confirmation', async () => {
  const f = await fixture();
  try {
    f.cipher(); f.direct(false, false);
    f.adapter.sqlite.exec('DELETE FROM config WHERE key LIKE \'organization.sync.%\'; DELETE FROM user_revisions;');
    assert.equal((await f.route(f.admin, `/api/organizations/${f.orgId}/users/${f.readerId}/revoke`, 'PUT', {})).status, 204);
    const revoked = await getProfileOrganizations(f.adapter.db, f.reader.id);
    assert.equal(revoked[0].key, null); assert.equal(revoked[0].status, -1);
    assert.equal((await getCipherPermissions(f.adapter.db, f.reader.id, 'shared')).read, false);
    const recipients = f.adapter.sqlite.prepare('SELECT user_id FROM user_revisions ORDER BY user_id').all().map((row) => row.user_id);
    assert.deepEqual(recipients, ['admin', 'owner', 'reader']);
    const outbox = JSON.parse(f.adapter.sqlite.prepare('SELECT value FROM config WHERE key LIKE \'organization.sync.%\'').get()!.value as string);
    assert.deepEqual(outbox.userIds.sort(), recipients);
    assert.equal((await f.route(f.admin, `/api/organizations/${f.orgId}/users/${f.readerId}/restore`, 'PUT', {})).status, 204);
    assert.equal((await getProfileOrganizations(f.adapter.db, f.reader.id))[0].status, 1);
    assert.equal((await getCipherPermissions(f.adapter.db, f.reader.id, 'shared')).read, false);
    assert.equal((await f.route(f.admin, `/api/organizations/${f.orgId}/users/${f.readerId}/confirm`, 'POST', {key: 'new-encrypted-key'})).status, 204);
    assert.equal((await getCipherPermissions(f.adapter.db, f.reader.id, 'shared')).read, true);
  } finally { f.adapter.close(); }
});

test('cross-organization assignments reject the whole mutation without revisions or audit events', async () => {
  const f = await fixture();
  try {
    const otherOrg = await createOrganization(f.adapter.db, f.outsider.id, {name: 'Other', billingEmail: f.outsider.email,
      key: 'key', publicKey: null, privateKey: null, collectionName: 'encrypted'});
    const otherCollection = f.adapter.sqlite.prepare('SELECT id FROM collections WHERE organization_id = ?').get(otherOrg.id)!.id as string;
    const eventCount = f.adapter.sqlite.prepare('SELECT COUNT(*) AS n FROM organization_events').get()!.n;
    const response = await f.route(f.owner, `/api/organizations/${f.orgId}/users/${f.readerId}`, 'PUT', {type: 1,
      collections: [{id: otherCollection, readOnly: false, hidePasswords: false, manage: true}]});
    assert.equal(response.status, 409);
    assert.equal(f.adapter.sqlite.prepare('SELECT type FROM organization_members WHERE id = ?').get(f.readerId)!.type, 2);
    assert.equal(f.adapter.sqlite.prepare('SELECT COUNT(*) AS n FROM organization_events').get()!.n, eventCount);
    assert.equal((await f.route(f.owner, `/api/organizations/${f.orgId}/groups`, 'POST', {name: 'Bad', users: ['nonexistent']})).status, 409);
  } finally { f.adapter.close(); }
});

test('collection and group CRUD use same-organization grants and invalidate membership access', async () => {
  const f = await fixture();
  try {
    let response = await f.route(f.owner, `/api/organizations/${f.orgId}/collections`, 'POST', {name: 'encrypted-name', users: [{id: f.readerId, readOnly: true, hidePasswords: true, manage: false}], groups: []});
    assert.equal(response.status, 200);
    const collection = await response.json() as {id: string; users: unknown[]};
    assert.equal(collection.users.length, 1);
    const accessible = await (await f.route(f.reader, '/api/collections')).json() as {data: {id: string}[]};
    assert.equal(accessible.data[0].id, collection.id);
    assert.equal((await f.route(f.reader, `/api/organizations/${f.orgId}/collections/${collection.id}`, 'PUT', {name: 'bad'})).status, 409);
    response = await f.route(f.owner, `/api/organizations/${f.orgId}/groups`, 'POST', {name: 'Team group', accessAll: true, users: [f.readerId], collections: []});
    assert.equal(response.status, 200);
    const group = await response.json() as {id: string; users: string[]};
    assert.deepEqual(group.users, [f.readerId]);
    f.cipher('without-collections', null);
    assert.equal((await getCipherPermissions(f.adapter.db, f.reader.id, 'without-collections')).write, true);
    assert.equal((await f.route(f.admin, `/api/organizations/${f.orgId}/groups/${group.id}`, 'PUT', {name: 'changed', accessAll: false, users: []})).status, 200);
    assert.equal((await getCipherPermissions(f.adapter.db, f.reader.id, 'without-collections')).read, false);
    assert.equal((await f.route(f.admin, `/api/organizations/${f.orgId}/groups/${group.id}`, 'DELETE')).status, 204);
    assert.equal((await f.route(f.admin, `/api/organizations/${f.orgId}/collections/${collection.id}`, 'DELETE')).status, 204);
  } finally { f.adapter.close(); }
});

test('collection management does not expose assignment lists to ordinary readers', async () => {
  const f = await fixture();
  try {
    f.direct();
    const response = await f.route(f.reader, `/api/organizations/${f.orgId}/collections/${f.collection}/details`);
    assert.equal(response.status, 200);
    assert.equal('users' in await response.json() as object, false);
    assert.equal((await f.route(f.reader, `/api/organizations/${f.orgId}/collections/${f.collection}/users`)).status, 403);
    assert.equal((await f.route(f.reader, `/api/organizations/${f.orgId}/users`)).status, 403);
  } finally { f.adapter.close(); }
});

test('organization deletion is owner-only, cascades ciphers, and keeps durable revision recipients', async () => {
  const f = await fixture();
  try {
    f.cipher();
    assert.equal((await f.route(f.admin, `/api/organizations/${f.orgId}`, 'DELETE', {})).status, 403);
    f.adapter.sqlite.exec('DELETE FROM config WHERE key LIKE \'organization.sync.%\'; DELETE FROM user_revisions;');
    assert.equal((await f.route(f.owner, `/api/organizations/${f.orgId}`, 'DELETE', {masterPasswordHash: 'hash'})).status, 204);
    assert.equal(f.adapter.sqlite.prepare('SELECT COUNT(*) AS n FROM ciphers').get()!.n, 0);
    assert.deepEqual(f.adapter.sqlite.prepare('SELECT user_id FROM user_revisions ORDER BY user_id').all().map((row) => row.user_id), ['admin', 'owner', 'reader']);
    assert.equal(f.adapter.sqlite.prepare('SELECT COUNT(*) AS n FROM organization_events').get()!.n, 0);
    assert.equal(f.adapter.sqlite.prepare('SELECT COUNT(*) AS n FROM config WHERE key LIKE \'organization.sync.%\'').get()!.n, 1);
  } finally { f.adapter.close(); }
});

test('unsupported policies/reset/mail/custom permissions never return misleading empty success', async () => {
  const f = await fixture();
  try {
    for (const path of ['policies', 'api-key', 'auto-enroll-status', 'billing/vnext/warnings']) {
      assert.equal((await f.route(f.owner, `/api/organizations/${f.orgId}/${path}`)).status, 501);
    }
    assert.equal((await f.route(f.owner, `/api/organizations/${f.orgId}/users/${f.readerId}/reinvite`, 'POST', {})).status, 501);
    assert.equal((await f.route(f.owner, `/api/organizations/${f.orgId}/users/${f.readerId}`, 'PUT', {type: 2, permissions: {managePolicies: true}})).status, 501);
    assert.equal((await f.route(f.owner, `/api/organizations/${f.orgId}/users/invite`, 'POST', {emails: Array.from({length: 51}, (_, i) => `${i}@example.test`)})).status, 400);
    assert.equal((await f.route(f.owner, `/api/organizations/${f.orgId}/users/${f.readerId}`, 'PUT', {type: 0, status: 2})).status, 400);
    assert.equal((await f.route(f.outsider, '/api/organizations')).status, 200);
  } finally { f.adapter.close(); }
});

test('organization audit is administrator-only with event-target fields and pagination validation', async () => {
  const f = await fixture();
  try {
    assert.equal((await f.route(f.reader, `/api/organizations/${f.orgId}/events`)).status, 403);
    const events = await (await f.route(f.owner, `/api/organizations/${f.orgId}/events`)).json() as {data: {type: number; object: string}[]};
    assert.equal(events.data[0].type, 1600); assert.equal(events.data[0].object, 'event');
    assert.equal((await f.route(f.owner, `/api/organizations/${f.orgId}/events?continuationToken=-1`)).status, 400);
  } finally { f.adapter.close(); }
});

test('organization DELETE requires fresh password proof and ignores cached user verifiers', async () => {
  const f = await fixture();
  try {
    const path = `/api/organizations/${f.orgId}`;
    assert.equal((await f.route(f.owner, path, 'DELETE', {})).status, 400);
    assert.equal((await f.route(f.owner, path, 'DELETE', {masterPasswordHash: 'wrong'})).status, 400);
    assert.equal((await f.route(f.owner, path, 'DELETE', {otp: '123456'})).status, 501);
    assert.equal((await f.route(f.owner, path, 'DELETE', {userVerificationToken: 'unverified-token'})).status, 501);
    f.adapter.sqlite.prepare('UPDATE users SET master_password_hash = ? WHERE id = ?').run('fresh-client-hash', f.owner.id);
    assert.equal((await f.route(f.owner, path, 'DELETE', {masterPasswordHash: 'hash'})).status, 400);
    assert.equal((await f.route(f.owner, path, 'DELETE', {authenticationData: {masterPasswordAuthenticationHash: 'fresh-client-hash'}})).status, 204);
  } finally { f.adapter.close(); }
});

test('password rotation after verification atomically rejects organization deletion', async () => {
  const f = await fixture();
  try {
    const originalBatch = f.adapter.batch.bind(f.adapter);
    f.adapter.batch = async (statements) => {
      f.adapter.sqlite.prepare('UPDATE users SET master_password_hash = ? WHERE id = ?').run('rotated-proof', f.owner.id);
      return originalBatch(statements);
    };
    assert.equal((await f.route(f.owner, `/api/organizations/${f.orgId}`, 'DELETE', {masterPasswordHash: 'hash'})).status, 409);
    assert.ok(f.adapter.sqlite.prepare('SELECT id FROM organizations WHERE id = ?').get(f.orgId));
  } finally { f.adapter.close(); }
});

test('organization deletion snapshots concurrent attachments atomically and cleans only committed organization blobs', async () => {
  const f = await fixture();
  try {
    f.cipher('org-with-attachment');
    f.adapter.sqlite.prepare(`INSERT INTO ciphers(id,user_id,type,data,created_at,updated_at) VALUES('personal-item',?,1,'{}',?,?)`).run(f.owner.id, initial, initial);
    f.adapter.sqlite.exec(`INSERT INTO attachments(id,cipher_id,file_name,size,size_name,key)
      VALUES('org-file','org-with-attachment','encrypted',1,'1 B','key'),('personal-file','personal-item','encrypted',1,'1 B','key')`);
    const deleted: string[] = [];
    f.env.ATTACHMENTS = {async delete(key: string) {
      assert.equal(f.adapter.sqlite.prepare('SELECT COUNT(*) AS n FROM organizations WHERE id = ?').get(f.orgId)!.n, 0);
      deleted.push(key);
    }} as unknown as R2Bucket;
    assert.equal((await f.route(f.owner, `/api/organizations/${f.orgId}`, 'DELETE', {masterPasswordHash: 'wrong'})).status, 400);
    assert.deepEqual(deleted, []);
    const originalBatch = f.adapter.batch.bind(f.adapter);
    f.adapter.batch = async (statements) => {
      // Appears after handler preflight but before the atomic metadata snapshot.
      f.adapter.sqlite.exec(`INSERT INTO attachments(id,cipher_id,file_name,size,size_name,key)
        VALUES('late-file','org-with-attachment','encrypted',1,'1 B','key')`);
      return originalBatch(statements);
    };
    assert.equal((await f.route(f.owner, `/api/organizations/${f.orgId}`, 'DELETE', {masterPasswordHash: 'hash'})).status, 204);
    assert.deepEqual(deleted.sort(), ['org-with-attachment/late-file', 'org-with-attachment/org-file']);
    assert.ok(f.adapter.sqlite.prepare('SELECT id FROM attachments WHERE id = ?').get('personal-file'));
  } finally { f.adapter.close(); }
});

test('organization revisions stay monotonic and delayed outboxes use the current user revision', async () => {
  const f = await fixture();
  try {
    const future = '2099-01-01T00:00:00.000Z';
    f.adapter.sqlite.prepare('UPDATE user_revisions SET revision_date = ? WHERE user_id = ?').run(future, f.owner.id);
    assert.equal((await f.route(f.owner, `/api/organizations/${f.orgId}`, 'PUT', {name: 'changed'})).status, 200);
    const current = f.adapter.sqlite.prepare('SELECT revision_date FROM user_revisions WHERE user_id = ?').get(f.owner.id)!.revision_date as string;
    assert.ok(current > future);
    const observed: string[] = [];
    await flushOrganizationNotifications(notificationEnv(f, async (request, userId) => {
      const body = await request.json() as {revisionDate: string};
      if (userId === f.owner.id) observed.push(body.revisionDate);
      return new Response(null, {status: 204});
    }));
    assert.ok(observed.length >= 2); assert.ok(observed.every((date) => date === current));
  } finally { f.adapter.close(); }
});

test('bulk lifecycle endpoints preserve last-owner safety and return per-member errors', async () => {
  const f = await fixture();
  try {
    f.adapter.sqlite.prepare('UPDATE organization_members SET type = 0 WHERE id = ?').run(f.adminId);
    const result = await (await f.route(f.owner, `/api/organizations/${f.orgId}/users`, 'DELETE', {Ids: [f.ownerId, f.adminId]})).json() as {data: {id: string; error: string}[]};
    assert.equal(result.data[0].error, ''); assert.ok(result.data[1].error);
    assert.equal(f.adapter.sqlite.prepare('SELECT COUNT(*) AS n FROM organization_members WHERE organization_id = ? AND type = 0 AND status = 2').get(f.orgId)!.n, 1);
    assert.equal((await f.route(f.admin, `/api/organizations/${f.orgId}/users/revoke`, 'PUT', {ids: [f.readerId]})).status, 200);
    assert.equal((await f.route(f.admin, `/api/organizations/${f.orgId}/users/restore`, 'PUT', {ids: [f.readerId]})).status, 200);
    const confirm = await (await f.route(f.admin, `/api/organizations/${f.orgId}/users/confirm`, 'POST', {keys: [{id: f.readerId, key: 'bulk-encrypted-key'}, {id: 'unknown', key: 'unused'}]})).json() as {data: {error: string}[]};
    assert.equal(confirm.data[0].error, ''); assert.ok(confirm.data[1].error);
    assert.equal((await getProfileOrganizations(f.adapter.db, f.reader.id))[0].key, 'bulk-encrypted-key');
  } finally { f.adapter.close(); }
});

test('missing organization keys can be provisioned once by an owner without exposing user keys', async () => {
  const f = await fixture();
  try {
    f.adapter.sqlite.prepare('UPDATE organizations SET public_key = NULL, private_key = NULL WHERE id = ?').run(f.orgId);
    const path = `/api/organizations/${f.orgId}/keys`;
    assert.equal((await f.route(f.admin, path, 'POST', {publicKey: 'org-rsa-public', encryptedPrivateKey: 'org-rsa-private-encrypted'})).status, 403);
    assert.equal((await f.route(f.owner, path, 'POST', {publicKey: 'org-rsa-public', encryptedPrivateKey: 'org-rsa-private-encrypted'})).status, 200);
    assert.equal((await f.route(f.owner, path, 'POST', {publicKey: 'replacement', encryptedPrivateKey: 'replacement'})).status, 409);
    assert.equal((await f.route(f.reader, path)).status, 403);
    assert.deepEqual(await (await f.route(f.admin, path)).json(), {publicKey: 'org-rsa-public', encryptedPrivateKey: 'org-rsa-private-encrypted', object: 'organizationKeys'});
  } finally { f.adapter.close(); }
});

test('atomic recipient snapshot includes a user who accepted between preflight lookup and deletion', async () => {
  const f = await fixture();
  try {
    const accepted = f.user('race-accepted');
    const invitation = await (await f.route(f.owner, `/api/organizations/${f.orgId}/users/invite`, 'POST', {emails: [accepted.email], type: 2})).json() as {data: {id: string}[]};
    const id = invitation.data[0].id;
    f.adapter.sqlite.exec('DELETE FROM config WHERE key LIKE \'organization.sync.%\'; DELETE FROM user_revisions;');
    const originalBatch = f.adapter.batch.bind(f.adapter);
    f.adapter.batch = async (statements) => {
      f.adapter.sqlite.prepare('UPDATE organization_members SET user_id = ?,status = 1 WHERE id = ?').run(accepted.id, id);
      return originalBatch(statements);
    };
    assert.equal((await f.route(f.admin, `/api/organizations/${f.orgId}/users/${id}`, 'DELETE')).status, 204);
    assert.ok(f.adapter.sqlite.prepare('SELECT user_id FROM user_revisions WHERE user_id = ?').get(accepted.id));
  } finally { f.adapter.close(); }
});

test('a failed permission predicate leaves no outbox rows or user revision side effects', async () => {
  const f = await fixture();
  try {
    f.adapter.sqlite.exec('DELETE FROM config WHERE key LIKE \'organization.sync.%\'; DELETE FROM user_revisions;');
    assert.equal(await commitOrganizationMutation(f.adapter.db, {organizationId: f.orgId, actorUserId: f.outsider.id, eventType: 1601, targetId: f.orgId,
      sql: 'UPDATE organizations SET name = ? WHERE id = ? AND 0', bindings: ['Forbidden', f.orgId]}), false);
    assert.equal(f.adapter.sqlite.prepare('SELECT COUNT(*) AS n FROM user_revisions').get()!.n, 0);
    assert.equal(f.adapter.sqlite.prepare('SELECT COUNT(*) AS n FROM config WHERE key LIKE \'organization.sync.%\'').get()!.n, 0);
  } finally { f.adapter.close(); }
});

function notificationEnv(f: Awaited<ReturnType<typeof fixture>>, deliver: (request: Request, userId: string) => Promise<Response>): Env {
  return {DB: f.adapter.db, NOTIFICATIONS_HUB: {
    idFromName(name: string) { return name; },
    get(name: string) { return {fetch(input: RequestInfo | URL, init?: RequestInit) { return deliver(new Request(input, init), name); }}; },
  }} as unknown as Env;
}

test('organization outbox acknowledges both vault and cipher broadcasts before removing recipients', async () => {
  const f = await fixture();
  try {
    const messages: {userId: string; updateType: number}[] = [];
    const env = notificationEnv(f, async (request, userId) => {
      assert.equal(new URL(request.url).pathname, '/internal/notify');
      assert.equal(request.headers.get('X-NodeWarden-UserId'), userId);
      const body = await request.json() as {updateType: number; payload: {UserId: string}};
      assert.equal(body.payload.UserId, userId); messages.push({userId, updateType: body.updateType});
      return new Response(null, {status: 204});
    });
    await flushOrganizationNotifications(env);
    assert.deepEqual(messages, [{userId: f.owner.id, updateType: 5}, {userId: f.owner.id, updateType: 4}]);
    assert.equal(f.adapter.sqlite.prepare('SELECT COUNT(*) AS n FROM config WHERE key LIKE \'organization.sync.%\'').get()!.n, 0);
  } finally { f.adapter.close(); }
});

test('notification failures remain durable for retry and partial broadcasts can be repeated safely', async () => {
  const f = await fixture();
  try {
    let successful = false; const messages: number[] = [];
    const env = notificationEnv(f, async (request) => {
      const body = await request.json() as {updateType: number}; messages.push(body.updateType);
      return new Response(null, {status: successful || body.updateType === 5 ? 204 : 503});
    });
    await flushOrganizationNotifications(env);
    assert.equal(f.adapter.sqlite.prepare('SELECT COUNT(*) AS n FROM config WHERE key LIKE \'organization.sync.%\'').get()!.n, 1);
    successful = true; await flushOrganizationNotifications(env);
    assert.deepEqual(messages, [5, 4, 5, 4]);
    assert.equal(f.adapter.sqlite.prepare('SELECT COUNT(*) AS n FROM config WHERE key LIKE \'organization.sync.%\'').get()!.n, 0);
  } finally { f.adapter.close(); }
});

test('notification fanout checkpoints large memberships and rejects forged stored recipient ids', async () => {
  const f = await fixture();
  try {
    for (let i = 0; i < 12; i++) f.membership(f.user(`extra-${i}`));
    f.adapter.sqlite.exec('DELETE FROM config WHERE key LIKE \'organization.sync.%\';');
    assert.equal((await f.route(f.owner, `/api/organizations/${f.orgId}`, 'PUT', {name: 'Changed'})).status, 200);
    const recipients = new Set<string>();
    const env = notificationEnv(f, async (_request, userId) => {recipients.add(userId); return new Response(null, {status: 204});});
    await flushOrganizationNotifications(env);
    assert.equal(recipients.size, 8);
    let row = f.adapter.sqlite.prepare('SELECT value FROM config WHERE key LIKE \'organization.sync.%\'').get()!;
    assert.equal((JSON.parse(row.value as string) as {userIds: string[]}).userIds.length, 7);
    await flushOrganizationNotifications(env); assert.equal(recipients.size, 15);
    assert.equal(f.adapter.sqlite.prepare('SELECT COUNT(*) AS n FROM config WHERE key LIKE \'organization.sync.%\'').get()!.n, 0);
    f.adapter.sqlite.prepare('INSERT INTO config(key,value) VALUES(?,?)').run('organization.sync.00000000-0000-0000-0000-000000000001',
      JSON.stringify({organizationId: f.orgId, revisionDate: initial, userIds: ['bad\r\nheader']}));
    await flushOrganizationNotifications(env); assert.equal(recipients.size, 15);
    row = f.adapter.sqlite.prepare('SELECT value FROM config WHERE key LIKE \'organization.sync.%\'').get()!;
    assert.ok(row);
  } finally { f.adapter.close(); }
});

test('organization notification drain delivers all fifteen recipients without another mutation or cron', async () => {
  const f = await fixture();
  try {
    for (let i = 0; i < 12; i++) f.membership(f.user(`drain-${i}`));
    f.adapter.sqlite.exec('DELETE FROM config WHERE key LIKE \'organization.sync.%\';');
    assert.equal((await f.route(f.owner, `/api/organizations/${f.orgId}`, 'PUT', {name: 'Drain'})).status, 200);
    const messages: {userId: string; updateType: number}[] = [];
    const env = notificationEnv(f, async (request, userId) => {
      messages.push({userId, updateType: (await request.json() as {updateType: number}).updateType});
      return new Response(null, {status: 204});
    });
    const progress = await drainOrganizationNotifications(env);
    assert.deepEqual(progress, {attemptedRecipients: 15, completedRecipients: 15, checkpointedRows: 2, failures: 0, hasBacklog: false});
    assert.equal(new Set(messages.map((message) => message.userId)).size, 15);
    assert.equal(messages.length, 30);
    for (const userId of new Set(messages.map((message) => message.userId))) {
      assert.deepEqual(messages.filter((message) => message.userId === userId).map((message) => message.updateType), [5, 4]);
    }
    assert.equal(f.adapter.sqlite.prepare('SELECT COUNT(*) AS n FROM config WHERE key LIKE \'organization.sync.%\'').get()!.n, 0);
  } finally { f.adapter.close(); }
});

test('notification drain stops after failure despite prior progress and retries only on a later invocation', async () => {
  const f = await fixture();
  try {
    const recipients = [f.owner.id, f.admin.id, f.reader.id];
    for (let i = 0; i < 12; i++) recipients.push(f.user(`retry-${i}`).id);
    const row = f.adapter.sqlite.prepare('SELECT key,value FROM config WHERE key LIKE \'organization.sync.%\'').get()!;
    f.adapter.sqlite.prepare('UPDATE config SET value = ? WHERE key = ?')
      .run(JSON.stringify({...JSON.parse(row.value as string), userIds: recipients}), row.key as string);
    let healthy = false; const messages: string[] = [];
    const env = notificationEnv(f, async (_request, userId) => {
      messages.push(userId);
      return new Response(null, {status: userId === f.admin.id && !healthy ? 503 : 204});
    });
    const progress = await drainOrganizationNotifications(env);
    assert.deepEqual(progress, {attemptedRecipients: 2, completedRecipients: 1, checkpointedRows: 1, failures: 1, hasBacklog: true});
    assert.deepEqual(messages, [f.owner.id, f.owner.id, f.admin.id]);
    const pending = f.adapter.sqlite.prepare('SELECT value FROM config WHERE key = ?').get(row.key as string)!;
    assert.deepEqual(JSON.parse(pending.value as string).userIds, recipients.slice(1));
    healthy = true;
    const retried = await drainOrganizationNotifications(env);
    assert.equal(retried.completedRecipients, 14); assert.equal(retried.hasBacklog, false);
  } finally { f.adapter.close(); }
});

test('notification drain does not erase concurrent outbox changes or repeat after a failed CAS', async () => {
  const f = await fixture();
  try {
    const row = f.adapter.sqlite.prepare('SELECT key,value FROM config WHERE key LIKE \'organization.sync.%\'').get()!;
    const event = {...JSON.parse(row.value as string), userIds: [f.owner.id, f.outsider.id]};
    const originalBatch = f.adapter.batch.bind(f.adapter);
    f.adapter.batch = async (statements) => {
      f.adapter.sqlite.prepare('UPDATE config SET value = ? WHERE key = ?').run(JSON.stringify(event), row.key as string);
      return originalBatch(statements);
    };
    const messages: string[] = [];
    const env = notificationEnv(f, async (_request, userId) => {messages.push(userId); return new Response(null, {status: 204});});
    const progress = await drainOrganizationNotifications(env);
    assert.deepEqual(progress, {attemptedRecipients: 1, completedRecipients: 0, checkpointedRows: 0, failures: 0, hasBacklog: true});
    assert.deepEqual(messages, [f.owner.id, f.owner.id]);
    assert.deepEqual(JSON.parse(f.adapter.sqlite.prepare('SELECT value FROM config WHERE key = ?').get(row.key as string)!.value as string), event);
    f.adapter.batch = originalBatch;
    const retried = await drainOrganizationNotifications(env);
    assert.equal(retried.completedRecipients, 2); assert.equal(retried.hasBacklog, false);
  } finally { f.adapter.close(); }
});

test('notification drain checkpoints deleted users without delivery and bounds large backlogs', async () => {
  const f = await fixture();
  try {
    const recipients = [f.owner.id];
    for (let i = 0; i < 39; i++) recipients.push(f.user(`budget-${i}`).id);
    f.adapter.sqlite.prepare('DELETE FROM users WHERE id = ?').run(recipients[1]);
    const row = f.adapter.sqlite.prepare('SELECT key,value FROM config WHERE key LIKE \'organization.sync.%\'').get()!;
    f.adapter.sqlite.prepare('UPDATE config SET value = ? WHERE key = ?')
      .run(JSON.stringify({...JSON.parse(row.value as string), userIds: recipients}), row.key as string);
    const notified = new Set<string>();
    const env = notificationEnv(f, async (_request, userId) => {notified.add(userId); return new Response(null, {status: 204});});
    const progress = await drainOrganizationNotifications(env);
    assert.deepEqual(progress, {attemptedRecipients: 32, completedRecipients: 32, checkpointedRows: 4, failures: 0, hasBacklog: true});
    assert.equal(notified.size, 31); assert.equal(notified.has(recipients[1]), false);
    assert.deepEqual(JSON.parse(f.adapter.sqlite.prepare('SELECT value FROM config WHERE key = ?').get(row.key as string)!.value as string).userIds, recipients.slice(32));
    const later = await drainOrganizationNotifications(env);
    assert.equal(later.completedRecipients, 8); assert.equal(later.hasBacklog, false); assert.equal(notified.size, 39);
  } finally { f.adapter.close(); }
});

test('notification drain respects its soft deadline between recipients and batches', async () => {
  const f = await fixture();
  const originalNow = Date.now;
  try {
    const recipients = [f.owner.id];
    for (let i = 0; i < 14; i++) recipients.push(f.user(`deadline-${i}`).id);
    const row = f.adapter.sqlite.prepare('SELECT key,value FROM config WHERE key LIKE \'organization.sync.%\'').get()!;
    f.adapter.sqlite.prepare('UPDATE config SET value = ? WHERE key = ?')
      .run(JSON.stringify({...JSON.parse(row.value as string), userIds: recipients}), row.key as string);
    let now = originalNow();
    Date.now = () => now;
    const env = notificationEnv(f, async () => {now += 10_001; return new Response(null, {status: 204});});
    const progress = await drainOrganizationNotifications(env);
    assert.deepEqual(progress, {attemptedRecipients: 1, completedRecipients: 1, checkpointedRows: 1, failures: 0, hasBacklog: true});
    assert.deepEqual(JSON.parse(f.adapter.sqlite.prepare('SELECT value FROM config WHERE key = ?').get(row.key as string)!.value as string).userIds, recipients.slice(1));
  } finally { Date.now = originalNow; f.adapter.close(); }
});

test('notification drain stops without progress on an invalid event instead of repeatedly scanning it', async () => {
  const f = await fixture();
  try {
    f.adapter.sqlite.prepare('UPDATE config SET value = ? WHERE key LIKE ?')
      .run(JSON.stringify({organizationId: f.orgId, revisionDate: initial, userIds: ['invalid\r\nheader']}), 'organization.sync.%');
    let queries = 0;
    const originalPrepare = f.adapter.prepare.bind(f.adapter);
    f.adapter.prepare = (sql) => {queries++; return originalPrepare(sql);};
    const env = notificationEnv(f, async () => {assert.fail('Malformed events must never be delivered');});
    const progress = await drainOrganizationNotifications(env);
    assert.deepEqual(progress, {attemptedRecipients: 0, completedRecipients: 0, checkpointedRows: 0, failures: 0, hasBacklog: true});
    assert.equal(queries, 2);
  } finally { f.adapter.close(); }
});

test('inactive users cannot create ownerless organizations', async () => {
  const f = await fixture();
  try {
    f.adapter.sqlite.prepare('UPDATE users SET status = \'banned\' WHERE id = ?').run(f.outsider.id);
    const count = f.adapter.sqlite.prepare('SELECT COUNT(*) AS n FROM organizations').get()!.n;
    assert.equal((await f.route(f.outsider, '/api/organizations', 'POST', {name: 'Blocked', billingEmail: f.outsider.email, key: 'key', collectionName: 'encrypted'})).status, 409);
    assert.equal(f.adapter.sqlite.prepare('SELECT COUNT(*) AS n FROM organizations').get()!.n, count);
  } finally { f.adapter.close(); }
});
