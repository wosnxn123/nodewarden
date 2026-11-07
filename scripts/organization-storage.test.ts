import assert from 'node:assert/strict';
import test from 'node:test';
import { SqliteD1 } from './helpers/sqlite-d1';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { createOrganization } from '../src/services/organization-repo';
import {
  createOrganizationCipher,
  sharePersonalCipher,
  replaceCipherCollections,
} from '../src/services/cipher-sharing';
import {
  getCipherForUser,
  getAllCiphers,
  getCiphersPage,
  saveCipher,
  updateCipherIfUnchanged,
  deleteCipher,
  saveCipherPreferences,
  bulkSoftDeleteCiphers,
  bulkRestoreCiphers,
  bulkUnarchiveCiphers,
  bulkArchiveCiphers,
  bulkMoveCiphers,
} from '../src/services/storage-cipher-repo';
import type { Attachment, Cipher } from '../src/types';

const initial = '2020-01-01T00:00:00.000Z';
const bind = (statement: D1PreparedStatement, ...values: unknown[]) =>
  statement.bind(...values.map((value) => value ?? null));
function cipher(id: string, organizationId: string | null = null): Cipher {
  return {
    id,
    userId: organizationId ? null : 'owner',
    organizationId,
    type: 1,
    folderId: null,
    name: 'encrypted-name',
    notes: null,
    favorite: false,
    login: null,
    card: null,
    identity: null,
    secureNote: null,
    sshKey: null,
    fields: null,
    passwordHistory: null,
    reprompt: 0,
    key: 'encrypted-item-key',
    createdAt: initial,
    updatedAt: initial,
    archivedAt: null,
    deletedAt: null,
  };
}
async function fixture() {
  const adapter = new SqliteD1();
  await ensureStorageSchema(adapter.db);
  for (const id of ['owner', 'reader', 'outsider'])
    adapter.sqlite
      .prepare(
        `INSERT INTO users(id,email,master_password_hash,key,public_key,kdf_type,kdf_iterations,security_stamp,created_at,updated_at)
    VALUES(?,?,'hash','wrapped-user','public',0,600000,'stamp',?,?)`
      )
      .run(id, `${id}@example.test`, initial, initial);
  const org = await createOrganization(adapter.db, 'owner', {
    name: 'Team',
    billingEmail: 'owner@example.test',
    key: 'wrapped-org',
    publicKey: 'public',
    privateKey: 'private',
    collectionName: 'collection',
  });
  const collection = adapter.sqlite
    .prepare('SELECT id FROM collections WHERE organization_id=?')
    .get(org.id)!.id as string;
  adapter.sqlite
    .prepare(
      `INSERT INTO organization_members(id,organization_id,user_id,email,type,status,access_all,key,created_at,updated_at)
    VALUES('reader-member',?,'reader','reader@example.test',2,2,0,'wrapped',?,?)`
    )
    .run(org.id, initial, initial);
  adapter.sqlite
    .prepare(
      "INSERT INTO collection_users(collection_id,member_id,read_only,hide_passwords,manage) VALUES(?,'reader-member',1,1,0)"
    )
    .run(collection);
  return { adapter, db: adapter.db, org: org.id, collection };
}

test('organization create is atomic and reads project relational permissions and user preferences', async (t) => {
  const f = await fixture();
  t.after(() => f.adapter.close());
  const shared = cipher('shared', f.org);
  assert.equal(
    await createOrganizationCipher(f.db, shared, 'owner', [f.collection]),
    true
  );
  const owner = await getCipherForUser(f.db, 'shared', 'owner'),
    reader = await getCipherForUser(f.db, 'shared', 'reader');
  assert.equal(owner?.edit, true);
  assert.equal(reader?.edit, false);
  assert.equal(reader?.viewPassword, false);
  assert.deepEqual(reader?.collectionIds, [f.collection]);
  assert.equal(reader?.userId, null);
  assert.equal(await getCipherForUser(f.db, 'shared', 'outsider'), null);
  assert.equal((await getAllCiphers(f.db, 'reader')).length, 1);
  assert.equal((await getCiphersPage(f.db, 'reader', false, 2, 0)).length, 1);
  assert.equal(
    await saveCipherPreferences(f.db, 'shared', 'reader', null, true),
    true
  );
  assert.equal(
    (await getCipherForUser(f.db, 'shared', 'reader'))?.favorite,
    true
  );
  assert.equal(
    (await getCipherForUser(f.db, 'shared', 'owner'))?.favorite,
    false
  );
  assert.equal(
    await updateCipherIfUnchanged(
      f.db,
      bind,
      { ...reader!, name: 'changed', updatedAt: '2021-01-01T00:00:00.000Z' },
      initial,
      'reader'
    ),
    false
  );
  assert.equal(await deleteCipher(f.db, 'shared', 'reader'), false);
});

test('personal opaque authority fields never grant ownership, groups or permissions', async (t) => {
  const f = await fixture();
  t.after(() => f.adapter.close());
  await saveCipher(f.db, bind, {
    ...cipher('personal'),
    OrganizationId: f.org,
    collectionIds: [f.collection],
    edit: false,
    permissions: { delete: false },
    futureField: { opaque: true },
  });
  const own = await getCipherForUser(f.db, 'personal', 'owner');
  assert.equal(own?.organizationId, null);
  assert.equal(own?.edit, true);
  assert.deepEqual(own?.collectionIds, []);
  assert.deepEqual(own?.futureField, { opaque: true });
  assert.equal(await getCipherForUser(f.db, 'personal', 'reader'), null);
});

test('legacy JSON-only encryption and state fields remain readable and clearable', async (t) => {
  const f = await fixture();
  t.after(() => f.adapter.close());
  f.adapter.sqlite
    .prepare(
      'INSERT INTO folders(id,user_id,name,created_at,updated_at) VALUES(?,?,?,?,?)'
    )
    .run('legacy-folder', 'owner', 'folder', initial, initial);
  const data = JSON.stringify({
    key: 'legacy-key',
    name: 'legacy-name',
    notes: 'legacy-notes',
    folderId: 'legacy-folder',
    favorite: true,
    reprompt: 1,
    archivedDate: initial,
    deletedDate: initial,
    organizationId: f.org,
  });
  f.adapter.sqlite
    .prepare(
      'INSERT INTO ciphers(id,user_id,type,data,favorite,reprompt,created_at,updated_at) VALUES(?,?,1,?,0,NULL,?,?)'
    )
    .run('legacy', 'owner', data, initial, initial);
  const legacy = (await getCipherForUser(f.db, 'legacy', 'owner'))!;
  assert.equal(legacy.key, 'legacy-key');
  assert.equal(legacy.notes, 'legacy-notes');
  assert.equal(legacy.folderId, 'legacy-folder');
  assert.equal(legacy.favorite, false);
  assert.equal(legacy.reprompt, 1);
  assert.equal(legacy.organizationId, null);
  assert.equal(
    (await getCiphersPage(f.db, 'owner', false, 20, 0)).some(
      (item) => item.id === 'legacy'
    ),
    false
  );
  const revise = async () => new Date().toISOString();
  assert.equal(
    await bulkArchiveCiphers(f.db, () => 50, revise, ['legacy'], 'owner'),
    null,
    'cannot archive an item deleted in legacy JSON'
  );
  await bulkRestoreCiphers(f.db, () => 50, revise, ['legacy'], 'owner');
  assert.equal(
    (await getCipherForUser(f.db, 'legacy', 'owner'))!.deletedAt,
    null
  );
  assert.equal(
    (await getCiphersPage(f.db, 'owner', false, 20, 0)).some(
      (item) => item.id === 'legacy'
    ),
    true
  );
  await bulkUnarchiveCiphers(f.db, () => 50, revise, ['legacy'], 'owner');
  assert.equal(
    (await getCipherForUser(f.db, 'legacy', 'owner'))!.archivedAt,
    null
  );
  await bulkMoveCiphers(f.db, () => 50, revise, ['legacy'], null, 'owner');
  const moved = (await getCipherForUser(f.db, 'legacy', 'owner'))!;
  assert.equal(moved.folderId, null);
  assert.equal(moved.key, 'legacy-key');
});

test('sharing validates destination, expected revision and entire attachment snapshot atomically', async (t) => {
  const f = await fixture();
  t.after(() => f.adapter.close());
  await saveCipher(f.db, bind, cipher('personal'));
  f.adapter.sqlite
    .prepare(
      "INSERT INTO attachments(id,cipher_id,file_name,size,size_name,key) VALUES('a','personal','old',1,'1 B','old-key')"
    )
    .run();
  const attachment: Attachment = {
    id: 'a',
    cipherId: 'personal',
    fileName: 'new',
    key: 'new-key',
    size: 1,
    sizeName: '1 B',
  };
  const next = {
    ...cipher('personal', f.org),
    name: 'org-encrypted',
    key: 'org-wrapped',
    updatedAt: '2021-01-01T00:00:00.000Z',
  };
  const original = {
    cipher: (await getCipherForUser(f.db, 'personal', 'owner'))!,
    attachments: [{ ...attachment, fileName: 'old', key: 'old-key' }],
  };
  assert.equal(
    await sharePersonalCipher(
      f.db,
      next,
      'owner',
      'bad-revision',
      [f.collection],
      [attachment],
      original
    ),
    false
  );
  assert.equal(
    await sharePersonalCipher(
      f.db,
      next,
      'owner',
      initial,
      [f.collection],
      [],
      original
    ),
    false
  );
  assert.equal(
    await sharePersonalCipher(
      f.db,
      next,
      'outsider',
      initial,
      [f.collection],
      [attachment],
      original
    ),
    false
  );
  assert.equal(
    (await getCipherForUser(f.db, 'personal', 'owner'))?.organizationId,
    null
  );
  assert.equal(
    await sharePersonalCipher(
      f.db,
      next,
      'owner',
      initial,
      ['nonexistent'],
      [attachment],
      original
    ),
    false
  );
  assert.equal(
    await sharePersonalCipher(
      f.db,
      next,
      'owner',
      initial,
      [f.collection],
      [attachment],
      original
    ),
    true
  );
  assert.equal(
    (await getCipherForUser(f.db, 'personal', 'reader'))?.organizationId,
    f.org
  );
  assert.equal(
    f.adapter.sqlite.prepare("SELECT key FROM attachments WHERE id='a'").get()!
      .key,
    'new-key'
  );
  assert.equal(
    await sharePersonalCipher(
      f.db,
      next,
      'owner',
      next.updatedAt,
      [f.collection],
      [attachment],
      original
    ),
    false
  );
});

test('sharing refuses source repairs which intentionally preserve revision timestamps', async (t) => {
  const f = await fixture();
  t.after(() => f.adapter.close());
  await saveCipher(f.db, bind, cipher('personal'));
  f.adapter.sqlite
    .prepare(
      "INSERT INTO attachments(id,cipher_id,file_name,size,size_name,key) VALUES('a','personal','old',1,'1 B','old-key')"
    )
    .run();
  const attachment: Attachment = {
    id: 'a',
    cipherId: 'personal',
    fileName: 'old',
    key: 'old-key',
    size: 1,
    sizeName: '1 B',
  };
  const original = {
    cipher: (await getCipherForUser(f.db, 'personal', 'owner'))!,
    attachments: [attachment],
  };
  const next = {
    ...cipher('personal', f.org),
    name: 'shared',
    updatedAt: '2022-01-01T00:00:00.000Z',
  };
  f.adapter.sqlite
    .prepare("UPDATE ciphers SET key='repaired-key' WHERE id='personal'")
    .run();
  assert.equal(
    await sharePersonalCipher(
      f.db,
      next,
      'owner',
      initial,
      [f.collection],
      [attachment],
      original
    ),
    false
  );
  f.adapter.sqlite
    .prepare("UPDATE ciphers SET key='encrypted-item-key' WHERE id='personal'")
    .run();
  f.adapter.sqlite
    .prepare(
      "UPDATE attachments SET key='repaired-attachment-key' WHERE id='a'"
    )
    .run();
  assert.equal(
    await sharePersonalCipher(
      f.db,
      next,
      'owner',
      initial,
      [f.collection],
      [attachment],
      original
    ),
    false
  );
  assert.equal(
    (await getCipherForUser(f.db, 'personal', 'owner'))?.organizationId,
    null
  );
  assert.equal(
    f.adapter.sqlite.prepare("SELECT key FROM attachments WHERE id='a'").get()!
      .key,
    'repaired-attachment-key'
  );
});

test('CAS binds all attachment updates, emits organization revisions and cannot recreate deleted ciphers', async (t) => {
  const f = await fixture();
  t.after(() => f.adapter.close());
  await createOrganizationCipher(f.db, cipher('shared', f.org), 'owner', [
    f.collection,
  ]);
  f.adapter.sqlite
    .prepare(
      "INSERT INTO attachments(id,cipher_id,file_name,size,size_name,key) VALUES('a','shared','old',1,'1 B','old')"
    )
    .run();
  const next = {
    ...(await getCipherForUser(f.db, 'shared', 'owner'))!,
    updatedAt: '2022-01-01T00:00:00.000Z',
    name: 'new-name',
  };
  const attachments: Attachment[] = [
    {
      id: 'a',
      cipherId: 'shared',
      fileName: 'new',
      key: 'new',
      size: 1,
      sizeName: '1 B',
    },
  ];
  assert.equal(
    await updateCipherIfUnchanged(
      f.db,
      bind,
      next,
      'bad',
      'owner',
      attachments
    ),
    false
  );
  assert.equal(
    f.adapter.sqlite.prepare("SELECT key FROM attachments WHERE id='a'").get()!
      .key,
    'old'
  );
  assert.equal(
    await updateCipherIfUnchanged(
      f.db,
      bind,
      next,
      initial,
      'owner',
      attachments
    ),
    true
  );
  assert.equal(
    f.adapter.sqlite.prepare("SELECT key FROM attachments WHERE id='a'").get()!
      .key,
    'new'
  );
  assert.ok(
    f.adapter.sqlite
      .prepare(
        "SELECT revision_date FROM user_revisions WHERE user_id='reader'"
      )
      .get()
  );
  assert.equal(await deleteCipher(f.db, 'shared', 'owner'), true);
  assert.equal(
    await updateCipherIfUnchanged(
      f.db,
      bind,
      next,
      next.updatedAt,
      'owner',
      attachments
    ),
    false
  );
});

test('collection reassignment preserves invisible links and unchanged read-only links', async (t) => {
  const f = await fixture();
  t.after(() => f.adapter.close());
  f.adapter.sqlite
    .prepare('INSERT INTO collections(id,organization_id,name) VALUES(?,?,?)')
    .run('write-col', f.org, 'write');
  f.adapter.sqlite
    .prepare('INSERT INTO collections(id,organization_id,name) VALUES(?,?,?)')
    .run('hidden-col', f.org, 'hidden');
  f.adapter.sqlite
    .prepare(
      "INSERT INTO collection_users(collection_id,member_id,read_only,hide_passwords,manage) VALUES('write-col','reader-member',0,0,0)"
    )
    .run();
  await createOrganizationCipher(f.db, cipher('shared', f.org), 'owner', [
    f.collection,
    'write-col',
    'hidden-col',
  ]);
  const before = (await getCipherForUser(f.db, 'shared', 'reader'))!;
  assert.equal(
    await replaceCipherCollections(f.db, 'reader', before, [
      f.collection,
      'write-col',
    ]),
    true
  );
  assert.equal(
    f.adapter.sqlite
      .prepare(
        "SELECT count(*) n FROM cipher_collections WHERE cipher_id='shared' AND collection_id='hidden-col'"
      )
      .get()!.n,
    1
  );
  const latest = (await getCipherForUser(f.db, 'shared', 'reader'))!;
  assert.equal(
    await replaceCipherCollections(f.db, 'reader', latest, ['write-col']),
    false,
    'cannot remove a read-only collection'
  );
  assert.equal(
    await replaceCipherCollections(f.db, 'reader', latest, [
      f.collection,
      'write-col',
      'hidden-col',
    ]),
    false,
    'cannot explicitly assign an inaccessible collection'
  );
  assert.deepEqual(
    (await getCipherForUser(f.db, 'shared', 'owner'))!.collectionIds.sort(),
    [f.collection, 'write-col', 'hidden-col'].sort()
  );
});

test('revoked access and stale collection updates cannot mutate shared data', async (t) => {
  const f = await fixture();
  t.after(() => f.adapter.close());
  await createOrganizationCipher(f.db, cipher('shared', f.org), 'owner', [
    f.collection,
  ]);
  const before = (await getCipherForUser(f.db, 'shared', 'owner'))!;
  assert.equal(
    await replaceCipherCollections(f.db, 'owner', before, [f.collection]),
    true
  );
  assert.equal(
    await replaceCipherCollections(f.db, 'owner', before, []),
    false
  );
  f.adapter.sqlite
    .prepare(
      "UPDATE organization_members SET status=-1,key=NULL WHERE id='reader-member'"
    )
    .run();
  assert.equal(await getCipherForUser(f.db, 'shared', 'reader'), null);
  assert.equal(
    await saveCipherPreferences(f.db, 'shared', 'reader', null, true),
    false
  );
  assert.equal(
    await bulkSoftDeleteCiphers(
      f.db,
      () => 50,
      async () => {
        throw new Error('Unexpected revision');
      },
      ['shared'],
      'reader'
    ),
    null
  );
});
