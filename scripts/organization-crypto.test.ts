import assert from 'node:assert/strict';
import test from 'node:test';
import { base64ToBytes, bytesToBase64, decryptBw, decryptBwFileData, decryptStr, encryptBw, encryptBwFileData, requireWebCrypto, toBufferSource } from '../webapp/src/lib/crypto';
import { decryptOrganizationKeys, generateOrganizationKeys, getOwnerKeyParts, unwrapOrganizationKey, wrapOrganizationKey } from '../webapp/src/lib/organization-crypto';
import { prepareCipherForSharing, confirmOrganizationMember, shareCipher } from '../webapp/src/lib/api/organizations';
import { decryptVaultCore } from '../webapp/src/lib/vault-decrypt';
import { decryptSingleCipher } from '../webapp/src/lib/decrypt-cipher';
import { buildCipherImportPayload, downloadCipherAttachmentDecrypted, updateCipher, updateCipherPreferences, uploadCipherAttachment } from '../webapp/src/lib/api/vault';
import { draftFromCipher } from '../webapp/src/components/vault/vault-page-helpers';
import type { Cipher, Organization, Profile, SessionState } from '../webapp/src/lib/types';

const cryptoApi = requireWebCrypto();
const randomKey = () => cryptoApi.getRandomValues(new Uint8Array(64));
const encode = (key: Uint8Array) => ({ symEncKey: bytesToBase64(key.slice(0, 32)), symMacKey: bytesToBase64(key.slice(32)) });
const encrypt = (text: string, key: Uint8Array) => encryptBw(new TextEncoder().encode(text), key.slice(0, 32), key.slice(32));
const revision = '2026-11-08T00:00:00.000Z';
async function rsaPair(hash: 'SHA-1' | 'SHA-256' = 'SHA-1') {
  const pair = await cryptoApi.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash }, true, ['encrypt', 'decrypt']);
  return { pair, publicKey: bytesToBase64(new Uint8Array(await cryptoApi.subtle.exportKey('spki', pair.publicKey))), privateBytes: new Uint8Array(await cryptoApi.subtle.exportKey('pkcs8', pair.privateKey)) };
}

 test('organization create generates independent secure RSA-wrapped membership and encrypted org private key', async () => {
  const owner = await rsaPair();
  const generated = await generateOrganizationKeys(owner.publicKey);
  assert.match(generated.key, /^4\.[A-Za-z0-9+/=]+$/);
  assert.equal(base64ToBytes(generated.key.slice(2)).length, 256);
  assert.deepEqual(await unwrapOrganizationKey(generated.key, owner.privateBytes), generated.rawKey);
  const orgPrivate = await decryptBw(generated.keys.encryptedPrivateKey, generated.rawKey.slice(0, 32), generated.rawKey.slice(32));
  await cryptoApi.subtle.importKey('pkcs8', toBufferSource(orgPrivate), { name: 'RSA-OAEP', hash: 'SHA-1' }, false, ['decrypt']);
  const another = await generateOrganizationKeys(owner.publicKey);
  assert.notDeepEqual(another.rawKey, generated.rawKey);
  const stranger = await rsaPair();
  await assert.rejects(unwrapOrganizationKey(generated.key, stranger.privateBytes));
});

 test('SHA256 canonical type3 unwrap works; wrong/malformed EncStrings and non64 keys reject', async () => {
  const owner = await rsaPair('SHA-256');
  const raw = randomKey();
  const encrypted = new Uint8Array(await cryptoApi.subtle.encrypt({ name: 'RSA-OAEP' }, owner.pair.publicKey, toBufferSource(raw)));
  assert.deepEqual(await unwrapOrganizationKey(`3.${bytesToBase64(encrypted)}`, owner.privateBytes), raw);
  await assert.rejects(unwrapOrganizationKey(`4.${bytesToBase64(encrypted)}`, owner.privateBytes));
  await assert.rejects(unwrapOrganizationKey(`4.${bytesToBase64(encrypted)}|bogus`, owner.privateBytes));
  await assert.rejects(wrapOrganizationKey(new Uint8Array(32), owner.publicKey));
});

 test('profile key hydration only uses confirmed membership, drops revoked keys, and never falls back', async () => {
  const user = randomKey(); const orgKey = randomKey(); const owner = await rsaPair();
  const profile = { privateKey: await encryptBw(owner.privateBytes, user.slice(0, 32), user.slice(32)) };
  const organization: Organization = { id: 'org', name: 'Organization', type: 0, status: 2, key: await wrapOrganizationKey(orgKey, owner.publicKey) };
  const session: SessionState = { email: 'owner@example.test', ...encode(user) };
  assert.deepEqual(await decryptOrganizationKeys(profile, [organization], session), { org: bytesToBase64(orgKey) });
  assert.deepEqual(await decryptOrganizationKeys(profile, [{ ...organization, status: 1 }, { ...organization, id: 'revoked', status: -1 }], session), {});
  assert.deepEqual(await decryptOrganizationKeys({ privateKey: 'broken' }, [organization], session), {});
  assert.throws(() => getOwnerKeyParts({ organizationId: 'org' }, session), /Organization key unavailable/);
  const direct: Cipher = { id: 'direct', type: 1, organizationId: 'org', name: await encrypt('Direct legacy org', orgKey), login: { password: await encrypt('secret', orgKey), decPassword: 'stale' } };
  const wrong = await decryptSingleCipher(direct, user.slice(0, 32), user.slice(32), { org: bytesToBase64(randomKey()) });
  assert.equal(wrong.decryptionUnavailable, true); assert.equal(wrong.login?.decPassword, undefined);
});

 test('batch and single decryption use organization owner->item chain; missing or wrong org keys fail closed', async () => {
  const user = randomKey(); const org = randomKey(); const item = randomKey();
  const cipher: Cipher = { id: 'cipher', type: 1, organizationId: 'org', key: await encryptBw(item, org.slice(0, 32), org.slice(32)), name: await encrypt('Shared', item), login: { password: await encrypt('org-secret', item) } };
  const args = { folders: [], ciphers: [cipher], symEncKeyB64: bytesToBase64(user.slice(0, 32)), symMacKeyB64: bytesToBase64(user.slice(32)), organizationKeys: { org: bytesToBase64(org) } };
  const result = await decryptVaultCore(args);
  assert.equal(result.ciphers[0].decName, 'Shared'); assert.equal(result.ciphers[0].login?.decPassword, 'org-secret');
  const single = await decryptSingleCipher(cipher, user.slice(0, 32), user.slice(32), args.organizationKeys);
  assert.equal(single.decName, 'Shared');
  const missing = (await decryptVaultCore({ ...args, organizationKeys: {} })).ciphers[0];
  assert.equal(missing.decryptionUnavailable, true); assert.equal(missing.decName, '');
  const personalEncryptedButOrgOwned = { ...cipher, key: null, name: await encrypt('must-not-use-user-key', user) };
  assert.equal((await decryptVaultCore({ ...args, ciphers: [personalEncryptedButOrgOwned] })).ciphers[0].decName, '');
  const brokenKey = { ...cipher, key: await encryptBw(item, user.slice(0, 32), user.slice(32)) };
  assert.equal((await decryptVaultCore({ ...args, ciphers: [brokenKey] })).ciphers[0].decryptionUnavailable, true);
});

 test('legacy direct share migrates unknown encrypted fields, fido2, history and attachment key without exposing user key', async () => {
  const user = randomKey(); const org = randomKey(); const attachment = randomKey();
  const cipher: Cipher = { id: 'cipher', type: 1, revisionDate: revision, name: await encrypt('Personal', user), notes: await encrypt('Notes', user), login: { password: await encrypt('secret', user), fido2Credentials: [{ credentialId: await encrypt('credential', user), creationDate: revision }], futureField: await encrypt('future', user) }, passwordHistory: [{ password: await encrypt('old', user), lastUsedDate: revision }], attachments: [{ id: 'attachment', fileName: await encrypt('file.txt', user), key: await encryptBw(attachment, user.slice(0, 32), user.slice(32)) }] };
  const session: SessionState = { email: 'owner@example.test', ...encode(user), organizationKeys: { org: bytesToBase64(org) } };
  const shared = await prepareCipherForSharing(cipher, session, 'org', ['collection']);
  assert.equal(shared.organizationId, 'org'); assert.deepEqual(shared.collectionIds, ['collection']);
  const item = await decryptBw(shared.key!, org.slice(0, 32), org.slice(32));
  assert.notDeepEqual(item, user);
  assert.equal(await decryptStr(shared.login?.futureField as string, item.slice(0, 32), item.slice(32)), 'future');
  assert.equal(await decryptStr(shared.login?.fido2Credentials?.[0].credentialId as string, item.slice(0, 32), item.slice(32)), 'credential');
  assert.deepEqual(await decryptBw(shared.attachments![0].key!, item.slice(0, 32), item.slice(32)), attachment);
  const plain = new TextEncoder().encode('attachment payload');
  const blob = await encryptBwFileData(plain, attachment.slice(0, 32), attachment.slice(32));
  assert.deepEqual(await decryptBwFileData(blob, attachment.slice(0, 32), attachment.slice(32)), plain);
  await assert.rejects(prepareCipherForSharing({ ...cipher, attachments: [{ id: 'legacy', key: null }] }, session, 'org', ['collection']), /Repair legacy attachments/);
  await assert.rejects(decryptBw(shared.key!, user.slice(0, 32), user.slice(32)));
});

 test('item-key sharing keeps original item key and rewraps it to org; revision share request exact shape', async () => {
  const user = randomKey(); const org = randomKey(); const item = randomKey();
  const session: SessionState = { email: 'owner@example.test', ...encode(user), organizationKeys: { org: bytesToBase64(org) } };
  const cipher: Cipher = { id: 'cipher', type: 1, revisionDate: revision, key: await encryptBw(item, user.slice(0, 32), user.slice(32)), name: await encrypt('Item', item) };
  let body: Record<string, unknown> = {};
  const shared = await shareCipher(async (path, init) => { assert.equal(path, '/api/ciphers/cipher/share'); assert.equal(init?.method, 'PUT'); body = JSON.parse(String(init?.body)); return new Response(JSON.stringify(body.cipher)); }, session, cipher, 'org', ['collection']);
  assert.equal(body.lastKnownRevisionDate, revision); assert.deepEqual(body.collectionIds, ['collection']);
  assert.deepEqual(await decryptBw(shared.key!, org.slice(0, 32), org.slice(32)), item);
});

 test('confirmation only wraps to server verified accepted member public key', async () => {
  const invitee = await rsaPair(); const org = randomKey(); const user = randomKey();
  const session: SessionState = { email: 'owner@example.test', ...encode(user), organizationKeys: { org: bytesToBase64(org) } };
  const member = { id: 'member', userId: 'user', email: 'invitee@example.test', type: 2, status: 1, accessAll: true, publicKey: 'untrusted-list-value' };
  let sentKey = '';
  await confirmOrganizationMember(async (path, init) => {
    if (path.endsWith('/confirm')) { sentKey = JSON.parse(String(init?.body)).key; return new Response(null, { status: 204 }); }
    return new Response(JSON.stringify({ ...member, publicKey: invitee.publicKey }));
  }, session, 'org', member);
  assert.deepEqual(await unwrapOrganizationKey(sentKey, invitee.privateBytes), org);
});

 test('organization save encrypts to org chain, preserves ownership and rejects missing key or edit=false', async () => {
  const user = randomKey(); const org = randomKey();
  const session: SessionState = { email: 'owner@example.test', ...encode(user), organizationKeys: { org: bytesToBase64(org) } };
  const cipher: Cipher = { id: 'cipher', type: 1, organizationId: 'org', collectionIds: ['collection'], revisionDate: revision, name: await encrypt('Name', org), login: { password: await encrypt('old', org), decPassword: 'old' }, decName: 'Name' };
  const draft = draftFromCipher(cipher); draft.loginPassword = 'new';
  let payload: Cipher | undefined;
  const fetcher = async (_path: string, init?: RequestInit) => { payload = JSON.parse(String(init?.body)); return new Response(JSON.stringify(payload)); };
  await updateCipher(fetcher, session, cipher, draft);
  assert.equal(payload?.organizationId, 'org'); assert.deepEqual(payload?.collectionIds, ['collection']);
  assert.equal(await decryptStr(payload?.login?.password, org.slice(0, 32), org.slice(32)), 'new');
  await assert.rejects(updateCipher(fetcher, { ...session, organizationKeys: {} }, cipher, draft), /Organization key unavailable/);
  await assert.rejects(updateCipher(fetcher, session, { ...cipher, edit: false }, draft), /read-only/);
});

test('hidden-password display masks secrets and non-secret edits retain original encrypted bytes', async () => {
  const user = randomKey(); const org = randomKey(); const item = randomKey();
  const session: SessionState = { email: 'member@example.test', ...encode(user), organizationKeys: { org: bytesToBase64(org) } };
  const encrypted: Cipher = {
    id: 'cipher', type: 1, organizationId: 'org', collectionIds: ['collection'], revisionDate: revision,
    edit: true, viewPassword: false, name: await encrypt('Shared', item),
    key: await encryptBw(item, org.slice(0, 32), org.slice(32)),
    login: { username: await encrypt('username', item), password: await encrypt('secret', item), totp: await encrypt('TOTPKEY', item), passwordRevisionDate: revision, fido2Credentials: [{ keyValue: await encrypt('private credential', item) }] },
    passwordHistory: [{ password: await encrypt('old secret', item), lastUsedDate: revision }],
    fields: [{ type: 1, name: await encrypt('Hidden', item), value: await encrypt('hidden value', item) }],
  };
  const decrypted = await decryptSingleCipher(encrypted, user.slice(0, 32), user.slice(32), session.organizationKeys);
  assert.equal(decrypted.login?.decPassword, ''); assert.equal(decrypted.login?.decTotp, '');
  assert.equal(decrypted.fields?.[0].decValue, ''); assert.equal(decrypted.passwordHistory?.[0].decPassword, '');
  assert.equal(decrypted.login?.decUsername, 'username');
  const draft = draftFromCipher(decrypted); draft.name = 'Renamed'; draft.loginPassword = 'must not replace hidden bytes'; draft.customFields = [];
  let payload: Cipher | undefined;
  await updateCipher(async (_path, init) => { payload = JSON.parse(String(init?.body)); return new Response(JSON.stringify(payload)); }, session, decrypted, draft);
  assert.equal(payload?.login?.password, encrypted.login?.password); assert.equal(payload?.login?.totp, encrypted.login?.totp);
  assert.equal(payload?.login?.passwordRevisionDate, revision); assert.deepEqual(payload?.login?.fido2Credentials, encrypted.login?.fido2Credentials);
  assert.deepEqual(payload?.fields, encrypted.fields); assert.deepEqual(payload?.passwordHistory, encrypted.passwordHistory);
  assert.equal(await decryptStr(payload?.name, item.slice(0, 32), item.slice(32)), 'Renamed');
  const unavailable = await decryptSingleCipher({ ...decrypted, login: { ...decrypted.login, decPassword: 'stale plaintext' } }, user.slice(0, 32), user.slice(32), {});
  assert.equal(unavailable.decryptionUnavailable, true); assert.equal(unavailable.login?.decPassword, undefined);
});

test('readonly organization preference update sends only per-user metadata and expected revision', async () => {
  const cipher: Cipher = { id: 'cipher', type: 1, organizationId: 'org', edit: false, revisionDate: revision, name: 'opaque ciphertext' };
  let body: Record<string, unknown> = {};
  await updateCipherPreferences(async (path, init) => {
    assert.equal(path, '/api/ciphers/cipher/partial');
    assert.equal(init?.method, 'PUT');
    body = JSON.parse(String(init?.body));
    return new Response(JSON.stringify({ ...cipher, ...body }));
  }, cipher, { folderId: 'folder', favorite: true });
  assert.deepEqual(body, { folderId: 'folder', favorite: true, lastKnownRevisionDate: revision });
  assert.equal(body.name, undefined); assert.equal(body.organizationId, undefined);
});

test('attachment upload with omitted cipher metadata fetches real owner and never assumes personal keys', async () => {
  const user = randomKey(); let requests = 0;
  await assert.rejects(uploadCipherAttachment(async (path) => {
    requests += 1; assert.equal(path, '/api/ciphers/cipher');
    return new Response(JSON.stringify({ id: 'cipher', type: 1, organizationId: 'org' }));
  }, { email: 'member@example.test', ...encode(user) }, 'cipher', new File(['file'], 'name.txt')), /Organization key unavailable/);
  assert.equal(requests, 1);
});
