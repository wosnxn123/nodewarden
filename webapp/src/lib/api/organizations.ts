import {
  base64ToBytes,
  decryptBw,
  encryptBw,
  requireWebCrypto,
} from '../crypto';
import {
  generateOrganizationKeys,
  getOwnerKeyParts,
  wrapOrganizationKey,
} from '../organization-crypto';
import type {
  Cipher,
  Organization,
  OrganizationCollection,
  OrganizationInvitation,
  OrganizationMember,
  Profile,
  SessionState,
} from '../types';
import { parseErrorMessage, parseJson, type AuthedFetch } from './shared';

async function request<T>(
  fetcher: AuthedFetch,
  path: string,
  method = 'GET',
  body?: unknown
): Promise<T> {
  const response = await fetcher(path, {
    method,
    ...(body !== undefined
      ? {
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        }
      : {}),
    cache: 'no-store',
  });
  if (!response.ok)
    throw new Error(
      await parseErrorMessage(response, 'Organization request failed')
    );
  return (await parseJson<T>(response)) as T;
}
async function list<T>(fetcher: AuthedFetch, path: string): Promise<T[]> {
  const body = await request<{ data?: T[] }>(fetcher, path);
  return Array.isArray(body?.data) ? body.data : [];
}
const orgPath = (id: string) => `/api/organizations/${encodeURIComponent(id)}`;
const memberPath = (org: string, id: string) =>
  `${orgPath(org)}/users/${encodeURIComponent(id)}`;

export const listOrganizations = (fetcher: AuthedFetch) =>
  list<Organization>(fetcher, '/api/organizations');
export const listOrganizationInvitations = (fetcher: AuthedFetch) =>
  list<OrganizationInvitation>(fetcher, '/api/organizations/invitations');
export const listOrganizationMembers = (fetcher: AuthedFetch, org: string) =>
  list<OrganizationMember>(fetcher, `${orgPath(org)}/users`);
export async function listOrganizationCollections(
  fetcher: AuthedFetch,
  org: string
): Promise<OrganizationCollection[]> {
  // The global collection projection includes effective readOnly/hidePasswords
  // grants; the organization administration list is not an authorization view.
  return (
    await list<OrganizationCollection>(fetcher, '/api/collections')
  ).filter((collection) => collection.organizationId === org);
}

export async function createOrganization(
  fetcher: AuthedFetch,
  profile: Profile,
  name: string,
  billingEmail: string,
  collectionName: string
): Promise<Organization> {
  if (!profile.publicKey) throw new Error('Account public key unavailable');
  const generated = await generateOrganizationKeys(profile.publicKey);
  try {
    return await request<Organization>(fetcher, '/api/organizations', 'POST', {
      name,
      billingEmail,
      key: generated.key,
      keys: generated.keys,
      collectionName: await encryptBw(
        new TextEncoder().encode(collectionName),
        generated.rawKey.slice(0, 32),
        generated.rawKey.slice(32)
      ),
    });
  } finally {
    generated.rawKey.fill(0);
  }
}

export async function createOrganizationCollection(
  fetcher: AuthedFetch,
  session: SessionState,
  organizationId: string,
  name: string
): Promise<OrganizationCollection> {
  const owner = getOwnerKeyParts({ organizationId }, session);
  return request(fetcher, `${orgPath(organizationId)}/collections`, 'POST', {
    name: await encryptBw(new TextEncoder().encode(name), owner.enc, owner.mac),
    users: [],
    groups: [],
  });
}

export async function updateOrganizationMember(
  fetcher: AuthedFetch,
  org: string,
  member: OrganizationMember
): Promise<void> {
  await request(fetcher, memberPath(org, member.id), 'PUT', {
    type: member.type,
    accessAll: member.accessAll,
    collections: member.collections || [],
    groups: member.groups || [],
  });
}
export async function deleteOrganizationCollection(
  fetcher: AuthedFetch,
  org: string,
  id: string
): Promise<void> {
  await request(
    fetcher,
    `${orgPath(org)}/collections/${encodeURIComponent(id)}`,
    'DELETE'
  );
}
export async function renameOrganizationCollection(
  fetcher: AuthedFetch,
  session: SessionState,
  collection: OrganizationCollection,
  name: string
): Promise<void> {
  const owner = getOwnerKeyParts(collection, session);
  const details = await request<OrganizationCollection>(
    fetcher,
    `${orgPath(collection.organizationId)}/collections/${encodeURIComponent(collection.id)}/details`
  );
  await request(
    fetcher,
    `${orgPath(collection.organizationId)}/collections/${encodeURIComponent(collection.id)}`,
    'PUT',
    {
      ...details,
      name: await encryptBw(
        new TextEncoder().encode(name),
        owner.enc,
        owner.mac
      ),
    }
  );
}

export async function inviteOrganizationMember(
  fetcher: AuthedFetch,
  org: string,
  email: string,
  type: number,
  accessAll: boolean,
  collectionIds: string[]
): Promise<void> {
  const result = await request<{
    data?: Array<{ email?: string; error?: string; object?: string }>;
  }>(fetcher, `${orgPath(org)}/users/invite`, 'POST', {
    emails: [email],
    type,
    accessAll,
    collections: collectionIds.map((id) => ({
      id,
      readOnly: false,
      hidePasswords: false,
      manage: false,
    })),
    groups: [],
  });
  const entry = result?.data?.find(
    (item) => item.email?.toLowerCase() === email.trim().toLowerCase()
  );
  if (!entry || entry.error || entry.object === 'organizationUserInviteError') {
    throw new Error(entry?.error || 'Organization invitation failed');
  }
}
export async function acceptOrganizationInvitation(
  fetcher: AuthedFetch,
  invitation: OrganizationInvitation
): Promise<void> {
  await request(
    fetcher,
    `${memberPath(invitation.organizationId, invitation.id)}/accept`,
    'POST',
    {}
  );
}
export async function confirmOrganizationMember(
  fetcher: AuthedFetch,
  session: SessionState,
  org: string,
  member: OrganizationMember
): Promise<void> {
  // Fetch a fresh verified member record, rather than trusting an email-entered public key.
  const details = await request<OrganizationMember>(
    fetcher,
    memberPath(org, member.id)
  );
  if (details.status !== 1 || !details.publicKey || !details.userId)
    throw new Error('Member must accept before confirmation');
  const encoded = session.organizationKeys?.[org];
  if (!encoded) throw new Error('Organization key unavailable');
  const raw = base64ToBytes(encoded);
  try {
    await request(fetcher, `${memberPath(org, member.id)}/confirm`, 'POST', {
      key: await wrapOrganizationKey(raw, details.publicKey),
    });
  } finally {
    raw.fill(0);
  }
}
export async function revokeOrganizationMember(
  fetcher: AuthedFetch,
  org: string,
  id: string
): Promise<void> {
  await request(fetcher, `${memberPath(org, id)}/revoke`, 'POST', {});
}
export async function restoreOrganizationMember(
  fetcher: AuthedFetch,
  org: string,
  id: string
): Promise<void> {
  await request(fetcher, `${memberPath(org, id)}/restore`, 'POST', {});
}

/** Migrate every EncString, including unknown client fields, without ever exposing the user vault key. */
export async function prepareCipherForSharing(
  cipher: Cipher,
  session: SessionState,
  organizationId: string,
  collectionIds: string[]
): Promise<Cipher> {
  if (cipher.organizationId)
    throw new Error('Only personal items can be shared');
  if (cipher.decryptionUnavailable)
    throw new Error('Cipher decryption unavailable');
  if (!cipher.revisionDate) throw new Error('Cipher revision required');
  const source = getOwnerKeyParts(cipher, session);
  const target = getOwnerKeyParts({ organizationId }, session);
  const itemRaw = cipher.key
    ? await decryptBw(cipher.key, source.enc, source.mac)
    : requireWebCrypto().getRandomValues(new Uint8Array(64));
  if (itemRaw.length !== 64) throw new Error('Invalid item key');
  const item = { enc: itemRaw.slice(0, 32), mac: itemRaw.slice(32) };
  const current = cipher.key ? item : source;
  try {
    // Without an explicit attachment key the blob may still use the old owner key;
    // transferring it would either lose the attachment or disclose the personal key.
    if (cipher.attachments?.some((attachment) => !attachment.key))
      throw new Error('Repair legacy attachments before sharing this item');
    async function migrate(value: unknown): Promise<unknown> {
      if (typeof value === 'string' && /^[012]\.\S+\|/.test(value)) {
        let plain: Uint8Array;
        try {
          plain = await decryptBw(value, current.enc, current.mac);
        } catch {
          plain = await decryptBw(value, source.enc, source.mac);
        }
        try {
          return await encryptBw(plain, item.enc, item.mac);
        } finally {
          plain.fill(0);
        }
      }
      if (Array.isArray(value)) return Promise.all(value.map(migrate));
      if (!value || typeof value !== 'object') return value;
      const result: Record<string, unknown> = {};
      for (const [key, field] of Object.entries(value)) {
        if (/^dec[A-Z]/.test(key) || key === 'decryptionUnavailable') continue;
        result[key] =
          key === 'key' && value === cipher ? field : await migrate(field);
      }
      return result;
    }
    const migrated = (await migrate(cipher)) as Cipher;
    migrated.key = await encryptBw(itemRaw, target.enc, target.mac);
    migrated.organizationId = organizationId;
    migrated.collectionIds = [...new Set(collectionIds)];
    return migrated;
  } finally {
    itemRaw.fill(0);
    item.enc.fill(0);
    item.mac.fill(0);
  }
}

export async function shareCipher(
  fetcher: AuthedFetch,
  session: SessionState,
  cipher: Cipher,
  organizationId: string,
  collectionIds: string[]
): Promise<Cipher> {
  if (!collectionIds.length) throw new Error('Select at least one collection');
  const encrypted = await prepareCipherForSharing(
    cipher,
    session,
    organizationId,
    collectionIds
  );
  return request(
    fetcher,
    `/api/ciphers/${encodeURIComponent(cipher.id)}/share`,
    'PUT',
    {
      cipher: { ...encrypted, lastKnownRevisionDate: cipher.revisionDate },
      collectionIds,
      lastKnownRevisionDate: cipher.revisionDate,
    }
  );
}
export async function updateCipherCollections(
  fetcher: AuthedFetch,
  cipher: Cipher,
  collectionIds: string[]
): Promise<void> {
  await request(
    fetcher,
    `/api/ciphers/${encodeURIComponent(cipher.id)}/collections`,
    'PUT',
    { collectionIds, lastKnownRevisionDate: cipher.revisionDate }
  );
}
