import {
  base64ToBytes,
  bytesToBase64,
  decryptBw,
  encryptBw,
  requireWebCrypto,
  toBufferSource,
} from './crypto';
import type { Cipher, Organization, Profile, SessionState } from './types';

export interface OwnerKeyParts {
  enc: Uint8Array;
  mac: Uint8Array;
}

// Bitwarden EncryptionType: 3 = RSA2048 OAEP SHA-256, 4 = RSA2048 OAEP SHA-1.
export async function wrapOrganizationKey(
  rawKey: Uint8Array,
  publicKeyB64: string
): Promise<string> {
  if (rawKey.length !== 64) throw new Error('Invalid organization key');
  const subtle = requireWebCrypto().subtle;
  const key = await subtle.importKey(
    'spki',
    toBufferSource(base64ToBytes(publicKeyB64)),
    { name: 'RSA-OAEP', hash: 'SHA-1' },
    false,
    ['encrypt']
  );
  const encrypted = await subtle.encrypt(
    { name: 'RSA-OAEP' },
    key,
    toBufferSource(rawKey)
  );
  return `4.${bytesToBase64(new Uint8Array(encrypted))}`;
}

export async function unwrapOrganizationKey(
  encryptedKey: string,
  privateKeyBytes: Uint8Array
): Promise<Uint8Array> {
  const match = /^(3|4)\.([A-Za-z0-9+/]+={0,2})$/.exec(encryptedKey);
  if (!match) throw new Error('Unsupported organization key encryption');
  const subtle = requireWebCrypto().subtle;
  const key = await subtle.importKey(
    'pkcs8',
    toBufferSource(privateKeyBytes),
    { name: 'RSA-OAEP', hash: match[1] === '4' ? 'SHA-1' : 'SHA-256' },
    false,
    ['decrypt']
  );
  const raw = new Uint8Array(
    await subtle.decrypt(
      { name: 'RSA-OAEP' },
      key,
      toBufferSource(base64ToBytes(match[2]))
    )
  );
  if (raw.length !== 64) {
    raw.fill(0);
    throw new Error('Invalid organization key');
  }
  return raw;
}

export async function generateOrganizationKeys(
  ownerPublicKey: string
): Promise<{
  key: string;
  keys: { publicKey: string; encryptedPrivateKey: string };
  rawKey: Uint8Array;
}> {
  const cryptoApi = requireWebCrypto();
  const rawKey = cryptoApi.getRandomValues(new Uint8Array(64));
  const pair = await cryptoApi.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-1',
    },
    true,
    ['encrypt', 'decrypt']
  );
  const privateBytes = new Uint8Array(
    await cryptoApi.subtle.exportKey('pkcs8', pair.privateKey)
  );
  try {
    return {
      rawKey,
      key: await wrapOrganizationKey(rawKey, ownerPublicKey),
      keys: {
        publicKey: bytesToBase64(
          new Uint8Array(
            await cryptoApi.subtle.exportKey('spki', pair.publicKey)
          )
        ),
        encryptedPrivateKey: await encryptBw(
          privateBytes,
          rawKey.slice(0, 32),
          rawKey.slice(32)
        ),
      },
    };
  } catch (error) {
    rawKey.fill(0);
    throw error;
  } finally {
    privateBytes.fill(0);
  }
}

export async function decryptOrganizationKeys(
  profile: Pick<Profile, 'privateKey'> | null | undefined,
  organizations: Organization[],
  session: SessionState
): Promise<Record<string, string>> {
  const keys: Record<string, string> = {};
  if (
    !profile?.privateKey ||
    !session.symEncKey ||
    !session.symMacKey ||
    !organizations.some(
      (org) => org.key && (org.status === undefined || org.status === 2)
    )
  )
    return keys;
  let privateBytes: Uint8Array;
  try {
    privateBytes = await decryptBw(
      profile.privateKey,
      base64ToBytes(session.symEncKey),
      base64ToBytes(session.symMacKey)
    );
  } catch {
    return keys;
  }
  try {
    for (const org of organizations) {
      if (!org.key || (org.status !== undefined && org.status !== 2)) continue;
      try {
        const raw = await unwrapOrganizationKey(org.key, privateBytes);
        keys[org.id] = bytesToBase64(raw);
        raw.fill(0);
      } catch {
        /* Never substitute personal keys for an unavailable org key. */
      }
    }
  } finally {
    privateBytes.fill(0);
  }
  return keys;
}

export function getOwnerKeyParts(
  cipher: Pick<Cipher, 'organizationId'> | null | undefined,
  session: SessionState
): OwnerKeyParts {
  if (cipher?.organizationId) {
    const encoded = session.organizationKeys?.[cipher.organizationId];
    if (!encoded) throw new Error('Organization key unavailable');
    const raw = base64ToBytes(encoded);
    if (raw.length !== 64) throw new Error('Invalid organization key');
    return { enc: raw.slice(0, 32), mac: raw.slice(32) };
  }
  if (!session.symEncKey || !session.symMacKey)
    throw new Error('Vault key unavailable');
  return {
    enc: base64ToBytes(session.symEncKey),
    mac: base64ToBytes(session.symMacKey),
  };
}
