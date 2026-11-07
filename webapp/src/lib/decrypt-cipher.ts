import { bytesToBase64 } from './crypto';
import { decryptVaultCore } from './vault-decrypt';
import type { Cipher } from './types';

export async function decryptSingleCipher(
  encrypted: Cipher,
  userEnc: Uint8Array,
  userMac: Uint8Array,
  organizationKeys?: Record<string, string>,
): Promise<Cipher> {
  const result = await decryptVaultCore({
    folders: [], ciphers: [encrypted],
    symEncKeyB64: bytesToBase64(userEnc), symMacKeyB64: bytesToBase64(userMac), organizationKeys,
  });
  return result.ciphers[0];
}
