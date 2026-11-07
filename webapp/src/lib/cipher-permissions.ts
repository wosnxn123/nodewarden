import type { Cipher } from './types';

/** hidePasswords is a client presentation restriction, not cryptographic isolation. */
const protectedFields: Record<string, string[]> = {
  login: ['password', 'totp'],
  card: ['number', 'code'],
  identity: ['ssn', 'passportNumber', 'licenseNumber'],
  sshKey: ['privateKey'],
  bankAccount: ['accountNumber', 'routingNumber', 'pin', 'iban'],
  driversLicense: ['licenseNumber'],
  passport: ['passportNumber', 'nationalIdentificationNumber'],
};

export function maskCipherSecrets(cipher: Cipher): Cipher {
  if (cipher.viewPassword !== false) return cipher;
  for (const [section, fields] of Object.entries(protectedFields)) {
    const value = (cipher as unknown as Record<string, unknown>)[section];
    if (!value || typeof value !== 'object') continue;
    const masked = { ...(value as Record<string, unknown>) };
    for (const field of fields)
      masked[`dec${field[0].toUpperCase()}${field.slice(1)}`] = '';
    (cipher as unknown as Record<string, unknown>)[section] = masked;
  }
  if (cipher.type === 2) cipher.decNotes = '';
  if (cipher.passwordHistory)
    cipher.passwordHistory = cipher.passwordHistory.map((entry) => ({
      ...entry,
      decPassword: '',
    }));
  if (cipher.fields)
    cipher.fields = cipher.fields.map((field) =>
      Number(field.type) === 1 ? { ...field, decValue: '' } : field
    );
  return cipher;
}

export function preserveHiddenCiphertext(
  payload: Record<string, unknown>,
  cipher: Cipher
): void {
  if (cipher.viewPassword !== false) return;
  // Retaining the same item/owner key lets non-secret edits preserve hidden bytes exactly.
  for (const [section, fields] of Object.entries(protectedFields)) {
    const original = (cipher as unknown as Record<string, unknown>)[section];
    const next = payload[section];
    if (
      !original ||
      !next ||
      typeof original !== 'object' ||
      typeof next !== 'object'
    )
      continue;
    for (const field of fields)
      (next as Record<string, unknown>)[field] =
        (original as Record<string, unknown>)[field] ?? null;
    if (section === 'login') {
      (next as Record<string, unknown>).passwordRevisionDate =
        (original as Record<string, unknown>).passwordRevisionDate ?? null;
      (next as Record<string, unknown>).fido2Credentials =
        (original as Record<string, unknown>).fido2Credentials ?? null;
    }
  }
  if (cipher.type === 2) payload.notes = cipher.notes ?? null;
  payload.passwordHistory =
    cipher.passwordHistory?.map(
      ({ decPassword: _decoded, ...entry }) => entry
    ) ?? null;
  // The restricted editor disables custom-field edits/reordering altogether.
  // Retain the original array, including linked/unknown field metadata.
  payload.fields =
    cipher.fields?.map((field) =>
      Object.fromEntries(
        Object.entries(field).filter(([key]) => !/^dec[A-Z]/.test(key))
      )
    ) ?? null;
}

export function clearCipherDecodedFields(cipher: Cipher): Cipher {
  function strip(value: unknown): unknown {
    if (Array.isArray(value)) return value.map(strip);
    if (!value || typeof value !== 'object') return value;
    return Object.fromEntries(
      Object.entries(value)
        .filter(
          ([key]) => !/^dec[A-Z]/.test(key) && key !== 'decryptionUnavailable'
        )
        .map(([key, entry]) => [key, strip(entry)])
    );
  }
  return strip(cipher) as Cipher;
}
