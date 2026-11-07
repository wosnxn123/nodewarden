import type { User } from '../types';

// Updating encrypted key material must not overwrite another concurrent password
// change, or strand organization keys under a replaced RSA identity. A full RSA
// rotation protocol must update all member envelopes together; it is not the
// ordinary password-change operation (which only rewraps the same user key).
export async function saveAccountKeysIfUnchanged(
  db: D1Database,
  before: User,
  after: User
): Promise<boolean> {
  const result = await db
    .prepare(
      `UPDATE users SET master_password_hash=?, key=?, private_key=?, public_key=?,
      master_password_hint=?, security_stamp=?, updated_at=?
    WHERE id=? AND status='active' AND master_password_hash=? AND security_stamp=?
      AND key=? AND private_key IS ? AND public_key IS ?
      AND (public_key IS NULL OR public_key IS ? OR NOT EXISTS (
        SELECT 1 FROM organization_members m WHERE m.user_id=users.id AND m.status>=0
      ))`
    )
    .bind(
      after.masterPasswordHash,
      after.key,
      after.privateKey,
      after.publicKey,
      after.masterPasswordHint,
      after.securityStamp,
      after.updatedAt,
      before.id,
      before.masterPasswordHash,
      before.securityStamp,
      before.key,
      before.privateKey,
      before.publicKey,
      after.publicKey
    )
    .run();
  return result.meta.changes === 1;
}
