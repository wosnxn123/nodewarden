export interface AccountProofSnapshot {
  id: string;
  masterPasswordHash: string;
  securityStamp: string;
}

export interface AccountKdfUpdate {
  verifier: string;
  key: string;
  type: 0 | 1;
  iterations: number;
  memory: number | null;
  parallelism: number | null;
  securityStamp: string;
  revisionDate: string;
}

export interface AccountBlobReference {
  cipher_id: string;
  id: string;
}
export interface AccountSendReference {
  id: string;
  data: string;
}
export interface PurgeVaultResult {
  changed: boolean;
  attachments: AccountBlobReference[];
  revisionDate: string;
}
export interface DeleteAccountResult {
  changed: boolean;
  reason: 'stale-proof' | 'last-owner' | 'last-admin' | null;
  attachments: AccountBlobReference[];
  sends: AccountSendReference[];
}

const PROOF =
  "EXISTS (SELECT 1 FROM users proof WHERE proof.id = ? AND proof.master_password_hash = ? AND proof.security_stamp = ? AND proof.status = 'active')";
function proofValues(user: AccountProofSnapshot): [string, string, string] {
  return [user.id, user.masterPasswordHash, user.securityStamp];
}

/** Rewrap only the user key; vault, RSA, item and organization key material stays untouched. */
export async function changeAccountKdf(
  db: D1Database,
  user: AccountProofSnapshot,
  next: AccountKdfUpdate
): Promise<boolean> {
  const changedProof = [user.id, next.verifier, next.securityStamp] as const;
  const result = await db.batch([
    db
      .prepare(
        `UPDATE users SET master_password_hash = ?, key = ?, kdf_type = ?, kdf_iterations = ?, kdf_memory = ?,
      kdf_parallelism = ?, security_stamp = ?, updated_at = ?
      WHERE id = ? AND master_password_hash = ? AND security_stamp = ? AND status = 'active' RETURNING id`
      )
      .bind(
        next.verifier,
        next.key,
        next.type,
        next.iterations,
        next.memory,
        next.parallelism,
        next.securityStamp,
        next.revisionDate,
        ...proofValues(user)
      ),
    db
      .prepare(`DELETE FROM refresh_tokens WHERE user_id = ? AND ${PROOF}`)
      .bind(user.id, ...changedProof),
    db
      .prepare(
        `DELETE FROM trusted_two_factor_device_tokens WHERE user_id = ? AND ${PROOF}`
      )
      .bind(user.id, ...changedProof),
    db
      .prepare(`DELETE FROM auth_requests WHERE user_id = ? AND ${PROOF}`)
      .bind(user.id, ...changedProof),
    db
      .prepare(
        `INSERT INTO user_revisions(user_id, revision_date) SELECT ?, ? WHERE ${PROOF}
      ON CONFLICT(user_id) DO UPDATE SET revision_date = MAX(user_revisions.revision_date, excluded.revision_date)`
      )
      .bind(user.id, next.revisionDate, ...changedProof),
  ]);
  return (result[0].results || []).length === 1;
}

/** Snapshots and deletes share one transaction, so cleanup cannot target a cipher shared concurrently. */
export async function purgePersonalVault(
  db: D1Database,
  user: AccountProofSnapshot,
  revisionDate: string
): Promise<PurgeVaultResult> {
  const result = await db.batch([
    db
      .prepare(
        `UPDATE users SET updated_at = ? WHERE id = ? AND master_password_hash = ? AND security_stamp = ? AND status = 'active' RETURNING id`
      )
      .bind(revisionDate, ...proofValues(user)),
    db
      .prepare(
        `SELECT a.cipher_id, a.id FROM attachments a JOIN ciphers c ON c.id = a.cipher_id
      WHERE c.user_id = ? AND c.organization_id IS NULL AND ${PROOF}`
      )
      .bind(user.id, ...proofValues(user)),
    db
      .prepare(
        `DELETE FROM ciphers WHERE user_id = ? AND organization_id IS NULL AND ${PROOF}`
      )
      .bind(user.id, ...proofValues(user)),
    db
      .prepare(`DELETE FROM folders WHERE user_id = ? AND ${PROOF}`)
      .bind(user.id, ...proofValues(user)),
    db
      .prepare(
        `INSERT INTO user_revisions(user_id, revision_date) SELECT ?, ? WHERE ${PROOF}
      ON CONFLICT(user_id) DO UPDATE SET revision_date = MAX(user_revisions.revision_date, excluded.revision_date)`
      )
      .bind(user.id, revisionDate, ...proofValues(user)),
  ]);
  const changed = (result[0].results || []).length === 1;
  return {
    changed,
    attachments: changed ? (result[1].results as AccountBlobReference[]) : [],
    revisionDate,
  };
}

// Evaluate this predicate inside the same D1 transaction as DELETE. Concurrent
// owner/admin deletions serialize: one succeeds, the newly final owner/admin does not.
const LAST_OWNER = `EXISTS (SELECT 1 FROM organization_members own
  WHERE own.user_id = ? AND own.type = 0 AND own.status = 2
  AND NOT EXISTS (SELECT 1 FROM organization_members other
    WHERE other.organization_id = own.organization_id AND other.type = 0 AND other.status = 2 AND other.user_id IS NOT NULL AND other.user_id <> own.user_id))`;
const LAST_ADMIN = `EXISTS (SELECT 1 FROM users target WHERE target.id = ? AND target.role = 'admin'
  AND EXISTS (SELECT 1 FROM users remaining WHERE remaining.id <> target.id)
  AND NOT EXISTS (SELECT 1 FROM users other WHERE other.id <> target.id AND other.role = 'admin' AND other.status = 'active'))`;
const DELETE_ALLOWED = `${PROOF} AND NOT (${LAST_OWNER}) AND NOT (${LAST_ADMIN})`;
function deleteValues(
  user: AccountProofSnapshot
): [string, string, string, string, string] {
  return [...proofValues(user), user.id, user.id];
}

/** Cascade only user-owned data. Organization assets have NULL user ownership and survive. */
export async function deleteOwnAccount(
  db: D1Database,
  user: AccountProofSnapshot
): Promise<DeleteAccountResult> {
  const result = await db.batch([
    db
      .prepare(
        `SELECT CASE WHEN ${LAST_OWNER} THEN 'last-owner' WHEN ${LAST_ADMIN} THEN 'last-admin' ELSE NULL END AS reason WHERE ${PROOF}`
      )
      .bind(user.id, user.id, ...proofValues(user)),
    db
      .prepare(
        `SELECT a.cipher_id, a.id FROM attachments a JOIN ciphers c ON c.id = a.cipher_id
      WHERE c.user_id = ? AND c.organization_id IS NULL AND ${DELETE_ALLOWED}`
      )
      .bind(user.id, ...deleteValues(user)),
    db
      .prepare(
        `SELECT id, data FROM sends WHERE user_id = ? AND type = 1 AND ${DELETE_ALLOWED}`
      )
      .bind(user.id, ...deleteValues(user)),
    // Challenge rows deliberately have no FK, unlike sessions, credentials and devices.
    db
      .prepare(
        `DELETE FROM webauthn_challenges WHERE user_id = ? AND ${DELETE_ALLOWED}`
      )
      .bind(user.id, ...deleteValues(user)),
    db
      .prepare(
        `DELETE FROM users WHERE id = ? AND ${DELETE_ALLOWED} RETURNING id`
      )
      .bind(user.id, ...deleteValues(user)),
  ]);
  const changed = (result[4].results || []).length === 1;
  const diagnostic = result[0].results?.[0] as
    | { reason: DeleteAccountResult['reason'] }
    | undefined;
  return {
    changed,
    reason: changed ? null : diagnostic?.reason || 'stale-proof',
    attachments: changed ? (result[1].results as AccountBlobReference[]) : [],
    sends: changed ? (result[2].results as AccountSendReference[]) : [],
  };
}
