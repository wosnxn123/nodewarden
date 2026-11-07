import type { Attachment } from '../types';
import { cipherAccessSql } from './organization-access';
import { commitOrganizationMutation, eventGuard } from './organization-repo';

type SafeBind = (stmt: D1PreparedStatement, ...values: any[]) => D1PreparedStatement;
type SqlChunkSize = (fixedBindCount: number) => number;

// Trusted restore helpers may move a record only within the same ownership scope.
const nextRevisionSql = `CASE WHEN updated_at >= ? THEN strftime('%Y-%m-%dT%H:%M:%fZ', updated_at, '+0.001 seconds') ELSE ? END`;

const sameOwnerSql = `(current_cipher.user_id IS NOT NULL AND current_cipher.user_id = next_cipher.user_id
  AND current_cipher.organization_id IS NULL AND next_cipher.organization_id IS NULL)
  OR (current_cipher.user_id IS NULL AND next_cipher.user_id IS NULL
    AND current_cipher.organization_id IS NOT NULL AND current_cipher.organization_id = next_cipher.organization_id)`;

async function commitAttachmentMutation(
  db: D1Database,
  cipherId: string,
  userId: string,
  sql: string,
  bindings: unknown[]
): Promise<boolean> {
  const cipher = await db.prepare('SELECT organization_id FROM ciphers WHERE id = ?').bind(cipherId)
    .first<{ organization_id: string | null }>();
  if (!cipher) return false;
  // Each mutation's EXISTS clause binds this scope too: a transfer after the lookup
  // cannot apply an event/revision to the wrong organization.
  const values = [...bindings, cipher.organization_id];
  if (cipher.organization_id) {
    return commitOrganizationMutation(db, {
      organizationId: cipher.organization_id, actorUserId: userId, eventType: 1101, targetId: cipherId,
      sql, bindings: values,
      additional: (eventId) => {
        const now = new Date().toISOString();
        return [db.prepare(`UPDATE ciphers SET updated_at = ${nextRevisionSql} WHERE id = ? AND ${eventGuard(eventId)}`)
          .bind(now, now, cipherId)];
      },
    });
  }
  const revisionDate = new Date().toISOString();
  const results = await db.batch([
    db.prepare(sql).bind(...values),
    db.prepare(`UPDATE ciphers SET updated_at = ${nextRevisionSql} WHERE id = ? AND changes() > 0`).bind(revisionDate, revisionDate, cipherId),
    db.prepare(`INSERT INTO user_revisions(user_id, revision_date)
      SELECT ?, updated_at FROM ciphers WHERE id = ? AND changes() > 0
      ON CONFLICT(user_id) DO UPDATE SET revision_date = CASE
        WHEN user_revisions.revision_date >= excluded.revision_date
          THEN strftime('%Y-%m-%dT%H:%M:%fZ', user_revisions.revision_date, '+0.001 seconds')
        ELSE excluded.revision_date END`).bind(userId, cipherId),
  ]);
  return (results[0]?.meta.changes ?? 0) > 0;
}

export async function createAttachmentForUser(
  db: D1Database,
  attachment: Attachment,
  userId: string
): Promise<boolean> {
  const values = [userId, attachment.id, attachment.cipherId, attachment.fileName, attachment.size,
    attachment.sizeName, attachment.key ?? null, attachment.cipherId];
  return commitAttachmentMutation(db, attachment.cipherId, userId, `WITH actor AS (SELECT ? AS user_id)
    INSERT INTO attachments(id, cipher_id, file_name, size, size_name, key)
    SELECT ?, ?, ?, ?, ?, ? WHERE EXISTS (
      SELECT 1 FROM ciphers c WHERE c.id = ? AND ${cipherAccessSql('write')} AND c.organization_id IS ?
    ) ON CONFLICT(id) DO NOTHING`, values);
}

export async function updateAttachmentForUser(
  db: D1Database,
  attachment: Attachment,
  userId: string,
  original: Attachment
): Promise<boolean> {
  if (attachment.id !== original.id || attachment.cipherId !== original.cipherId) return false;
  // The server-read snapshot must precede request parsing and any mutation of
  // the candidate. Authorization alone cannot detect a concurrent key rewrap.
  return commitAttachmentMutation(db, attachment.cipherId, userId, `WITH actor AS (SELECT ? AS user_id)
    UPDATE attachments SET file_name = ?, size = ?, size_name = ?, key = ?
    WHERE id = ? AND cipher_id = ? AND file_name IS ? AND key IS ? AND size IS ? AND size_name IS ?
      AND EXISTS (
        SELECT 1 FROM ciphers c WHERE c.id = attachments.cipher_id AND ${cipherAccessSql('write')}
          AND c.organization_id IS ?
      )`, [userId, attachment.fileName, attachment.size, attachment.sizeName, attachment.key ?? null,
    attachment.id, attachment.cipherId, original.fileName, original.key ?? null, original.size, original.sizeName]);
}

export async function getAttachment(db: D1Database, id: string): Promise<Attachment | null> {
  const row = await db
    .prepare('SELECT id, cipher_id, file_name, size, size_name, key FROM attachments WHERE id = ?')
    .bind(id)
    .first<any>();
  if (!row) return null;
  return {
    id: row.id,
    cipherId: row.cipher_id,
    fileName: row.file_name,
    size: row.size,
    sizeName: row.size_name,
    key: row.key,
  };
}

export async function getAttachmentForUser(db: D1Database, id: string, userId: string): Promise<Attachment | null> {
  const row = await db
    .prepare(
      `WITH actor AS (SELECT ? AS user_id)
       SELECT a.id, a.cipher_id, a.file_name, a.size, a.size_name, a.key
       FROM attachments a
       INNER JOIN ciphers c ON c.id = a.cipher_id
       WHERE a.id = ? AND ${cipherAccessSql('read')}`
    )
    .bind(userId, id)
    .first<any>();
  if (!row) return null;
  return {
    id: row.id,
    cipherId: row.cipher_id,
    fileName: row.file_name,
    size: row.size,
    sizeName: row.size_name,
    key: row.key,
  };
}

export async function saveAttachment(db: D1Database, safeBind: SafeBind, attachment: Attachment): Promise<void> {
  const stmt = db.prepare(
    'INSERT INTO attachments(id, cipher_id, file_name, size, size_name, key) VALUES(?, ?, ?, ?, ?, ?) ' +
    'ON CONFLICT(id) DO UPDATE SET cipher_id=excluded.cipher_id, file_name=excluded.file_name, size=excluded.size, size_name=excluded.size_name, key=excluded.key ' +
    'WHERE EXISTS (' +
    'SELECT 1 FROM ciphers current_cipher INNER JOIN ciphers next_cipher ON next_cipher.id = excluded.cipher_id ' +
    `WHERE current_cipher.id = attachments.cipher_id AND (${sameOwnerSql})` +
    ')'
  );
  await safeBind(stmt, attachment.id, attachment.cipherId, attachment.fileName, attachment.size, attachment.sizeName, attachment.key).run();
}

export async function deleteAttachment(db: D1Database, id: string): Promise<void> {
  await db.prepare('DELETE FROM attachments WHERE id = ?').bind(id).run();
}

export async function deleteAttachmentForUser(db: D1Database, id: string, userId: string): Promise<boolean> {
  const attachment = await getAttachment(db, id);
  if (!attachment) return false;
  return commitAttachmentMutation(db, attachment.cipherId, userId, `WITH actor AS (SELECT ? AS user_id)
    DELETE FROM attachments WHERE id = ? AND cipher_id = ? AND EXISTS (
      SELECT 1 FROM ciphers c WHERE c.id = attachments.cipher_id AND ${cipherAccessSql('write')}
        AND c.organization_id IS ?
    )`, [userId, id, attachment.cipherId]);
}

export async function bulkDeleteAttachmentsByIds(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  attachmentIds: string[]
): Promise<void> {
  const uniqueIds = [...new Set(attachmentIds.map((id) => String(id || '').trim()).filter(Boolean))];
  if (!uniqueIds.length) return;
  const chunkSize = sqlChunkSize(0);

  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    await db.prepare(`DELETE FROM attachments WHERE id IN (${placeholders})`).bind(...chunk).run();
  }
}

export async function getAttachmentsByCipher(db: D1Database, cipherId: string): Promise<Attachment[]> {
  const res = await db
    .prepare('SELECT id, cipher_id, file_name, size, size_name, key FROM attachments WHERE cipher_id = ?')
    .bind(cipherId)
    .all<any>();
  return (res.results || []).map((r) => ({
    id: r.id,
    cipherId: r.cipher_id,
    fileName: r.file_name,
    size: r.size,
    sizeName: r.size_name,
    key: r.key,
  }));
}

export async function getAttachmentsByCipherIds(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  cipherIds: string[]
): Promise<Map<string, Attachment[]>> {
  const grouped = new Map<string, Attachment[]>();
  if (cipherIds.length === 0) return grouped;

  const uniqueCipherIds = [...new Set(cipherIds)];
  const chunkSize = sqlChunkSize(0);

  for (let i = 0; i < uniqueCipherIds.length; i += chunkSize) {
    const chunk = uniqueCipherIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    const res = await db
      .prepare(`SELECT id, cipher_id, file_name, size, size_name, key FROM attachments WHERE cipher_id IN (${placeholders})`)
      .bind(...chunk)
      .all<any>();

    for (const row of res.results || []) {
      const item: Attachment = {
        id: row.id,
        cipherId: row.cipher_id,
        fileName: row.file_name,
        size: row.size,
        sizeName: row.size_name,
        key: row.key,
      };
      const list = grouped.get(item.cipherId);
      if (list) list.push(item);
      else grouped.set(item.cipherId, [item]);
    }
  }

  return grouped;
}

export async function getAttachmentsByUserId(db: D1Database, userId: string): Promise<Map<string, Attachment[]>> {
  const grouped = new Map<string, Attachment[]>();
  const res = await db
    .prepare(
      `WITH actor AS (SELECT ? AS user_id)
       SELECT a.id, a.cipher_id, a.file_name, a.size, a.size_name, a.key
       FROM attachments a
       INNER JOIN ciphers c ON c.id = a.cipher_id
       WHERE ${cipherAccessSql('read')}`
    )
    .bind(userId)
    .all<any>();

  for (const row of res.results || []) {
    const item: Attachment = {
      id: row.id,
      cipherId: row.cipher_id,
      fileName: row.file_name,
      size: row.size,
      sizeName: row.size_name,
      key: row.key,
    };
    const list = grouped.get(item.cipherId);
    if (list) list.push(item);
    else grouped.set(item.cipherId, [item]);
  }

  return grouped;
}

export async function addAttachmentToCipher(db: D1Database, cipherId: string, attachmentId: string): Promise<void> {
  await db.prepare('UPDATE attachments SET cipher_id = ? WHERE id = ?').bind(cipherId, attachmentId).run();
}

export async function addAttachmentToCipherForUser(
  db: D1Database,
  cipherId: string,
  attachmentId: string,
  userId: string
): Promise<void> {
  await db
    .prepare(
      `WITH actor AS (SELECT ? AS user_id)
       UPDATE attachments SET cipher_id = ? WHERE id = ? AND EXISTS (
         SELECT 1 FROM ciphers current_cipher
         JOIN ciphers next_cipher ON next_cipher.id = ?
         WHERE current_cipher.id = attachments.cipher_id AND (${sameOwnerSql})
           AND ${cipherAccessSql('write', 'current_cipher')} AND ${cipherAccessSql('write', 'next_cipher')}
       )`
    )
    .bind(userId, cipherId, attachmentId, cipherId)
    .run();
}

export async function deleteAllAttachmentsByCipher(db: D1Database, cipherId: string): Promise<void> {
  await db.prepare('DELETE FROM attachments WHERE cipher_id = ?').bind(cipherId).run();
}

export async function updateCipherRevisionDate(
  db: D1Database,
  cipherId: string,
  userId: string
): Promise<{ userId: string; userIds: string[]; revisionDate: string } | null> {
  const revisionDate = new Date().toISOString();
  const results = await db.batch([
    db.prepare(`WITH actor AS (SELECT ? AS user_id)
      UPDATE ciphers SET updated_at = ${nextRevisionSql} WHERE id = ? AND ${cipherAccessSql('write', 'ciphers')}
      RETURNING updated_at`).bind(userId, revisionDate, revisionDate, cipherId),
    db.prepare(`WITH recipients AS (
      SELECT u.id AS user_id, c.updated_at AS cipher_revision FROM users u JOIN ciphers c ON c.id = ?
      WHERE changes() > 0 AND (c.user_id = u.id OR EXISTS (
        SELECT 1 FROM organization_members m WHERE m.organization_id = c.organization_id
          AND m.user_id = u.id AND m.status = 2
      ))
    ), next_revision AS (
      SELECT CASE WHEN MAX(r.revision_date) >= MAX(p.cipher_revision)
        THEN strftime('%Y-%m-%dT%H:%M:%fZ', MAX(r.revision_date), '+0.001 seconds')
        ELSE MAX(p.cipher_revision) END AS revision_date
      FROM recipients p LEFT JOIN user_revisions r ON r.user_id = p.user_id
    ) INSERT INTO user_revisions(user_id, revision_date)
      SELECT p.user_id, next.revision_date FROM recipients p CROSS JOIN next_revision next
      WHERE next.revision_date IS NOT NULL
      ON CONFLICT(user_id) DO UPDATE SET revision_date = MAX(user_revisions.revision_date, excluded.revision_date)
      RETURNING user_id, revision_date`).bind(cipherId),
  ]);
  if (!(results[0]?.meta.changes ?? 0)) return null;
  const cipherRevision = (results[0]?.results[0] as { updated_at: string }).updated_at;
  const revisions = (results[1]?.results ?? []) as { user_id: string; revision_date: string }[];
  const actualRevision = revisions.reduce((latest, row) => row.revision_date > latest ? row.revision_date : latest, cipherRevision);
  return { userId, userIds: revisions.map((row) => row.user_id), revisionDate: actualRevision };
}
