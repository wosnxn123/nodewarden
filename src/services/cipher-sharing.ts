import type { Attachment, Cipher } from '../types';
import { collectionAccessSql, cipherAccessSql } from './organization-access';
import { commitOrganizationMutation, eventGuard } from './organization-repo';
import {
  buildCipherData,
  getCipherStorageSnapshot,
} from './storage-cipher-repo';

export function parseCollectionIds(value: unknown): string[] | null {
  if (
    !Array.isArray(value) ||
    value.length > 100 ||
    value.some((id) => typeof id !== 'string' || !id.trim())
  )
    return null;
  return [...new Set(value.map((id) => (id as string).trim()))];
}
// Validate EVERY requested collection in the mutation statement. A preflight read
// alone would permit sharing after membership/collection rights were revoked.
function destinationSql(): string {
  return `EXISTS(SELECT 1 FROM organization_members m WHERE m.organization_id=(SELECT org FROM destination)
    AND m.user_id=(SELECT user_id FROM actor) AND m.status=2 AND m.key IS NOT NULL
    AND (m.type IN (0,1) OR m.access_all=1 OR json_array_length((SELECT ids FROM destination))>0))
    AND NOT EXISTS(SELECT 1 FROM json_each((SELECT ids FROM destination)) selected
      WHERE NOT EXISTS(SELECT 1 FROM collections col WHERE col.id=selected.value
        AND col.organization_id=(SELECT org FROM destination) AND ${collectionAccessSql('write', 'col')}))`;
}
const CTE =
  'WITH actor AS (SELECT ? AS user_id), destination AS (SELECT ? AS org, ? AS ids) ';
function collectionStatements(
  db: D1Database,
  cipherId: string,
  ids: string[],
  eventId: string
): D1PreparedStatement[] {
  return [
    db
      .prepare(
        `DELETE FROM cipher_collections WHERE cipher_id=? AND ${eventGuard(eventId)}`
      )
      .bind(cipherId),
    db
      .prepare(
        `INSERT INTO cipher_collections(cipher_id,collection_id) SELECT ?,value FROM json_each(?) WHERE ${eventGuard(eventId)}`
      )
      .bind(cipherId, JSON.stringify(ids)),
  ];
}
function preferenceStatement(
  db: D1Database,
  cipher: Cipher,
  userId: string,
  eventId: string
): D1PreparedStatement {
  return db
    .prepare(
      `INSERT INTO cipher_user_preferences(cipher_id,user_id,folder_id,favorite)
    SELECT ?,?,?,? WHERE ${eventGuard(eventId)}
      AND (? IS NULL OR EXISTS(SELECT 1 FROM folders WHERE id=? AND user_id=?))
    ON CONFLICT(cipher_id,user_id) DO UPDATE SET folder_id=excluded.folder_id,favorite=excluded.favorite`
    )
    .bind(
      cipher.id,
      userId,
      cipher.folderId,
      cipher.favorite ? 1 : 0,
      cipher.folderId,
      cipher.folderId,
      userId
    );
}
export async function createOrganizationCipher(
  db: D1Database,
  cipher: Cipher,
  userId: string,
  collectionIds: string[]
): Promise<boolean> {
  if (!cipher.organizationId) return false;
  return commitOrganizationMutation(db, {
    organizationId: cipher.organizationId,
    actorUserId: userId,
    eventType: 1100,
    targetId: cipher.id,
    extraUserIds: [userId],
    sql:
      CTE +
      `INSERT INTO ciphers(id,user_id,organization_id,type,folder_id,name,notes,favorite,data,reprompt,key,created_at,updated_at,archived_at,deleted_at)
      SELECT ?,NULL,(SELECT org FROM destination),?,NULL,?,?,0,?,?,?,?,?,?,NULL WHERE ${destinationSql()}`,
    bindings: [
      userId,
      cipher.organizationId,
      JSON.stringify(collectionIds),
      cipher.id,
      cipher.type,
      cipher.name,
      cipher.notes,
      buildCipherData(cipher),
      cipher.reprompt,
      cipher.key,
      cipher.createdAt,
      cipher.updatedAt,
      cipher.archivedAt,
    ],
    additional: (eventId) => [
      ...collectionStatements(db, cipher.id, collectionIds, eventId),
      preferenceStatement(db, cipher, userId, eventId),
    ],
  });
}
export async function sharePersonalCipher(
  db: D1Database,
  cipher: Cipher,
  userId: string,
  expectedUpdatedAt: string,
  collectionIds: string[],
  attachments: Attachment[],
  original: { cipher: Cipher; attachments: Attachment[] }
): Promise<boolean> {
  const snapshot = getCipherStorageSnapshot(original.cipher);
  if (
    !cipher.organizationId ||
    !snapshot ||
    snapshot.id !== cipher.id ||
    snapshot.user_id !== userId
  )
    return false;
  const originalAttachments = JSON.stringify(original.attachments);
  return commitOrganizationMutation(db, {
    organizationId: cipher.organizationId,
    actorUserId: userId,
    eventType: 1102,
    targetId: cipher.id,
    extraUserIds: [userId],
    sql:
      CTE +
      `UPDATE ciphers SET user_id=NULL,organization_id=(SELECT org FROM destination),folder_id=NULL,favorite=0,
      type=?,name=?,notes=?,data=?,reprompt=?,key=?,updated_at=?
      WHERE id=? AND user_id=(SELECT user_id FROM actor) AND organization_id IS NULL AND updated_at=? AND deleted_at IS NULL
        AND data=? AND key IS ? AND name IS ? AND notes IS ? AND type IS ? AND reprompt IS ?
        AND archived_at IS ? AND favorite IS ? AND folder_id IS ?
        AND (SELECT count(*) FROM attachments WHERE cipher_id=ciphers.id)=?
        AND NOT EXISTS(SELECT 1 FROM attachments WHERE cipher_id=ciphers.id AND id NOT IN(SELECT value FROM json_each(?)))
        AND NOT EXISTS(SELECT 1 FROM attachments a LEFT JOIN json_each(?) prior ON json_extract(prior.value,'$.id')=a.id
          WHERE a.cipher_id=ciphers.id AND (prior.value IS NULL OR a.key IS NOT json_extract(prior.value,'$.key')
            OR a.file_name IS NOT json_extract(prior.value,'$.fileName') OR a.size IS NOT json_extract(prior.value,'$.size')))
        AND ${destinationSql()}`,
    bindings: [
      userId,
      cipher.organizationId,
      JSON.stringify(collectionIds),
      cipher.type,
      cipher.name,
      cipher.notes,
      buildCipherData(cipher),
      cipher.reprompt,
      cipher.key,
      cipher.updatedAt,
      cipher.id,
      expectedUpdatedAt,
      snapshot.data,
      snapshot.key,
      snapshot.name,
      snapshot.notes,
      snapshot.type,
      snapshot.reprompt,
      snapshot.archived_at,
      snapshot.favorite,
      snapshot.folder_id,
      attachments.length,
      JSON.stringify(attachments.map((attachment) => attachment.id)),
      originalAttachments,
    ],
    additional: (eventId) => [
      ...collectionStatements(db, cipher.id, collectionIds, eventId),
      preferenceStatement(db, cipher, userId, eventId),
      ...attachments.map((attachment) =>
        db
          .prepare(
            `UPDATE attachments SET file_name=?,key=? WHERE id=? AND cipher_id=? AND ${eventGuard(eventId)}`
          )
          .bind(attachment.fileName, attachment.key, attachment.id, cipher.id)
      ),
    ],
  });
}
export async function replaceCipherCollections(
  db: D1Database,
  userId: string,
  cipher: Cipher,
  collectionIds: string[]
): Promise<boolean> {
  if (!cipher.organizationId) return false;
  const ids = JSON.stringify(collectionIds);
  return commitOrganizationMutation(db, {
    organizationId: cipher.organizationId,
    actorUserId: userId,
    eventType: 1101,
    targetId: cipher.id,
    extraUserIds: [userId],
    sql:
      CTE +
      `UPDATE ciphers AS c SET updated_at=? WHERE c.id=? AND c.organization_id=(SELECT org FROM destination)
      AND c.updated_at=? AND ${cipherAccessSql('write')}
      AND NOT EXISTS(SELECT 1 FROM json_each((SELECT ids FROM destination)) posted
        WHERE NOT EXISTS(SELECT 1 FROM collections col WHERE col.id=posted.value
          AND col.organization_id=c.organization_id
          AND (${collectionAccessSql('write', 'col')} OR (${collectionAccessSql('read', 'col')}
            AND EXISTS(SELECT 1 FROM cipher_collections cc WHERE cc.cipher_id=c.id AND cc.collection_id=col.id)))))
      AND NOT EXISTS(SELECT 1 FROM cipher_collections cc JOIN collections col ON col.id=cc.collection_id
        WHERE cc.cipher_id=c.id AND ${collectionAccessSql('read', 'col')} AND NOT ${collectionAccessSql('write', 'col')}
          AND col.id NOT IN(SELECT value FROM json_each((SELECT ids FROM destination))))`,
    bindings: [
      userId,
      cipher.organizationId,
      ids,
      new Date(
        Math.max(Date.now(), Date.parse(cipher.updatedAt) + 1)
      ).toISOString(),
      cipher.id,
      cipher.updatedAt,
    ],
    // Mirror the reference's visible-collection difference. Inaccessible existing
    // links are preserved; unchanged read-only links need no write grant.
    additional: (eventId) => [
      db
        .prepare(
          `WITH actor AS (SELECT ? AS user_id) DELETE FROM cipher_collections
        WHERE cipher_id=? AND collection_id NOT IN(SELECT value FROM json_each(?))
          AND collection_id IN(SELECT col.id FROM collections col WHERE ${collectionAccessSql('write', 'col')})
          AND ${eventGuard(eventId)}`
        )
        .bind(userId, cipher.id, ids),
      db
        .prepare(
          `INSERT INTO cipher_collections(cipher_id,collection_id)
        SELECT ?,value FROM json_each(?) WHERE ${eventGuard(eventId)}
        ON CONFLICT(cipher_id,collection_id) DO NOTHING`
        )
        .bind(cipher.id, ids),
    ],
  });
}
