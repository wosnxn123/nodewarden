import type { Attachment, Cipher } from '../types';
import {
  cipherAccessSql,
  cipherHidePasswordsSql,
  cipherCollectionIdsSql,
} from './organization-access';
import { commitOrganizationMutation, eventGuard } from './organization-repo';
import { generateUUID } from '../utils/uuid';

function normalizeOptionalId(value: unknown): string | null {
  if (value == null) return null;
  return String(value).trim() || null;
}
type SafeBind = (
  stmt: D1PreparedStatement,
  ...values: any[]
) => D1PreparedStatement;
type SqlChunkSize = (fixedBindCount: number) => number;
type UpdateRevisionDate = (userId: string) => Promise<string>;
interface CipherRow {
  id: string;
  user_id: string | null;
  organization_id: string | null;
  type: number | null;
  folder_id: string | null;
  name: string | null;
  notes: string | null;
  favorite: number | null;
  data: string;
  reprompt: number | null;
  key: string | null;
  created_at: string;
  updated_at: string;
  archived_at: string | null;
  deleted_at: string | null;
  can_write?: number;
  hide_passwords?: number;
  collection_ids?: string;
}

// Request-local original rows support CAS across legacy revision-preserving
// repairs without exposing storage metadata in JSON or trusting client fields.
const storageSnapshots = new WeakMap<Cipher, CipherRow>();
export function getCipherStorageSnapshot(
  cipher: Cipher
): Readonly<CipherRow> | null {
  return storageSnapshots.get(cipher) ?? null;
}

// Ownership and authorization are columns/relations, NEVER opaque client data.
const CIPHER_SCALAR_DATA_KEYS = new Set([
  'id',
  'userId',
  'user_id',
  'organizationId',
  'organization_id',
  'OrganizationId',
  'type',
  'folderId',
  'folder_id',
  'name',
  'notes',
  'favorite',
  'reprompt',
  'key',
  'attachments',
  'Attachments',
  'attachments2',
  'Attachments2',
  'edit',
  'Edit',
  'viewPassword',
  'ViewPassword',
  'permissions',
  'Permissions',
  'collectionIds',
  'CollectionIds',
  'organizationUseTotp',
  'OrganizationUseTotp',
  'createdAt',
  'created_at',
  'creationDate',
  'updatedAt',
  'updated_at',
  'revisionDate',
  'lastKnownRevisionDate',
  'LastKnownRevisionDate',
  'archivedAt',
  'archived_at',
  'archivedDate',
  'deletedAt',
  'deleted_at',
  'deletedDate',
]);
export function buildCipherData(
  cipher: Cipher,
  _folderId?: string | null
): string {
  const payload: Record<string, unknown> = { ...cipher };
  for (const key of CIPHER_SCALAR_DATA_KEYS) delete payload[key];
  return JSON.stringify(payload);
}
function parseCipherRow(row: CipherRow | null | undefined): Cipher | null {
  if (!row?.data) return null;
  try {
    const parsed = JSON.parse(row.data) as Cipher;
    // Legacy opaque payloads may contain alternate-casing ownership/rights too.
    for (const key of [
      'OrganizationId',
      'organization_id',
      'CollectionIds',
      'Edit',
      'ViewPassword',
      'Permissions',
      'OrganizationUseTotp',
      'user_id',
    ])
      delete parsed[key];
    const writable =
      row.can_write == null ? !row.organization_id : !!row.can_write;
    const viewPassword = !row.hide_passwords;
    const cipher: Cipher = {
      ...parsed,
      id: row.id,
      userId: row.user_id,
      organizationId: row.organization_id ?? null,
      type: Number(row.type) || Number(parsed.type) || 1,
      folderId: normalizeOptionalId(
        row.organization_id ? row.folder_id : (row.folder_id ?? parsed.folderId)
      ),
      name: row.name ?? parsed.name ?? null,
      notes: row.notes ?? parsed.notes ?? null,
      favorite: row.favorite != null ? !!row.favorite : !!parsed.favorite,
      reprompt: row.reprompt ?? parsed.reprompt ?? 0,
      key: row.key ?? parsed.key ?? null,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      archivedAt:
        row.archived_at ?? parsed.archivedAt ?? parsed.archivedDate ?? null,
      deletedAt:
        row.deleted_at ?? parsed.deletedAt ?? parsed.deletedDate ?? null,
      collectionIds: JSON.parse(row.collection_ids || '[]'),
      edit: writable,
      viewPassword,
      organizationUseTotp: !!row.organization_id,
      permissions: { delete: writable, restore: writable },
    };
    storageSnapshots.set(cipher, row);
    return cipher;
  } catch {
    console.error('Corrupted cipher data, id:', row.id);
    return null;
  }
}
const ACTOR = 'WITH actor AS (SELECT ? AS user_id) ';
function columns(scoped = true): string {
  const base =
    'c.id,c.user_id,c.organization_id,c.type,c.name,c.notes,c.data,c.reprompt,c.key,c.created_at,c.updated_at,c.archived_at,c.deleted_at';
  if (!scoped) return base + ',c.folder_id,c.favorite';
  return (
    base +
    `,
    CASE WHEN c.organization_id IS NULL THEN c.folder_id ELSE
      (SELECT p.folder_id FROM cipher_user_preferences p WHERE p.cipher_id=c.id AND p.user_id=(SELECT user_id FROM actor)) END AS folder_id,
    CASE WHEN c.organization_id IS NULL THEN c.favorite ELSE COALESCE(
      (SELECT p.favorite FROM cipher_user_preferences p WHERE p.cipher_id=c.id AND p.user_id=(SELECT user_id FROM actor)),0) END AS favorite,
    (${cipherAccessSql('write')}) AS can_write, (${cipherHidePasswordsSql()}) AS hide_passwords,
    (${cipherCollectionIdsSql()}) AS collection_ids`
  );
}
function parseRows(rows: CipherRow[]): Cipher[] {
  return rows.flatMap((row) => {
    const cipher = parseCipherRow(row);
    return cipher ? [cipher] : [];
  });
}
export async function getCipher(
  db: D1Database,
  id: string
): Promise<Cipher | null> {
  return parseCipherRow(
    await db
      .prepare(`SELECT ${columns(false)} FROM ciphers c WHERE c.id=?`)
      .bind(id)
      .first<CipherRow>()
  );
}
export async function getCipherForUser(
  db: D1Database,
  id: string,
  userId: string
): Promise<Cipher | null> {
  return parseCipherRow(
    await db
      .prepare(
        ACTOR +
          `SELECT ${columns()} FROM ciphers c WHERE c.id=? AND ${cipherAccessSql('read')}`
      )
      .bind(userId, id)
      .first<CipherRow>()
  );
}
export async function saveCipher(
  db: D1Database,
  safeBind: SafeBind,
  cipher: Cipher,
  actorUserId?: string
): Promise<void> {
  if (cipher.organizationId) {
    // Organization creation/sharing must use the dedicated atomic ownership path.
    const actor = actorUserId;
    if (!actor) throw new Error('Organization cipher save requires an actor');
    if (
      !(await updateCipherIfUnchanged(
        db,
        safeBind,
        cipher,
        cipher.updatedAt,
        actor
      ))
    ) {
      throw new Error('Organization cipher changed or permission denied');
    }
    return;
  }
  if (!cipher.userId) throw new Error('Personal cipher requires an owner');
  await safeBind(
    db.prepare(
      'INSERT INTO ciphers(id,user_id,organization_id,type,folder_id,name,notes,favorite,data,reprompt,key,created_at,updated_at,archived_at,deleted_at) ' +
        'VALUES(?,?,NULL,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET ' +
        'type=excluded.type,folder_id=excluded.folder_id,name=excluded.name,notes=excluded.notes,favorite=excluded.favorite,data=excluded.data,' +
        'reprompt=excluded.reprompt,key=excluded.key,updated_at=excluded.updated_at,archived_at=excluded.archived_at,deleted_at=excluded.deleted_at ' +
        'WHERE ciphers.user_id=excluded.user_id AND ciphers.organization_id IS NULL'
    ),
    cipher.id,
    cipher.userId,
    Number(cipher.type) || 1,
    normalizeOptionalId(cipher.folderId),
    cipher.name,
    cipher.notes,
    cipher.favorite ? 1 : 0,
    buildCipherData(cipher),
    cipher.reprompt ?? 0,
    cipher.key,
    cipher.createdAt,
    cipher.updatedAt,
    cipher.archivedAt ?? null,
    cipher.deletedAt
  ).run();
}
export async function updateCipherIfUnchanged(
  db: D1Database,
  safeBind: SafeBind,
  cipher: Cipher,
  expectedUpdatedAt: string,
  actorUserId?: string,
  attachments: Attachment[] = []
): Promise<boolean> {
  const actor = actorUserId || cipher.userId;
  if (!actor) return false;
  const sql =
    ACTOR +
    `UPDATE ciphers AS c SET type=?,
    folder_id=CASE WHEN organization_id IS NULL THEN ? ELSE NULL END,
    name=?,notes=?,favorite=CASE WHEN organization_id IS NULL THEN ? ELSE 0 END,
    data=?,reprompt=?,key=?,updated_at=?,archived_at=?,deleted_at=?
    WHERE c.id=? AND c.updated_at=? AND c.user_id IS ? AND c.organization_id IS ? AND ${cipherAccessSql('write')}`;
  const bindings = [
    actor,
    Number(cipher.type) || 1,
    normalizeOptionalId(cipher.folderId),
    cipher.name,
    cipher.notes,
    cipher.favorite ? 1 : 0,
    buildCipherData(cipher),
    cipher.reprompt ?? 0,
    cipher.key,
    cipher.updatedAt,
    cipher.archivedAt ?? null,
    cipher.deletedAt,
    cipher.id,
    expectedUpdatedAt,
    cipher.userId,
    cipher.organizationId ?? null,
  ].map((value) => value ?? null);
  const metadata = (guard: string) =>
    attachments.map((attachment) =>
      db
        .prepare(
          `UPDATE attachments SET file_name=?,key=? WHERE id=? AND cipher_id=? AND ${guard}`
        )
        .bind(attachment.fileName, attachment.key, attachment.id, cipher.id)
    );
  if (cipher.organizationId) {
    return commitOrganizationMutation(db, {
      organizationId: cipher.organizationId,
      actorUserId: actor,
      eventType: 1101,
      targetId: cipher.id,
      sql,
      bindings,
      additional: (eventId) => [
        db
          .prepare(
            `INSERT INTO cipher_user_preferences(cipher_id,user_id,folder_id,favorite)
          SELECT ?,?,?,? WHERE ${eventGuard(eventId)}
          ON CONFLICT(cipher_id,user_id) DO UPDATE SET folder_id=excluded.folder_id,favorite=excluded.favorite`
          )
          .bind(
            cipher.id,
            actor,
            normalizeOptionalId(cipher.folderId),
            cipher.favorite ? 1 : 0
          ),
        ...metadata(eventGuard(eventId)),
      ],
      extraUserIds: [actor],
    });
  }
  const stmt = safeBind(db.prepare(sql), ...bindings);
  if (!attachments.length) return (await stmt.run()).meta.changes === 1;
  // A transaction-local marker binds ALL metadata writes to the successful CAS,
  // including compatibility repairs which deliberately preserve revisionDate.
  const marker = `cipher.mutation.${generateUUID()}`;
  const results = await db.batch([
    stmt,
    db
      .prepare("INSERT INTO config(key,value) SELECT ?,'1' WHERE changes()=1")
      .bind(marker),
    ...metadata(`EXISTS(SELECT 1 FROM config WHERE key='${marker}')`),
    db.prepare('DELETE FROM config WHERE key=?').bind(marker),
  ]);
  return results[0].meta.changes === 1;
}
function preferenceStatement(
  db: D1Database,
  id: string,
  userId: string,
  folderId: string | null,
  favorite: boolean,
  requireChanged = false
): D1PreparedStatement {
  return db
    .prepare(
      ACTOR +
        `INSERT INTO cipher_user_preferences(cipher_id,user_id,folder_id,favorite)
    SELECT c.id,(SELECT user_id FROM actor),?,? FROM ciphers c
    WHERE c.id=? AND c.organization_id IS NOT NULL AND ${cipherAccessSql('read')}
      AND (? IS NULL OR EXISTS(SELECT 1 FROM folders WHERE id=? AND user_id=(SELECT user_id FROM actor)))
      ${requireChanged ? 'AND changes()=1' : ''}
    ON CONFLICT(cipher_id,user_id) DO UPDATE SET folder_id=excluded.folder_id,favorite=excluded.favorite`
    )
    .bind(
      userId,
      normalizeOptionalId(folderId),
      favorite ? 1 : 0,
      id,
      folderId,
      folderId
    );
}
export async function saveCipherPreferences(
  db: D1Database,
  id: string,
  userId: string,
  folderId: string | null,
  favorite: boolean
): Promise<boolean> {
  return (
    (await preferenceStatement(db, id, userId, folderId, favorite).run()).meta
      .changes === 1
  );
}
function sanitizeIds(ids: string[]): string[] {
  return [...new Set(ids.map((id) => String(id || '').trim()).filter(Boolean))];
}
export async function deleteCipher(
  db: D1Database,
  id: string,
  userId: string,
  expectedUpdatedAt?: string
): Promise<boolean> {
  const cipher = await getCipherForUser(db, id, userId);
  if (!cipher) return false;
  const sql =
    ACTOR +
    `DELETE FROM ciphers AS c WHERE c.id=? AND c.organization_id IS ? AND (? IS NULL OR c.updated_at=?) AND ${cipherAccessSql('write')}`;
  const bindings = [
    userId,
    id,
    cipher.organizationId ?? null,
    expectedUpdatedAt ?? null,
    expectedUpdatedAt ?? null,
  ];
  if (cipher.organizationId)
    return commitOrganizationMutation(db, {
      organizationId: cipher.organizationId,
      actorUserId: userId,
      eventType: 1109,
      targetId: id,
      sql,
      bindings,
      extraUserIds: [userId],
    });
  return (
    (
      await db
        .prepare(sql)
        .bind(...bindings)
        .run()
    ).meta.changes === 1
  );
}
async function bulkMutation(
  db: D1Database,
  chunkSize: SqlChunkSize,
  revision: UpdateRevisionDate,
  ids: string[],
  userId: string,
  setSql: string,
  values: unknown[],
  extraPredicate = '1'
): Promise<string | null> {
  const accessible = await getCiphersByIds(db, chunkSize, ids, userId);
  const groups = new Map<string | null, string[]>();
  for (const cipher of accessible) {
    const owner = cipher.organizationId ?? null;
    groups.set(owner, [...(groups.get(owner) ?? []), cipher.id]);
  }
  let changed = false;
  const size = chunkSize(values.length + 2);
  for (const [organizationId, groupIds] of groups) {
    for (let i = 0; i < groupIds.length; i += size) {
      const chunk = groupIds.slice(i, i + size);
      const sql =
        ACTOR +
        `UPDATE ciphers AS c SET ${setSql} WHERE c.organization_id IS ? AND c.id IN (${chunk.map(() => '?').join(',')}) AND ${cipherAccessSql('write')} AND (${extraPredicate})`;
      const bindings = [userId, ...values, organizationId, ...chunk];
      const didChange = organizationId
        ? await commitOrganizationMutation(db, {
            organizationId,
            actorUserId: userId,
            eventType: 1101,
            targetId: null,
            sql,
            bindings,
            extraUserIds: [userId],
          })
        : (
            await db
              .prepare(sql)
              .bind(...bindings)
              .run()
          ).meta.changes > 0;
      changed = changed || didChange;
    }
  }
  return changed ? revision(userId) : null;
}
export async function bulkSoftDeleteCiphers(
  db: D1Database,
  size: SqlChunkSize,
  revision: UpdateRevisionDate,
  ids: string[],
  userId: string
): Promise<string | null> {
  const now = new Date().toISOString();
  return bulkMutation(
    db,
    size,
    revision,
    ids,
    userId,
    'deleted_at=?,updated_at=?',
    [now, now]
  );
}
export async function bulkRestoreCiphers(
  db: D1Database,
  size: SqlChunkSize,
  revision: UpdateRevisionDate,
  ids: string[],
  userId: string
): Promise<string | null> {
  return bulkMutation(
    db,
    size,
    revision,
    ids,
    userId,
    "deleted_at=NULL,updated_at=?,data=json_remove(data,'$.deletedAt','$.deletedDate','$.updatedAt','$.revisionDate')",
    [new Date().toISOString()]
  );
}
export async function bulkDeleteCiphers(
  db: D1Database,
  _size: SqlChunkSize,
  revision: UpdateRevisionDate,
  ids: string[],
  userId: string
): Promise<string | null> {
  let changed = false;
  for (const id of sanitizeIds(ids)) {
    const deleted = await deleteCipher(db, id, userId);
    changed = changed || deleted;
  }
  return changed ? revision(userId) : null;
}
export async function getAllCiphers(
  db: D1Database,
  userId: string
): Promise<Cipher[]> {
  const res = await db
    .prepare(
      ACTOR +
        `SELECT ${columns()} FROM ciphers c WHERE ${cipherAccessSql('read')} ORDER BY c.updated_at DESC,c.id`
    )
    .bind(userId)
    .all<CipherRow>();
  return parseRows(res.results || []);
}
export async function getCiphersPage(
  db: D1Database,
  userId: string,
  includeDeleted: boolean,
  limit: number,
  offset: number
): Promise<Cipher[]> {
  const visible = includeDeleted
    ? ''
    : "AND c.deleted_at IS NULL AND json_extract(c.data, '$.deletedAt') IS NULL AND json_extract(c.data, '$.deletedDate') IS NULL";
  const res = await db
    .prepare(
      ACTOR +
        `SELECT ${columns()} FROM ciphers c WHERE ${cipherAccessSql('read')} ${visible} ORDER BY c.updated_at DESC,c.id LIMIT ? OFFSET ?`
    )
    .bind(userId, limit, offset)
    .all<CipherRow>();
  return parseRows(res.results || []);
}
export async function getCiphersByIds(
  db: D1Database,
  size: SqlChunkSize,
  ids: string[],
  userId: string
): Promise<Cipher[]> {
  const unique = sanitizeIds(ids),
    out: Cipher[] = [];
  const n = size(1);
  for (let i = 0; i < unique.length; i += n) {
    const chunk = unique.slice(i, i + n);
    const res = await db
      .prepare(
        ACTOR +
          `SELECT ${columns()} FROM ciphers c WHERE c.id IN (${chunk.map(() => '?').join(',')}) AND ${cipherAccessSql('read')}`
      )
      .bind(userId, ...chunk)
      .all<CipherRow>();
    out.push(...parseRows(res.results || []));
  }
  return out;
}
export async function bulkMoveCiphers(
  db: D1Database,
  size: SqlChunkSize,
  revision: UpdateRevisionDate,
  ids: string[],
  folderId: string | null,
  userId: string
): Promise<string | null> {
  const unique = sanitizeIds(ids);
  if (!unique.length) return null;
  const folder = normalizeOptionalId(folderId);
  if (
    folder &&
    !(await db
      .prepare('SELECT id FROM folders WHERE id=? AND user_id=?')
      .bind(folder, userId)
      .first())
  )
    return null;
  let changed = 0;
  // Folder placement is personal metadata; a read-only collection can still be organized locally.
  for (const id of unique) {
    const result = await db.batch([
      db
        .prepare(
          "UPDATE ciphers SET folder_id=?,updated_at=?,data=json_remove(data,'$.folderId','$.folder_id','$.updatedAt','$.revisionDate') WHERE id=? AND user_id=? AND organization_id IS NULL"
        )
        .bind(folder, new Date().toISOString(), id, userId),
      db
        .prepare(
          ACTOR +
            `INSERT INTO cipher_user_preferences(cipher_id,user_id,folder_id,favorite)
        SELECT c.id,(SELECT user_id FROM actor),?,COALESCE((SELECT favorite FROM cipher_user_preferences WHERE cipher_id=c.id AND user_id=(SELECT user_id FROM actor)),0)
        FROM ciphers c WHERE c.id=? AND c.organization_id IS NOT NULL AND ${cipherAccessSql('read')}
        ON CONFLICT(cipher_id,user_id) DO UPDATE SET folder_id=excluded.folder_id`
        )
        .bind(userId, folder, id),
    ]);
    changed += result.reduce((n, r) => n + r.meta.changes, 0);
  }
  return changed ? revision(userId) : null;
}
export async function bulkArchiveCiphers(
  db: D1Database,
  size: SqlChunkSize,
  revision: UpdateRevisionDate,
  ids: string[],
  userId: string
): Promise<string | null> {
  const now = new Date().toISOString();
  return bulkMutation(
    db,
    size,
    revision,
    ids,
    userId,
    "archived_at=?,updated_at=?,data=json_remove(data,'$.archivedAt','$.archivedDate','$.updatedAt','$.revisionDate')",
    [now, now],
    "c.deleted_at IS NULL AND json_extract(c.data,'$.deletedAt') IS NULL AND json_extract(c.data,'$.deletedDate') IS NULL"
  );
}
export async function bulkUnarchiveCiphers(
  db: D1Database,
  size: SqlChunkSize,
  revision: UpdateRevisionDate,
  ids: string[],
  userId: string
): Promise<string | null> {
  return bulkMutation(
    db,
    size,
    revision,
    ids,
    userId,
    "archived_at=NULL,updated_at=?,data=json_remove(data,'$.archivedAt','$.archivedDate','$.updatedAt','$.revisionDate')",
    [new Date().toISOString()]
  );
}
