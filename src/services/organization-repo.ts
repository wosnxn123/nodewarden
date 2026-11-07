import type { Attachment } from '../types';
import { generateUUID } from '../utils/uuid';
import {
  organizationFeatures,
  collectionGrantSql,
} from './organization-access';

export interface OrganizationRow {
  id: string;
  name: string;
  billing_email: string;
  public_key: string | null;
  private_key: string | null;
  created_at: string;
  updated_at: string;
}
export interface OrganizationMemberRow {
  id: string;
  organization_id: string;
  user_id: string | null;
  email: string;
  type: number;
  status: number;
  access_all: number;
  key: string | null;
  external_id: string | null;
  created_at: string;
  updated_at: string;
}
export interface CollectionAssignment {
  id: string;
  readOnly: boolean;
  hidePasswords: boolean;
  manage: boolean;
}
export interface OrganizationCollectionRow {
  id: string;
  organization_id: string;
  name: string;
  external_id: string | null;
}
export interface OrganizationGroupRow extends OrganizationCollectionRow {
  access_all: number;
}

export function organizationToResponse(
  row: OrganizationRow
): Record<string, unknown> {
  return {
    ...organizationFeatures(),
    id: row.id,
    name: row.name,
    billingEmail: row.billing_email,
    businessName: row.name,
    businessAddress1: null,
    businessAddress2: null,
    businessAddress3: null,
    businessCountry: null,
    businessTaxNumber: null,
    hasPublicAndPrivateKeys: !!row.public_key && !!row.private_key,
    creationDate: row.created_at,
    revisionDate: row.updated_at,
    object: 'organization',
  };
}

export async function getOrganizationMember(
  db: D1Database,
  organizationId: string,
  userId: string
): Promise<OrganizationMemberRow | null> {
  return db
    .prepare(
      'SELECT * FROM organization_members WHERE organization_id = ? AND user_id = ?'
    )
    .bind(organizationId, userId)
    .first<OrganizationMemberRow>();
}

// All mutations must use these predicates in SQL, not only a preflight lookup.
export function organizationAdminSql(
  organization = '?',
  ownerOnly = false
): string {
  return `EXISTS (SELECT 1 FROM organization_members actor_member WHERE actor_member.organization_id = ${organization}
    AND actor_member.user_id = (SELECT user_id FROM actor) AND actor_member.status = 2
    AND actor_member.type ${ownerOnly ? '= 0' : 'IN (0, 1)'})`;
}
export function collectionManagementSql(): string {
  return `EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = collections.organization_id
    AND m.user_id = (SELECT user_id FROM actor) AND m.status = 2 AND ${collectionGrantSql('manage', 'collections')})`;
}

export function lastOwnerSql(memberAlias = 'organization_members'): string {
  return `NOT (${memberAlias}.type = 0 AND ${memberAlias}.status = 2 AND NOT EXISTS (
    SELECT 1 FROM organization_members other_owner WHERE other_owner.organization_id = ${memberAlias}.organization_id
    AND other_owner.type = 0 AND other_owner.status = 2 AND other_owner.id <> ${memberAlias}.id))`;
}

export interface OrganizationMutation {
  organizationId: string;
  actorUserId: string;
  eventType: number;
  targetId: string | null;
  sql: string;
  bindings: unknown[];
  additional?: (eventId: string) => D1PreparedStatement[];
  extraUserIds?: string[];
}

function revisionStatements(
  db: D1Database,
  eventId: string,
  organizationId: string,
  date: string,
  extraUserIds: string[]
): D1PreparedStatement[] {
  // Runtime outbox is not an audit log. It carries only durable notification recipients;
  // backup exporters must exclude the organization.sync. prefix.
  const key = `organization.sync.${eventId}`;
  return [
    db
      .prepare(
        `INSERT INTO config(key, value)
    SELECT ?, json_object('organizationId', ?, 'revisionDate', ?, 'userIds', json((
      SELECT json_group_array(user_id) FROM (
        SELECT user_id FROM organization_members WHERE organization_id = ? AND status = 2 AND user_id IS NOT NULL
        UNION SELECT value AS user_id FROM json_each(?) WHERE value IS NOT NULL
        UNION SELECT j.value AS user_id FROM config snapshot, json_each(snapshot.value, '$.userIds') j
          WHERE snapshot.key = ?
      )
    ))) WHERE EXISTS (SELECT 1 FROM organization_events WHERE id = ?)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value`
      )
      .bind(
        key,
        organizationId,
        date,
        organizationId,
        JSON.stringify(extraUserIds),
        key,
        eventId
      ),
    db
      .prepare(
        `INSERT INTO user_revisions(user_id, revision_date)
      SELECT j.value, ? FROM config cfg, json_each(cfg.value, '$.userIds') j WHERE cfg.key = ?
      AND EXISTS (SELECT 1 FROM organization_events WHERE id = ?)
      ON CONFLICT(user_id) DO UPDATE SET revision_date = CASE
        WHEN user_revisions.revision_date >= excluded.revision_date
          THEN COALESCE(strftime('%Y-%m-%dT%H:%M:%fZ', user_revisions.revision_date, '+0.001 seconds'), excluded.revision_date)
        ELSE excluded.revision_date END`
      )
      .bind(date, key, eventId),
  ];
}

export async function commitOrganizationMutation(
  db: D1Database,
  mutation: OrganizationMutation
): Promise<boolean> {
  const eventId = generateUUID();
  const date = new Date().toISOString();
  const key = `organization.sync.${eventId}`;
  const statements = [
    // Snapshot within the write transaction, before a deletion/revocation can remove
    // its target. Reading target.user_id in a preflight request would be racy.
    db
      .prepare(
        `INSERT INTO config(key,value) SELECT ?, json_object('userIds', json((
      SELECT json_group_array(user_id) FROM organization_members WHERE organization_id = ? AND user_id IS NOT NULL
    ))) WHERE EXISTS (SELECT 1 FROM organizations WHERE id = ?)`
      )
      .bind(key, mutation.organizationId, mutation.organizationId),
    db.prepare(mutation.sql).bind(...mutation.bindings),
    db
      .prepare(
        `INSERT INTO organization_events(id, organization_id, actor_user_id, type, target_id, date, data)
      SELECT ?, ?, ?, ?, ?, ?, NULL WHERE changes() > 0`
      )
      .bind(
        eventId,
        mutation.organizationId,
        mutation.actorUserId,
        mutation.eventType,
        mutation.targetId,
        date
      ),
    ...(mutation.additional?.(eventId) ?? []),
    ...revisionStatements(
      db,
      eventId,
      mutation.organizationId,
      date,
      mutation.extraUserIds ?? []
    ),
    db
      .prepare(
        'DELETE FROM config WHERE key = ? AND NOT EXISTS (SELECT 1 FROM organization_events WHERE id = ?)'
      )
      .bind(key, eventId),
  ];
  const results = await db.batch(statements);
  return (results[2]?.meta.changes ?? 0) > 0;
}

export function eventGuard(eventId: string): string {
  // eventId is generated by this module, but keep the binding-based variant for callers.
  if (!/^[0-9a-f-]{36}$/i.test(eventId)) throw new Error('Invalid event id');
  return `EXISTS (SELECT 1 FROM organization_events WHERE id = '${eventId}')`;
}

export async function createOrganization(
  db: D1Database,
  userId: string,
  values: {
    name: string;
    billingEmail: string;
    key: string;
    publicKey: string | null;
    privateKey: string | null;
    collectionName: string;
  }
): Promise<OrganizationRow> {
  const id = generateUUID();
  const memberId = generateUUID();
  const collectionId = generateUUID();
  const eventId = generateUUID();
  const now = new Date().toISOString();
  await db.batch([
    db
      .prepare(
        `INSERT INTO organizations(id,name,billing_email,public_key,private_key,created_at,updated_at)
      SELECT ?,?,?,?,?,?,? FROM users WHERE id = ? AND status = 'active'`
      )
      .bind(
        id,
        values.name,
        values.billingEmail,
        values.publicKey,
        values.privateKey,
        now,
        now,
        userId
      ),
    db
      .prepare(
        `INSERT INTO organization_members(id,organization_id,user_id,email,type,status,access_all,key,external_id,created_at,updated_at)
      SELECT ?, ?, id, email, 0, 2, 1, ?, NULL, ?, ? FROM users WHERE id = ? AND status = 'active'`
      )
      .bind(memberId, id, values.key, now, now, userId),
    db
      .prepare(
        `INSERT INTO collections(id,organization_id,name,external_id) VALUES(?,?,?,NULL)`
      )
      .bind(collectionId, id, values.collectionName),
    db
      .prepare(
        `INSERT INTO organization_events(id,organization_id,actor_user_id,type,target_id,date,data) VALUES(?,?,?,1600,?,?,NULL)`
      )
      .bind(eventId, id, userId, id, now),
    ...revisionStatements(db, eventId, id, now, [userId]),
  ]);
  return {
    id,
    name: values.name,
    billing_email: values.billingEmail,
    public_key: values.publicKey,
    private_key: values.privateKey,
    created_at: now,
    updated_at: now,
  };
}

export async function deleteOrganization(
  db: D1Database,
  organizationId: string,
  userId: string,
  verifiedPasswordHash: string
): Promise<{ deleted: boolean; attachments: Attachment[] }> {
  const eventId = generateUUID();
  const key = `organization.sync.${eventId}`;
  const date = new Date().toISOString();
  // Capture recipients and attachment metadata in the authorized write transaction,
  // before cascades. Verify both current owner membership and the freshly proven
  // account verifier; password rotation after preflight invalidates this operation.
  const results = await db.batch<Attachment>([
    db
      .prepare(
        `WITH actor AS (SELECT ? AS user_id) INSERT INTO config(key,value)
      SELECT ?, json_object('organizationId', ?, 'revisionDate', ?, 'userIds', json((
        SELECT json_group_array(user_id) FROM organization_members WHERE organization_id = ? AND user_id IS NOT NULL
      ))) WHERE ${organizationAdminSql('?', true)} AND EXISTS (
        SELECT 1 FROM users WHERE id = (SELECT user_id FROM actor) AND status = 'active' AND master_password_hash = ?)`
      )
      .bind(
        userId,
        key,
        organizationId,
        date,
        organizationId,
        organizationId,
        verifiedPasswordHash
      ),
    db
      .prepare(
        `SELECT a.id,a.cipher_id AS cipherId,a.file_name AS fileName,a.size,a.size_name AS sizeName,a.key
      FROM attachments a JOIN ciphers c ON c.id = a.cipher_id WHERE c.organization_id = ?
        AND EXISTS (SELECT 1 FROM config WHERE key = ?)`
      )
      .bind(organizationId, key),
    db
      .prepare(
        'DELETE FROM organizations WHERE id = ? AND EXISTS (SELECT 1 FROM config WHERE key = ?)'
      )
      .bind(organizationId, key),
    db
      .prepare(
        `INSERT INTO user_revisions(user_id,revision_date)
      SELECT j.value, ? FROM config cfg, json_each(cfg.value,'$.userIds') j WHERE cfg.key = ?
      ON CONFLICT(user_id) DO UPDATE SET revision_date = CASE
        WHEN user_revisions.revision_date >= excluded.revision_date
          THEN COALESCE(strftime('%Y-%m-%dT%H:%M:%fZ', user_revisions.revision_date, '+0.001 seconds'), excluded.revision_date)
        ELSE excluded.revision_date END`
      )
      .bind(date, key),
  ]);
  const deleted = (results[2]?.meta.changes ?? 0) > 0;
  return { deleted, attachments: deleted ? results[1].results : [] };
}

export async function memberToResponse(
  db: D1Database,
  row: OrganizationMemberRow
): Promise<Record<string, unknown>> {
  const [user, collections, groups] = await Promise.all([
    row.user_id
      ? db
          .prepare('SELECT name,public_key FROM users WHERE id = ?')
          .bind(row.user_id)
          .first<{ name: string | null; public_key: string | null }>()
      : Promise.resolve(null),
    db
      .prepare(
        'SELECT collection_id,read_only,hide_passwords,manage FROM collection_users WHERE member_id = ?'
      )
      .bind(row.id)
      .all<{
        collection_id: string;
        read_only: number;
        hide_passwords: number;
        manage: number;
      }>(),
    db
      .prepare(
        'SELECT group_id FROM organization_group_members WHERE member_id = ?'
      )
      .bind(row.id)
      .all<{ group_id: string }>(),
  ]);
  // A user's encrypted organization key is intentionally never in administrative responses.
  return {
    id: row.id,
    userId: row.user_id,
    email: row.email,
    name: user?.name ?? null,
    publicKey: user?.public_key ?? null,
    type: row.type,
    status: row.status,
    accessAll: !!row.access_all,
    externalId: row.external_id,
    twoFactorEnabled: false,
    resetPasswordEnrolled: false,
    collections: collections.results.map((entry) => ({
      id: entry.collection_id,
      readOnly: !!entry.read_only,
      hidePasswords: !!entry.hide_passwords,
      manage: !!entry.manage,
    })),
    groups: groups.results.map((entry) => entry.group_id),
    permissions: null,
    object: 'organizationUserDetails',
  };
}

export async function collectionToResponse(
  db: D1Database,
  row: OrganizationCollectionRow,
  details = true
): Promise<Record<string, unknown>> {
  const base = {
    id: row.id,
    organizationId: row.organization_id,
    name: row.name,
    externalId: row.external_id,
    object: details ? 'collectionDetails' : 'collection',
  };
  if (!details) return base;
  const [users, groups] = await Promise.all([
    db
      .prepare(
        'SELECT member_id AS id,read_only,hide_passwords,manage FROM collection_users WHERE collection_id = ?'
      )
      .bind(row.id)
      .all<{
        id: string;
        read_only: number;
        hide_passwords: number;
        manage: number;
      }>(),
    db
      .prepare(
        'SELECT group_id AS id,read_only,hide_passwords,manage FROM collection_groups WHERE collection_id = ?'
      )
      .bind(row.id)
      .all<{
        id: string;
        read_only: number;
        hide_passwords: number;
        manage: number;
      }>(),
  ]);
  const shape = (entry: {
    id: string;
    read_only: number;
    hide_passwords: number;
    manage: number;
  }) => ({
    id: entry.id,
    readOnly: !!entry.read_only,
    hidePasswords: !!entry.hide_passwords,
    manage: !!entry.manage,
  });
  return {
    ...base,
    users: users.results.map(shape),
    groups: groups.results.map(shape),
    assigned: false,
  };
}

export async function groupToResponse(
  db: D1Database,
  row: OrganizationGroupRow
): Promise<Record<string, unknown>> {
  const [users, collections] = await Promise.all([
    db
      .prepare(
        'SELECT member_id FROM organization_group_members WHERE group_id = ?'
      )
      .bind(row.id)
      .all<{ member_id: string }>(),
    db
      .prepare(
        'SELECT collection_id,read_only,hide_passwords,manage FROM collection_groups WHERE group_id = ?'
      )
      .bind(row.id)
      .all<{
        collection_id: string;
        read_only: number;
        hide_passwords: number;
        manage: number;
      }>(),
  ]);
  return {
    id: row.id,
    organizationId: row.organization_id,
    name: row.name,
    externalId: row.external_id,
    accessAll: !!row.access_all,
    users: users.results.map((entry) => entry.member_id),
    collections: collections.results.map((entry) => ({
      id: entry.collection_id,
      readOnly: !!entry.read_only,
      hidePasswords: !!entry.hide_passwords,
      manage: !!entry.manage,
    })),
    object: 'groupDetails',
  };
}
