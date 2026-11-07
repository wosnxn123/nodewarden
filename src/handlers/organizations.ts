import type { Env, User } from '../types';
import { jsonResponse, errorResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { verifyPasswordVerifier } from '../services/password-verifier';
import { deleteAttachmentBlobs } from './attachments';
import {
  getProfileOrganizations,
  listAccessibleCollections,
  collectionAccessSql,
} from '../services/organization-access';
import {
  type OrganizationRow,
  type OrganizationMemberRow,
  type OrganizationCollectionRow,
  type OrganizationGroupRow,
  type CollectionAssignment,
  getOrganizationMember,
  organizationToResponse,
  memberToResponse,
  collectionToResponse,
  groupToResponse,
  createOrganization,
  deleteOrganization,
  commitOrganizationMutation,
  organizationAdminSql,
  collectionManagementSql,
  lastOwnerSql,
  eventGuard,
} from '../services/organization-repo';

const MAX_BULK = 50;
class OrganizationError extends Error {
  constructor(
    message: string,
    readonly status = 400
  ) {
    super(message);
  }
}
type Body = Record<string, unknown>;
function field(body: Body, name: string): unknown {
  const snake = name.replace(/[A-Z]/g, (letter) => `_${letter.toLowerCase()}`);
  return (
    body[name] ?? body[name[0].toUpperCase() + name.slice(1)] ?? body[snake]
  );
}
function text(value: unknown, label: string, max = 10000): string {
  if (typeof value !== 'string' || !value.trim() || value.length > max)
    throw new OrganizationError(
      `${label} is required and must be a valid string`
    );
  return value;
}
function optionalText(value: unknown, max = 10000): string | null {
  if (value === undefined || value === null || value === '') return null;
  return text(value, 'Value', max);
}
function flag(value: unknown, fallback = false): boolean {
  if (value === undefined || value === null) return fallback;
  if (typeof value !== 'boolean')
    throw new OrganizationError('Permission flags must be booleans');
  return value;
}
function role(value: unknown): number {
  const names: Record<string, number> = {
    Owner: 0,
    Admin: 1,
    User: 2,
    Manager: 3,
  };
  const parsed =
    typeof value === 'string' && Object.hasOwn(names, value)
      ? names[value]
      : typeof value === 'number'
        ? value
        : typeof value === 'string' && /^[0-3]$/.test(value)
          ? Number(value)
          : NaN;
  if (!Number.isInteger(parsed) || parsed < 0 || parsed > 3)
    throw new OrganizationError(
      'Only Owner, Admin, User and Manager roles are supported'
    );
  return parsed;
}
function array(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value) || value.length > MAX_BULK)
    throw new OrganizationError(
      `${label} must be an array of at most ${MAX_BULK} entries`
    );
  return value;
}
function ids(value: unknown, label: string): string[] {
  const result = array(value, label).map((entry) =>
    text(
      typeof entry === 'object' && entry !== null
        ? field(entry as Body, 'id')
        : entry,
      label,
      100
    )
  );
  if (new Set(result).size !== result.length)
    throw new OrganizationError(`${label} contains duplicate ids`);
  return result;
}
function assignments(value: unknown): CollectionAssignment[] {
  const result = array(value, 'Assignments').map((entry) => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry))
      throw new OrganizationError('Invalid assignment');
    const body = entry as Body;
    return {
      id: text(field(body, 'id'), 'Assignment id', 100),
      readOnly: flag(field(body, 'readOnly')),
      hidePasswords: flag(field(body, 'hidePasswords')),
      manage: flag(field(body, 'manage')),
    };
  });
  if (new Set(result.map((entry) => entry.id)).size !== result.length)
    throw new OrganizationError('Duplicate assignments');
  return result;
}
async function readBody(request: Request): Promise<Body> {
  let result: unknown;
  const content = await request.text();
  if (content.length > 262144)
    throw new OrganizationError('Request body is too large', 413);
  try {
    result = content ? JSON.parse(content) : {};
  } catch {
    throw new OrganizationError('Invalid JSON');
  }
  if (!result || typeof result !== 'object' || Array.isArray(result))
    throw new OrganizationError('Expected a JSON object');
  return result as Body;
}
function list(data: unknown[], extra: Body = {}): Response {
  return jsonResponse({
    data,
    object: 'list',
    continuationToken: null,
    ...extra,
  });
}
function succeeded(changed: boolean): void {
  if (!changed)
    throw new OrganizationError(
      'Not authorized, invalid membership state, invalid assignment, or last confirmed owner would be removed',
      409
    );
}
function unsupportedBody(body: Body): void {
  const permissions = field(body, 'permissions');
  if (
    permissions &&
    (typeof permissions !== 'object' || Object.keys(permissions).length)
  ) {
    throw new OrganizationError(
      'Custom organization permissions are not supported',
      501
    );
  }
  if (field(body, 'resetPasswordKey') != null)
    throw new OrganizationError(
      'Organization account recovery is not supported',
      501
    );
}
async function admin(
  db: D1Database,
  org: string,
  user: User,
  ownerOnly = false
): Promise<OrganizationMemberRow> {
  const membership = await getOrganizationMember(db, org, user.id);
  if (
    !membership ||
    membership.status !== 2 ||
    (ownerOnly ? membership.type !== 0 : ![0, 1].includes(membership.type))
  ) {
    throw new OrganizationError(
      'Organization management permission is required',
      403
    );
  }
  return membership;
}
async function organizationDeleteProof(
  request: Request,
  db: D1Database,
  user: User
): Promise<string> {
  const body = await readBody(request);
  const authentication = field(body, 'authenticationData');
  if (
    authentication !== undefined &&
    (authentication === null ||
      typeof authentication !== 'object' ||
      Array.isArray(authentication))
  ) {
    throw new OrganizationError('Invalid authentication data');
  }
  const proof =
    field(body, 'masterPasswordHash') ??
    (authentication
      ? field(authentication as Body, 'masterPasswordAuthenticationHash')
      : undefined);
  if (
    proof === undefined &&
    (field(body, 'otp') !== undefined ||
      field(body, 'userVerificationToken') !== undefined)
  ) {
    throw new OrganizationError(
      'OTP and token-based organization deletion are not supported',
      501
    );
  }
  const clientHash = text(proof, 'masterPasswordHash', 4096);
  const current = await db
    .prepare('SELECT email,master_password_hash,status FROM users WHERE id = ?')
    .bind(user.id)
    .first<{ email: string; master_password_hash: string; status: string }>();
  if (
    !current ||
    current.status !== 'active' ||
    !(await verifyPasswordVerifier(
      clientHash,
      current.master_password_hash,
      current.email
    ))
  ) {
    throw new OrganizationError('Invalid password', 400);
  }
  return current.master_password_hash;
}

async function member(
  db: D1Database,
  org: string,
  id: string
): Promise<OrganizationMemberRow> {
  const result = await db
    .prepare(
      'SELECT * FROM organization_members WHERE id = ? AND organization_id = ?'
    )
    .bind(id, org)
    .first<OrganizationMemberRow>();
  if (!result)
    throw new OrganizationError('Organization member not found', 404);
  return result;
}
function validAssignmentsSql(
  table: 'collections' | 'organization_groups' | 'organization_members',
  json: string,
  org: string
): { sql: string; bindings: unknown[] } {
  // Validate every id within the mutation transaction, even after a concurrent delete.
  return {
    sql: `NOT EXISTS (SELECT 1 FROM json_each(?) assignment LEFT JOIN ${table} entity
    ON entity.id = CASE WHEN assignment.type = 'object' THEN json_extract(assignment.value, '$.id') ELSE assignment.value END
    AND entity.organization_id = ? ${table === 'organization_members' ? 'AND entity.status >= 0' : ''} WHERE entity.id IS NULL)`,
    bindings: [json, org],
  };
}
function memberAssignments(
  db: D1Database,
  memberId: string,
  collections: CollectionAssignment[] | undefined,
  groups: string[] | undefined,
  eventId: string
): D1PreparedStatement[] {
  const guard = eventGuard(eventId);
  const result: D1PreparedStatement[] = [];
  if (collections !== undefined) {
    result.push(
      db
        .prepare(
          `DELETE FROM collection_users WHERE member_id = ? AND ${guard}`
        )
        .bind(memberId)
    );
    result.push(
      db
        .prepare(
          `INSERT INTO collection_users(collection_id,member_id,read_only,hide_passwords,manage)
      SELECT json_extract(value,'$.id'), ?, json_extract(value,'$.readOnly'), json_extract(value,'$.hidePasswords'), json_extract(value,'$.manage')
      FROM json_each(?) WHERE ${guard}`
        )
        .bind(memberId, JSON.stringify(collections))
    );
  }
  if (groups !== undefined) {
    result.push(
      db
        .prepare(
          `DELETE FROM organization_group_members WHERE member_id = ? AND ${guard}`
        )
        .bind(memberId)
    );
    result.push(
      db
        .prepare(
          `INSERT INTO organization_group_members(group_id,member_id) SELECT value, ? FROM json_each(?) WHERE ${guard}`
        )
        .bind(memberId, JSON.stringify(groups))
    );
  }
  return result;
}
async function invitationList(db: D1Database, user: User): Promise<Response> {
  const rows = await db
    .prepare(
      `SELECT m.id,m.organization_id,m.email,m.status,o.name FROM organization_members m
    JOIN organizations o ON o.id = m.organization_id JOIN users u ON u.id = ?
    WHERE m.status = 0 AND m.email = u.email COLLATE NOCASE AND (m.user_id IS NULL OR m.user_id = u.id)`
    )
    .bind(user.id)
    .all<{
      id: string;
      organization_id: string;
      email: string;
      status: number;
      name: string;
    }>();
  return list(
    rows.results.map((row) => ({
      id: row.id,
      organizationId: row.organization_id,
      organizationName: row.name,
      email: row.email,
      status: row.status,
      object: 'organizationInvitation',
    }))
  );
}

async function inviteMembers(
  request: Request,
  db: D1Database,
  org: string,
  user: User
): Promise<Response> {
  await admin(db, org, user);
  const body = await readBody(request);
  unsupportedBody(body);
  const emails = array(field(body, 'emails'), 'Emails').map((value) => {
    const email = text(value, 'Email', 320).trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      throw new OrganizationError('Invalid email address');
    return email;
  });
  if (!emails.length || new Set(emails).size !== emails.length)
    throw new OrganizationError('Unique invitation emails are required');
  const type = role(field(body, 'type') ?? 2);
  const accessAll = flag(field(body, 'accessAll'));
  const collections = assignments(field(body, 'collections') ?? []);
  const groups = ids(field(body, 'groups') ?? [], 'Groups');
  const cv = validAssignmentsSql(
    'collections',
    JSON.stringify(collections),
    org
  );
  const gv = validAssignmentsSql(
    'organization_groups',
    JSON.stringify(groups),
    org
  );
  const data: Record<string, unknown>[] = [];
  // Each invitation is its own atomic lifecycle transition; never report email delivery.
  for (const email of emails) {
    const id = generateUUID();
    const now = new Date().toISOString();
    const changed = await commitOrganizationMutation(db, {
      organizationId: org,
      actorUserId: user.id,
      eventType: 1500,
      targetId: id,
      sql: `WITH actor AS (SELECT ? AS user_id) INSERT INTO organization_members
        (id,organization_id,user_id,email,type,status,access_all,key,external_id,created_at,updated_at)
        SELECT ?, ?, NULL, ?, ?, 0, ?, NULL, ?, ?, ? WHERE ${organizationAdminSql('?', type === 0)} AND ${cv.sql} AND ${gv.sql}
        AND NOT EXISTS (SELECT 1 FROM organization_members WHERE organization_id = ? AND email = ? COLLATE NOCASE)`,
      bindings: [
        user.id,
        id,
        org,
        email,
        type,
        +accessAll,
        optionalText(field(body, 'externalId')),
        now,
        now,
        org,
        ...cv.bindings,
        ...gv.bindings,
        org,
        email,
      ],
      additional: (eventId) =>
        memberAssignments(db, id, collections, groups, eventId),
    });
    if (changed)
      data.push({
        ...(await memberToResponse(db, await member(db, org, id))),
        mailSent: false,
      });
    else
      data.push({
        email,
        error: 'Already invited or not authorized or invalid assignment',
        object: 'organizationUserInviteError',
      });
  }
  return list(data, { mailSent: false, mailDeliverySupported: false });
}

async function mutateMember(
  request: Request,
  db: D1Database,
  org: string,
  id: string,
  user: User,
  action: string
): Promise<Response> {
  const target = await member(db, org, id);
  const now = new Date().toISOString();
  if (action === 'accept') {
    const body = await readBody(request);
    unsupportedBody(body);
    if (field(body, 'key') != null)
      throw new OrganizationError(
        'Organization keys may only be set by administrator confirmation'
      );
    // Authoritative database email must still match: a stale token/email cannot accept an invitation.
    const changed = await commitOrganizationMutation(db, {
      organizationId: org,
      actorUserId: user.id,
      eventType: 1502,
      targetId: id,
      sql: `WITH actor AS (SELECT ? AS user_id) UPDATE organization_members SET user_id = (SELECT user_id FROM actor), status = 1, key = NULL, updated_at = ?
        WHERE id = ? AND organization_id = ? AND status = 0 AND (user_id IS NULL OR user_id = (SELECT user_id FROM actor))
        AND EXISTS (SELECT 1 FROM users u WHERE u.id = (SELECT user_id FROM actor) AND u.status = 'active'
          AND u.email = organization_members.email COLLATE NOCASE AND u.email = ? COLLATE NOCASE)`,
      bindings: [user.id, now, id, org, user.email],
      extraUserIds: [user.id],
    });
    succeeded(changed);
    return jsonResponse({ object: 'organizationUser', id, status: 1 });
  }
  await admin(db, org, user);
  const ownerGuard = organizationAdminSql(
    'organization_members.organization_id',
    target.type === 0
  );
  if (action === 'confirm') {
    const body = await readBody(request);
    unsupportedBody(body);
    const key = text(field(body, 'key'), 'Encrypted organization key', 65536);
    const changed = await commitOrganizationMutation(db, {
      organizationId: org,
      actorUserId: user.id,
      eventType: 1501,
      targetId: id,
      sql: `WITH actor AS (SELECT ? AS user_id) UPDATE organization_members SET status = 2, key = ?, updated_at = ?
        WHERE id = ? AND organization_id = ? AND status = 1 AND ${organizationAdminSql('organization_members.organization_id')}
        AND (type <> 0 OR ${organizationAdminSql('organization_members.organization_id', true)})
        AND EXISTS (SELECT 1 FROM users u WHERE u.id = organization_members.user_id AND u.status = 'active'
          AND u.email = organization_members.email COLLATE NOCASE AND u.public_key IS NOT NULL)`,
      bindings: [user.id, key, now, id, org],
      extraUserIds: target.user_id ? [target.user_id] : [],
    });
    succeeded(changed);
    return new Response(null, { status: 204 });
  }
  if (action === 'delete' || action === 'revoke' || action === 'restore') {
    const sql =
      action === 'delete'
        ? 'DELETE FROM organization_members'
        : action === 'revoke'
          ? 'UPDATE organization_members SET status = -1, key = NULL, updated_at = ?'
          : 'UPDATE organization_members SET status = 1, key = NULL, updated_at = ?';
    const lifecycle =
      action === 'revoke'
        ? 'AND status IN (1,2)'
        : action === 'restore'
          ? `AND status = -1 AND user_id IS NOT NULL AND EXISTS (SELECT 1 FROM users u WHERE u.id = organization_members.user_id AND u.status = 'active')`
          : '';
    const changed = await commitOrganizationMutation(db, {
      organizationId: org,
      actorUserId: user.id,
      eventType: action === 'delete' ? 1503 : action === 'revoke' ? 1511 : 1512,
      targetId: id,
      sql: `WITH actor AS (SELECT ? AS user_id) ${sql} WHERE id = ? AND organization_id = ? AND ${organizationAdminSql('organization_members.organization_id')}
        AND (type <> 0 OR ${organizationAdminSql('organization_members.organization_id', true)}) AND ${lastOwnerSql()} ${lifecycle}`,
      bindings: [user.id, ...(action === 'delete' ? [] : [now]), id, org],
      extraUserIds: target.user_id ? [target.user_id] : [],
    });
    succeeded(changed);
    return new Response(null, { status: 204 });
  }
  if (action !== 'update')
    throw new OrganizationError('Unsupported membership operation', 501);
  const body = await readBody(request);
  unsupportedBody(body);
  if (
    field(body, 'status') !== undefined ||
    field(body, 'key') !== undefined ||
    field(body, 'userId') !== undefined ||
    field(body, 'email') !== undefined
  ) {
    throw new OrganizationError(
      'Membership identity, status and keys require explicit lifecycle operations'
    );
  }
  const type = role(field(body, 'type') ?? target.type);
  const accessAll = flag(field(body, 'accessAll'), !!target.access_all);
  const collections =
    field(body, 'collections') === undefined
      ? undefined
      : assignments(field(body, 'collections'));
  const groups =
    field(body, 'groups') === undefined
      ? undefined
      : ids(field(body, 'groups'), 'Groups');
  const cv = validAssignmentsSql(
    'collections',
    JSON.stringify(collections ?? []),
    org
  );
  const gv = validAssignmentsSql(
    'organization_groups',
    JSON.stringify(groups ?? []),
    org
  );
  const changed = await commitOrganizationMutation(db, {
    organizationId: org,
    actorUserId: user.id,
    eventType: 1502,
    targetId: id,
    sql: `WITH actor AS (SELECT ? AS user_id) UPDATE organization_members SET type = ?, access_all = ?, external_id = ?, updated_at = ?
      WHERE id = ? AND organization_id = ? AND status >= 0 AND ${organizationAdminSql('organization_members.organization_id')}
      AND ((type <> 0 AND ? <> 0) OR ${organizationAdminSql('organization_members.organization_id', true)})
      AND (? = 0 OR ${lastOwnerSql()}) AND ${cv.sql} AND ${gv.sql}`,
    bindings: [
      user.id,
      type,
      +accessAll,
      field(body, 'externalId') === undefined
        ? target.external_id
        : optionalText(field(body, 'externalId')),
      now,
      id,
      org,
      type,
      type,
      ...cv.bindings,
      ...gv.bindings,
    ],
    additional: (eventId) =>
      memberAssignments(db, id, collections, groups, eventId),
    extraUserIds: target.user_id ? [target.user_id] : [],
  });
  succeeded(changed);
  return jsonResponse(await memberToResponse(db, await member(db, org, id)));
}

function collectionAssignments(
  db: D1Database,
  id: string,
  users: CollectionAssignment[] | undefined,
  groups: CollectionAssignment[] | undefined,
  eventId: string
): D1PreparedStatement[] {
  const guard = eventGuard(eventId);
  const statements: D1PreparedStatement[] = [];
  for (const [table, column, rows] of [
    ['collection_users', 'member_id', users],
    ['collection_groups', 'group_id', groups],
  ] as const) {
    if (rows === undefined) continue;
    statements.push(
      db
        .prepare(`DELETE FROM ${table} WHERE collection_id = ? AND ${guard}`)
        .bind(id)
    );
    statements.push(
      db
        .prepare(
          `INSERT INTO ${table}(collection_id,${column},read_only,hide_passwords,manage)
      SELECT ?, json_extract(value,'$.id'), json_extract(value,'$.readOnly'), json_extract(value,'$.hidePasswords'), json_extract(value,'$.manage')
      FROM json_each(?) WHERE ${guard}`
        )
        .bind(id, JSON.stringify(rows))
    );
  }
  return statements;
}
async function collectionRoute(
  request: Request,
  db: D1Database,
  org: string,
  user: User,
  id: string | undefined,
  detail: string | undefined,
  method: string
): Promise<Response> {
  const collection = id
    ? await db
        .prepare(
          'SELECT * FROM collections WHERE id = ? AND organization_id = ?'
        )
        .bind(id, org)
        .first<OrganizationCollectionRow>()
    : null;
  if (id && !collection)
    throw new OrganizationError('Collection not found', 404);
  const membership = await getOrganizationMember(db, org, user.id);
  if (!membership || membership.status !== 2)
    throw new OrganizationError(
      'Confirmed organization membership is required',
      403
    );
  if (method === 'GET') {
    if (!id) {
      const isAdmin = [0, 1].includes(membership.type);
      const rows = await db
        .prepare(
          `WITH actor AS (SELECT ? AS user_id) SELECT * FROM collections col
        WHERE col.organization_id = ? AND ${collectionAccessSql('read')}`
        )
        .bind(user.id, org)
        .all<OrganizationCollectionRow>();
      return list(
        await Promise.all(
          rows.results.map((row) => collectionToResponse(db, row, isAdmin))
        )
      );
    }
    const allowed = await db
      .prepare(
        `WITH actor AS (SELECT ? AS user_id) SELECT id FROM collections col
      WHERE col.id = ? AND ${collectionAccessSql('read')}`
      )
      .bind(user.id, id)
      .first();
    if (!allowed) throw new OrganizationError('Collection not found', 404);
    // Assignment lists are management data, not visible to ordinary read-only members.
    const canManage = await db
      .prepare(
        `WITH actor AS (SELECT ? AS user_id) SELECT id FROM collections WHERE id = ?
      AND ${collectionManagementSql()}`
      )
      .bind(user.id, id)
      .first();
    if (detail === 'users' && !canManage)
      throw new OrganizationError(
        'Collection management permission is required',
        403
      );
    const response = await collectionToResponse(db, collection!, !!canManage);
    return detail === 'users'
      ? list(response.users as unknown[])
      : jsonResponse(response);
  }
  if (method === 'DELETE' && id) {
    succeeded(
      await commitOrganizationMutation(db, {
        organizationId: org,
        actorUserId: user.id,
        eventType: 1302,
        targetId: id,
        sql: `WITH actor AS (SELECT ? AS user_id) DELETE FROM collections WHERE id = ? AND organization_id = ? AND ${collectionManagementSql()}`,
        bindings: [user.id, id, org],
      })
    );
    return new Response(null, { status: 204 });
  }
  if (!((method === 'POST' && !id) || (method === 'PUT' && id)))
    throw new OrganizationError('Unsupported collection operation', 501);
  const body = await readBody(request);
  const name = text(
    field(body, 'name') ?? collection?.name,
    'Encrypted collection name'
  );
  const externalId =
    field(body, 'externalId') === undefined
      ? (collection?.external_id ?? null)
      : optionalText(field(body, 'externalId'));
  const users =
    field(body, 'users') === undefined
      ? undefined
      : assignments(field(body, 'users'));
  const groups =
    field(body, 'groups') === undefined
      ? undefined
      : assignments(field(body, 'groups'));
  const uv = validAssignmentsSql(
    'organization_members',
    JSON.stringify(users ?? []),
    org
  );
  const gv = validAssignmentsSql(
    'organization_groups',
    JSON.stringify(groups ?? []),
    org
  );
  const collectionId = id ?? generateUUID();
  const sql = id
    ? `UPDATE collections SET name = ?, external_id = ? WHERE id = ? AND organization_id = ? AND ${collectionManagementSql()}`
    : `INSERT INTO collections(id,organization_id,name,external_id) SELECT ?,?,?,? WHERE ${organizationAdminSql('?')}`;
  const bindings = id
    ? [user.id, name, externalId, id, org]
    : [user.id, collectionId, org, name, externalId, org];
  succeeded(
    await commitOrganizationMutation(db, {
      organizationId: org,
      actorUserId: user.id,
      eventType: id ? 1301 : 1300,
      targetId: collectionId,
      sql: `WITH actor AS (SELECT ? AS user_id) ${sql} AND ${uv.sql} AND ${gv.sql}`,
      bindings: [...bindings, ...uv.bindings, ...gv.bindings],
      additional: (eventId) =>
        collectionAssignments(db, collectionId, users, groups, eventId),
    })
  );
  return jsonResponse(
    await collectionToResponse(db, {
      id: collectionId,
      organization_id: org,
      name,
      external_id: externalId,
    })
  );
}

function groupAssignments(
  db: D1Database,
  id: string,
  users: string[] | undefined,
  collections: CollectionAssignment[] | undefined,
  eventId: string
): D1PreparedStatement[] {
  const guard = eventGuard(eventId);
  const result: D1PreparedStatement[] = [];
  if (users !== undefined) {
    result.push(
      db
        .prepare(
          `DELETE FROM organization_group_members WHERE group_id = ? AND ${guard}`
        )
        .bind(id)
    );
    result.push(
      db
        .prepare(
          `INSERT INTO organization_group_members(group_id,member_id) SELECT ?, value FROM json_each(?) WHERE ${guard}`
        )
        .bind(id, JSON.stringify(users))
    );
  }
  if (collections !== undefined) {
    result.push(
      db
        .prepare(
          `DELETE FROM collection_groups WHERE group_id = ? AND ${guard}`
        )
        .bind(id)
    );
    result.push(
      db
        .prepare(
          `INSERT INTO collection_groups(collection_id,group_id,read_only,hide_passwords,manage)
      SELECT json_extract(value,'$.id'), ?, json_extract(value,'$.readOnly'), json_extract(value,'$.hidePasswords'), json_extract(value,'$.manage')
      FROM json_each(?) WHERE ${guard}`
        )
        .bind(id, JSON.stringify(collections))
    );
  }
  return result;
}
async function groupRoute(
  request: Request,
  db: D1Database,
  org: string,
  user: User,
  id: string | undefined,
  detail: string | undefined,
  method: string
): Promise<Response> {
  await admin(db, org, user);
  const row = id
    ? await db
        .prepare(
          'SELECT * FROM organization_groups WHERE id = ? AND organization_id = ?'
        )
        .bind(id, org)
        .first<OrganizationGroupRow>()
    : null;
  if (id && !row) throw new OrganizationError('Group not found', 404);
  if (method === 'GET') {
    if (!id) {
      const rows = await db
        .prepare(
          'SELECT * FROM organization_groups WHERE organization_id = ? ORDER BY id'
        )
        .bind(org)
        .all<OrganizationGroupRow>();
      return list(
        await Promise.all(
          rows.results.map((entry) => groupToResponse(db, entry))
        )
      );
    }
    const response = await groupToResponse(db, row!);
    return detail === 'users'
      ? jsonResponse(response.users)
      : jsonResponse(response);
  }
  if (method === 'DELETE' && id) {
    succeeded(
      await commitOrganizationMutation(db, {
        organizationId: org,
        actorUserId: user.id,
        eventType: 1402,
        targetId: id,
        sql: `WITH actor AS (SELECT ? AS user_id) DELETE FROM organization_groups WHERE id = ? AND organization_id = ? AND ${organizationAdminSql('organization_groups.organization_id')}`,
        bindings: [user.id, id, org],
      })
    );
    return new Response(null, { status: 204 });
  }
  if (!((method === 'POST' && !id) || (method === 'PUT' && id)))
    throw new OrganizationError('Unsupported group operation', 501);
  const body = await readBody(request);
  const name = text(field(body, 'name') ?? row?.name, 'Group name', 256);
  const accessAll = flag(field(body, 'accessAll'), !!row?.access_all);
  const externalId =
    field(body, 'externalId') === undefined
      ? (row?.external_id ?? null)
      : optionalText(field(body, 'externalId'));
  const users =
    field(body, 'users') === undefined
      ? undefined
      : ids(field(body, 'users'), 'Members');
  const collections =
    field(body, 'collections') === undefined
      ? undefined
      : assignments(field(body, 'collections'));
  const uv = validAssignmentsSql(
    'organization_members',
    JSON.stringify(users ?? []),
    org
  );
  const cv = validAssignmentsSql(
    'collections',
    JSON.stringify(collections ?? []),
    org
  );
  const groupId = id ?? generateUUID();
  const sql = id
    ? `UPDATE organization_groups SET name = ?, access_all = ?, external_id = ? WHERE id = ? AND organization_id = ? AND ${organizationAdminSql('organization_groups.organization_id')}`
    : `INSERT INTO organization_groups(id,organization_id,name,access_all,external_id) SELECT ?,?,?,?,? WHERE ${organizationAdminSql('?')}`;
  const bindings = id
    ? [user.id, name, +accessAll, externalId, id, org]
    : [user.id, groupId, org, name, +accessAll, externalId, org];
  succeeded(
    await commitOrganizationMutation(db, {
      organizationId: org,
      actorUserId: user.id,
      eventType: id ? 1401 : 1400,
      targetId: groupId,
      sql: `WITH actor AS (SELECT ? AS user_id) ${sql} AND ${uv.sql} AND ${cv.sql}`,
      bindings: [...bindings, ...uv.bindings, ...cv.bindings],
      additional: (eventId) =>
        groupAssignments(db, groupId, users, collections, eventId),
    })
  );
  return jsonResponse(
    await groupToResponse(db, {
      id: groupId,
      organization_id: org,
      name,
      access_all: +accessAll,
      external_id: externalId,
    })
  );
}

async function bulkMemberRoute(
  request: Request,
  db: D1Database,
  org: string,
  user: User,
  action: 'confirm' | 'delete' | 'revoke' | 'restore'
): Promise<Response> {
  await admin(db, org, user);
  const body = await readBody(request);
  const entries =
    action === 'confirm'
      ? array(field(body, 'keys') ?? [], 'Confirmations').map((value) => {
          if (!value || typeof value !== 'object' || Array.isArray(value))
            throw new OrganizationError('Invalid confirmation');
          const entry = value as Body;
          return {
            id: text(field(entry, 'id'), 'Member id', 100),
            key: text(field(entry, 'key'), 'Encrypted organization key', 65536),
          };
        })
      : ids(field(body, 'ids'), 'Member ids').map((id) => ({ id }));
  if (new Set(entries.map((entry) => entry.id)).size !== entries.length)
    throw new OrganizationError('Duplicate member ids');
  const results: Record<string, unknown>[] = [];
  // Official bulk lifecycle endpoints report per-member outcomes. Each member
  // operation remains atomic and rechecks the last-owner invariant in SQL.
  for (const entry of entries) {
    try {
      await mutateMember(
        new Request(request.url, {
          method: 'POST',
          body: JSON.stringify(entry),
        }),
        db,
        org,
        entry.id,
        user,
        action
      );
      results.push({
        id: entry.id,
        error: '',
        object: 'organizationUserBulkResponse',
      });
    } catch (error) {
      if (error instanceof OrganizationError)
        results.push({
          id: entry.id,
          error: error.message,
          object: 'organizationUserBulkResponse',
        });
      else if (
        error instanceof Error &&
        /constraint|UNIQUE|FOREIGN KEY/i.test(error.message)
      ) {
        results.push({
          id: entry.id,
          error: 'Invalid or conflicting organization data',
          object: 'organizationUserBulkResponse',
        });
      } else throw error;
    }
  }
  return list(results);
}

async function organizationEvents(
  request: Request,
  db: D1Database,
  org: string,
  user: User
): Promise<Response> {
  await admin(db, org, user);
  const url = new URL(request.url);
  const token = url.searchParams.get('continuationToken');
  const offset = token === null ? 0 : Number(token);
  if (!Number.isSafeInteger(offset) || offset < 0)
    throw new OrganizationError('Invalid continuation token');
  const start = url.searchParams.get('start');
  const end = url.searchParams.get('end');
  if (
    (start && !Number.isFinite(Date.parse(start))) ||
    (end && !Number.isFinite(Date.parse(end)))
  )
    throw new OrganizationError('Invalid event date');
  const result = await db
    .prepare(
      `SELECT * FROM organization_events WHERE organization_id = ?
    AND (? IS NULL OR date >= ?) AND (? IS NULL OR date <= ?) ORDER BY date DESC,id DESC LIMIT 101 OFFSET ?`
    )
    .bind(org, start, start, end, end, offset)
    .all<{
      id: string;
      organization_id: string;
      actor_user_id: string | null;
      type: number;
      target_id: string | null;
      date: string;
    }>();
  return jsonResponse({
    object: 'list',
    continuationToken:
      result.results.length > 100 ? String(offset + 100) : null,
    data: result.results
      .slice(0, 100)
      .map((entry) => ({
        id: entry.id,
        organizationId: entry.organization_id,
        type: entry.type,
        actingUserId: entry.actor_user_id,
        userId: null,
        organizationUserId:
          entry.type >= 1500 && entry.type < 1600 ? entry.target_id : null,
        collectionId:
          entry.type >= 1300 && entry.type < 1400 ? entry.target_id : null,
        groupId:
          entry.type >= 1400 && entry.type < 1500 ? entry.target_id : null,
        cipherId:
          entry.type >= 1100 && entry.type < 1200 ? entry.target_id : null,
        date: entry.date,
        deviceType: null,
        ipAddress: null,
        object: 'event',
      })),
  });
}

// This dispatcher intentionally does not advertise policies, directory, SCIM, reset
// password, mail invitation delivery, or organization API keys as implemented.
export async function handleOrganizationRoute(
  request: Request,
  env: Env,
  user: User,
  path: string,
  method: string
): Promise<Response | null> {
  if (
    path !== '/api/collections' &&
    path !== '/api/organizations' &&
    !path.startsWith('/api/organizations/')
  )
    return null;
  try {
    const db = env.DB;
    if (path === '/api/collections')
      return method === 'GET'
        ? list(await listAccessibleCollections(db, user.id))
        : errorResponse('Unsupported collections operation', 501);
    if (path === '/api/organizations/invitations' && method === 'GET')
      return await invitationList(db, user);
    if (path === '/api/organizations') {
      if (method === 'GET')
        return list(await getProfileOrganizations(db, user.id));
      if (method !== 'POST')
        throw new OrganizationError('Unsupported organization operation', 501);
      const body = await readBody(request);
      const keysValue = field(body, 'keys');
      if (
        keysValue !== undefined &&
        keysValue !== null &&
        (typeof keysValue !== 'object' || Array.isArray(keysValue))
      )
        throw new OrganizationError('Invalid organization keys');
      const keys = keysValue as Body | undefined;
      const publicKey = keys
        ? text(field(keys, 'publicKey'), 'Organization public key', 65536)
        : null;
      const privateKey = keys
        ? text(
            field(keys, 'encryptedPrivateKey'),
            'Encrypted organization private key',
            65536
          )
        : null;
      const billingEmail = text(
        field(body, 'billingEmail'),
        'Billing email',
        320
      )
        .trim()
        .toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(billingEmail))
        throw new OrganizationError('Invalid billing email');
      const created = await createOrganization(db, user.id, {
        name: text(field(body, 'name'), 'Organization name', 256),
        billingEmail,
        key: text(
          field(body, 'key'),
          'Encrypted owner organization key',
          65536
        ),
        publicKey,
        privateKey,
        collectionName: text(
          field(body, 'collectionName'),
          'Encrypted collection name'
        ),
      });
      return jsonResponse(organizationToResponse(created));
    }
    const parts = path.slice('/api/organizations/'.length).split('/');
    const [org, resource, id, operation] = parts;
    if (!org || parts.length > 5)
      throw new OrganizationError('Organization route not found', 404);
    if (resource === 'users') {
      if (id === 'invite' && method === 'POST')
        return await inviteMembers(request, db, org, user);
      if (
        ['reinvite', 'reset-password-enrollment', 'recover-account'].includes(
          id ?? ''
        )
      )
        throw new OrganizationError(
          'Invitation email delivery and account recovery are not supported',
          501
        );
      if (id === 'confirm' && method === 'POST')
        return await bulkMemberRoute(request, db, org, user, 'confirm');
      if (!id && method === 'DELETE')
        return await bulkMemberRoute(request, db, org, user, 'delete');
      if (id === 'revoke' && method === 'PUT')
        return await bulkMemberRoute(request, db, org, user, 'revoke');
      if (id === 'restore' && method === 'PUT')
        return await bulkMemberRoute(request, db, org, user, 'restore');
      if (id === 'public-keys' && method === 'POST') {
        await admin(db, org, user);
        const body = await readBody(request);
        const requested = ids(field(body, 'ids'), 'Member ids');
        const rows = await db
          .prepare(
            `SELECT m.id,u.public_key FROM organization_members m JOIN users u ON u.id = m.user_id
          WHERE m.organization_id = ? AND m.id IN (SELECT value FROM json_each(?))`
          )
          .bind(org, JSON.stringify(requested))
          .all<{ id: string; public_key: string | null }>();
        return list(
          rows.results.map((row) => ({
            id: row.id,
            publicKey: row.public_key,
            object: 'organizationUserPublicKey',
          }))
        );
      }
      if (method === 'GET') {
        await admin(db, org, user);
        if (!id || ['list', 'mini-details'].includes(id)) {
          const rows = await db
            .prepare(
              'SELECT * FROM organization_members WHERE organization_id = ? ORDER BY id'
            )
            .bind(org)
            .all<OrganizationMemberRow>();
          return list(
            await Promise.all(
              rows.results.map((row) => memberToResponse(db, row))
            )
          );
        }
        return jsonResponse(
          await memberToResponse(db, await member(db, org, id))
        );
      }
      if (id && operation === 'accept' && method === 'POST')
        return await mutateMember(request, db, org, id, user, 'accept');
      if (id && operation === 'confirm' && method === 'POST')
        return await mutateMember(request, db, org, id, user, 'confirm');
      if (
        id &&
        ['revoke', 'restore'].includes(operation ?? '') &&
        ['PUT', 'POST'].includes(method)
      )
        return await mutateMember(request, db, org, id, user, operation!);
      if (id && !operation && ['PUT', 'POST'].includes(method))
        return await mutateMember(request, db, org, id, user, 'update');
      if (id && !operation && method === 'DELETE')
        return await mutateMember(request, db, org, id, user, 'delete');
      throw new OrganizationError('Unsupported membership operation', 501);
    }
    if (resource === 'collections')
      return await collectionRoute(
        request,
        db,
        org,
        user,
        id === 'details' ? undefined : id,
        operation,
        method
      );
    if (resource === 'groups')
      return await groupRoute(
        request,
        db,
        org,
        user,
        id === 'details' ? undefined : id,
        operation,
        method
      );
    if (resource === 'events' && method === 'GET')
      return await organizationEvents(request, db, org, user);
    if (resource === 'public-key' && method === 'GET') {
      const membership = await getOrganizationMember(db, org, user.id);
      if (!membership || membership.status !== 2)
        throw new OrganizationError(
          'Confirmed organization membership is required',
          403
        );
      const row = await db
        .prepare('SELECT public_key FROM organizations WHERE id = ?')
        .bind(org)
        .first<{ public_key: string | null }>();
      return jsonResponse({
        publicKey: row?.public_key ?? null,
        object: 'organizationPublicKey',
      });
    }
    if (resource === 'keys' && method === 'POST') {
      await admin(db, org, user, true);
      const body = await readBody(request);
      const publicKey = text(
        field(body, 'publicKey'),
        'Organization public key',
        65536
      );
      const privateKey = text(
        field(body, 'encryptedPrivateKey'),
        'Encrypted organization private key',
        65536
      );
      succeeded(
        await commitOrganizationMutation(db, {
          organizationId: org,
          actorUserId: user.id,
          eventType: 1600,
          targetId: org,
          sql: `WITH actor AS (SELECT ? AS user_id) UPDATE organizations SET public_key = ?, private_key = ?, updated_at = ?
          WHERE id = ? AND public_key IS NULL AND private_key IS NULL AND ${organizationAdminSql('organizations.id', true)}`,
          bindings: [
            user.id,
            publicKey,
            privateKey,
            new Date().toISOString(),
            org,
          ],
        })
      );
      return jsonResponse({
        publicKey,
        encryptedPrivateKey: privateKey,
        object: 'organizationKeys',
      });
    }
    if (resource === 'keys' && method === 'GET') {
      await admin(db, org, user);
      const row = await db
        .prepare(
          'SELECT public_key,private_key FROM organizations WHERE id = ?'
        )
        .bind(org)
        .first<{ public_key: string | null; private_key: string | null }>();
      return jsonResponse({
        publicKey: row?.public_key ?? null,
        encryptedPrivateKey: row?.private_key ?? null,
        object: 'organizationKeys',
      });
    }
    if (resource === 'leave' && method === 'POST') {
      const own = await getOrganizationMember(db, org, user.id);
      if (!own)
        throw new OrganizationError('Organization membership not found', 404);
      succeeded(
        await commitOrganizationMutation(db, {
          organizationId: org,
          actorUserId: user.id,
          eventType: 1516,
          targetId: own.id,
          sql: `WITH actor AS (SELECT ? AS user_id) DELETE FROM organization_members WHERE id = ? AND organization_id = ?
          AND user_id = (SELECT user_id FROM actor) AND ${lastOwnerSql()}`,
          bindings: [user.id, own.id, org],
          extraUserIds: [user.id],
        })
      );
      return new Response(null, { status: 204 });
    }
    if (resource)
      throw new OrganizationError(
        'This organization feature is not supported by this server',
        501
      );
    await admin(db, org, user, method === 'DELETE');
    const row = await db
      .prepare('SELECT * FROM organizations WHERE id = ?')
      .bind(org)
      .first<OrganizationRow>();
    if (!row) throw new OrganizationError('Organization not found', 404);
    if (method === 'GET') return jsonResponse(organizationToResponse(row));
    if (method === 'DELETE') {
      const proof = await organizationDeleteProof(request, db, user);
      const result = await deleteOrganization(db, org, user.id, proof);
      succeeded(result.deleted);
      // The repository snapshot is from the same authorized transaction as the
      // cascade. Never delete blobs for a rejected operation or a personal cipher.
      await deleteAttachmentBlobs(env, result.attachments);
      return new Response(null, { status: 204 });
    }
    if (method === 'PUT' || method === 'POST') {
      const body = await readBody(request);
      const name = text(
        field(body, 'name') ?? row.name,
        'Organization name',
        256
      );
      const billingEmail = text(
        field(body, 'billingEmail') ?? row.billing_email,
        'Billing email',
        320
      )
        .trim()
        .toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(billingEmail))
        throw new OrganizationError('Invalid billing email');
      const date = new Date().toISOString();
      succeeded(
        await commitOrganizationMutation(db, {
          organizationId: org,
          actorUserId: user.id,
          eventType: 1600,
          targetId: org,
          sql: `WITH actor AS (SELECT ? AS user_id) UPDATE organizations SET name = ?, billing_email = ?, updated_at = ?
          WHERE id = ? AND ${organizationAdminSql('organizations.id')}`,
          bindings: [user.id, name, billingEmail, date, org],
        })
      );
      return jsonResponse(
        organizationToResponse({
          ...row,
          name,
          billing_email: billingEmail,
          updated_at: date,
        })
      );
    }
    throw new OrganizationError('Unsupported organization operation', 501);
  } catch (error) {
    if (error instanceof OrganizationError)
      return errorResponse(error.message, error.status);
    if (
      error instanceof Error &&
      /constraint|UNIQUE|FOREIGN KEY/i.test(error.message)
    )
      return errorResponse('Invalid or conflicting organization data', 409);
    throw error;
  }
}
