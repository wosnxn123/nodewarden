// Authorization comes exclusively from relational membership/collection grants.
// Cipher JSON is opaque ciphertext and is never an authority for permissions.
export type CipherAction = 'read' | 'write';

const actor = '(SELECT user_id FROM actor)';

function aliasName(alias: string): string {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(alias))
    throw new Error('Invalid SQL alias');
  return alias;
}

export function organizationWideAccessSql(member = 'm'): string {
  aliasName(member);
  return `(${member}.type IN (0, 1) OR ${member}.access_all = 1 OR EXISTS (
    SELECT 1 FROM organization_group_members ogm JOIN organization_groups og ON og.id = ogm.group_id
    WHERE ogm.member_id = ${member}.id AND og.organization_id = ${member}.organization_id AND og.access_all = 1
  ))`;
}

export function collectionGrantSql(
  action: CipherAction | 'unhidden' | 'manage',
  collection = 'col',
  member = 'm'
): string {
  aliasName(collection);
  aliasName(member);
  const condition = (alias: string) =>
    action === 'write'
      ? `AND (${alias}.read_only = 0 OR ${alias}.manage = 1)`
      : action === 'unhidden'
        ? `AND (${alias}.hide_passwords = 0 OR ${alias}.manage = 1)`
        : action === 'manage'
          ? `AND ${alias}.manage = 1`
          : '';
  return `(${organizationWideAccessSql(member)} OR EXISTS (
    SELECT 1 FROM collection_users cu WHERE cu.collection_id = ${collection}.id
    AND cu.member_id = ${member}.id ${condition('cu')}
  ) OR EXISTS (
    SELECT 1 FROM collection_groups cg
    JOIN organization_group_members gm ON gm.group_id = cg.group_id
    JOIN organization_groups g ON g.id = gm.group_id
    WHERE cg.collection_id = ${collection}.id AND gm.member_id = ${member}.id
      AND g.organization_id = ${collection}.organization_id ${condition('cg')}
  ))`;
}

export function cipherAccessSql(action: CipherAction, alias = 'c'): string {
  aliasName(alias);
  return `(${alias}.user_id = ${actor} OR (${alias}.organization_id IS NOT NULL AND EXISTS (
    SELECT 1 FROM organization_members m
    WHERE m.organization_id = ${alias}.organization_id AND m.user_id = ${actor} AND m.status = 2
      AND (${organizationWideAccessSql()} OR EXISTS (
        SELECT 1 FROM cipher_collections cc JOIN collections col ON col.id = cc.collection_id
        WHERE cc.cipher_id = ${alias}.id AND col.organization_id = ${alias}.organization_id
          AND ${collectionGrantSql(action)}
      ))
  )))`;
}

export function collectionAccessSql(
  action: CipherAction,
  alias = 'col'
): string {
  aliasName(alias);
  return `EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = ${alias}.organization_id
    AND m.user_id = ${actor} AND m.status = 2 AND ${collectionGrantSql(action, alias)})`;
}

export function cipherHidePasswordsSql(alias = 'c'): string {
  aliasName(alias);
  return `(${cipherAccessSql('read', alias)} AND NOT (COALESCE(${alias}.user_id = ${actor}, 0) OR EXISTS (
    SELECT 1 FROM organization_members m WHERE m.user_id = ${actor} AND m.status = 2
    AND m.organization_id = ${alias}.organization_id AND (${organizationWideAccessSql()} OR EXISTS (
      SELECT 1 FROM cipher_collections cc JOIN collections col ON col.id = cc.collection_id
      WHERE cc.cipher_id = ${alias}.id AND col.organization_id = ${alias}.organization_id AND ${collectionGrantSql('unhidden')}
    ))
  )))`;
}

export function cipherCollectionIdsSql(alias = 'c'): string {
  aliasName(alias);
  return `(SELECT json_group_array(cc.collection_id) FROM cipher_collections cc
    JOIN collections col ON col.id = cc.collection_id WHERE cc.cipher_id = ${alias}.id
    AND col.organization_id = ${alias}.organization_id AND ${collectionAccessSql('read')})`;
}

export interface CipherPermissions {
  read: boolean;
  write: boolean;
  hidePasswords: boolean;
  organizationId: string | null;
  collectionIds: string[];
}

export async function getCipherPermissions(
  db: D1Database,
  userId: string,
  cipherId: string
): Promise<CipherPermissions> {
  const row = await db
    .prepare(
      `WITH actor AS (SELECT ? AS user_id)
    SELECT c.organization_id, ${cipherAccessSql('read')} AS can_read, ${cipherAccessSql('write')} AS can_write,
    (c.user_id = ${actor} OR EXISTS (
      SELECT 1 FROM organization_members m WHERE m.user_id = ${actor} AND m.status = 2
      AND m.organization_id = c.organization_id AND (${organizationWideAccessSql()} OR EXISTS (
        SELECT 1 FROM cipher_collections cc JOIN collections col ON col.id = cc.collection_id
        WHERE cc.cipher_id = c.id AND col.organization_id = c.organization_id AND ${collectionGrantSql('unhidden')}
      ))
    )) AS unhidden FROM ciphers c WHERE c.id = ?`
    )
    .bind(userId, cipherId)
    .first<{
      organization_id: string | null;
      can_read: number;
      can_write: number;
      unhidden: number;
    }>();
  if (!row?.can_read)
    return {
      read: false,
      write: false,
      hidePasswords: false,
      organizationId: null,
      collectionIds: [],
    };
  const collections = row.organization_id
    ? await db
        .prepare(
          `SELECT cc.collection_id FROM cipher_collections cc
    JOIN collections col ON col.id = cc.collection_id JOIN organization_members m ON m.organization_id = col.organization_id
    WHERE cc.cipher_id = ? AND m.user_id = ? AND m.status = 2 AND ${collectionGrantSql('read')} ORDER BY cc.collection_id`
        )
        .bind(cipherId, userId)
        .all<{ collection_id: string }>()
    : { results: [] };
  return {
    read: true,
    write: !!row.can_write,
    hidePasswords: !row.unhidden,
    organizationId: row.organization_id,
    collectionIds: collections.results.map((entry) => entry.collection_id),
  };
}

export async function listAccessibleCollections(
  db: D1Database,
  userId: string
): Promise<Record<string, unknown>[]> {
  const rows = await db
    .prepare(
      `SELECT col.*, ${collectionGrantSql('write')} AS can_write,
    ${collectionGrantSql('unhidden')} AS unhidden, ${collectionGrantSql('manage')} AS can_manage
    FROM collections col JOIN organization_members m ON m.organization_id = col.organization_id
    WHERE m.user_id = ? AND m.status = 2 AND ${collectionGrantSql('read')} ORDER BY col.id`
    )
    .bind(userId)
    .all<{
      id: string;
      organization_id: string;
      name: string;
      external_id: string | null;
      can_write: number;
      unhidden: number;
      can_manage: number;
    }>();
  return rows.results.map((row) => ({
    id: row.id,
    organizationId: row.organization_id,
    name: row.name,
    externalId: row.external_id,
    readOnly: !row.can_write,
    hidePasswords: !row.unhidden,
    manage: !!row.can_manage,
    object: 'collection',
  }));
}

export function organizationFeatures(): Record<string, unknown> {
  return {
    enabled: true,
    seats: null,
    maxCollections: null,
    maxStorageGb: null,
    use2fa: false,
    useCustomPermissions: false,
    useDirectory: false,
    useEvents: true,
    useGroups: true,
    useTotp: true,
    usePolicies: false,
    useScim: false,
    useSso: false,
    useKeyConnector: false,
    usePasswordManager: true,
    useSecretsManager: false,
    selfHost: true,
    useApi: false,
    useDisableSMAdsForUsers: true,
    useInviteLinks: false,
    useMyItems: false,
    useOrganizationDomains: false,
    usePam: false,
    usePhishingBlocker: false,
    useResetPassword: false,
    usersGetPremium: true,
    allowAdminAccessToAllCollectionItems: true,
    limitCollectionCreation: true,
    limitCollectionDeletion: true,
    limitItemDeletion: false,
    planType: 6,
  };
}

export async function getProfileOrganizations(
  db: D1Database,
  userId: string
): Promise<Record<string, unknown>[]> {
  const rows = await db
    .prepare(
      `SELECT o.*, m.id AS member_id, m.type, m.status, m.key AS member_key, m.access_all
    FROM organizations o JOIN organization_members m ON m.organization_id = o.id
    JOIN users u ON u.id = ? WHERE m.user_id = u.id OR (m.status = 0 AND m.email = u.email COLLATE NOCASE AND m.user_id IS NULL)
    ORDER BY o.id`
    )
    .bind(userId)
    .all<{
      id: string;
      name: string;
      billing_email: string;
      public_key: string | null;
      private_key: string | null;
      member_id: string;
      type: number;
      status: number;
      member_key: string | null;
      access_all: number;
    }>();
  return rows.results.map((row) => ({
    ...organizationFeatures(),
    id: row.id,
    name: row.name,
    organizationUserId: row.member_id,
    key: row.status === 2 ? row.member_key : null,
    publicKey: row.status === 2 ? row.public_key : null,
    privateKey: row.status === 2 ? row.private_key : null,
    hasPublicAndPrivateKeys: !!row.public_key && !!row.private_key,
    status: row.status,
    type: row.type,
    accessAll: !!row.access_all,
    permissions: null,
    familySponsorshipFriendlyName: null,
    familySponsorshipAvailable: false,
    familySponsorshipLastSyncDate: null,
    familySponsorshipValidUntil: null,
    providerId: null,
    providerName: null,
    isProviderUser: false,
    isMember: true,
    isExemptFromPolicies: true,
    object: 'profileOrganization',
  }));
}
