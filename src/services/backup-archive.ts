import { zipSync, unzipSync, type UnzipFileInfo } from 'fflate';
import type { Env } from '../types';
import { APP_VERSION } from '../../shared/app-version';
import { BACKUP_FORMAT_VERSION, ORGANIZATION_BACKUP_TABLES, ORGANIZATION_BACKUP_TABLE_COLUMNS, type BackupFormatVersion, type OrganizationBackupTableName } from '../../shared/backup-schema';
import { BACKUP_SETTINGS_CONFIG_KEY } from './backup-config';
import { YUBICO_BOOTSTRAP_CLAIM_CONFIG_KEY } from './yubico-config';
import { exportPortableBackupSettingsEnvelope } from './backup-settings-crypto';
import {
  getAttachmentObjectKey,
  getBlobStorageKind,
} from './blob-store';

// CONTRACT:
// This file defines the exported instance-backup archive shape. Keep it in lock
// step with src/services/backup-import.ts and webapp/src/lib/api/backup.ts.
//
// WHEN CHANGING THIS:
// - Add persistent tables to BackupPayload, export SQL, manifest tableCounts,
//   and validateBackupPayloadContents().
// - Keep secrets and transient runtime rows sanitized before writing db.json.
// - Runtime authentication state (devices, sessions, auth requests, remembered
//   2FA devices, and one-time tokens) must never enter an instance backup.
// - users.api_key is intentionally not exported.
// - backup.settings.v1 is exported as portable-only; the current server runtime
//   envelope must not leave the instance.
type SqlRow = Record<string, string | number | null>;

const BACKUP_RUNNER_LOCK_CONFIG_KEY = 'backup.runner.lock.v1';
const BACKUP_FILE_HASH_PREFIX_LENGTH = 5;
// Worker-side backup export must stay well below Cloudflare CPU limits.
// Prefer store-only ZIP entries over heavier compression to keep exports reliable.
const BACKUP_TEXT_COMPRESSION_LEVEL = 0;
const BACKUP_JSON_INDENT = 2;
export const MAX_BACKUP_ARCHIVE_BYTES = 64 * 1024 * 1024;
const MAX_BACKUP_ARCHIVE_ENTRY_COUNT = 10_000;
const MAX_BACKUP_EXTRACTED_BYTES = 64 * 1024 * 1024;
const MAX_BACKUP_DB_JSON_BYTES = 32 * 1024 * 1024;
const MAX_BACKUP_PATH_SEGMENT_LENGTH = 128;

export interface BackupManifest {
  formatVersion: BackupFormatVersion;
  exportedAt: string;
  appVersion: string;
  storageKind: 'r2' | 'kv' | null;
  tableCounts: Record<string, number>;
  includes: {
    attachments: boolean;
  };
  blobSummary: {
    attachmentFiles: number;
    totalBytes: number;
    largestObjectBytes: number;
  };
  attachmentBlobs?: BackupManifestAttachmentBlob[];
}

export interface BackupManifestAttachmentBlob {
  cipherId: string;
  attachmentId: string;
  blobName: string;
  sizeBytes: number;
}

export interface BackupPayload {
  manifest: BackupManifest;
  db: {
    config: SqlRow[];
    users: SqlRow[];
    domain_settings: SqlRow[];
    user_revisions: SqlRow[];
    folders: SqlRow[];
    ciphers: SqlRow[];
    attachments: SqlRow[];
    webauthn_credentials?: SqlRow[];
  } & Partial<Record<OrganizationBackupTableName, SqlRow[]>>;
}

export interface BackupArchiveBundle {
  bytes: Uint8Array;
  fileName: string;
  manifest: BackupManifest;
}

export interface BackupFileIntegrityCheckResult {
  hasChecksumPrefix: boolean;
  expectedPrefix: string | null;
  actualPrefix: string;
  matches: boolean;
}

export interface BuildBackupArchiveOptions {
  includeAttachments?: boolean;
  progress?: BackupArchiveBuildProgressReporter;
  timeZone?: string;
}

export interface BackupArchiveBuildProgressEvent {
  step: string;
  fileName?: string;
  stageTitle: string;
  stageDetail: string;
  includeAttachments: boolean;
}

export type BackupArchiveBuildProgressReporter = (event: BackupArchiveBuildProgressEvent) => Promise<void>;

function sanitizeConfigRowsForExport(rows: SqlRow[]): SqlRow[] {
  const sanitized: SqlRow[] = [];
  for (const row of rows) {
    const key = String(row.key || '').trim();
    if (!key || key === BACKUP_RUNNER_LOCK_CONFIG_KEY || key === YUBICO_BOOTSTRAP_CLAIM_CONFIG_KEY || key.startsWith('organization.sync.')) continue;

    if (key === BACKUP_SETTINGS_CONFIG_KEY) {
      const portableOnly = exportPortableBackupSettingsEnvelope(typeof row.value === 'string' ? row.value : null);
      if (portableOnly) sanitized.push({ ...row, value: portableOnly });
      continue;
    }

    sanitized.push({ ...row });
  }
  return sanitized;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function getDateParts(date: Date, timeZone: string): string {
  const formatter = new Intl.DateTimeFormat('en-CA', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  });
  const parts = formatter.formatToParts(date);
  const pick = (type: string): string => parts.find((part) => part.type === type)?.value || '';
  return `${pick('year')}${pick('month')}${pick('day')}_${pick('hour')}${pick('minute')}${pick('second')}`;
}

function buildBackupFileNameInTimeZone(
  date: Date = new Date(),
  checksumPrefix: string | null = null,
  timeZone: string = 'UTC'
): string {
  const parts = getDateParts(date, timeZone);
  const suffix = checksumPrefix ? `_${checksumPrefix}` : '';
  return `nodewarden_backup_${parts}${suffix}.zip`;
}

export function extractBackupFileChecksumPrefix(fileName: string): string | null {
  const normalized = String(fileName || '').trim();
  const match = normalized.match(/_([0-9a-f]{5})\.zip$/i);
  return match ? match[1].toLowerCase() : null;
}

export async function inspectBackupArchiveFileNameChecksum(
  bytes: Uint8Array,
  fileName: string
): Promise<BackupFileIntegrityCheckResult> {
  const expectedPrefix = extractBackupFileChecksumPrefix(fileName);
  const actualHash = await sha256Hex(bytes);
  const actualPrefix = actualHash.slice(0, BACKUP_FILE_HASH_PREFIX_LENGTH);
  return {
    hasChecksumPrefix: !!expectedPrefix,
    expectedPrefix,
    actualPrefix,
    matches: !expectedPrefix || actualPrefix === expectedPrefix,
  };
}

export async function verifyBackupArchiveFileNameChecksum(bytes: Uint8Array, fileName: string): Promise<boolean> {
  const result = await inspectBackupArchiveFileNameChecksum(bytes, fileName);
  return result.matches;
}

function validateArchiveSize(bytes: Uint8Array): void {
  if (bytes.byteLength > MAX_BACKUP_ARCHIVE_BYTES) {
    throw new Error(`Backup archive is too large. The current restore limit is ${Math.floor(MAX_BACKUP_ARCHIVE_BYTES / (1024 * 1024))} MiB`);
  }
}

function isSafeBackupPathSegment(value: string): boolean {
  if (!value || value.length > MAX_BACKUP_PATH_SEGMENT_LENGTH) return false;
  if (value === '.' || value === '..') return false;
  return /^[A-Za-z0-9._-]+$/.test(value);
}

export function isSafeBackupAttachmentBlobName(value: unknown): boolean {
  const normalized = String(value ?? '').trim();
  const parts = normalized.split('/');
  return parts.length === 2 && parts.every(isSafeBackupPathSegment);
}

function isSafeBackupAttachmentEntryName(value: string): boolean {
  if (!value.startsWith('attachments/') || !value.endsWith('.bin')) return false;
  const relative = value.slice('attachments/'.length, -'.bin'.length);
  return isSafeBackupAttachmentBlobName(relative);
}

function validateBackupEntryName(name: string): void {
  const normalized = String(name || '').trim();
  if (normalized !== name || !normalized) {
    throw new Error('Backup archive contains an invalid file name');
  }
  if (normalized.includes('\\') || normalized.includes('\0') || normalized.startsWith('/') || normalized.includes('//')) {
    throw new Error(`Backup archive contains an unsafe file name: ${normalized}`);
  }
  if (normalized !== 'manifest.json' && normalized !== 'db.json' && !isSafeBackupAttachmentEntryName(normalized)) {
    throw new Error(`Backup archive contains an unsupported file: ${normalized}`);
  }
}

function createBackupUnzipFilter(): (file: UnzipFileInfo) => boolean {
  let entryCount = 0;
  let totalOriginalBytes = 0;
  return (file: UnzipFileInfo): boolean => {
    entryCount += 1;
    if (entryCount > MAX_BACKUP_ARCHIVE_ENTRY_COUNT) {
      throw new Error('Backup archive contains too many files');
    }
    validateBackupEntryName(file.name);
    const originalSize = Number(file.originalSize);
    if (!Number.isFinite(originalSize) || originalSize < 0) {
      throw new Error(`Backup archive contains an invalid file size: ${file.name}`);
    }
    if (file.name === 'db.json' && originalSize > MAX_BACKUP_DB_JSON_BYTES) {
      throw new Error('Backup archive database payload is too large');
    }
    totalOriginalBytes += originalSize;
    if (totalOriginalBytes > MAX_BACKUP_EXTRACTED_BYTES) {
      throw new Error('Backup archive expands beyond the current restore limit');
    }
    return true;
  };
}

function getRequiredZipEntries(db: BackupPayload['db']): string[] {
  const entries: string[] = [];
  for (const row of db.attachments) {
    const cipherId = String(row.cipher_id || '').trim();
    const attachmentId = String(row.id || '').trim();
    if (!cipherId || !attachmentId) continue;
    entries.push(`attachments/${cipherId}/${attachmentId}.bin`);
  }
  return entries;
}

function ensureRowArray(value: unknown, table: string): SqlRow[] {
  if (!Array.isArray(value)) {
    throw new Error(`Backup archive table ${table} is invalid`);
  }
  return value as SqlRow[];
}

function normalizeParsedBackupDb(value: unknown, formatVersion: BackupFormatVersion): BackupPayload['db'] {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Backup archive database payload is invalid');
  }
  const source = value as Record<string, unknown>;
  if (formatVersion === BACKUP_FORMAT_VERSION) {
    const supportedTables = new Set(['config', 'users', 'domain_settings', 'user_revisions', 'folders', 'ciphers', 'attachments', 'webauthn_credentials', ...ORGANIZATION_BACKUP_TABLES]);
    for (const table of Object.keys(source)) {
      if (!supportedTables.has(table)) throw new Error(`Backup archive contains an unsupported table: ${table}`);
    }
  }
  // Runtime authentication tables remain outside the explicit restore allowlist.
  const organizations: Partial<Record<OrganizationBackupTableName, SqlRow[]>> = {};
  for (const table of ORGANIZATION_BACKUP_TABLES) {
    if (formatVersion === 1) {
      if (source[table] != null && (!Array.isArray(source[table]) || (source[table] as unknown[]).length)) {
        throw new Error('Legacy backup format cannot contain organization data');
      }
      organizations[table] = [];
    } else {
      organizations[table] = ensureRowArray(source[table], table);
    }
  }
  return {
    ...organizations,
    config: source.config as SqlRow[],
    users: source.users as SqlRow[],
    domain_settings: source.domain_settings as SqlRow[],
    user_revisions: source.user_revisions as SqlRow[],
    folders: source.folders as SqlRow[],
    ciphers: source.ciphers as SqlRow[],
    attachments: source.attachments as SqlRow[],
    webauthn_credentials: source.webauthn_credentials as SqlRow[] | undefined,
  };
}

function createZipEntries(files: Record<string, Uint8Array>): Record<string, Uint8Array | [Uint8Array, { level: 0 | 1 | 6 }]> {
  const entries: Record<string, Uint8Array | [Uint8Array, { level: 0 | 1 | 6 }]> = {};
  for (const [path, bytes] of Object.entries(files)) {
    entries[path] = [bytes, { level: BACKUP_TEXT_COMPRESSION_LEVEL }];
  }
  return entries;
}

export interface ParseBackupArchiveOptions {
  allowExternalAttachmentBlobs?: boolean;
}

export function parseBackupArchive(
  bytes: Uint8Array,
  options: ParseBackupArchiveOptions = {}
): { payload: BackupPayload; files: Record<string, Uint8Array> } {
  validateArchiveSize(bytes);
  let zipped: Record<string, Uint8Array>;
  try {
    zipped = unzipSync(bytes, { filter: createBackupUnzipFilter() });
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('Backup archive ')) {
      throw error;
    }
    throw new Error('Invalid backup archive');
  }

  const entryNames = Object.keys(zipped);
  if (entryNames.length > MAX_BACKUP_ARCHIVE_ENTRY_COUNT) {
    throw new Error('Backup archive contains too many files');
  }

  let totalExtractedBytes = 0;
  for (const entry of entryNames) {
    validateBackupEntryName(entry);
    const entryBytes = zipped[entry];
    totalExtractedBytes += entryBytes.byteLength;
    if (entry === 'db.json' && entryBytes.byteLength > MAX_BACKUP_DB_JSON_BYTES) {
      throw new Error('Backup archive database payload is too large');
    }
    if (totalExtractedBytes > MAX_BACKUP_EXTRACTED_BYTES) {
      throw new Error('Backup archive expands beyond the current restore limit');
    }
  }

  const manifestBytes = zipped['manifest.json'];
  const dbBytes = zipped['db.json'];
  if (!manifestBytes || !dbBytes) {
    throw new Error('Backup archive is missing manifest.json or db.json');
  }

  const decoder = new TextDecoder();
  let manifest: BackupManifest;
  let rawDb: unknown;
  try {
    manifest = JSON.parse(decoder.decode(manifestBytes)) as BackupManifest;
    rawDb = JSON.parse(decoder.decode(dbBytes));
  } catch {
    throw new Error('Backup archive contains invalid JSON metadata');
  }

  if (manifest?.formatVersion !== 1 && manifest?.formatVersion !== BACKUP_FORMAT_VERSION) {
    throw new Error('Unsupported backup format version');
  }
  const db = normalizeParsedBackupDb(rawDb, manifest.formatVersion);

  const externalAttachmentKeys = new Set<string>(
    options.allowExternalAttachmentBlobs
      ? (manifest.attachmentBlobs || []).map((item) => `attachments/${String(item.cipherId || '').trim()}/${String(item.attachmentId || '').trim()}.bin`)
      : []
  );
  const requiredEntries = getRequiredZipEntries(db).filter((entry) => !externalAttachmentKeys.has(entry));
  for (const entry of requiredEntries) {
    if (!zipped[entry]) {
      throw new Error(`Backup archive is missing required file: ${entry}`);
    }
  }

  return {
    payload: { manifest, db },
    files: zipped,
  };
}

export interface ValidateBackupPayloadOptions {
  allowExternalAttachmentBlobs?: boolean;
}

function validateOrganizationBackupRows(payload: BackupPayload, userIds: Set<string>): Set<string> {
  const tables = {} as Record<OrganizationBackupTableName, SqlRow[]>;
  for (const table of ORGANIZATION_BACKUP_TABLES) {
    tables[table] = ensureRowArray(payload.db[table] ?? (payload.manifest.formatVersion === 1 ? [] : undefined), table);
    if (payload.manifest.formatVersion === 1 && tables[table].length) throw new Error('Legacy backup format cannot contain organization data');
    if (payload.manifest.formatVersion === 2 && payload.manifest.tableCounts?.[table] !== tables[table].length) {
      throw new Error(`Backup archive table count does not match ${table}`);
    }
  }
  const text = (row: SqlRow, field: string): string => String(row[field] ?? '').trim();
  const index = (rows: SqlRow[], table: string): Map<string, SqlRow> => {
    const result = new Map<string, SqlRow>();
    for (const row of rows) {
      const id = text(row, 'id');
      if (!id || result.has(id)) throw new Error(`Backup archive contains an invalid or duplicate ${table} id`);
      result.set(id, row);
    }
    return result;
  };
  const organizations = index(tables.organizations, 'organization');
  for (const row of organizations.values()) {
    if (!text(row, 'name') || !text(row, 'billing_email') || !text(row, 'created_at') || !text(row, 'updated_at')) {
      throw new Error('Backup archive contains an invalid organization row');
    }
  }
  const members = index(tables.organization_members, 'organization member');
  const groups = index(tables.organization_groups, 'organization group');
  const collections = index(tables.collections, 'collection');
  const events = index(tables.organization_events, 'organization event');
  const memberEmails = new Set<string>();
  const memberUsers = new Set<string>();
  for (const row of [...members.values(), ...groups.values(), ...collections.values(), ...events.values()]) {
    if (!organizations.has(text(row, 'organization_id'))) throw new Error('Backup archive contains a row for an unknown organization');
  }
  for (const row of members.values()) {
    const userId = text(row, 'user_id');
    const emailKey = JSON.stringify([row.organization_id, text(row, 'email').replace(/[A-Z]/g, (letter) => letter.toLowerCase())]);
    const userKey = JSON.stringify([row.organization_id, userId]);
    if (!text(row, 'email') || (row.user_id !== null && !userIds.has(userId))
      || !Number.isInteger(row.type) || ![0, 1, 2, 3].includes(Number(row.type))
      || !Number.isInteger(row.status) || ![-1, 0, 1, 2].includes(Number(row.status))
      || !text(row, 'created_at') || !text(row, 'updated_at') || memberEmails.has(emailKey) || (userId && memberUsers.has(userKey))) {
      throw new Error('Backup archive contains an invalid organization member row');
    }
    memberEmails.add(emailKey);
    if (userId) memberUsers.add(userKey);
  }
  for (const row of [...groups.values(), ...collections.values()]) {
    if (!text(row, 'name')) throw new Error('Backup archive contains an invalid collection or group row');
  }
  for (const row of events.values()) {
    if (!Number.isInteger(row.type) || !text(row, 'date') || (row.actor_user_id !== null && !userIds.has(text(row, 'actor_user_id')))) {
      throw new Error('Backup archive contains an invalid organization event row');
    }
  }
  const ciphers = new Map(payload.db.ciphers.map((row) => [text(row, 'id'), row]));
  const links: Array<[OrganizationBackupTableName, string, Map<string, SqlRow>, string, Map<string, SqlRow>]> = [
    ['organization_group_members', 'group_id', groups, 'member_id', members],
    ['collection_users', 'collection_id', collections, 'member_id', members],
    ['collection_groups', 'collection_id', collections, 'group_id', groups],
    ['cipher_collections', 'cipher_id', ciphers, 'collection_id', collections],
  ];
  for (const [table, leftColumn, left, rightColumn, right] of links) {
    const pairs = new Set<string>();
    for (const row of tables[table]) {
      const l = left.get(text(row, leftColumn));
      const r = right.get(text(row, rightColumn));
      const pair = JSON.stringify([row[leftColumn], row[rightColumn]]);
      if (!l || !r || !l.organization_id || l.organization_id !== r.organization_id || pairs.has(pair)) {
        throw new Error(`Backup archive contains an invalid cross-organization or duplicate ${table} association`);
      }
      pairs.add(pair);
    }
  }
  const folders = new Map(payload.db.folders.map((row) => [text(row, 'id'), row]));
  const preferences = new Set<string>();
  for (const row of tables.cipher_user_preferences) {
    const pair = JSON.stringify([row.cipher_id, row.user_id]);
    const folderId = text(row, 'folder_id');
    if (!ciphers.has(text(row, 'cipher_id')) || !userIds.has(text(row, 'user_id')) || preferences.has(pair)
      || (row.folder_id !== null && (!folderId || folders.get(folderId)?.user_id !== row.user_id))) {
      throw new Error('Backup archive contains an invalid cipher user preference row');
    }
    preferences.add(pair);
  }
  return new Set(organizations.keys());
}

export function validateBackupPayloadContents(
  payload: BackupPayload,
  files: Record<string, Uint8Array>,
  options: ValidateBackupPayloadOptions = {}
): void {
  if (payload.manifest?.formatVersion !== 1 && payload.manifest?.formatVersion !== BACKUP_FORMAT_VERSION) {
    throw new Error('Unsupported backup format version');
  }
  const configRows = ensureRowArray(payload.db.config, 'config');
  const userRows = ensureRowArray(payload.db.users, 'users');
  const revisionRows = ensureRowArray(payload.db.user_revisions, 'user_revisions');
  const domainSettingsRows = ensureRowArray(payload.db.domain_settings || [], 'domain_settings');
  const folderRows = ensureRowArray(payload.db.folders, 'folders');
  const cipherRows = ensureRowArray(payload.db.ciphers, 'ciphers');
  const attachmentRows = ensureRowArray(payload.db.attachments, 'attachments');
  const accountPasskeyRows = ensureRowArray(payload.db.webauthn_credentials || [], 'webauthn_credentials');
  const externalAttachmentKeys = new Set<string>(
    options.allowExternalAttachmentBlobs
      ? (payload.manifest.attachmentBlobs || []).map((item) => `attachments/${String(item.cipherId || '').trim()}/${String(item.attachmentId || '').trim()}.bin`)
      : []
  );

  const userIds = new Set<string>();
  for (const row of userRows) {
    const id = String(row.id || '').trim();
    const email = String(row.email || '').trim();
    if (!id || !email) throw new Error('Backup archive contains an invalid user row');
    if (userIds.has(id)) throw new Error(`Backup archive contains duplicate user id: ${id}`);
    userIds.add(id);
  }

  for (const row of configRows) {
    const key = String(row.key || '').trim();
    if (!key) throw new Error('Backup archive contains an invalid config row');
  }

  for (const row of revisionRows) {
    const userId = String(row.user_id || '').trim();
    if (!userId || !userIds.has(userId)) {
      throw new Error(`Backup archive contains a revision for an unknown user: ${userId || '(empty)'}`);
    }
  }

  const domainSettingUserIds = new Set<string>();
  for (const row of domainSettingsRows) {
    const userId = String(row.user_id || '').trim();
    if (!userId || !userIds.has(userId)) {
      throw new Error(`Backup archive contains domain settings for an unknown user: ${userId || '(empty)'}`);
    }
    if (domainSettingUserIds.has(userId)) {
      throw new Error(`Backup archive contains duplicate domain settings for user: ${userId}`);
    }
    domainSettingUserIds.add(userId);
  }

  const folderIds = new Set<string>();
  for (const row of folderRows) {
    const id = String(row.id || '').trim();
    const userId = String(row.user_id || '').trim();
    if (!id || !userIds.has(userId)) throw new Error('Backup archive contains an invalid folder row');
    if (folderIds.has(id)) throw new Error(`Backup archive contains duplicate folder id: ${id}`);
    folderIds.add(id);
  }

  const organizationIds = validateOrganizationBackupRows(payload, userIds);
  const cipherIds = new Set<string>();
  for (const row of cipherRows) {
    const id = String(row.id || '').trim();
    const userId = String(row.user_id || '').trim();
    const folderId = String(row.folder_id || '').trim();
    const organizationId = String(row.organization_id ?? '').trim();
    if (payload.manifest.formatVersion === 1 && row.organization_id != null) throw new Error('Legacy backup format cannot contain organization-owned ciphers');
    const personal = (payload.manifest.formatVersion === 1 || row.organization_id === null) && userIds.has(userId);
    const organizational = row.user_id === null && !!organizationId && organizationIds.has(organizationId);
    if (!id || (!personal && !organizational)) throw new Error('Backup archive contains an invalid cipher row');
    if (folderId && !folderIds.has(folderId)) {
      throw new Error(`Backup archive contains a cipher for an unknown folder: ${folderId}`);
    }
    if (cipherIds.has(id)) throw new Error(`Backup archive contains duplicate cipher id: ${id}`);
    cipherIds.add(id);
  }

  for (const row of attachmentRows) {
    const id = String(row.id || '').trim();
    const cipherId = String(row.cipher_id || '').trim();
    if (!id || !cipherId || !isSafeBackupPathSegment(id) || !isSafeBackupPathSegment(cipherId) || !cipherIds.has(cipherId)) {
      throw new Error('Backup archive contains an invalid attachment row');
    }
    const attachmentPath = `attachments/${cipherId}/${id}.bin`;
    if (!files[attachmentPath] && !externalAttachmentKeys.has(attachmentPath)) {
      throw new Error(`Backup archive is missing required file: attachments/${cipherId}/${id}.bin`);
    }
  }

  const accountPasskeyIds = new Set<string>();
  const accountPasskeyCredentialIds = new Set<string>();
  for (const row of accountPasskeyRows) {
    const id = String(row.id || '').trim();
    const userId = String(row.user_id || '').trim();
    const purpose = row.purpose == null ? 'login' : String(row.purpose || '').trim();
    const credentialId = String(row.credential_id || '').trim();
    const publicKey = String(row.public_key || '').trim();
    if (!id || !userIds.has(userId) || !credentialId || !publicKey || (purpose !== 'login' && purpose !== 'twoFactor')) {
      throw new Error('Backup archive contains an invalid account passkey row');
    }
    if (accountPasskeyIds.has(id)) throw new Error(`Backup archive contains duplicate account passkey id: ${id}`);
    if (accountPasskeyCredentialIds.has(credentialId)) throw new Error(`Backup archive contains duplicate account passkey credential id: ${credentialId}`);
    accountPasskeyIds.add(id);
    accountPasskeyCredentialIds.add(credentialId);
  }

}

export async function buildBackupArchive(
  env: Env,
  date: Date = new Date(),
  options: BuildBackupArchiveOptions = {}
): Promise<BackupArchiveBundle> {
  const includeAttachments = options.includeAttachments !== false;
  await options.progress?.({
    step: 'collect_data',
    fileName: '',
    stageTitle: 'txt_backup_archive_progress_collect_title',
    stageDetail: includeAttachments
      ? 'txt_backup_archive_progress_collect_with_attachments_detail'
      : 'txt_backup_archive_progress_collect_detail',
    includeAttachments,
  });
  const encoder = new TextEncoder();
  const baseQueries = [
    'SELECT key, value FROM config ORDER BY key ASC',
    'SELECT id, email, name, master_password_hint, master_password_hash, key, private_key, public_key, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, role, status, verify_devices, totp_secret, totp_recovery_code, yubikey_key1, yubikey_key2, yubikey_key3, yubikey_key4, yubikey_key5, yubikey_nfc, created_at, updated_at FROM users ORDER BY created_at ASC',
    'SELECT user_id, equivalent_domains, custom_equivalent_domains, excluded_global_equivalent_domains, updated_at FROM domain_settings ORDER BY user_id ASC',
    'SELECT user_id, revision_date FROM user_revisions ORDER BY user_id ASC',
    'SELECT id, user_id, name, created_at, updated_at FROM folders ORDER BY created_at ASC',
    'SELECT id, user_id, organization_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, archived_at, deleted_at FROM ciphers ORDER BY created_at ASC',
    'SELECT id, cipher_id, file_name, size, size_name, key FROM attachments ORDER BY cipher_id ASC, id ASC',
    'SELECT id, user_id, purpose, name, public_key, credential_id, counter, type, aa_guid, transports, encrypted_user_key, encrypted_public_key, encrypted_private_key, supports_prf, created_at, updated_at FROM webauthn_credentials ORDER BY created_at ASC',
  ];
  const organizationQueries = ORGANIZATION_BACKUP_TABLES.map((table) =>
    `SELECT ${ORGANIZATION_BACKUP_TABLE_COLUMNS[table].join(', ')} FROM ${table} ORDER BY ${ORGANIZATION_BACKUP_TABLE_COLUMNS[table].join(', ')}`);
  // D1 executes the entire batch in one transaction. Personal ownership, organization
  // links, membership keys and attachment metadata must all describe the same snapshot.
  // Blob contents remain external to this SQL transaction, as with remote backups.
  const snapshot = await env.DB.batch<SqlRow>([...baseQueries, ...organizationQueries].map((sql) => env.DB.prepare(sql)));
  const rows = snapshot.map((result) => (result.results || []).map((row) => ({ ...row })));
  const [configRows, userRows, domainSettingsRows, revisionRows, folderRows, cipherRows, attachmentRows, accountPasskeyRows] = rows;
  const organizationEntries = ORGANIZATION_BACKUP_TABLES.map((table, index) => [table, rows[baseQueries.length + index]] as const);
  const organizationRows = Object.fromEntries(organizationEntries) as Record<OrganizationBackupTableName, SqlRow[]>;
  const organizationCounts = Object.fromEntries(organizationEntries.map(([table, rows]) => [table, rows.length]));
  const exportedConfigRows = sanitizeConfigRowsForExport(configRows);
  const exportedAttachmentRows = includeAttachments ? attachmentRows : [];
  const attachmentBlobs: BackupManifestAttachmentBlob[] = exportedAttachmentRows.map((row) => {
    const cipherId = String(row.cipher_id || '').trim();
    const attachmentId = String(row.id || '').trim();
    return {
      cipherId,
      attachmentId,
      blobName: getAttachmentObjectKey(cipherId, attachmentId),
      sizeBytes: Number(row.size || 0) || 0,
    };
  });

  const manifestBase = {
    formatVersion: BACKUP_FORMAT_VERSION,
    exportedAt: date.toISOString(),
    appVersion: APP_VERSION,
    storageKind: getBlobStorageKind(env),
    tableCounts: {
      ...organizationCounts,
      config: exportedConfigRows.length,
      users: userRows.length,
      domain_settings: domainSettingsRows.length,
      user_revisions: revisionRows.length,
      folders: folderRows.length,
      ciphers: cipherRows.length,
      attachments: exportedAttachmentRows.length,
      webauthn_credentials: accountPasskeyRows.length,
    },
    includes: {
      attachments: includeAttachments,
    },
    blobSummary: {
      attachmentFiles: attachmentBlobs.length,
      totalBytes: attachmentBlobs.reduce((sum, item) => sum + item.sizeBytes, 0),
      largestObjectBytes: attachmentBlobs.reduce((max, item) => Math.max(max, item.sizeBytes), 0),
    },
    attachmentBlobs: includeAttachments ? attachmentBlobs : [],
  } satisfies BackupManifest;

  const files: Record<string, Uint8Array> = {
    'manifest.json': encoder.encode(JSON.stringify(manifestBase, null, BACKUP_JSON_INDENT)),
    'db.json': encoder.encode(JSON.stringify({
      ...organizationRows,
      config: exportedConfigRows,
      users: userRows,
      domain_settings: domainSettingsRows,
      user_revisions: revisionRows,
      folders: folderRows,
      ciphers: cipherRows,
      attachments: exportedAttachmentRows,
      webauthn_credentials: accountPasskeyRows,
    }, null, BACKUP_JSON_INDENT)),
  };

  await options.progress?.({
    step: 'package_archive',
    fileName: '',
    stageTitle: 'txt_backup_archive_progress_package_title',
    stageDetail: includeAttachments
      ? 'txt_backup_archive_progress_package_with_attachments_detail'
      : 'txt_backup_archive_progress_package_detail',
    includeAttachments,
  });
  const bytes = zipSync(createZipEntries(files));
  const fileHashPrefix = (await sha256Hex(bytes)).slice(0, BACKUP_FILE_HASH_PREFIX_LENGTH);
  const backupTimeZone = options.timeZone || 'UTC';
  const fileName = buildBackupFileNameInTimeZone(date, fileHashPrefix, backupTimeZone);
  await options.progress?.({
    step: 'archive_ready',
    fileName,
    stageTitle: 'txt_backup_archive_progress_ready_title',
    stageDetail: 'txt_backup_archive_progress_ready_detail',
    includeAttachments,
  });

  return {
    bytes,
    fileName,
    manifest: manifestBase,
  };
}
