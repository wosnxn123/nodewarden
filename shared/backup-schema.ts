// Shared backup settings types used by both Worker and webapp code.
//
// CONTRACT:
// Keep this file serializable and provider-neutral. Runtime state is operational
// metadata; destination fields can contain provider credentials and must be
// encrypted by src/services/backup-settings-crypto.ts before storage/export.
// User-facing provider names should use canonical values here. Legacy aliases
// belong in backend normalization, not in this shared type.
// Archive v2 makes organization ownership explicit. Older restores must reject it,
// not silently discard organization records while restoring the personal tables.
export const BACKUP_FORMAT_VERSION = 2;
export type BackupFormatVersion = 1 | typeof BACKUP_FORMAT_VERSION;
export const ORGANIZATION_BACKUP_TABLE_COLUMNS = {
  organizations: ['id', 'name', 'billing_email', 'public_key', 'private_key', 'created_at', 'updated_at'],
  organization_members: ['id', 'organization_id', 'user_id', 'email', 'type', 'status', 'access_all', 'key', 'external_id', 'created_at', 'updated_at'],
  collections: ['id', 'organization_id', 'name', 'external_id'],
  organization_groups: ['id', 'organization_id', 'name', 'access_all', 'external_id'],
  organization_group_members: ['group_id', 'member_id'],
  collection_users: ['collection_id', 'member_id', 'read_only', 'hide_passwords', 'manage'],
  collection_groups: ['collection_id', 'group_id', 'read_only', 'hide_passwords', 'manage'],
  cipher_collections: ['cipher_id', 'collection_id'],
  cipher_user_preferences: ['cipher_id', 'user_id', 'folder_id', 'favorite'],
  organization_events: ['id', 'organization_id', 'actor_user_id', 'type', 'target_id', 'date', 'data'],
} as const;
export type OrganizationBackupTableName = keyof typeof ORGANIZATION_BACKUP_TABLE_COLUMNS;
export const ORGANIZATION_BACKUP_TABLES = Object.keys(ORGANIZATION_BACKUP_TABLE_COLUMNS) as OrganizationBackupTableName[];
export interface OrganizationBackupImportCounts {
  organizations: number;
  organizationMembers: number;
  collections: number;
  organizationGroups: number;
  organizationGroupMembers: number;
  collectionUsers: number;
  collectionGroups: number;
  cipherCollections: number;
  cipherUserPreferences: number;
  organizationEvents: number;
}

export const BACKUP_DEFAULT_TIMEZONE = 'UTC';
export const BACKUP_DEFAULT_RETENTION_COUNT = 30;
export const BACKUP_DEFAULT_S3_REGION = 'auto';
export const BACKUP_DEFAULT_S3_ROOT_PATH = '';
export const BACKUP_DEFAULT_WEBDAV_REMOTE_PATH = 'nodewarden';
export const BACKUP_DEFAULT_INTERVAL_HOURS = 24;
export const BACKUP_DEFAULT_START_TIME = '03:00';

export type BackupDestinationType = 's3' | 'webdav';
export type S3BackupAddressingStyle = 'path-style' | 'virtual-hosted-style';

export interface S3BackupDestination {
  endpoint: string;
  bucket: string;
  addressingStyle: S3BackupAddressingStyle;
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
  rootPath: string;
}

export interface WebDavBackupDestination {
  baseUrl: string;
  username: string;
  password: string;
  remotePath: string;
}

export type BackupDestinationConfig =
  | S3BackupDestination
  | WebDavBackupDestination;

export interface BackupRuntimeState {
  lastAttemptAt: string | null;
  lastAttemptLocalDate: string | null;
  lastSuccessAt: string | null;
  lastErrorAt: string | null;
  lastErrorMessage: string | null;
  lastUploadedFileName: string | null;
  lastUploadedSizeBytes: number | null;
  lastUploadedDestination: string | null;
}

export interface BackupScheduleConfig {
  enabled: boolean;
  intervalHours: number;
  startTime: string;
  timezone: string;
  retentionCount: number | null;
}

export interface BackupDestinationRecord {
  id: string;
  name: string;
  type: BackupDestinationType;
  includeAttachments: boolean;
  destination: BackupDestinationConfig;
  schedule: BackupScheduleConfig;
  runtime: BackupRuntimeState;
}

export interface BackupSettings {
  destinations: BackupDestinationRecord[];
}

export function createBackupRandomId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return `backup-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

export function createDefaultBackupRuntimeState(): BackupRuntimeState {
  return {
    lastAttemptAt: null,
    lastAttemptLocalDate: null,
    lastSuccessAt: null,
    lastErrorAt: null,
    lastErrorMessage: null,
    lastUploadedFileName: null,
    lastUploadedSizeBytes: null,
    lastUploadedDestination: null,
  };
}

export function createDefaultBackupScheduleConfig(timezone: string = BACKUP_DEFAULT_TIMEZONE): BackupScheduleConfig {
  return {
    enabled: false,
    intervalHours: BACKUP_DEFAULT_INTERVAL_HOURS,
    startTime: BACKUP_DEFAULT_START_TIME,
    timezone,
    retentionCount: BACKUP_DEFAULT_RETENTION_COUNT,
  };
}

export function createDefaultBackupDestinationConfig(type: BackupDestinationType): BackupDestinationConfig {
  if (type === 's3') {
    return {
      endpoint: '',
      bucket: '',
      addressingStyle: 'path-style',
      region: BACKUP_DEFAULT_S3_REGION,
      accessKeyId: '',
      secretAccessKey: '',
      rootPath: BACKUP_DEFAULT_S3_ROOT_PATH,
    };
  }
  return {
    baseUrl: '',
    username: '',
    password: '',
    remotePath: BACKUP_DEFAULT_WEBDAV_REMOTE_PATH,
  };
}

export function createDefaultBackupDestinationName(type: BackupDestinationType, index: number): string {
  if (type === 's3') return `S3 ${index}`;
  return `WebDAV ${index}`;
}

export interface CreateBackupDestinationRecordOptions {
  id?: string;
  name?: string;
  timezone?: string;
}

export function createBackupDestinationRecord(
  type: BackupDestinationType,
  index: number,
  options: CreateBackupDestinationRecordOptions = {}
): BackupDestinationRecord {
  return {
    id: options.id || createBackupRandomId(),
    name: options.name || createDefaultBackupDestinationName(type, index),
    type,
    includeAttachments: false,
    destination: createDefaultBackupDestinationConfig(type),
    schedule: createDefaultBackupScheduleConfig(options.timezone || BACKUP_DEFAULT_TIMEZONE),
    runtime: createDefaultBackupRuntimeState(),
  };
}

export function createDefaultBackupSettings(
  timezone: string = BACKUP_DEFAULT_TIMEZONE,
  options: { destinationName?: string } = {}
): BackupSettings {
  return {
    destinations: [
      createBackupDestinationRecord('webdav', 1, {
        timezone,
        name: options.destinationName,
      }),
    ],
  };
}
