PRAGMA foreign_keys = ON;

-- IMPORTANT:
-- This is the initial D1 schema. Keep it in sync with
-- src/services/storage-schema.ts (SCHEMA_STATEMENTS).
-- Any new table/column/index must be added to both places together.
--
-- WHEN CHANGING THIS:
-- - Also bump STORAGE_SCHEMA_VERSION in src/services/storage.ts.
-- - If the new table stores persistent data, update backup export/import.
-- - Keep src/services/storage-schema.ts idempotent for existing installs.

CREATE TABLE IF NOT EXISTS config (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  name TEXT,
  master_password_hint TEXT,
  master_password_hash TEXT NOT NULL,
  key TEXT NOT NULL,
  private_key TEXT,
  public_key TEXT,
  kdf_type INTEGER NOT NULL,
  kdf_iterations INTEGER NOT NULL,
  kdf_memory INTEGER,
  kdf_parallelism INTEGER,
  security_stamp TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  status TEXT NOT NULL DEFAULT 'active',
  verify_devices INTEGER NOT NULL DEFAULT 0,
  totp_secret TEXT,
  totp_recovery_code TEXT,
  yubikey_key1 TEXT,
  yubikey_key2 TEXT,
  yubikey_key3 TEXT,
  yubikey_key4 TEXT,
  yubikey_key5 TEXT,
  yubikey_nfc INTEGER NOT NULL DEFAULT 0,
  api_key TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS domain_settings (
  user_id TEXT PRIMARY KEY,
  equivalent_domains TEXT NOT NULL DEFAULT '[]',
  custom_equivalent_domains TEXT NOT NULL DEFAULT '[]',
  excluded_global_equivalent_domains TEXT NOT NULL DEFAULT '[]',
  updated_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Per-user sync revision date
CREATE TABLE IF NOT EXISTS user_revisions (
  user_id TEXT PRIMARY KEY,
  revision_date TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS organizations (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, billing_email TEXT NOT NULL, public_key TEXT, private_key TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS organization_members (
  id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, user_id TEXT, email TEXT NOT NULL COLLATE NOCASE,
  type INTEGER NOT NULL CHECK (type IN (0, 1, 2, 3)), status INTEGER NOT NULL CHECK (status IN (-1, 0, 1, 2)),
  access_all INTEGER NOT NULL DEFAULT 0, key TEXT, external_id TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE (organization_id, email), UNIQUE (organization_id, user_id),
  FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_organization_members_user ON organization_members(user_id, status);
CREATE TABLE IF NOT EXISTS collections (
  id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, name TEXT NOT NULL, external_id TEXT,
  FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_collections_organization ON collections(organization_id);
CREATE TABLE IF NOT EXISTS organization_groups (
  id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, name TEXT NOT NULL, access_all INTEGER NOT NULL DEFAULT 0, external_id TEXT,
  FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_organization_groups_organization ON organization_groups(organization_id);
CREATE TABLE IF NOT EXISTS organization_group_members (
  group_id TEXT NOT NULL, member_id TEXT NOT NULL, PRIMARY KEY (group_id, member_id),
  FOREIGN KEY (group_id) REFERENCES organization_groups(id) ON DELETE CASCADE,
  FOREIGN KEY (member_id) REFERENCES organization_members(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_organization_group_members_member ON organization_group_members(member_id);
CREATE TABLE IF NOT EXISTS collection_users (
  collection_id TEXT NOT NULL, member_id TEXT NOT NULL, read_only INTEGER NOT NULL DEFAULT 0,
  hide_passwords INTEGER NOT NULL DEFAULT 0, manage INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (collection_id, member_id),
  FOREIGN KEY (collection_id) REFERENCES collections(id) ON DELETE CASCADE,
  FOREIGN KEY (member_id) REFERENCES organization_members(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_collection_users_member ON collection_users(member_id);
CREATE TABLE IF NOT EXISTS collection_groups (
  collection_id TEXT NOT NULL, group_id TEXT NOT NULL, read_only INTEGER NOT NULL DEFAULT 0,
  hide_passwords INTEGER NOT NULL DEFAULT 0, manage INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (collection_id, group_id),
  FOREIGN KEY (collection_id) REFERENCES collections(id) ON DELETE CASCADE,
  FOREIGN KEY (group_id) REFERENCES organization_groups(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_collection_groups_group ON collection_groups(group_id);

CREATE TABLE IF NOT EXISTS ciphers (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  organization_id TEXT,
  type INTEGER NOT NULL,
  folder_id TEXT,
  name TEXT,
  notes TEXT,
  favorite INTEGER NOT NULL DEFAULT 0,
  data TEXT NOT NULL,
  reprompt INTEGER,
  key TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  archived_at TEXT,
  deleted_at TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
  CHECK ((user_id IS NOT NULL AND organization_id IS NULL) OR (user_id IS NULL AND organization_id IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_ciphers_user_updated ON ciphers(user_id, updated_at);
CREATE INDEX IF NOT EXISTS idx_ciphers_user_archived ON ciphers(user_id, archived_at);
CREATE INDEX IF NOT EXISTS idx_ciphers_user_deleted ON ciphers(user_id, deleted_at);
CREATE INDEX IF NOT EXISTS idx_ciphers_user_deleted_updated ON ciphers(user_id, deleted_at, updated_at);
CREATE INDEX IF NOT EXISTS idx_ciphers_user_folder ON ciphers(user_id, folder_id);

CREATE TABLE IF NOT EXISTS folders (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_folders_user_updated ON folders(user_id, updated_at);

CREATE TABLE IF NOT EXISTS attachments (
  id TEXT PRIMARY KEY,
  cipher_id TEXT NOT NULL,
  file_name TEXT NOT NULL,
  size INTEGER NOT NULL,
  size_name TEXT NOT NULL,
  key TEXT,
  FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_attachments_cipher ON attachments(cipher_id);
CREATE INDEX IF NOT EXISTS idx_ciphers_organization_updated ON ciphers(organization_id, updated_at);

CREATE TABLE IF NOT EXISTS cipher_collections (
  cipher_id TEXT NOT NULL, collection_id TEXT NOT NULL, PRIMARY KEY (cipher_id, collection_id),
  FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE,
  FOREIGN KEY (collection_id) REFERENCES collections(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_cipher_collections_collection ON cipher_collections(collection_id);
CREATE TABLE IF NOT EXISTS cipher_user_preferences (
  cipher_id TEXT NOT NULL, user_id TEXT NOT NULL, folder_id TEXT, favorite INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (cipher_id, user_id), FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_cipher_user_preferences_user ON cipher_user_preferences(user_id);
CREATE TABLE IF NOT EXISTS organization_events (
  id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, actor_user_id TEXT, type INTEGER NOT NULL, target_id TEXT, date TEXT NOT NULL, data TEXT,
  FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
  FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_organization_events_date ON organization_events(organization_id, date);

-- Links must share SQL organization ownership, including after parent updates.
CREATE TRIGGER IF NOT EXISTS organization_group_members_same_org_insert BEFORE INSERT ON organization_group_members
WHEN NOT EXISTS (SELECT 1 FROM organization_groups l JOIN organization_members r ON l.organization_id = r.organization_id WHERE l.id = NEW.group_id AND r.id = NEW.member_id)
BEGIN SELECT RAISE(ABORT, 'Cross-organization association'); END;
CREATE TRIGGER IF NOT EXISTS organization_group_members_same_org_update BEFORE UPDATE ON organization_group_members
WHEN NOT EXISTS (SELECT 1 FROM organization_groups l JOIN organization_members r ON l.organization_id = r.organization_id WHERE l.id = NEW.group_id AND r.id = NEW.member_id)
BEGIN SELECT RAISE(ABORT, 'Cross-organization association'); END;
CREATE TRIGGER IF NOT EXISTS organization_group_members_organization_groups_ownership_update BEFORE UPDATE OF organization_id ON organization_groups
WHEN EXISTS (SELECT 1 FROM organization_group_members link JOIN organization_members other ON other.id = link.member_id WHERE link.group_id = OLD.id AND other.organization_id IS NOT NEW.organization_id)
BEGIN SELECT RAISE(ABORT, 'Cross-organization association'); END;
CREATE TRIGGER IF NOT EXISTS organization_group_members_organization_members_ownership_update BEFORE UPDATE OF organization_id ON organization_members
WHEN EXISTS (SELECT 1 FROM organization_group_members link JOIN organization_groups other ON other.id = link.group_id WHERE link.member_id = OLD.id AND other.organization_id IS NOT NEW.organization_id)
BEGIN SELECT RAISE(ABORT, 'Cross-organization association'); END;

CREATE TRIGGER IF NOT EXISTS collection_users_same_org_insert BEFORE INSERT ON collection_users
WHEN NOT EXISTS (SELECT 1 FROM collections l JOIN organization_members r ON l.organization_id = r.organization_id WHERE l.id = NEW.collection_id AND r.id = NEW.member_id)
BEGIN SELECT RAISE(ABORT, 'Cross-organization association'); END;
CREATE TRIGGER IF NOT EXISTS collection_users_same_org_update BEFORE UPDATE ON collection_users
WHEN NOT EXISTS (SELECT 1 FROM collections l JOIN organization_members r ON l.organization_id = r.organization_id WHERE l.id = NEW.collection_id AND r.id = NEW.member_id)
BEGIN SELECT RAISE(ABORT, 'Cross-organization association'); END;
CREATE TRIGGER IF NOT EXISTS collection_users_collections_ownership_update BEFORE UPDATE OF organization_id ON collections
WHEN EXISTS (SELECT 1 FROM collection_users link JOIN organization_members other ON other.id = link.member_id WHERE link.collection_id = OLD.id AND other.organization_id IS NOT NEW.organization_id)
BEGIN SELECT RAISE(ABORT, 'Cross-organization association'); END;
CREATE TRIGGER IF NOT EXISTS collection_users_organization_members_ownership_update BEFORE UPDATE OF organization_id ON organization_members
WHEN EXISTS (SELECT 1 FROM collection_users link JOIN collections other ON other.id = link.collection_id WHERE link.member_id = OLD.id AND other.organization_id IS NOT NEW.organization_id)
BEGIN SELECT RAISE(ABORT, 'Cross-organization association'); END;

CREATE TRIGGER IF NOT EXISTS collection_groups_same_org_insert BEFORE INSERT ON collection_groups
WHEN NOT EXISTS (SELECT 1 FROM collections l JOIN organization_groups r ON l.organization_id = r.organization_id WHERE l.id = NEW.collection_id AND r.id = NEW.group_id)
BEGIN SELECT RAISE(ABORT, 'Cross-organization association'); END;
CREATE TRIGGER IF NOT EXISTS collection_groups_same_org_update BEFORE UPDATE ON collection_groups
WHEN NOT EXISTS (SELECT 1 FROM collections l JOIN organization_groups r ON l.organization_id = r.organization_id WHERE l.id = NEW.collection_id AND r.id = NEW.group_id)
BEGIN SELECT RAISE(ABORT, 'Cross-organization association'); END;
CREATE TRIGGER IF NOT EXISTS collection_groups_collections_ownership_update BEFORE UPDATE OF organization_id ON collections
WHEN EXISTS (SELECT 1 FROM collection_groups link JOIN organization_groups other ON other.id = link.group_id WHERE link.collection_id = OLD.id AND other.organization_id IS NOT NEW.organization_id)
BEGIN SELECT RAISE(ABORT, 'Cross-organization association'); END;
CREATE TRIGGER IF NOT EXISTS collection_groups_organization_groups_ownership_update BEFORE UPDATE OF organization_id ON organization_groups
WHEN EXISTS (SELECT 1 FROM collection_groups link JOIN collections other ON other.id = link.collection_id WHERE link.group_id = OLD.id AND other.organization_id IS NOT NEW.organization_id)
BEGIN SELECT RAISE(ABORT, 'Cross-organization association'); END;

CREATE TRIGGER IF NOT EXISTS cipher_collections_same_org_insert BEFORE INSERT ON cipher_collections
WHEN NOT EXISTS (SELECT 1 FROM ciphers l JOIN collections r ON l.organization_id = r.organization_id WHERE l.id = NEW.cipher_id AND r.id = NEW.collection_id)
BEGIN SELECT RAISE(ABORT, 'Cross-organization association'); END;
CREATE TRIGGER IF NOT EXISTS cipher_collections_same_org_update BEFORE UPDATE ON cipher_collections
WHEN NOT EXISTS (SELECT 1 FROM ciphers l JOIN collections r ON l.organization_id = r.organization_id WHERE l.id = NEW.cipher_id AND r.id = NEW.collection_id)
BEGIN SELECT RAISE(ABORT, 'Cross-organization association'); END;
CREATE TRIGGER IF NOT EXISTS cipher_collections_ciphers_ownership_update BEFORE UPDATE OF organization_id ON ciphers
WHEN EXISTS (SELECT 1 FROM cipher_collections link JOIN collections other ON other.id = link.collection_id WHERE link.cipher_id = OLD.id AND other.organization_id IS NOT NEW.organization_id)
BEGIN SELECT RAISE(ABORT, 'Cross-organization association'); END;
CREATE TRIGGER IF NOT EXISTS cipher_collections_collections_ownership_update BEFORE UPDATE OF organization_id ON collections
WHEN EXISTS (SELECT 1 FROM cipher_collections link JOIN ciphers other ON other.id = link.cipher_id WHERE link.collection_id = OLD.id AND other.organization_id IS NOT NEW.organization_id)
BEGIN SELECT RAISE(ABORT, 'Cross-organization association'); END;

CREATE TRIGGER IF NOT EXISTS cipher_user_preferences_folder_insert BEFORE INSERT ON cipher_user_preferences
WHEN NEW.folder_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM folders WHERE id = NEW.folder_id AND user_id = NEW.user_id)
BEGIN SELECT RAISE(ABORT, 'Cipher preference folder belongs to another user'); END;
CREATE TRIGGER IF NOT EXISTS cipher_user_preferences_folder_update BEFORE UPDATE ON cipher_user_preferences
WHEN NEW.folder_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM folders WHERE id = NEW.folder_id AND user_id = NEW.user_id)
BEGIN SELECT RAISE(ABORT, 'Cipher preference folder belongs to another user'); END;
CREATE TRIGGER IF NOT EXISTS cipher_user_preferences_folder_owner_update BEFORE UPDATE OF user_id ON folders
WHEN EXISTS (SELECT 1 FROM cipher_user_preferences WHERE folder_id = OLD.id AND user_id IS NOT NEW.user_id)
BEGIN SELECT RAISE(ABORT, 'Cipher preference folder belongs to another user'); END;

CREATE TABLE IF NOT EXISTS sends (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  type INTEGER NOT NULL,
  name TEXT NOT NULL,
  notes TEXT,
  data TEXT NOT NULL,
  key TEXT NOT NULL,
  password_hash TEXT,
  password_salt TEXT,
  password_iterations INTEGER,
  auth_type INTEGER NOT NULL DEFAULT 2,
  emails TEXT,
  max_access_count INTEGER,
  access_count INTEGER NOT NULL DEFAULT 0,
  disabled INTEGER NOT NULL DEFAULT 0,
  hide_email INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  expiration_date TEXT,
  deletion_date TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sends_user_updated ON sends(user_id, updated_at);
CREATE INDEX IF NOT EXISTS idx_sends_user_deletion ON sends(user_id, deletion_date);
CREATE INDEX IF NOT EXISTS idx_sends_user_updated_id ON sends(user_id, updated_at, id);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  device_identifier TEXT,
  device_session_stamp TEXT,
  security_stamp TEXT,
  created_at INTEGER,
  last_used_at INTEGER,
  absolute_expires_at INTEGER,
  client_type TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);

CREATE TABLE IF NOT EXISTS invites (
  code TEXT PRIMARY KEY,
  created_by TEXT NOT NULL,
  used_by TEXT,
  expires_at TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (used_by) REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_invites_status_expires ON invites(status, expires_at);
CREATE INDEX IF NOT EXISTS idx_invites_created_by ON invites(created_by, created_at);

CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  actor_user_id TEXT,
  action TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'system',
  level TEXT NOT NULL DEFAULT 'info',
  target_type TEXT,
  target_id TEXT,
  metadata TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_created ON audit_logs(actor_user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_category_created ON audit_logs(category, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_level_created ON audit_logs(level, created_at);

CREATE TABLE IF NOT EXISTS devices (
  user_id TEXT NOT NULL,
  device_identifier TEXT NOT NULL,
  name TEXT NOT NULL,
  type INTEGER NOT NULL,
  session_stamp TEXT,
  encrypted_user_key TEXT,
  encrypted_public_key TEXT,
  encrypted_private_key TEXT,
  push_uuid TEXT,
  push_token TEXT,
  banned INTEGER NOT NULL DEFAULT 0,
  banned_at TEXT,
  device_note TEXT,
  last_seen_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (user_id, device_identifier),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_devices_user_updated ON devices(user_id, updated_at);
CREATE INDEX IF NOT EXISTS idx_devices_user_last_seen ON devices(user_id, last_seen_at);
CREATE INDEX IF NOT EXISTS idx_devices_user_push ON devices(user_id, push_token);

CREATE TABLE IF NOT EXISTS auth_requests (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  organization_id TEXT,
  type INTEGER NOT NULL,
  request_device_identifier TEXT NOT NULL,
  request_device_type INTEGER NOT NULL,
  request_ip_address TEXT,
  request_country_name TEXT,
  response_device_identifier TEXT,
  access_code TEXT NOT NULL,
  public_key TEXT NOT NULL,
  key TEXT,
  master_password_hash TEXT,
  approved INTEGER,
  creation_date TEXT NOT NULL,
  response_date TEXT,
  authentication_date TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_auth_requests_user_created
  ON auth_requests(user_id, creation_date);
CREATE INDEX IF NOT EXISTS idx_auth_requests_user_pending
  ON auth_requests(user_id, approved, response_date, authentication_date, creation_date);
CREATE INDEX IF NOT EXISTS idx_auth_requests_device_pending
  ON auth_requests(user_id, request_device_identifier, creation_date);

CREATE TABLE IF NOT EXISTS trusted_two_factor_device_tokens (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  device_identifier TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_trusted_two_factor_device_tokens_user_device
  ON trusted_two_factor_device_tokens(user_id, device_identifier);

CREATE TABLE IF NOT EXISTS totp_login_replays (
  user_id TEXT NOT NULL,
  time_counter INTEGER NOT NULL,
  consumed_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, time_counter),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_totp_login_replays_consumed_at
  ON totp_login_replays(consumed_at);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  purpose TEXT NOT NULL DEFAULT 'login',
  name TEXT NOT NULL,
  public_key TEXT NOT NULL,
  credential_id TEXT NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  type TEXT,
  aa_guid TEXT,
  transports TEXT,
  encrypted_user_key TEXT,
  encrypted_public_key TEXT,
  encrypted_private_key TEXT,
  supports_prf INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_webauthn_credentials_credential_id
  ON webauthn_credentials(credential_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user
  ON webauthn_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_updated
  ON webauthn_credentials(user_id, updated_at);

CREATE TABLE IF NOT EXISTS webauthn_challenges (
  challenge_hash TEXT PRIMARY KEY,
  scope TEXT NOT NULL,
  user_id TEXT,
  expires_at INTEGER NOT NULL,
  used_at INTEGER,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_expires
  ON webauthn_challenges(expires_at);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_user_scope
  ON webauthn_challenges(user_id, scope);

-- Rate limiting
CREATE TABLE IF NOT EXISTS login_attempts_ip (
  ip TEXT PRIMARY KEY,
  attempts INTEGER NOT NULL,
  locked_until INTEGER,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS used_attachment_download_tokens (
  jti TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);
