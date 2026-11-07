import type { Env, User } from '../types';
import { AuthService } from '../services/auth';
import { getUserById } from '../services/storage-user-repo';
import {
  safeWriteAuditEvent,
  auditRequestMetadata,
} from '../services/audit-events';
import {
  changeAccountKdf,
  purgePersonalVault,
  deleteOwnAccount,
  type AccountKdfUpdate,
  type AccountBlobReference,
  type AccountSendReference,
} from '../services/account-lifecycle-repo';
import {
  deleteBlobObject,
  getAttachmentObjectKey,
  getSendFileObjectKey,
} from '../services/blob-store';
import {
  notifyUserLogout,
  notifyUserVaultSync,
} from '../durable/notifications-hub';
import { errorResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';

class LifecycleError extends Error {
  constructor(
    message: string,
    readonly status = 400
  ) {
    super(message);
  }
}
type Body = Record<string, unknown>;
function isBody(value: unknown): value is Body {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}
function field(body: Body, name: string): unknown {
  return body[name] ?? body[name[0].toUpperCase() + name.slice(1)];
}
function text(value: unknown, label: string, max = 1024): string {
  if (typeof value !== 'string' || !value.trim() || value.length > max)
    throw new LifecycleError(`${label} is required and must be a valid string`);
  return value.trim();
}
async function readBody(request: Request): Promise<Body> {
  const raw = await request.text();
  if (raw.length > 65536)
    throw new LifecycleError('Request body is too large', 413);
  let body: unknown;
  try {
    body = JSON.parse(raw);
  } catch {
    throw new LifecycleError('Invalid JSON');
  }
  if (!isBody(body)) throw new LifecycleError('Expected a JSON object');
  return body;
}
async function verifiedUser(
  env: Env,
  userId: string,
  body: Body
): Promise<User> {
  // Never use the access-token user cache as authority for destructive operations.
  const user = await getUserById(env.DB, userId);
  if (!user || user.status !== 'active')
    throw new LifecycleError('User not found or inactive', 401);
  const proof = text(
    field(body, 'masterPasswordHash') ?? field(body, 'currentPasswordHash'),
    'Current password hash'
  );
  if (
    !(await new AuthService(env).verifyPassword(
      proof,
      user.masterPasswordHash,
      user.email
    ))
  )
    throw new LifecycleError('Invalid password');
  return user;
}
function integer(
  value: unknown,
  name: string,
  min: number,
  max = 2147483647
): number {
  if (
    typeof value !== 'number' ||
    !Number.isInteger(value) ||
    value < min ||
    value > max
  )
    throw new LifecycleError(
      `${name} must be an integer between ${min} and ${max}`
    );
  return value;
}
function kdfSettings(
  body: Body
): Pick<AccountKdfUpdate, 'type' | 'iterations' | 'memory' | 'parallelism'> {
  const type = integer(
    field(body, 'kdfType') ?? field(body, 'kdf'),
    'KDF type',
    0,
    1
  ) as 0 | 1;
  const iterations = integer(
    field(body, 'iterations') ?? field(body, 'kdfIterations'),
    'KDF iterations',
    type === 0 ? 100000 : 1
  );
  if (type === 0) {
    if (
      (field(body, 'memory') ?? field(body, 'kdfMemory')) != null ||
      (field(body, 'parallelism') ?? field(body, 'kdfParallelism')) != null
    ) {
      throw new LifecycleError(
        'PBKDF2 does not use memory or parallelism parameters'
      );
    }
    return { type, iterations, memory: null, parallelism: null };
  }
  // Vaultwarden 1.37.5: Argon2id memory 15..1024 MiB and parallelism 1..16.
  return {
    type,
    iterations,
    memory: integer(
      field(body, 'memory') ?? field(body, 'kdfMemory'),
      'Argon2id memory',
      15,
      1024
    ),
    parallelism: integer(
      field(body, 'parallelism') ?? field(body, 'kdfParallelism'),
      'Argon2id parallelism',
      1,
      16
    ),
  };
}
function base64Bytes(value: string): number {
  if (
    !value ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      value
    )
  )
    return -1;
  try {
    const decoded = atob(value);
    return btoa(decoded) === value ? decoded.length : -1;
  } catch {
    return -1;
  }
}
function wrappedUserKey(value: unknown): string {
  const key = text(value, 'Rewrapped user key', 8192);
  const match = /^([02])\.(.+)$/.exec(key);
  if (!match)
    throw new LifecycleError(
      'Rewrapped user key is not a supported encrypted string'
    );
  const pieces = match[2].split('|');
  const ciphertextBytes = base64Bytes(pieces[1] || '');
  if (
    pieces.length !== (match[1] === '2' ? 3 : 2) ||
    base64Bytes(pieces[0]) !== 16 ||
    ciphertextBytes <= 0 ||
    ciphertextBytes % 16 !== 0 ||
    (match[1] === '2' && base64Bytes(pieces[2]) !== 32)
  )
    throw new LifecycleError(
      'Rewrapped user key is not a valid encrypted string'
    );
  return key;
}
function newKdfData(
  body: Body,
  user: User
): Omit<AccountKdfUpdate, 'securityStamp' | 'revisionDate' | 'verifier'> & {
  newHash: string;
} {
  const authentication = field(body, 'authenticationData');
  const unlock = field(body, 'unlockData');
  if (authentication !== undefined || unlock !== undefined) {
    if (!isBody(authentication) || !isBody(unlock))
      throw new LifecycleError(
        'authenticationData and unlockData must be provided together'
      );
    const authenticationKdf = field(authentication, 'kdf');
    const unlockKdf = field(unlock, 'kdf');
    if (!isBody(authenticationKdf) || !isBody(unlockKdf))
      throw new LifecycleError(
        'authenticationData and unlockData must include KDF settings'
      );
    const settings = kdfSettings(authenticationKdf);
    if (JSON.stringify(settings) !== JSON.stringify(kdfSettings(unlockKdf)))
      throw new LifecycleError(
        'authenticationData and unlockData must use the same KDF settings'
      );
    const salt = user.email.trim().toLowerCase();
    if (
      field(authentication, 'salt') !== salt ||
      field(unlock, 'salt') !== salt
    )
      throw new LifecycleError('Invalid master password salt');
    return {
      ...settings,
      newHash: text(
        field(authentication, 'masterPasswordAuthenticationHash'),
        'New master password hash'
      ),
      key: wrappedUserKey(field(unlock, 'masterKeyWrappedUserKey')),
    };
  }
  return {
    ...kdfSettings(body),
    newHash: text(
      field(body, 'newMasterPasswordHash'),
      'New master password hash'
    ),
    key: wrappedUserKey(field(body, 'key') ?? field(body, 'newKey')),
  };
}
async function audit(
  env: Env,
  request: Request,
  userId: string,
  action: string,
  deleted = false
): Promise<void> {
  await safeWriteAuditEvent(env, {
    actorUserId: deleted ? null : userId,
    action,
    category: 'security',
    level: 'security',
    targetType: 'user',
    targetId: userId,
    metadata: auditRequestMetadata(request),
  });
}
async function cleanupBlobs(
  env: Env,
  attachments: AccountBlobReference[],
  sends: AccountSendReference[] = []
): Promise<void> {
  // Metadata was captured in the successful deletion transaction. Failure here
  // may leave inaccessible orphan blobs, never partially restore deleted records.
  const keys = attachments.map((row) =>
    getAttachmentObjectKey(row.cipher_id, row.id)
  );
  for (const send of sends) {
    try {
      const data: unknown = JSON.parse(send.data);
      if (
        isBody(data) &&
        typeof data.id === 'string' &&
        /^[A-Za-z0-9_-]{1,128}$/.test(data.id)
      )
        keys.push(getSendFileObjectKey(send.id, data.id));
    } catch {
      /* Opaque or malformed Send metadata is not authority for another blob. */
    }
  }
  for (const key of keys) {
    try {
      await deleteBlobObject(env, key);
    } catch {
      console.warn('Account lifecycle blob cleanup deferred');
    }
  }
}

// POST/PUT /api/accounts/kdf. Client rewraps the existing user key; no server decryption.
export async function handleChangeKdf(
  request: Request,
  env: Env,
  userId: string
): Promise<Response> {
  try {
    const body = await readBody(request);
    const user = await verifiedUser(env, userId, body);
    const next = newKdfData(body, user);
    const auth = new AuthService(env);
    const changed = await changeAccountKdf(env.DB, user, {
      ...next,
      verifier: await auth.hashPasswordServer(next.newHash),
      securityStamp: generateUUID(),
      revisionDate: new Date().toISOString(),
    });
    if (!changed)
      throw new LifecycleError(
        'Account changed during verification; retry with current credentials',
        409
      );
    AuthService.invalidateUserCache(user.id);
    notifyUserLogout(env, user.id);
    await audit(env, request, user.id, 'user.kdf.change');
    return new Response(null, { status: 200 });
  } catch (error) {
    if (error instanceof LifecycleError)
      return errorResponse(error.message, error.status);
    throw error;
  }
}

// POST /api/ciphers/purge. Does not touch organization items, memberships or Sends.
export async function handlePurgeVault(
  request: Request,
  env: Env,
  userId: string
): Promise<Response> {
  try {
    const body = await readBody(request);
    const user = await verifiedUser(env, userId, body);
    const result = await purgePersonalVault(
      env.DB,
      user,
      new Date().toISOString()
    );
    if (!result.changed)
      throw new LifecycleError(
        'Account changed during verification; retry with current credentials',
        409
      );
    AuthService.invalidateUserCache(user.id);
    notifyUserVaultSync(
      env,
      user.id,
      result.revisionDate,
      request.headers.get('X-Context-Id')
    );
    await cleanupBlobs(env, result.attachments);
    await audit(env, request, user.id, 'user.vault.purge');
    return new Response(null, { status: 200 });
  } catch (error) {
    if (error instanceof LifecycleError)
      return errorResponse(error.message, error.status);
    throw error;
  }
}

// POST /api/accounts/delete and DELETE /api/accounts (aliases integrated by router).
export async function handleDeleteAccount(
  request: Request,
  env: Env,
  userId: string
): Promise<Response> {
  try {
    const body = await readBody(request);
    const user = await verifiedUser(env, userId, body);
    const result = await deleteOwnAccount(env.DB, user);
    if (!result.changed) {
      if (result.reason === 'last-owner')
        throw new LifecycleError(
          'Cannot delete the last confirmed organization owner',
          409
        );
      if (result.reason === 'last-admin')
        throw new LifecycleError(
          'Cannot delete the last active administrator while other users remain',
          409
        );
      throw new LifecycleError(
        'Account changed during verification; retry with current credentials',
        409
      );
    }
    AuthService.invalidateUserCache(user.id);
    notifyUserLogout(env, user.id);
    await cleanupBlobs(env, result.attachments, result.sends);
    await audit(env, request, user.id, 'user.account.delete', true);
    return new Response(null, { status: 200 });
  } catch (error) {
    if (error instanceof LifecycleError)
      return errorResponse(error.message, error.status);
    throw error;
  }
}
