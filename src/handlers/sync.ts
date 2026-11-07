import { Env, SyncResponse, CipherResponse, FolderResponse } from '../types';
import { StorageService } from '../services/storage';
import { errorResponse } from '../utils/response';
import {
  cipherToResponse,
  isCipherResponseSyncCompatible,
  shouldPreserveRepairableCipherUris,
} from './ciphers';
import { sendToResponse } from './sends';
import {
  getProfileOrganizations,
  listAccessibleCollections,
} from '../services/organization-access';
import {
  buildUserDecryptionCompat,
  buildUserDecryptionOptions,
} from '../utils/user-decryption';
import { buildDomainsResponse } from '../services/domain-rules';
import { buildWebAuthnPrfOption } from '../utils/account-passkeys';
import { buildProfileResponse } from '../utils/profile-response';

// Organization permissions are checked against D1 for each sync, rather than
// returning previously cached ciphertext after a member/collection is revoked.
export async function handleSync(
  request: Request,
  env: Env,
  userId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const url = new URL(request.url);
  const excludeDomains = /^(1|true|yes)$/i.test(
    url.searchParams.get('excludeDomains') || ''
  );
  const excludeSends = /^(1|true|yes)$/i.test(
    url.searchParams.get('excludeSends') || ''
  );
  const preserveRepairableUris = shouldPreserveRepairableCipherUris(request);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  const [
    ciphers,
    folders,
    sends,
    domainSettings,
    accountPasskeys,
    organizations,
    collections,
  ] = await Promise.all([
    storage.getAllCiphers(userId),
    storage.getAllFolders(userId),
    excludeSends ? Promise.resolve([]) : storage.getAllSends(userId),
    excludeDomains
      ? Promise.resolve(null)
      : storage.getUserDomainSettings(userId),
    storage.getAccountPasskeyCredentialsByUserId(userId),
    getProfileOrganizations(env.DB, userId),
    listAccessibleCollections(env.DB, userId),
  ]);
  const attachmentsByCipher = await storage.getAttachmentsByCipherIds(
    ciphers.map((cipher) => cipher.id)
  );
  const webAuthnPrfOptions = accountPasskeys
    .map(buildWebAuthnPrfOption)
    .filter((option): option is NonNullable<typeof option> => !!option);
  const userDecryptionOptions = buildUserDecryptionOptions(
    user,
    webAuthnPrfOptions[0] || null
  );
  const validFolderIds = new Set(folders.map((folder) => folder.id));
  const cipherResponses: CipherResponse[] = [];
  for (const cipher of ciphers) {
    const response = cipherToResponse(
      cipher,
      attachmentsByCipher.get(cipher.id) || [],
      { preserveRepairableUris, validFolderIds }
    );
    if (isCipherResponseSyncCompatible(response))
      cipherResponses.push(response);
  }
  const folderResponses: FolderResponse[] = folders.map((folder) => ({
    id: folder.id,
    name: folder.name,
    revisionDate: folder.updatedAt,
    creationDate: folder.createdAt,
    object: 'folder',
  }));
  const syncResponse: SyncResponse = {
    profile: buildProfileResponse(user, env, organizations),
    folders: folderResponses,
    collections,
    ciphers: cipherResponses,
    domains: excludeDomains
      ? null
      : buildDomainsResponse(
          domainSettings?.equivalentDomains || [],
          domainSettings?.customEquivalentDomains || [],
          domainSettings?.excludedGlobalEquivalentDomains || [],
          { omitExcludedGlobals: true }
        ),
    policies: [],
    policiesNew: [],
    sends: sends.map(sendToResponse),
    UserDecryption: {
      MasterPasswordUnlock: userDecryptionOptions.MasterPasswordUnlock,
      TrustedDeviceOption: null,
      KeyConnectorOption: null,
      WebAuthnPrfOption: webAuthnPrfOptions[0] || null,
      WebAuthnPrfOptions: webAuthnPrfOptions,
      V2UpgradeToken: null,
      Object: 'userDecryption',
    },
    UserDecryptionOptions: userDecryptionOptions,
    userDecryption: buildUserDecryptionCompat(
      user
    ) as SyncResponse['userDecryption'],
    object: 'sync',
  };
  return new Response(JSON.stringify(syncResponse), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
    },
  });
}
