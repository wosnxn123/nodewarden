import { parseErrorMessage, parseJson, type AuthedFetch } from './shared';

export interface AdminStorageSettings {
  object: 'storage-settings';
  currentProvider: 'r2' | 'kv' | 'microsoft_graph' | null;
  r2Configured: boolean;
  kvConfigured: boolean;
  microsoftGraph: {
    configured: boolean;
    provider: string;
    tenantId: string;
    clientId: string;
    driveId: string;
    rootPath: string;
    clientSecretConfigured: boolean;
    missing: string[];
  };
  notes: string[];
}

export interface AdminStorageTestResponse {
  object: 'storage-test';
  ok: boolean;
  provider: string | null;
  error?: string;
}

export async function getAdminStorageSettings(authedFetch: AuthedFetch): Promise<AdminStorageSettings> {
  const resp = await authedFetch('/api/admin/storage/settings', { method: 'GET' });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, '加载存储库设置失败'));
  const body = await parseJson<AdminStorageSettings>(resp);
  if (!body || body.object !== 'storage-settings') throw new Error('存储库设置响应无效');
  return body;
}

export async function testAdminStorage(authedFetch: AuthedFetch): Promise<AdminStorageTestResponse> {
  const resp = await authedFetch('/api/admin/storage/test', { method: 'POST' });
  const body = await parseJson<AdminStorageTestResponse>(resp);
  if (!resp.ok) {
    throw new Error(body?.error || await parseErrorMessage(resp, '存储库测试失败'));
  }
  if (!body || body.object !== 'storage-test') throw new Error('存储库测试响应无效');
  return body;
}
