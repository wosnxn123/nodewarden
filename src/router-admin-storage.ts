import type { Env, User } from './types';
import { deleteBlobObject, getBlobObject, getBlobStorageKind, putBlobObject } from './services/blob-store';

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function envString(env: Env, ...names: string[]): string {
  const record = env as unknown as Record<string, unknown>;
  for (const name of names) {
    const value = String(record[name] || '').trim();
    if (value) return value;
  }
  return '';
}

function mask(value: string): string {
  const text = String(value || '').trim();
  if (!text) return '';
  if (text.length <= 8) return `${text.slice(0, 2)}***${text.slice(-2)}`;
  return `${text.slice(0, 4)}***${text.slice(-4)}`;
}

function graphSettings(env: Env) {
  const tenantId = envString(env, 'MICROSOFT_GRAPH_TENANT_ID', 'GRAPH_TENANT_ID', 'M365_GRAPH_TENANT_ID');
  const clientId = envString(env, 'MICROSOFT_GRAPH_CLIENT_ID', 'GRAPH_CLIENT_ID', 'M365_GRAPH_CLIENT_ID');
  const clientSecret = envString(env, 'MICROSOFT_GRAPH_CLIENT_SECRET', 'GRAPH_CLIENT_SECRET', 'M365_GRAPH_CLIENT_SECRET');
  const driveId = envString(env, 'MICROSOFT_GRAPH_DRIVE_ID', 'GRAPH_DRIVE_ID', 'M365_GRAPH_DRIVE_ID');
  const rootPath = envString(env, 'MICROSOFT_GRAPH_ROOT_PATH', 'GRAPH_ROOT_PATH', 'M365_GRAPH_ROOT_PATH') || 'nodewarden';
  const provider = envString(env, 'STORAGE_PROVIDER', 'ATTACHMENT_STORAGE_PROVIDER', 'BLOB_STORAGE_PROVIDER');
  return {
    configured: !!(tenantId && clientId && clientSecret && driveId),
    provider,
    tenantId: mask(tenantId),
    clientId: mask(clientId),
    driveId: mask(driveId),
    rootPath,
    clientSecretConfigured: !!clientSecret,
    missing: [
      tenantId ? '' : 'MICROSOFT_GRAPH_TENANT_ID',
      clientId ? '' : 'MICROSOFT_GRAPH_CLIENT_ID',
      clientSecret ? '' : 'MICROSOFT_GRAPH_CLIENT_SECRET',
      driveId ? '' : 'MICROSOFT_GRAPH_DRIVE_ID',
    ].filter(Boolean),
  };
}

export async function handleAdminStorageRoute(
  request: Request,
  env: Env,
  actorUser: User,
  path: string,
  method: string
): Promise<Response | null> {
  if (path === '/api/admin/storage/settings' && method === 'GET') {
    const current = getBlobStorageKind(env);
    return json({
      object: 'storage-settings',
      currentProvider: current,
      r2Configured: !!env.ATTACHMENTS,
      kvConfigured: !!env.ATTACHMENTS_KV,
      microsoftGraph: graphSettings(env),
      notes: [
        '数据库仍使用 Cloudflare D1；这里控制的是附件和文件 Send 的对象存储。',
        '要启用 Microsoft 365，请设置 STORAGE_PROVIDER=microsoft_graph 并配置 Microsoft Graph 环境变量。',
      ],
      actorUserId: actorUser.id,
    });
  }

  if (path === '/api/admin/storage/test' && method === 'POST') {
    const provider = getBlobStorageKind(env);
    if (!provider) return json({ error: 'Attachment storage is not configured' }, 400);

    const key = `__nodewarden_storage_test__/${crypto.randomUUID()}.txt`;
    const content = `NodeWarden storage test ${new Date().toISOString()}`;
    const bytes = new TextEncoder().encode(content);
    try {
      await putBlobObject(env, key, bytes, {
        size: bytes.byteLength,
        contentType: 'text/plain; charset=utf-8',
      });
      const object = await getBlobObject(env, key);
      const readText = object?.body ? await new Response(object.body).text() : '';
      await deleteBlobObject(env, key);
      if (readText !== content) {
        return json({ object: 'storage-test', ok: false, provider, error: 'Roundtrip content mismatch' }, 500);
      }
      return json({ object: 'storage-test', ok: true, provider });
    } catch (error) {
      try { await deleteBlobObject(env, key); } catch { /* ignore cleanup failure */ }
      return json({
        object: 'storage-test',
        ok: false,
        provider,
        error: error instanceof Error ? error.message : String(error),
      }, 500);
    }
  }

  return null;
}
