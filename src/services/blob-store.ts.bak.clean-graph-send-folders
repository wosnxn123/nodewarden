import { Env } from '../types';

const DEFAULT_CONTENT_TYPE = 'application/octet-stream';
const GRAPH_BASE_URL = 'https://graph.microsoft.com/v1.0';
const GRAPH_TOKEN_EARLY_REFRESH_MS = 60_000;
const GRAPH_DIRECT_UPLOAD_LIMIT_BYTES = 250 * 1024 * 1024;
const GRAPH_UPLOAD_CHUNK_BYTES = 10 * 1024 * 1024;

export const KV_MAX_OBJECT_BYTES = 25 * 1024 * 1024;

interface KVBlobMetadata {
  size?: number;
  contentType?: string;
  customMetadata?: Record<string, string> | null;
}

export interface BlobObject {
  body: ReadableStream | null;
  size: number;
  contentType: string;
}

export interface PutBlobOptions {
  size: number;
  contentType?: string;
  customMetadata?: Record<string, string>;
}

type BlobStorageKind = 'r2' | 'kv' | 'microsoft_graph';

interface GraphConfig {
  tenantId: string;
  clientId: string;
  clientSecret: string;
  driveId: string;
  rootPath: string;
}

interface GraphTokenCacheEntry {
  accessToken: string;
  expiresAt: number;
}

const graphTokenCache = new Map<string, GraphTokenCacheEntry>();

function hasR2Storage(env: Env): env is Env & { ATTACHMENTS: R2Bucket } {
  return !!env.ATTACHMENTS;
}

function hasKvStorage(env: Env): env is Env & { ATTACHMENTS_KV: KVNamespace } {
  return !!env.ATTACHMENTS_KV;
}

function envString(env: Env, ...names: string[]): string {
  const record = env as unknown as Record<string, unknown>;
  for (const name of names) {
    const value = String(record[name] || '').trim();
    if (value) return value;
  }
  return '';
}

function requestedStorageProvider(env: Env): string {
  return envString(env, 'STORAGE_PROVIDER', 'ATTACHMENT_STORAGE_PROVIDER', 'BLOB_STORAGE_PROVIDER').toLowerCase();
}

function getGraphConfig(env: Env): GraphConfig | null {
  const tenantId = envString(env, 'MICROSOFT_GRAPH_TENANT_ID', 'GRAPH_TENANT_ID', 'M365_GRAPH_TENANT_ID');
  const clientId = envString(env, 'MICROSOFT_GRAPH_CLIENT_ID', 'GRAPH_CLIENT_ID', 'M365_GRAPH_CLIENT_ID');
  const clientSecret = envString(env, 'MICROSOFT_GRAPH_CLIENT_SECRET', 'GRAPH_CLIENT_SECRET', 'M365_GRAPH_CLIENT_SECRET');
  const driveId = envString(env, 'MICROSOFT_GRAPH_DRIVE_ID', 'GRAPH_DRIVE_ID', 'M365_GRAPH_DRIVE_ID');
  const rootPath = envString(env, 'MICROSOFT_GRAPH_ROOT_PATH', 'GRAPH_ROOT_PATH', 'M365_GRAPH_ROOT_PATH') || 'nodewarden';
  if (!tenantId || !clientId || !clientSecret || !driveId) return null;
  return { tenantId, clientId, clientSecret, driveId, rootPath };
}

function hasGraphStorage(env: Env): boolean {
  return !!getGraphConfig(env);
}

function wantsGraphStorage(env: Env): boolean {
  const provider = requestedStorageProvider(env);
  return provider === 'graph' || provider === 'microsoft_graph' || provider === 'm365' || provider === 'microsoft365' || provider === 'onedrive' || provider === 'sharepoint';
}

function normalizeRootSegments(rootPath: string): string[] {
  return String(rootPath || 'nodewarden')
    .replace(/^\/+|\/+$/g, '')
    .split('/')
    .map((part) => part.trim())
    .filter(Boolean);
}

function normalizeObjectKeySegments(key: string): string[] {
  return String(key || '')
    .replace(/^\/+|\/+$/g, '')
    .split('/')
    .map((part) => part.trim())
    .filter(Boolean);
}

function graphObjectSegments(config: GraphConfig, key: string): string[] {
  return [...normalizeRootSegments(config.rootPath), ...normalizeObjectKeySegments(key)];
}

function encodeGraphSegment(segment: string): string {
  return encodeURIComponent(segment).replace(/[!'()*]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);
}

function graphPathFromSegments(segments: string[]): string {
  return segments.map(encodeGraphSegment).join('/');
}

function graphDrivePath(config: GraphConfig, suffix: string): string {
  return `/drives/${encodeURIComponent(config.driveId)}${suffix}`;
}

async function getGraphAccessToken(config: GraphConfig): Promise<string> {
  const cacheKey = `${config.tenantId}\u0000${config.clientId}`;
  const cached = graphTokenCache.get(cacheKey);
  const now = Date.now();
  if (cached && cached.expiresAt - GRAPH_TOKEN_EARLY_REFRESH_MS > now) {
    return cached.accessToken;
  }

  const body = new URLSearchParams();
  body.set('client_id', config.clientId);
  body.set('client_secret', config.clientSecret);
  body.set('scope', 'https://graph.microsoft.com/.default');
  body.set('grant_type', 'client_credentials');

  const response = await fetch(`https://login.microsoftonline.com/${encodeURIComponent(config.tenantId)}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  const text = await response.text();
  let json: any = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }

  if (!response.ok || !json?.access_token) {
    const message = json?.error_description || json?.error || text || `HTTP ${response.status}`;
    throw new Error(`Microsoft Graph token request failed: ${message}`);
  }

  const expiresIn = Math.max(60, Number(json.expires_in || 3600));
  graphTokenCache.set(cacheKey, {
    accessToken: String(json.access_token),
    expiresAt: now + expiresIn * 1000,
  });
  return String(json.access_token);
}

async function graphFetch(env: Env, suffix: string, init: RequestInit = {}, okStatuses: number[] = [200]): Promise<Response> {
  const config = getGraphConfig(env);
  if (!config) throw new Error('Microsoft Graph storage is not configured');
  const token = await getGraphAccessToken(config);
  const headers = new Headers(init.headers || {});
  headers.set('Authorization', `Bearer ${token}`);
  const response = await fetch(`${GRAPH_BASE_URL}${suffix}`, { ...init, headers });
  if (!okStatuses.includes(response.status)) {
    const text = await response.text().catch(() => '');
    throw new Error(`Microsoft Graph request failed: HTTP ${response.status}${text ? ` ${text}` : ''}`);
  }
  return response;
}

async function graphFetchMaybe(env: Env, suffix: string, init: RequestInit = {}): Promise<Response | null> {
  const config = getGraphConfig(env);
  if (!config) throw new Error('Microsoft Graph storage is not configured');
  const token = await getGraphAccessToken(config);
  const headers = new Headers(init.headers || {});
  headers.set('Authorization', `Bearer ${token}`);
  const response = await fetch(`${GRAPH_BASE_URL}${suffix}`, { ...init, headers });
  if (response.status === 404) return null;
  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(`Microsoft Graph request failed: HTTP ${response.status}${text ? ` ${text}` : ''}`);
  }
  return response;
}

async function graphGetMetadata(env: Env, config: GraphConfig, segments: string[]): Promise<any | null> {
  if (!segments.length) {
    const response = await graphFetch(env, graphDrivePath(config, '/root'), {}, [200]);
    return response.json();
  }
  const response = await graphFetchMaybe(env, graphDrivePath(config, `/root:/${graphPathFromSegments(segments)}`));
  if (!response) return null;
  return response.json();
}

async function ensureGraphFolders(env: Env, config: GraphConfig, folderSegments: string[]): Promise<void> {
  const current: string[] = [];
  for (const segment of folderSegments) {
    current.push(segment);
    const existing = await graphGetMetadata(env, config, current);
    if (existing?.folder) continue;
    if (existing && !existing.folder) {
      throw new Error(`Microsoft Graph path exists but is not a folder: ${current.join('/')}`);
    }
    const parent = current.slice(0, -1);
    const parentSuffix = parent.length
      ? graphDrivePath(config, `/root:/${graphPathFromSegments(parent)}:/children`)
      : graphDrivePath(config, '/root/children');
    const response = await graphFetch(env, parentSuffix, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: segment,
        folder: {},
        '@microsoft.graph.conflictBehavior': 'fail',
      }),
    }, [200, 201, 409]);
    if (response.status === 409) continue;
  }
}

async function valueToArrayBuffer(value: string | ArrayBuffer | ArrayBufferView | ReadableStream): Promise<ArrayBuffer> {
  if (typeof value === 'string') return new TextEncoder().encode(value).buffer;
  if (value instanceof ArrayBuffer) return value;
  if (ArrayBuffer.isView(value)) {
    return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength);
  }
  return new Response(value).arrayBuffer();
}

async function uploadGraphLarge(env: Env, config: GraphConfig, segments: string[], value: string | ArrayBuffer | ArrayBufferView | ReadableStream, contentType: string): Promise<void> {
  const path = graphPathFromSegments(segments);
  const fileName = segments[segments.length - 1] || 'blob.bin';
  const sessionResponse = await graphFetch(env, graphDrivePath(config, `/root:/${path}:/createUploadSession`), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      item: {
        name: fileName,
        '@microsoft.graph.conflictBehavior': 'replace',
      },
    }),
  }, [200, 201]);
  const session = await sessionResponse.json() as { uploadUrl?: string };
  if (!session.uploadUrl) throw new Error('Microsoft Graph did not return an uploadUrl');

  const buffer = await valueToArrayBuffer(value);
  const total = buffer.byteLength;
  for (let start = 0; start < total; start += GRAPH_UPLOAD_CHUNK_BYTES) {
    const endExclusive = Math.min(total, start + GRAPH_UPLOAD_CHUNK_BYTES);
    const chunk = buffer.slice(start, endExclusive);
    const response = await fetch(session.uploadUrl, {
      method: 'PUT',
      headers: {
        'Content-Length': String(chunk.byteLength),
        'Content-Range': `bytes ${start}-${endExclusive - 1}/${total}`,
        'Content-Type': contentType,
      },
      body: chunk,
    });
    if (![200, 201, 202].includes(response.status)) {
      const text = await response.text().catch(() => '');
      throw new Error(`Microsoft Graph chunk upload failed: HTTP ${response.status}${text ? ` ${text}` : ''}`);
    }
  }
}

async function putGraphObject(env: Env, key: string, value: string | ArrayBuffer | ArrayBufferView | ReadableStream, options: PutBlobOptions): Promise<void> {
  const config = getGraphConfig(env);
  if (!config) throw new Error('Microsoft Graph storage is not configured');
  const contentType = options.contentType || DEFAULT_CONTENT_TYPE;
  const segments = graphObjectSegments(config, key);
  if (!segments.length) throw new Error('Invalid Microsoft Graph object key');
  await ensureGraphFolders(env, config, segments.slice(0, -1));

  if (options.size > GRAPH_DIRECT_UPLOAD_LIMIT_BYTES) {
    await uploadGraphLarge(env, config, segments, value, contentType);
    return;
  }

  await graphFetch(env, graphDrivePath(config, `/root:/${graphPathFromSegments(segments)}:/content`), {
    method: 'PUT',
    headers: { 'Content-Type': contentType },
    body: value as any,
  }, [200, 201]);
}

async function getGraphObject(env: Env, key: string): Promise<BlobObject | null> {
  const config = getGraphConfig(env);
  if (!config) throw new Error('Microsoft Graph storage is not configured');
  const segments = graphObjectSegments(config, key);
  if (!segments.length) return null;
  const metadata = await graphGetMetadata(env, config, segments);
  if (!metadata) return null;
  const response = await graphFetchMaybe(env, graphDrivePath(config, `/root:/${graphPathFromSegments(segments)}:/content`));
  if (!response) return null;
  return {
    body: response.body,
    size: Number(metadata.size || response.headers.get('Content-Length') || 0) || 0,
    contentType: String(metadata.file?.mimeType || response.headers.get('Content-Type') || DEFAULT_CONTENT_TYPE),
  };
}

async function deleteGraphObject(env: Env, key: string): Promise<void> {
  const config = getGraphConfig(env);
  if (!config) throw new Error('Microsoft Graph storage is not configured');
  const segments = graphObjectSegments(config, key);
  if (!segments.length) return;
  await graphFetchMaybe(env, graphDrivePath(config, `/root:/${graphPathFromSegments(segments)}`), { method: 'DELETE' });
}

export function getBlobStorageKind(env: Env): BlobStorageKind | null {
  const requested = requestedStorageProvider(env);

  if (wantsGraphStorage(env)) {
    return hasGraphStorage(env) ? 'microsoft_graph' : null;
  }
  if (requested === 'r2') return hasR2Storage(env) ? 'r2' : null;
  if (requested === 'kv') return hasKvStorage(env) ? 'kv' : null;

  // Keep R2 as preferred backend when both are bound.
  if (hasR2Storage(env)) return 'r2';
  if (hasKvStorage(env)) return 'kv';
  if (hasGraphStorage(env)) return 'microsoft_graph';
  return null;
}

export function getBlobStorageMaxBytes(env: Env, configuredLimit: number): number {
  if (getBlobStorageKind(env) === 'kv') {
    return Math.min(configuredLimit, KV_MAX_OBJECT_BYTES);
  }
  return configuredLimit;
}

export function getAttachmentObjectKey(cipherId: string, attachmentId: string): string {
  return `${cipherId}/${attachmentId}`;
}

export function getSendFileObjectKey(sendId: string, fileId: string): string {
  return `sends/${sendId}/${fileId}`;
}

export async function putBlobObject(
  env: Env,
  key: string,
  value: string | ArrayBuffer | ArrayBufferView | ReadableStream,
  options: PutBlobOptions
): Promise<void> {
  const contentType = options.contentType || DEFAULT_CONTENT_TYPE;
  const kind = getBlobStorageKind(env);

  if (kind === 'microsoft_graph') {
    await putGraphObject(env, key, value, { ...options, contentType });
    return;
  }

  if (kind === 'r2' && hasR2Storage(env)) {
    await env.ATTACHMENTS.put(key, value, {
      httpMetadata: { contentType },
      customMetadata: options.customMetadata,
    });
    return;
  }

  if (kind === 'kv' && hasKvStorage(env)) {
    if (options.size > KV_MAX_OBJECT_BYTES) {
      throw new Error('KV object too large');
    }
    const metadata: KVBlobMetadata = {
      size: options.size,
      contentType,
      customMetadata: options.customMetadata || null,
    };
    await env.ATTACHMENTS_KV.put(key, value, { metadata });
    return;
  }

  throw new Error('Attachment storage is not configured');
}

export async function getBlobObject(env: Env, key: string): Promise<BlobObject | null> {
  const kind = getBlobStorageKind(env);

  if (kind === 'microsoft_graph') {
    return getGraphObject(env, key);
  }

  if (kind === 'r2' && hasR2Storage(env)) {
    const object = await env.ATTACHMENTS.get(key);
    if (!object) return null;
    return {
      body: object.body,
      size: Number(object.size) || 0,
      contentType: object.httpMetadata?.contentType || DEFAULT_CONTENT_TYPE,
    };
  }

  if (kind === 'kv' && hasKvStorage(env)) {
    const result = await env.ATTACHMENTS_KV.getWithMetadata<KVBlobMetadata>(key, 'arrayBuffer');
    if (!result.value) return null;
    const sizeFromMeta = Number(result.metadata?.size || 0);
    const size = sizeFromMeta > 0 ? sizeFromMeta : result.value.byteLength;
    const body = new Response(result.value).body;
    return {
      body,
      size,
      contentType: result.metadata?.contentType || DEFAULT_CONTENT_TYPE,
    };
  }

  return null;
}

export async function deleteBlobObject(env: Env, key: string): Promise<void> {
  const kind = getBlobStorageKind(env);

  if (kind === 'microsoft_graph') {
    await deleteGraphObject(env, key);
    return;
  }

  if (kind === 'r2' && hasR2Storage(env)) {
    await env.ATTACHMENTS.delete(key);
    return;
  }

  if (kind === 'kv' && hasKvStorage(env)) {
    await env.ATTACHMENTS_KV.delete(key);
    return;
  }
}
