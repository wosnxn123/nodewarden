import { useEffect, useState } from 'preact/hooks';
import { AlertTriangle, CheckCircle2, Cloud, Copy, Database, HardDrive, KeyRound, RefreshCw, ShieldCheck } from 'lucide-preact';
import { getAdminStorageSettings, testAdminStorage, type AdminStorageSettings } from '@/lib/api/storage';
import type { AuthedFetch } from '@/lib/api/shared';

interface StorageSettingsPageProps {
  authedFetch: AuthedFetch;
  onNotify?: (type: 'success' | 'error' | 'warning', text: string) => void;
}

type NotifyType = NonNullable<StorageSettingsPageProps['onNotify']>;

const setupCommands = `npx wrangler secret put STORAGE_PROVIDER                 # microsoft_graph
npx wrangler secret put MICROSOFT_GRAPH_TENANT_ID
npx wrangler secret put MICROSOFT_GRAPH_CLIENT_ID
npx wrangler secret put MICROSOFT_GRAPH_CLIENT_SECRET
npx wrangler secret put MICROSOFT_GRAPH_DRIVE_ID
npx wrangler secret put MICROSOFT_GRAPH_ROOT_PATH          # 例如 nodewarden`;

function providerLabel(provider: string | null | undefined): string {
  if (provider === 'r2') return 'Cloudflare R2';
  if (provider === 'kv') return 'Cloudflare KV';
  if (provider === 'microsoft_graph') return 'Microsoft 365 / Graph Drive';
  return '未配置';
}

function displayValue(value: string | null | undefined, fallback = '未设置'): string {
  const text = String(value || '').trim();
  return text || fallback;
}

function maskMiddle(value: string | null | undefined): string {
  const text = String(value || '').trim();
  if (!text) return '未设置';
  if (text.length <= 14) return text;
  return `${text.slice(0, 8)}…${text.slice(-6)}`;
}

function StatusPill(props: { ok: boolean; label: string; value?: string }) {
  const Icon = props.ok ? CheckCircle2 : AlertTriangle;
  return (
    <div className={`storage-pill ${props.ok ? 'ok' : 'warn'}`}>
      <Icon size={16} />
      <span>{props.label}</span>
      {props.value && <strong>{props.value}</strong>}
    </div>
  );
}

function InfoRow(props: { label: string; value: string; secret?: boolean }) {
  return (
    <div className="storage-info-row">
      <span>{props.label}</span>
      <strong className={props.secret ? 'secret' : ''}>{props.value}</strong>
    </div>
  );
}

function copyCommands(onNotify?: NotifyType) {
  const clipboard = globalThis.navigator?.clipboard;
  if (!clipboard) {
    onNotify?.('warning', '当前浏览器不支持自动复制，请手动复制命令。');
    return;
  }
  void clipboard.writeText(setupCommands).then(
    () => onNotify?.('success', 'Wrangler 命令已复制'),
    () => onNotify?.('warning', '复制失败，请手动复制命令。'),
  );
}

const pageCss = `
.storage-polish {
  --nw-page-text: #182235;
  --nw-page-muted: #60728f;
  --nw-surface: #ffffff;
  --nw-surface-2: #f8fbff;
  --nw-surface-3: #eef4ff;
  --nw-border: rgba(148, 163, 184, .34);
  --nw-shadow: 0 14px 34px rgba(15, 23, 42, .08);
  --nw-blue: #2563eb;
  --nw-blue-soft: rgba(37, 99, 235, .10);
  --nw-green: #059669;
  --nw-amber: #d97706;
  display: grid;
  gap: 18px;
  padding-bottom: 28px;
  color: var(--nw-page-text);
}

html.dark .storage-polish,
body.dark .storage-polish,
.dark .storage-polish,
html[data-theme="dark"] .storage-polish,
body[data-theme="dark"] .storage-polish,
[data-theme="dark"] .storage-polish,
html[data-color-scheme="dark"] .storage-polish,
body[data-color-scheme="dark"] .storage-polish,
html[data-mode="dark"] .storage-polish,
body[data-mode="dark"] .storage-polish {
  --nw-page-text: #e7eefc;
  --nw-page-muted: #9fb1cf;
  --nw-surface: rgba(15, 23, 42, .72);
  --nw-surface-2: rgba(30, 41, 59, .58);
  --nw-surface-3: rgba(15, 23, 42, .50);
  --nw-border: rgba(148, 163, 184, .22);
  --nw-shadow: 0 20px 55px rgba(2, 6, 23, .22);
  --nw-blue: #7db0ff;
  --nw-blue-soft: rgba(59, 130, 246, .16);
  --nw-green: #86efac;
  --nw-amber: #fcd34d;
}

.storage-polish * { box-sizing: border-box; }

.storage-hero,
.storage-panel,
.storage-card {
  border: 1px solid var(--nw-border);
  background: var(--nw-surface);
  box-shadow: var(--nw-shadow);
}

.storage-hero {
  border-radius: 22px;
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 22px;
  padding: 26px;
}

.storage-title {
  display: flex;
  gap: 16px;
  align-items: flex-start;
  min-width: 0;
}

.storage-title-icon,
.storage-provider-icon {
  border: 1px solid color-mix(in srgb, var(--nw-blue) 28%, transparent);
  background: var(--nw-blue-soft);
  color: var(--nw-blue);
  flex: 0 0 auto;
}

.storage-title-icon {
  width: 44px;
  height: 44px;
  border-radius: 16px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
}

.storage-title h1 {
  margin: 0 0 6px;
  font-size: 24px;
  line-height: 1.2;
  color: var(--nw-page-text);
}

.storage-title p,
.storage-panel p {
  margin: 0;
  color: var(--nw-page-muted);
  line-height: 1.65;
}

.storage-actions {
  display: flex;
  gap: 10px;
  align-items: center;
  flex-wrap: wrap;
  justify-content: flex-end;
}

.storage-button {
  appearance: none;
  border: 1px solid var(--nw-border);
  border-radius: 999px;
  min-height: 38px;
  padding: 0 16px;
  color: var(--nw-page-text);
  background: var(--nw-surface-2);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  font-weight: 700;
  cursor: pointer;
  white-space: nowrap;
}

.storage-button.primary {
  color: var(--nw-blue);
  border-color: color-mix(in srgb, var(--nw-blue) 38%, transparent);
  background: var(--nw-blue-soft);
}

.storage-button:disabled {
  opacity: .55;
  cursor: not-allowed;
}

.storage-alert {
  border-radius: 16px;
  padding: 12px 14px;
  border: 1px solid color-mix(in srgb, var(--nw-amber) 32%, transparent);
  background: color-mix(in srgb, var(--nw-amber) 10%, transparent);
  color: var(--nw-amber);
}

.storage-alert.error {
  border-color: rgba(239, 68, 68, .35);
  background: rgba(239, 68, 68, .10);
  color: #dc2626;
}

html.dark .storage-alert.error,
body.dark .storage-alert.error,
.dark .storage-alert.error,
[data-theme="dark"] .storage-alert.error {
  color: #fecaca;
}

.storage-grid {
  display: grid;
  grid-template-columns: repeat(12, minmax(0, 1fr));
  gap: 18px;
}

.storage-card {
  grid-column: span 6;
  border-radius: 20px;
  padding: 20px;
  min-width: 0;
}

.storage-card.full { grid-column: 1 / -1; }

.storage-card h2 {
  margin: 0 0 14px;
  font-size: 16px;
  color: var(--nw-page-text);
  display: flex;
  align-items: center;
  gap: 10px;
}

.storage-provider {
  display: flex;
  align-items: center;
  gap: 14px;
  margin: 6px 0 12px;
}

.storage-provider strong {
  display: block;
  font-size: 22px;
  color: var(--nw-page-text);
  line-height: 1.25;
}

.storage-provider span {
  color: var(--nw-page-muted);
  font-size: 13px;
}

.storage-provider-icon {
  width: 42px;
  height: 42px;
  border-radius: 14px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
}

.storage-pills {
  display: grid;
  gap: 10px;
}

.storage-pill {
  min-height: 42px;
  border-radius: 14px;
  padding: 9px 12px;
  border: 1px solid var(--nw-border);
  display: flex;
  align-items: center;
  gap: 10px;
  color: var(--nw-page-text);
  background: var(--nw-surface-3);
}

.storage-pill.ok svg { color: var(--nw-green); }
.storage-pill.warn svg { color: var(--nw-amber); }

.storage-pill strong {
  margin-left: auto;
  font-size: 13px;
  color: var(--nw-page-muted);
}

.storage-panel {
  border-radius: 22px;
  padding: 24px;
}

.storage-panel-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 18px;
}

.storage-panel-head h2 {
  margin: 0 0 6px;
  font-size: 20px;
  color: var(--nw-page-text);
}

.storage-info-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}

.storage-info-row {
  border: 1px solid var(--nw-border);
  border-radius: 16px;
  padding: 13px 14px;
  background: var(--nw-surface-2);
  min-width: 0;
}

.storage-info-row span {
  display: block;
  color: var(--nw-page-muted);
  font-size: 12px;
  letter-spacing: .02em;
  margin-bottom: 7px;
}

.storage-info-row strong {
  display: block;
  color: var(--nw-page-text);
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', monospace;
  font-size: 13px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.storage-info-row strong.secret { color: var(--nw-green); }

.storage-code {
  margin-top: 16px;
  border: 1px solid var(--nw-border);
  border-radius: 18px;
  background: var(--nw-surface-2);
  overflow: hidden;
}

.storage-code-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 12px 14px;
  border-bottom: 1px solid var(--nw-border);
  color: var(--nw-page-muted);
}

.storage-code pre {
  margin: 0;
  padding: 16px;
  overflow-x: auto;
  color: var(--nw-page-text);
  font-size: 13px;
  line-height: 1.75;
  white-space: pre;
}

.storage-empty {
  border: 1px dashed var(--nw-border);
  border-radius: 18px;
  padding: 22px;
  color: var(--nw-page-muted);
  text-align: center;
  background: var(--nw-surface);
}

@media (max-width: 900px) {
  .storage-hero,
  .storage-panel-head { flex-direction: column; }
  .storage-actions { justify-content: flex-start; }
  .storage-card { grid-column: 1 / -1; }
  .storage-info-grid { grid-template-columns: 1fr; }
}
`;

export default function StorageSettingsPage(props: StorageSettingsPageProps) {
  const [settings, setSettings] = useState<AdminStorageSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [testing, setTesting] = useState(false);
  const [error, setError] = useState('');

  async function load() {
    setLoading(true);
    setError('');
    try {
      setSettings(await getAdminStorageSettings(props.authedFetch));
    } catch (err) {
      const message = err instanceof Error ? err.message : '加载存储库设置失败';
      setError(message);
      props.onNotify?.('error', message);
    } finally {
      setLoading(false);
    }
  }

  async function runTest() {
    setTesting(true);
    try {
      const result = await testAdminStorage(props.authedFetch);
      if (result.ok) {
        props.onNotify?.('success', `存储库测试成功：${providerLabel(result.provider)}`);
      } else {
        props.onNotify?.('error', result.error || '存储库测试失败');
      }
      await load();
    } catch (err) {
      props.onNotify?.('error', err instanceof Error ? err.message : '存储库测试失败');
    } finally {
      setTesting(false);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  const graph = settings?.microsoftGraph;
  const currentProvider = providerLabel(settings?.currentProvider);
  const graphMissing = graph?.missing || [];

  return (
    <div className="storage-polish">
      <style>{pageCss}</style>

      <section className="storage-hero">
        <div className="storage-title">
          <div className="storage-title-icon"><Database size={24} /></div>
          <div>
            <h1>存储库设置</h1>
            <p>这里仅控制附件和文件 Send 的对象存储。密码库主数据仍然保存在 Cloudflare D1。</p>
          </div>
        </div>
        <div className="storage-actions">
          <button type="button" className="storage-button" onClick={() => void load()} disabled={loading}>
            <RefreshCw size={15} /> 刷新
          </button>
          <button type="button" className="storage-button primary" onClick={() => void runTest()} disabled={testing || !settings?.currentProvider}>
            <ShieldCheck size={15} /> {testing ? '测试中...' : '测试当前存储'}
          </button>
        </div>
      </section>

      {error && <div className="storage-alert error">{error}</div>}

      {loading && !settings ? (
        <div className="storage-empty">正在加载存储库设置...</div>
      ) : settings ? (
        <>
          <section className="storage-grid">
            <div className="storage-card">
              <h2><HardDrive size={18} /> 当前生效后端</h2>
              <div className="storage-provider">
                <div className="storage-provider-icon"><Cloud size={22} /></div>
                <div>
                  <strong>{currentProvider}</strong>
                  <span>{settings.currentProvider === 'microsoft_graph' ? '正在使用 Microsoft Graph' : '未设置 STORAGE_PROVIDER=microsoft_graph 时，会按 R2 / KV 绑定自动选择。'}</span>
                </div>
              </div>
            </div>

            <div className="storage-card">
              <h2><Cloud size={18} /> 可用绑定</h2>
              <div className="storage-pills">
                <StatusPill ok={settings.r2Configured} label="Cloudflare R2" value={settings.r2Configured ? '已绑定' : '未绑定'} />
                <StatusPill ok={settings.kvConfigured} label="Cloudflare KV" value={settings.kvConfigured ? '已绑定' : '未绑定'} />
                <StatusPill ok={graph?.configured || false} label="Microsoft Graph" value={graph?.configured ? '已配置' : '未配置'} />
              </div>
            </div>
          </section>

          <section className="storage-panel">
            <div className="storage-panel-head">
              <div>
                <h2>Microsoft 365 / Graph Drive</h2>
                <p>推荐使用 SharePoint 站点文档库或专用 Drive，不建议把个人 OneDrive 当作长期系统存储。</p>
              </div>
              <button type="button" className="storage-button" onClick={() => copyCommands(props.onNotify)}>
                <Copy size={15} /> 复制命令
              </button>
            </div>

            <div className="storage-info-grid">
              <InfoRow label="STORAGE_PROVIDER" value={displayValue(graph?.provider)} />
              <InfoRow label="Tenant ID" value={maskMiddle(graph?.tenantId)} />
              <InfoRow label="Client ID" value={maskMiddle(graph?.clientId)} />
              <InfoRow label="Client Secret" value={graph?.clientSecretConfigured ? '已设置，不显示' : '未设置'} secret={graph?.clientSecretConfigured} />
              <InfoRow label="Drive ID" value={maskMiddle(graph?.driveId)} />
              <InfoRow label="Root Path" value={displayValue(graph?.rootPath, 'nodewarden')} />
            </div>

            {graphMissing.length > 0 && (
              <div className="storage-alert" style={{ marginTop: '16px' }}>
                还缺少：{graphMissing.join(', ')}
              </div>
            )}

            <div className="storage-code">
              <div className="storage-code-head">
                <span><KeyRound size={15} /> Wrangler Secrets</span>
                <span>在仓库根目录执行</span>
              </div>
              <pre>{setupCommands}</pre>
            </div>
          </section>
        </>
      ) : null}
    </div>
  );
}
