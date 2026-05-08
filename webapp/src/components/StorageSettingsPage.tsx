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
  --nw-text: #172033;
  --nw-muted: #66758f;
  --nw-soft: #f6f9ff;
  --nw-panel: #ffffff;
  --nw-panel-2: #f8fbff;
  --nw-border: rgba(148, 163, 184, .32);
  --nw-border-strong: rgba(96, 165, 250, .32);
  --nw-blue: #2563eb;
  --nw-blue-soft: rgba(37, 99, 235, .10);
  --nw-green: #059669;
  --nw-amber: #d97706;
  --nw-red: #dc2626;
  width: 100%;
  max-width: 980px;
  min-width: 0;
  margin: 0 auto;
  padding: 6px 0 104px;
  display: grid;
  gap: 14px;
  color: var(--nw-text);
  overflow-x: hidden;
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
  --nw-text: #e8efff;
  --nw-muted: #9fb0cc;
  --nw-soft: rgba(15, 23, 42, .72);
  --nw-panel: rgba(15, 23, 42, .76);
  --nw-panel-2: rgba(30, 41, 59, .58);
  --nw-border: rgba(148, 163, 184, .22);
  --nw-border-strong: rgba(125, 176, 255, .34);
  --nw-blue: #7db0ff;
  --nw-blue-soft: rgba(59, 130, 246, .16);
  --nw-green: #86efac;
  --nw-amber: #fcd34d;
  --nw-red: #fca5a5;
}

.storage-polish,
.storage-polish * {
  box-sizing: border-box;
}

.storage-hero,
.storage-card,
.storage-panel,
.storage-empty,
.storage-alert {
  width: 100%;
  max-width: 100%;
  min-width: 0;
}

.storage-hero,
.storage-card,
.storage-panel {
  border: 1px solid var(--nw-border);
  background: var(--nw-panel);
  box-shadow: 0 16px 40px rgba(15, 23, 42, .08);
}

html.dark .storage-hero,
body.dark .storage-hero,
.dark .storage-hero,
html.dark .storage-card,
body.dark .storage-card,
.dark .storage-card,
html.dark .storage-panel,
body.dark .storage-panel,
.dark .storage-panel {
  box-shadow: 0 18px 45px rgba(2, 6, 23, .22);
}

.storage-hero {
  border-radius: 22px;
  padding: 20px;
  display: grid;
  gap: 16px;
  overflow: hidden;
}

.storage-title {
  display: flex;
  align-items: flex-start;
  gap: 13px;
  min-width: 0;
}

.storage-title-icon {
  width: 42px;
  height: 42px;
  border-radius: 15px;
  flex: 0 0 auto;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  color: var(--nw-blue);
  background: var(--nw-blue-soft);
  border: 1px solid var(--nw-border-strong);
}

.storage-title-copy {
  min-width: 0;
}

.storage-title h1 {
  margin: 0 0 7px;
  color: var(--nw-text);
  font-size: 24px;
  line-height: 1.18;
  letter-spacing: -.02em;
}

.storage-title p,
.storage-panel p,
.storage-card p {
  margin: 0;
  color: var(--nw-muted);
  line-height: 1.65;
  font-size: 14px;
}

.storage-actions {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  align-items: center;
}

.storage-button {
  appearance: none;
  border: 1px solid var(--nw-border);
  border-radius: 999px;
  min-height: 40px;
  padding: 0 15px;
  color: var(--nw-text);
  background: var(--nw-panel-2);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  font-weight: 800;
  font-size: 14px;
  line-height: 1;
  cursor: pointer;
  white-space: nowrap;
  transition: transform .16s ease, border-color .16s ease, background .16s ease;
}

.storage-button:hover {
  transform: translateY(-1px);
}

.storage-button.primary {
  color: var(--nw-blue);
  border-color: var(--nw-border-strong);
  background: var(--nw-blue-soft);
}

.storage-button.icon-only {
  width: 40px;
  padding: 0;
}

.storage-button:disabled {
  opacity: .56;
  cursor: not-allowed;
  transform: none;
}

.storage-summary-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.1fr) minmax(0, .9fr);
  gap: 14px;
}

.storage-card {
  border-radius: 20px;
  padding: 18px;
}

.storage-card-title {
  margin: 0 0 13px;
  color: var(--nw-text);
  display: flex;
  align-items: center;
  gap: 9px;
  font-size: 15px;
  font-weight: 900;
}

.storage-provider {
  display: flex;
  align-items: flex-start;
  gap: 13px;
  min-width: 0;
}

.storage-provider-icon {
  width: 42px;
  height: 42px;
  border-radius: 15px;
  flex: 0 0 auto;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  color: var(--nw-blue);
  background: var(--nw-blue-soft);
  border: 1px solid var(--nw-border-strong);
}

.storage-provider-copy {
  min-width: 0;
}

.storage-provider-copy strong {
  display: block;
  color: var(--nw-text);
  font-size: 21px;
  line-height: 1.22;
  letter-spacing: -.02em;
  overflow-wrap: anywhere;
}

.storage-provider-copy span {
  display: block;
  margin-top: 5px;
  color: var(--nw-muted);
  font-size: 13px;
  line-height: 1.55;
}

.storage-pills {
  display: grid;
  gap: 9px;
}

.storage-pill {
  min-width: 0;
  min-height: 40px;
  border-radius: 14px;
  padding: 9px 11px;
  border: 1px solid var(--nw-border);
  background: var(--nw-panel-2);
  display: flex;
  align-items: center;
  gap: 9px;
  color: var(--nw-text);
}

.storage-pill.ok svg {
  color: var(--nw-green);
}

.storage-pill.warn svg {
  color: var(--nw-amber);
}

.storage-pill span {
  min-width: 0;
  flex: 1 1 auto;
  font-weight: 700;
  font-size: 13px;
}

.storage-pill strong {
  flex: 0 0 auto;
  color: var(--nw-muted);
  font-size: 12px;
  font-weight: 800;
}

.storage-panel {
  border-radius: 22px;
  padding: 20px;
  display: grid;
  gap: 16px;
}

.storage-panel-head {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 14px;
}

.storage-panel-head h2 {
  margin: 0 0 6px;
  color: var(--nw-text);
  font-size: 20px;
  line-height: 1.25;
  letter-spacing: -.02em;
}

.storage-info-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 11px;
}

.storage-info-row {
  min-width: 0;
  border: 1px solid var(--nw-border);
  border-radius: 16px;
  padding: 12px 13px;
  background: var(--nw-panel-2);
}

.storage-info-row span {
  display: block;
  margin-bottom: 6px;
  color: var(--nw-muted);
  font-size: 12px;
  line-height: 1.2;
  letter-spacing: .02em;
}

.storage-info-row strong {
  display: block;
  max-width: 100%;
  color: var(--nw-text);
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', monospace;
  font-size: 13px;
  line-height: 1.45;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.storage-info-row strong.secret {
  color: var(--nw-green);
}

.storage-alert {
  border-radius: 16px;
  padding: 12px 14px;
  border: 1px solid color-mix(in srgb, var(--nw-amber) 34%, transparent);
  background: color-mix(in srgb, var(--nw-amber) 10%, transparent);
  color: var(--nw-amber);
  line-height: 1.6;
  overflow-wrap: anywhere;
}

.storage-alert.error {
  border-color: color-mix(in srgb, var(--nw-red) 34%, transparent);
  background: color-mix(in srgb, var(--nw-red) 10%, transparent);
  color: var(--nw-red);
}

.storage-code {
  min-width: 0;
  border: 1px solid var(--nw-border);
  border-radius: 18px;
  background: var(--nw-panel-2);
  overflow: hidden;
}

.storage-code-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 11px 13px;
  border-bottom: 1px solid var(--nw-border);
  color: var(--nw-muted);
  font-size: 12px;
}

.storage-code-head span {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  min-width: 0;
}

.storage-code pre {
  margin: 0;
  padding: 14px;
  color: var(--nw-text);
  font-size: 12px;
  line-height: 1.7;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  word-break: break-word;
  overflow-x: hidden;
}

.storage-empty {
  border: 1px dashed var(--nw-border);
  border-radius: 18px;
  padding: 24px 16px;
  color: var(--nw-muted);
  text-align: center;
  background: var(--nw-panel);
}

@media (max-width: 900px) {
  .storage-polish {
    gap: 12px;
  }

  .storage-summary-grid,
  .storage-info-grid {
    grid-template-columns: minmax(0, 1fr);
  }

  .storage-panel-head {
    display: grid;
  }
}

@media (max-width: 640px) {
  .storage-polish {
    max-width: 100%;
    padding: 0 16px 108px;
  }

  .storage-hero,
  .storage-card,
  .storage-panel {
    border-radius: 18px;
    padding: 15px;
    box-shadow: none;
  }

  .storage-title {
    gap: 11px;
  }

  .storage-title-icon {
    width: 38px;
    height: 38px;
    border-radius: 14px;
  }

  .storage-title h1 {
    font-size: 22px;
    margin-bottom: 5px;
  }

  .storage-title p,
  .storage-panel p,
  .storage-card p {
    font-size: 13px;
    line-height: 1.58;
  }

  .storage-actions {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) 40px;
    gap: 8px;
  }

  .storage-button {
    width: 100%;
    min-width: 0;
    min-height: 39px;
    padding: 0 10px;
    font-size: 13px;
  }

  .storage-button svg {
    flex: 0 0 auto;
  }

  .storage-provider-copy strong {
    font-size: 19px;
  }

  .storage-card-title {
    font-size: 14px;
    margin-bottom: 11px;
  }

  .storage-pill {
    min-height: 38px;
  }

  .storage-pill strong {
    font-size: 11px;
  }

  .storage-panel-head h2 {
    font-size: 18px;
  }

  .storage-info-row {
    border-radius: 15px;
    padding: 11px 12px;
  }

  .storage-info-row strong {
    white-space: normal;
    overflow: visible;
    text-overflow: clip;
    overflow-wrap: anywhere;
    word-break: break-word;
  }

  .storage-code-head {
    align-items: flex-start;
    flex-direction: column;
  }
}

@media (max-width: 390px) {
  .storage-polish {
    padding-left: 12px;
    padding-right: 12px;
  }

  .storage-actions {
    grid-template-columns: minmax(0, 1fr);
  }

  .storage-button.icon-only {
    width: 100%;
  }
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
  const graphConfigured = graph?.configured || false;

  return (
    <div className="storage-polish">
      <style>{pageCss}</style>

      <section className="storage-hero">
        <div className="storage-title">
          <div className="storage-title-icon">
            <Database size={22} />
          </div>
          <div className="storage-title-copy">
            <h1>存储库设置</h1>
            <p>集中管理附件和文件 Send 的对象存储。密码库主数据仍保存在 Cloudflare D1。</p>
          </div>
        </div>

        <div className="storage-actions">
          <button type="button" className="storage-button primary" onClick={() => void runTest()} disabled={testing || loading || !settings?.currentProvider}>
            <ShieldCheck size={15} />
            {testing ? '测试中...' : '测试存储'}
          </button>
          <button type="button" className="storage-button" onClick={() => copyCommands(props.onNotify)}>
            <Copy size={15} />
            复制命令
          </button>
          <button type="button" className="storage-button icon-only" onClick={() => void load()} disabled={loading} title="刷新">
            <RefreshCw size={15} />
          </button>
        </div>
      </section>

      {error && <div className="storage-alert error">{error}</div>}

      {loading && !settings ? (
        <div className="storage-empty">正在加载存储库设置...</div>
      ) : settings ? (
        <>
          <section className="storage-summary-grid">
            <div className="storage-card">
              <h2 className="storage-card-title">
                <HardDrive size={17} />
                后端
              </h2>
              <div className="storage-provider">
                <div className="storage-provider-icon">
                  <Cloud size={21} />
                </div>
                <div className="storage-provider-copy">
                  <strong>{currentProvider}</strong>
                  <span>
                    {settings.currentProvider === 'microsoft_graph'
                      ? '通过 Microsoft Graph 使用 OneDrive / SharePoint Drive 作为对象存储。'
                      : '未设置 STORAGE_PROVIDER=microsoft_graph 时，会按 R2 / KV 绑定自动选择。'}
                  </span>
                </div>
              </div>
            </div>

            <div className="storage-card">
              <h2 className="storage-card-title">
                <Cloud size={17} />
                可用绑定
              </h2>
              <div className="storage-pills">
                <StatusPill ok={settings.r2Configured} label="Cloudflare R2" value={settings.r2Configured ? '已绑定' : '未绑定'} />
                <StatusPill ok={settings.kvConfigured} label="Cloudflare KV" value={settings.kvConfigured ? '已绑定' : '未绑定'} />
                <StatusPill ok={graphConfigured} label="Microsoft Graph" value={graphConfigured ? '已配置' : '未配置'} />
              </div>
            </div>
          </section>

          <section className="storage-panel">
            <div className="storage-panel-head">
              <div>
                <h2>Microsoft 365 / Graph Drive</h2>
                <p>推荐使用 SharePoint 站点文档库或专用 Drive，不建议把个人 OneDrive 当作长期系统存储。</p>
              </div>
            </div>

            <div className="storage-info-grid">
              <InfoRow label="STORAGE_PROVIDER" value={displayValue(graph?.provider)} />
              <InfoRow label="Tenant ID" value={maskMiddle(graph?.tenantId)} />
              <InfoRow label="Client ID" value={maskMiddle(graph?.clientId)} />
              <InfoRow label="Client Secret" value={graph?.clientSecretConfigured ? '已设置，不显示' : '未设置'} secret={graph?.clientSecretConfigured} />
              <InfoRow label="Drive ID" value={maskMiddle(graph?.driveId)} />
              <InfoRow label="Drive Path" value={displayValue(graph?.rootPath, 'nodewarden')} />
            </div>

            {graphMissing.length > 0 && (
              <div className="storage-alert">
                还缺少：{graphMissing.join(', ')}
              </div>
            )}

            <div className="storage-code">
              <div className="storage-code-head">
                <span>
                  <KeyRound size={15} />
                  Wrangler Secrets
                </span>
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
