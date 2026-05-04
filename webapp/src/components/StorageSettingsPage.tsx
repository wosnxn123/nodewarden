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
.storage-polish { --nw-card: rgba(15, 23, 42, .58); --nw-card-2: rgba(30, 41, 59, .48); --nw-line: rgba(148, 163, 184, .22); --nw-muted: #9fb1cf; --nw-text: #e7eefc; --nw-blue: #7db0ff; --nw-green: #86efac; --nw-amber: #fcd34d; display: grid; gap: 18px; padding-bottom: 28px; }
.storage-polish * { box-sizing: border-box; }
.storage-hero, .storage-panel { border: 1px solid var(--nw-line); border-radius: 22px; background: linear-gradient(180deg, rgba(15,23,42,.86), rgba(15,23,42,.62)); box-shadow: 0 20px 55px rgba(2, 6, 23, .22); }
.storage-hero { display: flex; align-items: flex-start; justify-content: space-between; gap: 22px; padding: 26px; }
.storage-title { display: flex; gap: 16px; align-items: flex-start; min-width: 0; }
.storage-title-icon { width: 44px; height: 44px; border-radius: 16px; display: inline-flex; align-items: center; justify-content: center; color: var(--nw-blue); background: rgba(59, 130, 246, .12); border: 1px solid rgba(125, 176, 255, .24); flex: 0 0 auto; }
.storage-title h1 { margin: 0 0 6px; font-size: 24px; line-height: 1.2; color: var(--nw-text); }
.storage-title p, .storage-panel p { margin: 0; color: var(--nw-muted); line-height: 1.65; }
.storage-actions { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; justify-content: flex-end; }
.storage-button { appearance: none; border: 1px solid var(--nw-line); border-radius: 999px; min-height: 38px; padding: 0 16px; color: var(--nw-text); background: rgba(15, 23, 42, .72); display: inline-flex; align-items: center; justify-content: center; gap: 8px; font-weight: 700; cursor: pointer; white-space: nowrap; }
.storage-button.primary { border-color: rgba(125, 176, 255, .42); background: linear-gradient(180deg, rgba(59, 130, 246, .30), rgba(37, 99, 235, .20)); }
.storage-button:disabled { opacity: .55; cursor: not-allowed; }
.storage-alert { border-radius: 16px; padding: 12px 14px; border: 1px solid var(--nw-line); background: rgba(245, 158, 11, .10); color: #fde68a; }
.storage-alert.error { background: rgba(239, 68, 68, .12); color: #fecaca; }
.storage-grid { display: grid; grid-template-columns: repeat(12, minmax(0, 1fr)); gap: 18px; }
.storage-card { grid-column: span 6; border: 1px solid var(--nw-line); border-radius: 20px; background: var(--nw-card); padding: 20px; min-width: 0; }
.storage-card.full { grid-column: 1 / -1; }
.storage-card h2 { margin: 0 0 14px; font-size: 16px; color: var(--nw-text); display: flex; align-items: center; gap: 10px; }
.storage-provider { display: flex; align-items: center; gap: 14px; margin: 6px 0 12px; }
.storage-provider strong { display: block; font-size: 22px; color: #fff; line-height: 1.25; }
.storage-provider span { color: var(--nw-muted); font-size: 13px; }
.storage-provider-icon { width: 42px; height: 42px; border-radius: 14px; display: inline-flex; align-items: center; justify-content: center; background: rgba(125, 176, 255, .10); color: var(--nw-blue); border: 1px solid rgba(125, 176, 255, .22); flex: 0 0 auto; }
.storage-pills { display: grid; gap: 10px; }
.storage-pill { min-height: 42px; border-radius: 14px; padding: 9px 12px; border: 1px solid var(--nw-line); display: flex; align-items: center; gap: 10px; color: var(--nw-text); background: rgba(15, 23, 42, .42); }
.storage-pill.ok svg { color: var(--nw-green); }
.storage-pill.warn svg { color: var(--nw-amber); }
.storage-pill strong { margin-left: auto; font-size: 13px; color: var(--nw-muted); }
.storage-panel { padding: 24px; }
.storage-panel-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; margin-bottom: 18px; }
.storage-panel-head h2 { margin: 0 0 6px; font-size: 20px; color: var(--nw-text); }
.storage-info-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
.storage-info-row { border: 1px solid var(--nw-line); border-radius: 16px; padding: 13px 14px; background: var(--nw-card-2); min-width: 0; }
.storage-info-row span { display: block; color: var(--nw-muted); font-size: 12px; letter-spacing: .02em; margin-bottom: 7px; }
.storage-info-row strong { display: block; color: var(--nw-text); font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', monospace; font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.storage-info-row strong.secret { color: var(--nw-green); }
.storage-code { margin-top: 16px; border: 1px solid var(--nw-line); border-radius: 18px; background: rgba(2, 6, 23, .38); overflow: hidden; }
.storage-code-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 12px 14px; border-bottom: 1px solid var(--nw-line); color: var(--nw-muted); }
.storage-code pre { margin: 0; padding: 16px; overflow-x: auto; color: #dbeafe; font-size: 13px; line-height: 1.75; white-space: pre; }
.storage-empty { border: 1px dashed var(--nw-line); border-radius: 18px; padding: 22px; color: var(--nw-muted); text-align: center; }
@media (max-width: 900px) { .storage-hero, .storage-panel-head { flex-direction: column; } .storage-actions { justify-content: flex-start; } .storage-card { grid-column: 1 / -1; } .storage-info-grid { grid-template-columns: 1fr; } }
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
