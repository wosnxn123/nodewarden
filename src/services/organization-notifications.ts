import type { Env } from '../types';
import { notifyMobilePush } from './push-relay';

const PREFIX = 'organization.sync.';
const MAX_ROWS = 50;
// Two hub requests and two mobile-device lookups per recipient. Bound fanout so
// request/scheduled callers can retry large organizations without exhausting the
// Workers subrequest budget. Successful recipients are checkpointed atomically.
const MAX_RECIPIENTS = 8;
const MAX_DRAIN_BATCHES = 4;
const MAX_DRAIN_DURATION_MS = 10_000;
const USER_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
interface OrganizationSyncEvent {
  organizationId: string;
  revisionDate: string;
  userIds: string[];
}

function parseEvent(value: string): OrganizationSyncEvent | null {
  try {
    const event = JSON.parse(value) as Record<string, unknown>;
    if (
      !event ||
      typeof event !== 'object' ||
      typeof event.organizationId !== 'string' ||
      !USER_ID.test(event.organizationId) ||
      typeof event.revisionDate !== 'string' ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(
        event.revisionDate
      ) ||
      !Number.isFinite(Date.parse(event.revisionDate)) ||
      !Array.isArray(event.userIds) ||
      event.userIds.some((id) => typeof id !== 'string' || !USER_ID.test(id))
    )
      return null;
    return {
      organizationId: event.organizationId,
      revisionDate: event.revisionDate,
      userIds: Array.from(new Set(event.userIds as string[])),
    };
  } catch {
    return null;
  }
}

async function deliverSync(
  env: Env,
  userId: string,
  revisionDate: string
): Promise<void> {
  const stub = env.NOTIFICATIONS_HUB.get(
    env.NOTIFICATIONS_HUB.idFromName(userId)
  );
  // The public notifyUserVaultSync/notifyUserCiphersSync helpers return void and
  // swallow failures, so they cannot acknowledge an outbox. Use their existing
  // internal hub protocol directly and await both accepted broadcasts instead.
  for (const updateType of [5, 4]) {
    const payload = { UserId: userId, Date: revisionDate };
    const response = await stub.fetch('https://notifications/internal/notify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-NodeWarden-UserId': userId,
      },
      body: JSON.stringify({
        revisionDate,
        contextId: null,
        updateType,
        targetDeviceIdentifier: null,
        payload,
      }),
    });
    if (!response.ok)
      throw new Error('Organization sync notification was not accepted');
    // Mobile push uses the existing best-effort relay; its helper exposes no
    // delivery receipt. Durable acknowledgment here means hub acceptance, not
    // guaranteed receipt by an offline device. Sync revisions remain durable.
    await notifyMobilePush(env, {
      userId,
      updateType,
      revisionDate,
      contextId: null,
      payload,
    });
  }
}

export interface OrganizationNotificationProgress {
  attemptedRecipients: number;
  completedRecipients: number;
  checkpointedRows: number;
  failures: number;
  hasBacklog: boolean;
}

async function hasBacklog(env: Env): Promise<boolean> {
  return !!(await env.DB.prepare(
    'SELECT 1 AS present FROM config WHERE key LIKE ? LIMIT 1'
  )
    .bind(`${PREFIX}%`)
    .first());
}

async function flushBatch(
  env: Env,
  deadline: number
): Promise<OrganizationNotificationProgress> {
  const progress: OrganizationNotificationProgress = {
    attemptedRecipients: 0,
    completedRecipients: 0,
    checkpointedRows: 0,
    failures: 0,
    hasBacklog: false,
  };
  if (!env.NOTIFICATIONS_HUB)
    return { ...progress, hasBacklog: await hasBacklog(env) };
  const rows = await env.DB.prepare(
    'SELECT key,value FROM config WHERE key LIKE ? ORDER BY key LIMIT ?'
  )
    .bind(`${PREFIX}%`, MAX_ROWS)
    .all<{ key: string; value: string }>();
  const checkpoints: D1PreparedStatement[] = [];
  const checkpointRecipients: number[] = [];
  let budget = MAX_RECIPIENTS;
  for (const row of rows.results) {
    if (Date.now() >= deadline) break;
    if (
      !row.key.startsWith(PREFIX) ||
      !/^[0-9a-f-]{36}$/i.test(row.key.slice(PREFIX.length))
    )
      continue;
    const event = parseEvent(row.value);
    // Invalid stored data is never an authority to notify a user or delete a
    // purported event. Leave it for diagnosis without exposing its contents.
    if (!event) continue;
    if (!event.userIds.length) {
      checkpoints.push(
        env.DB.prepare('DELETE FROM config WHERE key = ? AND value = ?').bind(
          row.key,
          row.value
        )
      );
      checkpointRecipients.push(0);
      continue;
    }
    if (!budget) break;
    const candidates = event.userIds.slice(0, budget);
    const existing = await env.DB.prepare(
      `SELECT u.id,r.revision_date FROM users u
      LEFT JOIN user_revisions r ON r.user_id = u.id WHERE u.id IN (SELECT value FROM json_each(?))`
    )
      .bind(JSON.stringify(candidates))
      .all<{ id: string; revision_date: string | null }>();
    const existingUsers = new Map(
      existing.results.map((entry) => [entry.id, entry.revision_date])
    );
    let completed = 0;
    for (const userId of candidates) {
      if (Date.now() >= deadline) break;
      budget--;
      progress.attemptedRecipients++;
      try {
        // Deleted accounts have no devices or vault to invalidate.
        if (existingUsers.has(userId)) {
          const currentRevision = existingUsers.get(userId);
          // A delayed outbox cannot roll a client's clock back after another
          // mutation. Repository revisions are monotonic, even within one ms.
          await deliverSync(
            env,
            userId,
            currentRevision && currentRevision > event.revisionDate
              ? currentRevision
              : event.revisionDate
          );
        }
        completed++;
      } catch {
        // Retain this and all later recipients. Retrying a successfully delivered
        // first message is harmless: sync notifications contain no ciphertext.
        progress.failures++;
        break;
      }
    }
    if (!completed) continue;
    const remaining = event.userIds.slice(completed);
    checkpoints.push(
      remaining.length
        ? env.DB.prepare(
            'UPDATE config SET value = ? WHERE key = ? AND value = ?'
          ).bind(
            JSON.stringify({ ...event, userIds: remaining }),
            row.key,
            row.value
          )
        : env.DB.prepare('DELETE FROM config WHERE key = ? AND value = ?').bind(
            row.key,
            row.value
          )
    );
    checkpointRecipients.push(completed);
  }
  // Compare-and-swap means concurrent flushes can duplicate broadcasts but cannot
  // delete a newer checkpoint or erase undelivered recipients. Only committed CAS
  // checkpoints count as progress, so a competing writer cannot cause a hot loop.
  if (checkpoints.length) {
    const results = await env.DB.batch(checkpoints);
    for (let i = 0; i < results.length; i++) {
      if ((results[i].meta.changes ?? 0) > 0) {
        progress.checkpointedRows++;
        progress.completedRecipients += checkpointRecipients[i];
      }
    }
  }
  progress.hasBacklog = await hasBacklog(env);
  return progress;
}

/** One bounded batch of at-least-once hub delivery, with durable CAS progress. */
export async function flushOrganizationNotifications(
  env: Env
): Promise<OrganizationNotificationProgress> {
  return flushBatch(env, Infinity);
}

/**
 * Continue successful batches without waiting for another mutation or cron tick.
 * Failure/no-progress ends this invocation: retry remains scheduled work, not a
 * busy loop. The deadline is checked between recipients and batches; an in-flight
 * recipient may finish after it. Larger backlogs remain durable for scheduled work.
 */
export async function drainOrganizationNotifications(
  env: Env
): Promise<OrganizationNotificationProgress> {
  const progress: OrganizationNotificationProgress = {
    attemptedRecipients: 0,
    completedRecipients: 0,
    checkpointedRows: 0,
    failures: 0,
    hasBacklog: false,
  };
  const deadline = Date.now() + MAX_DRAIN_DURATION_MS;
  for (
    let batch = 0;
    batch < MAX_DRAIN_BATCHES && Date.now() < deadline;
    batch++
  ) {
    const current = await flushBatch(env, deadline);
    progress.attemptedRecipients += current.attemptedRecipients;
    progress.completedRecipients += current.completedRecipients;
    progress.checkpointedRows += current.checkpointedRows;
    progress.failures += current.failures;
    progress.hasBacklog = current.hasBacklog;
    if (!current.hasBacklog || current.failures || !current.checkpointedRows)
      break;
  }
  return progress;
}
