/* =========================================================================
 * Nostr Grocery — publish retry / offline queue.
 *
 * Events are published to an explicit relay list. When every relay rejects a
 * publish (all offline, or none reachable), the signed event is kept in a
 * persisted queue and retried in the background — on the next connection poll
 * and at startup — with exponential backoff, so a save isn't lost just because
 * the network was briefly down.
 *
 * Addressable events (kind 30078 with a `d` tag) are deduped by kind+d, so a
 * newer edit supersedes an older queued one for the same list.
 *
 * Pure with respect to the network: takes a pool + store, so it can be tested.
 * ========================================================================= */

export const QUEUE_KEY = "gl_publish_queue";

function eventKey(ev) {
  const d = ev.tags?.find((t) => t[0] === "d");
  return d ? `${ev.kind}:${d[1]}` : `${ev.kind}:${ev.id}`;
}

export function createPublishQueue({
  pool,
  relays,
  store,
  baseBackoffMs = 2000,
  maxBackoffMs = 60000,
} = {}) {
  const pending = new Map();
  let failures = 0;
  let nextAllowed = 0;

  function load() {
    try {
      const raw = store?.get(QUEUE_KEY, []);
      if (Array.isArray(raw)) for (const ev of raw) if (ev?.kind != null) pending.set(eventKey(ev), ev);
    } catch (_) {}
  }

  function save() {
    try {
      store?.set(QUEUE_KEY, [...pending.values()]);
    } catch (_) {}
  }

  async function publishTo(targets, ev) {
    let results;
    try {
      results = await Promise.allSettled(pool.publish(targets, ev));
    } catch (_) {
      return 0;
    }
    return results.filter((r) => r.status === "fulfilled").length;
  }

  /** Publish an event now; queue it (for retry) if no relay accepted it. */
  async function publish(ev) {
    if (!pool || !relays?.length) {
      pending.set(eventKey(ev), ev);
      save();
      return { ok: 0, queued: true };
    }
    const ok = await publishTo(relays, ev);
    if (ok > 0) {
      pending.delete(eventKey(ev));
      save();
      return { ok, queued: false };
    }
    pending.set(eventKey(ev), ev);
    save();
    failures = 0;
    nextAllowed = Date.now() + baseBackoffMs;
    return { ok: 0, queued: true };
  }

  /** Retry every queued event that relays might now accept. */
  async function flush(now = Date.now()) {
    if (!pending.size) {
      failures = 0;
      return { flushed: 0, remaining: 0 };
    }
    if (now < nextAllowed) return { flushed: 0, remaining: pending.size };

    let flushed = 0;
    for (const [key, ev] of [...pending]) {
      const ok = await publishTo(relays, ev);
      if (ok > 0) {
        pending.delete(key);
        flushed++;
      }
    }
    save();

    if (pending.size) {
      failures++;
      nextAllowed = Date.now() + Math.min(baseBackoffMs * 2 ** failures, maxBackoffMs);
    } else {
      failures = 0;
    }
    return { flushed, remaining: pending.size };
  }

  load();

  return { publish, flush, size: () => pending.size };
}
