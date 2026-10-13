/* Glue between the Marmot client and this app: a relay-pool network adapter,
 * localStorage-backed key/value stores for MLS state, and a persisted message
 * history so chats survive reloads.
 *
 * Note: Marmot stores raw bytes (SerializedClientState is a Uint8Array, key
 * packages nest Uint8Arrays, and MLS carries bigints), which JSON would mangle.
 * The store below tags those so they round-trip through localStorage. */
import { GroupRumorHistory } from "../vendor/marmot.js";

/* ------------------------------ base64 bytes ----------------------------- */

function u8ToB64(bytes) {
  let s = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(s);
}

function b64ToU8(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const jsonReplacer = (_key, value) => {
  if (value instanceof Uint8Array) return { $u8: u8ToB64(value) };
  if (typeof value === "bigint") return { $big: value.toString() };
  return value;
};

const jsonReviver = (_key, value) => {
  if (value && typeof value === "object") {
    if (typeof value.$u8 === "string") return b64ToU8(value.$u8);
    if (typeof value.$big === "string") return BigInt(value.$big);
  }
  return value;
};

/* --------------------------- key/value store ----------------------------- */

/** A binary-safe localStorage store implementing marmot's GenericKeyValueStore. */
export function createLocalStorageStore(keyPrefix) {
  const full = (key) => keyPrefix + key;
  return {
    async getItem(key) {
      try {
        const v = localStorage.getItem(full(key));
        return v == null ? null : JSON.parse(v, jsonReviver);
      } catch (_) {
        return null;
      }
    },
    async setItem(key, value) {
      try {
        localStorage.setItem(full(key), JSON.stringify(value, jsonReplacer));
      } catch (_) {}
      return value;
    },
    async removeItem(key) {
      try {
        localStorage.removeItem(full(key));
      } catch (_) {}
    },
    async clear() {
      try {
        for (const k of Object.keys(localStorage)) {
          if (k.startsWith(keyPrefix)) localStorage.removeItem(k);
        }
      } catch (_) {}
    },
    async keys() {
      try {
        const out = [];
        for (let i = 0; i < localStorage.length; i++) {
          const k = localStorage.key(i);
          if (k && k.startsWith(keyPrefix)) out.push(k.slice(keyPrefix.length));
        }
        return out;
      } catch (_) {
        return [];
      }
    },
  };
}

/* ------------------------------- history --------------------------------- */

function matchFilter(filter, event) {
  if (filter.ids && !filter.ids.includes(event.id)) return false;
  if (filter.kinds && !filter.kinds.includes(event.kind)) return false;
  if (filter.authors && !filter.authors.includes(event.pubkey)) return false;
  for (const key of Object.keys(filter)) {
    if (key[0] !== "#") continue;
    const values = filter[key];
    const tag = key.slice(1);
    if (values && !event.tags.some((t) => t[0] === tag && values.includes(t[1]))) return false;
  }
  if (filter.since && event.created_at < filter.since) return false;
  if (filter.until && event.created_at > filter.until) return false;
  return true;
}

function matchFilters(filters, event) {
  const list = Array.isArray(filters) ? filters : [filters];
  return list.some((f) => matchFilter(f, event));
}

/** A GroupRumorHistory backend persisted in localStorage (rumors are JSON-safe). */
export function createRumorHistoryBackend(keyPrefix) {
  const load = () => {
    try {
      const raw = localStorage.getItem(keyPrefix);
      return raw ? JSON.parse(raw) : [];
    } catch (_) {
      return [];
    }
  };
  const save = (items) => {
    try {
      localStorage.setItem(keyPrefix, JSON.stringify(items));
    } catch (_) {}
  };
  return {
    async queryRumors(filters) {
      const items = load().filter((r) => matchFilters(filters, r));
      return items.sort((a, b) => b.created_at - a.created_at);
    },
    async addRumor(rumor) {
      const items = load();
      if (!items.some((r) => r.id === rumor.id)) items.push(rumor);
      save(items);
    },
    async clear() {
      save([]);
    },
  };
}

/** GroupHistoryFactory for MarmotClient: a persisted history per group id. */
export function historyFactory() {
  return GroupRumorHistory.makeFactory((groupId) => {
    const hex = [...groupId].map((b) => b.toString(16).padStart(2, "0")).join("");
    return createRumorHistoryBackend("gl_marmot_hist_" + hex);
  });
}

/* -------------------------------- network -------------------------------- */

/** Implements Marmot's NostrNetworkInterface on top of nostr-tools' SimplePool. */
export class SimplePoolNetworkAdapter {
  constructor(pool, relays) {
    this.pool = pool;
    this.relays = relays;
  }

  async publish(relays, event) {
    const target = relays && relays.length ? relays : this.relays;
    const results = await Promise.allSettled(this.pool.publish(target, event));
    const out = {};
    target.forEach((url, i) => {
      const r = results[i];
      out[url] =
        r && r.status === "fulfilled"
          ? { from: url, ok: true }
          : { from: url, ok: false, message: String(r?.reason?.message || r?.reason || "failed") };
    });
    return out;
  }

  async request(relays, filters) {
    const target = relays && relays.length ? relays : this.relays;
    const list = Array.isArray(filters) ? filters : [filters];
    try {
      return await this.pool.list(target, list);
    } catch (_) {
      return [];
    }
  }

  subscription(relays, filters) {
    const target = relays && relays.length ? relays : this.relays;
    const list = Array.isArray(filters) ? filters : [filters];
    const sub = this.pool.sub(target, list);
    return {
      subscribe(observer) {
        sub.on("event", (ev) => observer.next?.(ev));
        sub.on("eose", () => observer.complete?.());
        sub.on("error", (err) => observer.error?.(err));
        return {
          unsubscribe() {
            try {
              if (typeof sub.unsub === "function") sub.unsub();
              else if (typeof sub.close === "function") sub.close();
            } catch (_) {}
          },
        };
      },
    };
  }

  async getUserInboxRelays(pubkey) {
    // Marmot key-package relay list (kind 10051); fall back to NIP-17 DM
    // relays (kind 10050). If neither is published, fall back to the shared
    // relay set so the Welcome gift wrap still reaches the invitee — Marmot
    // throws (rather than falling back) when this returns an empty list.
    for (const kind of [10051, 10050]) {
      try {
        const events = await this.pool.list(this.relays, [{ kinds: [kind], authors: [pubkey], limit: 1 }]);
        if (events.length) {
          const relays = events[0].tags.filter((t) => t[0] === "relay").map((t) => t[1]).filter(Boolean);
          if (relays.length) return relays;
        }
      } catch (_) {}
    }
    return this.relays;
  }
}
