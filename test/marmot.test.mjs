import { test } from "node:test";
import assert from "node:assert/strict";

// The app modules use localStorage + WebCrypto; provide a minimal shim so the
// real store/history code runs under Node.
if (typeof globalThis.localStorage === "undefined") {
  const mem = new Map();
  globalThis.localStorage = {
    getItem: (k) => (mem.has(k) ? mem.get(k) : null),
    setItem: (k, v) => mem.set(k, String(v)),
    removeItem: (k) => mem.delete(k),
    clear: () => mem.clear(),
    key: (i) => [...mem.keys()][i] ?? null,
    get length() {
      return mem.size;
    },
  };
}

const { MarmotClient } = await import("@internet-privacy/marmot-ts/client");
const { createLocalStorageStore, historyFactory } = await import(
  "../src/marmot-adapter.js"
);
const { newLocalIdentity } = await import("../src/core.js");
const { wrapIdentityAsSigner } = await import("../src/marmot-identity.js");

const RELAY = "wss://memory.relay";

/* --------------------- in-memory relay (shared bus) ---------------------- */

function matches(filters, ev) {
  const list = Array.isArray(filters) ? filters : [filters];
  return list.some((f) => {
    if (f.ids && !f.ids.includes(ev.id)) return false;
    if (f.kinds && !f.kinds.includes(ev.kind)) return false;
    if (f.authors && !f.authors.includes(ev.pubkey)) return false;
    for (const key of Object.keys(f)) {
      if (key[0] !== "#") continue;
      const tag = key.slice(1);
      const vals = f[key];
      if (vals && !ev.tags.some((t) => t[0] === tag && vals.includes(t[1]))) return false;
    }
    if (f.since && ev.created_at < f.since) return false;
    if (f.until && ev.created_at > f.until) return false;
    return true;
  });
}

function makeBus() {
  const events = [];
  const subs = new Set();
  return {
    events,
    async publish(relays, event) {
      events.push(event);
      for (const sub of [...subs]) {
        if (matches(sub.filters, event)) queueMicrotask(() => sub.fn(event));
      }
      const out = {};
      for (const url of relays) out[url] = { from: url, ok: true };
      return out;
    },
    async request(_relays, filters) {
      return events.filter((e) => matches(filters, e));
    },
    subscription(_relays, filters) {
      return {
        subscribe(observer) {
          const sub = { filters, fn: (ev) => observer.next?.(ev) };
          subs.add(sub);
          return { unsubscribe: () => subs.delete(sub) };
        },
      };
    },
    async getUserInboxRelays() {
      return [RELAY];
    },
  };
}

function makeClient(bus, clientId) {
  const identity = newLocalIdentity();
  const client = new MarmotClient({
    signer: wrapIdentityAsSigner(identity),
    network: bus,
    clientId,
    groupStateStore: createLocalStorageStore("test_gs_" + clientId + "_"),
    keyPackageStore: createLocalStorageStore("test_kp_" + clientId + "_"),
    inviteStore: createLocalStorageStore("test_inv_" + clientId + "_"),
    historyFactory: historyFactory(),
  });
  return { identity, client, pubkey: identity.pubkey };
}

async function firstKeyPackageEvent(bus, pubkey) {
  const evs = await bus.request([RELAY], [
    { kinds: [30443, 443], authors: [pubkey], limit: 5 },
  ]);
  return evs.filter((e) => e.tags.some((t) => t[0] === "i"))[0] || null;
}

async function timeline(group) {
  const out = [];
  const gen = group.history.subscribe([{ kinds: [9] }]);
  const first = await gen.next();
  for (const r of first.value) out.push(r);
  await gen.return();
  return out.sort((a, b) => a.created_at - b.created_at);
}

/* ------------------------------- the test -------------------------------- */

test("two parties exchange MLS chat messages end-to-end", async () => {
  localStorage.clear();
  const bus = makeBus();
  const a = makeClient(bus, "owner");
  const b = makeClient(bus, "guest");

  // Both advertise key packages.
  await a.client.keyPackages.create({ relays: [RELAY] });
  await b.client.keyPackages.create({ relays: [RELAY] });

  // Owner creates the list chat group.
  const groupA = await a.client.groups.create("chat_list1", { relays: [RELAY] });

  // Invite the guest using their published key package.
  const kpB = await firstKeyPackageEvent(bus, b.pubkey);
  assert.ok(kpB, "guest key package is published");
  await groupA.inviteByKeyPackageEvent(kpB);

  // Guest receives the gift-wrapped welcome and joins.
  const wraps = bus.events.filter(
    (e) => e.kind === 1059 && e.tags.some((t) => t[0] === "p" && t[1] === b.pubkey)
  );
  assert.ok(wraps.length >= 1, "a welcome gift wrap was sent to the guest");
  for (const w of wraps) await b.client.invites.ingestEvent(w);
  const unread = await b.client.invites.decryptGiftWraps();
  assert.equal(unread.length, 1, "guest decrypts one welcome");
  const { group: groupB } = await b.client.joinGroupFromWelcome({
    welcomeRumor: unread[0],
  });
  await b.client.invites.markAsRead(unread[0].id);

  // Owner sends a message; it lands in the owner's own history immediately.
  await groupA.sendChatMessage("milk and eggs");
  let aTimeline = await timeline(groupA);
  assert.deepEqual(aTimeline.map((r) => r.content), ["milk and eggs"]);

  // Guest ingests the owner's group message (kind 445).
  const msgEvents = bus.events.filter((e) => e.kind === 445);
  for (const ev of msgEvents) {
    for await (const _r of groupB.ingest([ev])) {
      /* drained */
    }
  }
  let bTimeline = await timeline(groupB);
  assert.deepEqual(bTimeline.map((r) => r.content), ["milk and eggs"]);

  // Guest replies; owner ingests it.
  await groupB.sendChatMessage("got it");
  const replyEvents = bus.events.filter(
    (e) => e.kind === 445 && !msgEvents.includes(e)
  );
  for (const ev of replyEvents) {
    for await (const _r of groupA.ingest([ev])) {
      /* drained */
    }
  }
  aTimeline = await timeline(groupA);
  bTimeline = await timeline(groupB);
  assert.deepEqual(aTimeline.map((r) => r.content), ["milk and eggs", "got it"]);
  assert.deepEqual(bTimeline.map((r) => r.content), ["milk and eggs", "got it"]);
});

test("group state and history survive a reload", async () => {
  localStorage.clear();
  const bus = makeBus();
  const identity = newLocalIdentity();
  const signer = wrapIdentityAsSigner(identity);
  const build = () =>
    new MarmotClient({
      signer,
      network: bus,
      clientId: "reload",
      groupStateStore: createLocalStorageStore("reload_gs_"),
      keyPackageStore: createLocalStorageStore("reload_kp_"),
      inviteStore: createLocalStorageStore("reload_inv_"),
      historyFactory: historyFactory(),
    });

  const c1 = build();
  await c1.keyPackages.create({ relays: [RELAY] });
  const group1 = await c1.groups.create("chat_persist", { relays: [RELAY] });
  await group1.sendChatMessage("first");
  const gid = group1.idStr;

  // A fresh client reusing the same stores acts like a page reload.
  const c2 = build();
  const groups = await c2.groups.loadAll();
  const found = groups.find((g) => g.groupData?.name === "chat_persist");
  assert.ok(found, "group is restored after reload");
  assert.equal(found.idStr, gid);
  const t = await timeline(found);
  assert.deepEqual(t.map((r) => r.content), ["first"]);
});

test("localStorage store round-trips binary and bigint values", async () => {
  const store = createLocalStorageStore("rt_");
  const value = {
    bytes: new Uint8Array([0, 1, 2, 255, 128]),
    nested: { big: 12345678901234567890n, arr: [new Uint8Array([9, 8, 7])] },
  };
  await store.setItem("k", value);
  const back = await store.getItem("k");
  assert.deepEqual([...back.bytes], [0, 1, 2, 255, 128]);
  assert.equal(back.nested.big, 12345678901234567890n);
  assert.deepEqual([...back.nested.arr[0]], [9, 8, 7]);
  assert.deepEqual(await store.keys(), ["k"]);
  await store.removeItem("k");
  assert.equal(await store.getItem("k"), null);
});
