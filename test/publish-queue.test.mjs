/* Unit tests for the publish retry / offline queue. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createPublishQueue, QUEUE_KEY } from "../src/publish-queue.js";

const RELAYS = ["wss://a", "wss://b", "wss://c"];

function fakeStore(initial = {}) {
  const data = { ...initial };
  return {
    get: (k, d = null) => (k in data ? data[k] : d),
    set: (k, v) => {
      data[k] = v;
    },
    _raw: data,
  };
}

/** A pool whose relays accept/reject according to `accept(url)`. */
function fakePool(accept) {
  const calls = [];
  return {
    calls,
    publish(relays, ev) {
      calls.push({ relays: [...relays], ev });
      return relays.map((url) => (accept(url) ? Promise.resolve(url) : Promise.reject(new Error("down"))));
    },
  };
}

const event = (over = {}) => ({
  id: over.id || "id-" + Math.random().toString(16).slice(2),
  kind: over.kind ?? 30078,
  tags: over.tags || [["d", "grocery:list1"]],
  content: over.content || "ciphertext",
  ...over,
});

test("a publish accepted by any relay is not queued", async () => {
  const pool = fakePool((url) => url === "wss://b");
  const q = createPublishQueue({ pool, relays: RELAYS, store: fakeStore() });
  const res = await q.publish(event());
  assert.equal(res.ok, 1);
  assert.equal(res.queued, false);
  assert.equal(q.size(), 0);
});

test("a publish that no relay accepts is queued and persisted", async () => {
  const store = fakeStore();
  const pool = fakePool(() => false);
  const q = createPublishQueue({ pool, relays: RELAYS, store });
  const res = await q.publish(event());
  assert.equal(res.ok, 0);
  assert.equal(res.queued, true);
  assert.equal(q.size(), 1);
  assert.equal(store._raw[QUEUE_KEY].length, 1);
});

test("flush retries queued events after relays recover", async () => {
  const store = fakeStore();
  let up = false;
  const pool = fakePool(() => up);
  const q = createPublishQueue({ pool, relays: RELAYS, store, baseBackoffMs: 1000 });
  await q.publish(event());

  // Immediately after queueing we're still within the backoff window.
  assert.deepEqual(await q.flush(Date.now()), { flushed: 0, remaining: 1 });

  up = true;
  const out = await q.flush(Date.now() + 1000);
  assert.deepEqual(out, { flushed: 1, remaining: 0 });
  assert.equal(q.size(), 0);
  assert.equal(store._raw[QUEUE_KEY].length, 0);
});

test("queued events are deduped by addressable key, newest wins", async () => {
  const store = fakeStore();
  const pool = fakePool(() => false);
  const q = createPublishQueue({ pool, relays: RELAYS, store });
  await q.publish(event({ content: "old" }));
  await q.publish(event({ content: "new" }));
  assert.equal(q.size(), 1);
  assert.equal(store._raw[QUEUE_KEY][0].content, "new");
});

test("queued events survive a reload (new queue reads them back)", async () => {
  const store = fakeStore();
  await createPublishQueue({ pool: fakePool(() => false), relays: RELAYS, store }).publish(event());
  let up = false;
  const pool = fakePool(() => up);
  const q2 = createPublishQueue({ pool, relays: RELAYS, store, baseBackoffMs: 0 });
  assert.equal(q2.size(), 1);
  up = true;
  assert.equal((await q2.flush()).flushed, 1);
  assert.equal(q2.size(), 0);
});
