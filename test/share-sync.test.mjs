/* Regression tests for sharing by npub and for keeping joined lists live:
 *
 *   • Sharing a household by npub must publish the key grant and the encrypted
 *     household (it used to crash while re-rendering a list-only view).
 *   • A list joined by key must keep syncing after a reload. Its key grant and
 *     metadata are cached locally, so the app must rebuild a targeted `#d`
 *     subscription from that cache instead of forgetting it.
 *
 * The mock relay below actually matches events against the REQ filters, so a
 * missing subscription shows up as an event that never reaches the app. */
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { webcrypto } from "node:crypto";
import { JSDOM } from "jsdom";

const html = fs.readFileSync(new URL("../index.html", import.meta.url), "utf8");
const sockets = [];

function matchesFilter(f, ev) {
  if (f.kinds && !f.kinds.includes(ev.kind)) return false;
  if (f.ids && !f.ids.includes(ev.id)) return false;
  if (f.authors && !f.authors.includes(ev.pubkey)) return false;
  for (const key of Object.keys(f)) {
    if (!key.startsWith("#")) continue;
    const want = f[key];
    const got = ev.tags.filter((t) => t[0] === key.slice(1)).map((t) => t[1]);
    if (!got.some((v) => want.includes(v))) return false;
  }
  if (f.since != null && ev.created_at < f.since) return false;
  if (f.until != null && ev.created_at > f.until) return false;
  return true;
}

class MockWebSocket {
  constructor(url) {
    this.url = url;
    this.readyState = 0;
    this.sent = [];
    this.subs = new Map(); // subId -> filters[]
    sockets.push(this);
    setTimeout(() => {
      this.readyState = 1;
      this.onopen?.();
    }, 1);
  }
  send(data) {
    this.sent.push(data);
    try {
      const m = JSON.parse(data);
      if (m[0] === "REQ") this.subs.set(m[1], m.slice(2));
      else if (m[0] === "CLOSE") this.subs.delete(m[1]);
      else if (m[0] === "EVENT" && m[1]?.id) setTimeout(() => this.emit(["OK", m[1].id, true, ""]), 1);
    } catch (_) {}
  }
  close() {
    if (this.readyState === 3) return;
    this.readyState = 3;
    this.onclose?.();
  }
  emit(message) {
    this.onmessage?.({ data: JSON.stringify(message) });
  }
}

const tick = (ms = 5) => new Promise((r) => setTimeout(r, ms));
const submit = (window, sel) =>
  window.document.querySelector(sel).dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));

const setGlobal = (name, value) => {
  try {
    globalThis[name] = value;
  } catch (_) {
    Object.defineProperty(globalThis, name, { value, configurable: true, writable: true });
  }
};

function installGlobals(window) {
  for (const [name, value] of Object.entries({
    window,
    document: window.document,
    navigator: window.navigator,
    location: window.location,
    history: window.history,
    localStorage: window.localStorage,
    crypto: webcrypto,
    WebSocket: MockWebSocket,
  })) {
    setGlobal(name, value);
  }
  globalThis.btoa = (s) => Buffer.from(s, "binary").toString("base64");
  globalThis.atob = (s) => Buffer.from(s, "base64").toString("binary");
}

function snapshotStorage(window) {
  const out = {};
  for (let i = 0; i < window.localStorage.length; i++) {
    const k = window.localStorage.key(i);
    out[k] = window.localStorage.getItem(k);
  }
  return out;
}

function closeSockets() {
  for (const s of sockets) {
    try {
      s.close();
    } catch (_) {}
  }
}

/** Every unique event the app published to any relay in this session. */
function publishedEvents() {
  const seen = new Map();
  for (const s of sockets) {
    for (const raw of s.sent) {
      let m;
      try {
        m = JSON.parse(raw);
      } catch (_) {
        continue;
      }
      if (m[0] === "EVENT" && m[1]?.id) seen.set(m[1].id, m[1]);
    }
  }
  return [...seen.values()];
}

/** Deliver an event to the first subscription whose filters match it. */
function deliver(ev) {
  for (const socket of sockets) {
    for (const [subId, filters] of socket.subs) {
      if (filters.some((f) => matchesFilter(f, ev))) {
        socket.emit(["EVENT", subId, ev]);
        return true;
      }
    }
  }
  return false;
}

function reqFilters() {
  const out = [];
  for (const s of sockets) for (const filters of s.subs.values()) for (const f of filters) out.push(f);
  return out;
}

function watchIntervals() {
  const intervals = [];
  const realSetInterval = globalThis.setInterval;
  globalThis.setInterval = (...args) => {
    const id = realSetInterval(...args);
    intervals.push(id);
    return id;
  };
  return intervals;
}

async function boot(window, query) {
  installGlobals(window);
  await import(`../app.js?share-sync=${query}-${Date.now()}`);
  window.document.dispatchEvent(new window.Event("DOMContentLoaded"));
  await tick(160);
}

async function signInFresh(window) {
  window.document.querySelector("#gen-btn").click();
  await tick();
  window.document.querySelector("#backup-done").click();
  await tick(160);
}

test("sharing a household by npub publishes the grant and the recipient can read it", async () => {
  const d1 = new JSDOM(html, { url: "https://grocery.test/", pretendToBeVisual: true });
  // nostr-tools captures the global WebSocket when it is first imported, so
  // install the mock before importing core/app.
  installGlobals(d1.window);
  const core = await import("../src/core.js");
  const intervals = watchIntervals();
  const doms = [d1];
  let ownerEvents = [];

  try {
    /* ---- owner: create a household and share it with Bob's npub ---- */
    sockets.length = 0;
    await boot(d1.window, "owner");
    await signInFresh(d1.window);

    d1.window.document.querySelector("#new-household-btn").click();
    await tick();
    d1.window.document.querySelector("#ask-input").value = "Home";
    submit(d1.window, "#ask-form");
    await tick(160);

    // Add one product so the recipient can verify the encrypted payload.
    d1.window.document.querySelector('button[data-tab="products"]').click();
    await tick(20);
    d1.window.document.querySelector("#h-new-product").click();
    await tick();
    d1.window.document.querySelector("#p-name").value = "Milk";
    d1.window.document.querySelector("#p-unit").value = "l";
    submit(d1.window, "#prod-form");
    await tick(160);

    const bob = core.newLocalIdentity();
    const beforeShare = publishedEvents();
    const firstHousehold = beforeShare.find((ev) =>
      ev.tags.some((t) => t[0] === "t" && t[1] === "grocery-household")
    );
    assert.ok(firstHousehold, "the household should have been published");

    d1.window.document.querySelector("#h-share-btn").click();
    await tick();
    const keyCode = d1.window.document.querySelector("#list-key").textContent;
    assert.match(keyCode, /^grocery1:/, "the share dialog exposes the list key");

    d1.window.document.querySelector("#share-input").value = core.hexToNpub(bob.pubkey);
    submit(d1.window, "#share-form");
    await tick(120);

    // The old bug threw while rendering a household as a list, which showed an
    // error and aborted both publishes.
    assert.equal(d1.window.document.querySelector("#share-error").hidden, true);
    assert.ok(
      d1.window.document.querySelector(".members-list").textContent.includes(core.hexToNpub(bob.pubkey)),
      "Bob should be listed as a member"
    );

    const afterShare = publishedEvents();
    const grant = afterShare.find(
      (ev) =>
        ev.kind === 30078 &&
        ev.tags.some((t) => t[0] === "t" && t[1] === "grocery-key") &&
        ev.tags.some((t) => t[0] === "p" && t[1] === bob.pubkey)
    );
    assert.ok(grant, "a key grant addressed to Bob should have been published");

    const sharedHousehold = afterShare
      .filter((ev) => ev.tags.some((t) => t[0] === "t" && t[1] === "grocery-household"))
      .sort((a, b) => b.created_at - a.created_at)[0];
    assert.ok(sharedHousehold, "the household should have been republished");
    assert.ok(
      sharedHousehold.tags.some((t) => t[0] === "p" && t[1] === bob.pubkey),
      "the republished household should tag Bob so his device discovers it"
    );
    assert.ok(
      sharedHousehold.created_at > firstHousehold.created_at,
      "the shared version must be newer than the original, even in the same second"
    );

    ownerEvents = afterShare.filter((ev) => ev.kind === 30078);
    const bobSk = Buffer.from(bob.secretKey).toString("hex");

    /* ---- recipient: start with only Bob's identity, like a new device ---- */
    closeSockets();
    d1.window.close();
    sockets.length = 0;

    const d2 = new JSDOM(html, { url: "https://grocery.test/", pretendToBeVisual: true });
    doms.push(d2);
    d2.window.localStorage.setItem("gl_sk", JSON.stringify(bobSk));
    await boot(d2.window, "bob");

    let delivered = 0;
    for (const ev of ownerEvents.sort((a, b) => a.created_at - b.created_at)) {
      if (deliver(ev)) delivered += 1;
    }
    assert.ok(delivered >= 2, "Bob's subscription should receive the grant and the household");
    await tick(240);

    const card = d2.window.document.querySelector("#lists-grid .household-card");
    assert.ok(card, "the shared household should appear on Bob's device");
    assert.match(card.textContent, /Home/);
    assert.match(card.textContent, /0\/1 in stock/);

    card.click();
    await tick(40);
    assert.equal(d2.window.document.querySelector("#household-view").hidden, false);
    assert.match(d2.window.document.querySelector("#h-stock-list").textContent, /Milk/);
    assert.match(d2.window.document.querySelector("#h-stock-list").textContent, /0 l/);
  } finally {
    closeSockets();
    for (const d of doms) {
      try {
        d.window.close();
      } catch (_) {}
    }
    for (const id of intervals) clearInterval(id);
  }
});

test("a list joined by key keeps a targeted subscription after a reload", async () => {
  const d1 = new JSDOM(html, { url: "https://grocery.test/", pretendToBeVisual: true });
  installGlobals(d1.window);
  const core = await import("../src/core.js");
  const bob = core.newLocalIdentity();
  const bobSk = Buffer.from(bob.secretKey).toString("hex");
  const intervals = watchIntervals();
  const doms = [d1];
  let ownerEvents = [];
  let keyCode = "";
  let listId = "";
  let owner = null;

  try {
    /* ---- owner: create a plain list and expose its key ---- */
    sockets.length = 0;
    await boot(d1.window, "key-owner");
    await signInFresh(d1.window);

    d1.window.document.querySelector("#new-list-btn").click();
    await tick();
    d1.window.document.querySelector("#ask-input").value = "Key shop";
    submit(d1.window, "#ask-form");
    await tick(40);
    d1.window.document.querySelector("#add-input").value = "bread";
    submit(d1.window, "#add-form");
    await tick(900); // let the debounced item publish settle

    d1.window.document.querySelector("#share-btn").click();
    await tick();
    keyCode = d1.window.document.querySelector("#list-key").textContent;
    assert.match(keyCode, /^grocery1:/);

    const ownerSk = JSON.parse(d1.window.localStorage.getItem("gl_sk"));
    owner = core.createLocalIdentity(ownerSk);
    ownerEvents = publishedEvents().filter((ev) => ev.kind === 30078);
    const latest = ownerEvents
      .filter((ev) => ev.tags.some((t) => t[0] === "t" && t[1] === "grocery-list"))
      .sort((a, b) => b.created_at - a.created_at)[0];
    assert.ok(latest, "the owner's list should have been published");
    listId = latest.tags.find((t) => t[0] === "d")[1].replace(/^grocery:/, "");

    closeSockets();
    d1.window.close();
    sockets.length = 0;

    /* ---- first Bob session: join with the key only, then receive the list ---- */
    const d2 = new JSDOM(html, { url: "https://grocery.test/", pretendToBeVisual: true });
    doms.push(d2);
    d2.window.localStorage.setItem("gl_sk", JSON.stringify(bobSk));
    await boot(d2.window, "key-bob-1");

    d2.window.document.querySelector("#join-list-btn").click();
    await tick();
    d2.window.document.querySelector("#join-input").value = keyCode;
    submit(d2.window, "#join-form");
    await tick(40);

    for (const ev of ownerEvents.sort((a, b) => a.created_at - b.created_at)) deliver(ev);
    await tick(240);

    const card = d2.window.document.querySelector("#lists-grid .list-card");
    assert.ok(card, "the key-joined list should arrive");
    assert.match(card.textContent, /Key shop/);
    card.click();
    await tick(20);
    assert.deepEqual(
      [...d2.window.document.querySelectorAll("#items .item .text")].map((n) => n.textContent),
      ["bread"]
    );

    const bobStorage = snapshotStorage(d2.window);
    closeSockets();
    d2.window.close();
    sockets.length = 0;

    /* ---- reload: the cached key must turn into a live #d subscription ---- */
    const d3 = new JSDOM(html, { url: "https://grocery.test/", pretendToBeVisual: true });
    doms.push(d3);
    for (const [k, v] of Object.entries(bobStorage)) d3.window.localStorage.setItem(k, v);
    await boot(d3.window, "key-bob-2");

    for (const f of reqFilters()) {
      assert.ok(f && typeof f === "object" && !Array.isArray(f), "every REQ filter must be a NIP-01 object");
    }
    assert.ok(
      reqFilters().some((f) => (f["#d"] || []).includes(`grocery:${listId}`)),
      "the reloaded app should subscribe to the joined list's d tag"
    );

    // The owner never tagged Bob in the list (key-only join), so only that #d
    // subscription can deliver this update.
    const joinedKey = JSON.parse(d3.window.localStorage.getItem("gl_lists"))[listId].key;
    const data = core.emptyList("Key shop");
    data.items.push(core.newItem("bread"), core.newItem("jam"));
    const updateEvent = await core.makeListEvent(owner, {
      listId,
      members: [owner.pubkey],
      listKeyHex: joinedKey,
      data,
      createdAt: Math.max(...ownerEvents.map((e) => e.created_at)) + 5,
    });
    assert.equal(deliver(updateEvent), true, "the #d subscription should match the owner's update");
    await tick(240);

    const card3 = d3.window.document.querySelector("#lists-grid .list-card");
    assert.ok(card3, "the cached list should still be listed");
    card3.click();
    await tick(20);
    assert.deepEqual(
      [...d3.window.document.querySelectorAll("#items .item .text")].map((n) => n.textContent),
      ["bread", "jam"]
    );
  } finally {
    closeSockets();
    for (const d of doms) {
      try {
        d.window.close();
      } catch (_) {}
    }
    for (const id of intervals) clearInterval(id);
  }
});
