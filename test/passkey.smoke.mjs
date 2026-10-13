/* Headless smoke test for the passkey sign-in path. jsdom has no WebAuthn, so
 * we stub `navigator.credentials` with a fake authenticator whose PRF extension
 * returns a fixed 32-byte secret. The app must derive a deterministic Nostr key
 * from that secret and sign in — and re-derive the same npub on unlock. */
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { webcrypto } from "node:crypto";
import { JSDOM } from "jsdom";
import { getPublicKey } from "nostr-tools/pure";

const sockets = [];
class MockWebSocket {
  constructor(url) {
    this.url = url;
    this.readyState = 0;
    this.sent = [];
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
      if (m[0] === "EVENT" && m[1]?.id) setTimeout(() => this.emit(["OK", m[1].id, true, ""]), 1);
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

// A fixed authenticator secret so the derived npub is predictable.
const PRF = Uint8Array.from({ length: 32 }, (_, i) => i + 1);

async function expectedPubkey() {
  const salt = new TextEncoder().encode("nostr-grocery-passkey-v1");
  const joined = new Uint8Array(PRF.length + salt.length);
  joined.set(PRF, 0);
  joined.set(salt, PRF.length);
  const sk = new Uint8Array(await webcrypto.subtle.digest("SHA-256", joined));
  return getPublicKey(sk);
}

function prfResults() {
  return { prf: { results: { first: PRF.slice().buffer } } };
}

function fakeCredentials() {
  return {
    async create() {
      return {
        rawId: Uint8Array.from([1, 2, 3, 4]).buffer,
        response: { getTransports: () => ["internal"] },
        getClientExtensionResults: prfResults,
      };
    },
    async get() {
      return { getClientExtensionResults: prfResults };
    },
  };
}

async function setup() {
  const html = fs.readFileSync(new URL("../index.html", import.meta.url), "utf8");
  const dom = new JSDOM(html, { url: "https://grocery.test/", pretendToBeVisual: true });
  const { window } = dom;

  const creds = fakeCredentials();
  try {
    window.navigator.credentials = creds;
  } catch (_) {
    Object.defineProperty(window.navigator, "credentials", { value: creds, configurable: true });
  }

  const setGlobal = (name, value) => {
    try {
      globalThis[name] = value;
    } catch (_) {
      Object.defineProperty(globalThis, name, { value, configurable: true, writable: true });
    }
  };
  for (const [name, value] of Object.entries({
    window,
    document: window.document,
    navigator: window.navigator,
    location: window.location,
    history: window.history,
    localStorage: window.localStorage,
    crypto: webcrypto,
    WebSocket: MockWebSocket,
    PublicKeyCredential: function PublicKeyCredential() {},
  })) {
    setGlobal(name, value);
  }
  globalThis.btoa = (s) => Buffer.from(s, "binary").toString("base64");
  globalThis.atob = (s) => Buffer.from(s, "base64").toString("binary");
  sockets.length = 0;

  const intervals = [];
  const realSetInterval = globalThis.setInterval;
  globalThis.setInterval = (...args) => {
    const id = realSetInterval(...args);
    intervals.push(id);
    return id;
  };

  await import("../src/core.js");
  await import(`../app.js?v=${Date.now()}${Math.random()}`);

  const cleanup = () => {
    for (const id of intervals) clearInterval(id);
    for (const s of sockets) {
      try {
        s.close();
      } catch (_) {}
    }
    dom.window.close();
  };
  return { window, dom, cleanup };
}

function reqFilters(window) {
  const req = sockets
    .flatMap((s) => s.sent)
    .map((m) => JSON.parse(m))
    .find((m) => m[0] === "REQ");
  return req ? req.slice(2) : [];
}

test("creates an identity backed by a passkey (WebAuthn PRF)", async () => {
  const { window, cleanup } = await setup();
  try {
    window.document.dispatchEvent(new window.Event("DOMContentLoaded"));
    await tick(20);
    assert.equal(window.document.querySelector("#login-view").hidden, false);

    const btn = window.document.querySelector("#passkey-btn");
    assert.equal(btn.hidden, false, "passkey button should show when WebAuthn is available");
    assert.match(btn.textContent, /Create an identity with a passkey/);

    btn.click();
    await tick(200);
    assert.equal(window.document.querySelector("#lists-view").hidden, false, "should sign in");

    const saved = JSON.parse(window.localStorage.getItem("gl_passkey"));
    assert.ok(saved && saved.id, "the credential id should be persisted");

    const me = await expectedPubkey();
    const authors = reqFilters(window).flatMap((f) => f.authors || []);
    assert.ok(authors.includes(me), "the subscription should watch the derived npub");

    // The identity is reported as passkey-backed.
    window.document.querySelector("#identity-btn").click();
    await tick();
    assert.match(window.document.querySelector("#modal-body").textContent, /passkey/i);
  } finally {
    cleanup();
  }
});

test("unlocks an existing passkey identity to the same npub", async () => {
  const { window, cleanup } = await setup();
  try {
    window.localStorage.setItem("gl_passkey", JSON.stringify({ id: "cred-abc" }));
    window.document.dispatchEvent(new window.Event("DOMContentLoaded"));
    await tick(20);

    const btn = window.document.querySelector("#passkey-btn");
    assert.equal(btn.hidden, false);
    assert.match(btn.textContent, /Unlock with your passkey/);

    btn.click();
    await tick(200);
    assert.equal(window.document.querySelector("#lists-view").hidden, false, "should sign in");

    const me = await expectedPubkey();
    const authors = reqFilters(window).flatMap((f) => f.authors || []);
    assert.ok(authors.includes(me), "unlock should re-derive the same npub");
  } finally {
    cleanup();
  }
});
