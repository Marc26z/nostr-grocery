/* Reproduction: a list created in one session must be recovered from the
 * relays after the app is closed and reopened, even when the browser lost its
 * localStorage cache (fresh storage, new device, cleared data, private mode).
 *
 * Session 1 creates a list and captures the kind-30078 events it published
 * (the encrypted list + the self key-grant). Session 2 starts with only the
 * identity (gl_sk) — no cached lists — and replays those events as a relay
 * would. The list should decrypt and render from the relays alone. */
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { webcrypto } from "node:crypto";
import { JSDOM } from "jsdom";

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

test("a list is recovered from the relays after reopening without a cache", async () => {
  const html = fs.readFileSync(new URL("../index.html", import.meta.url), "utf8");
  const setGlobal = (name, value) => {
    try {
      globalThis[name] = value;
    } catch (_) {
      Object.defineProperty(globalThis, name, { value, configurable: true, writable: true });
    }
  };
  const installGlobals = (window) => {
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
  };
  const publishedEvents = () =>
    sockets
      .flatMap((s) => s.sent)
      .map((m) => {
        try {
          return JSON.parse(m);
        } catch (_) {
          return null;
        }
      })
      .filter((m) => m && m[0] === "EVENT" && m[1]?.kind === 30078)
      .map((m) => m[1]);

  const intervals = [];
  const realSetInterval = globalThis.setInterval;
  globalThis.setInterval = (...args) => {
    const id = realSetInterval(...args);
    intervals.push(id);
    return id;
  };

  let identity = null;
  let relayEvents = [];
  try {
    /* ---- session 1: create a list, then "close" ---- */
    const dom1 = new JSDOM(html, { url: "https://grocery.test/", pretendToBeVisual: true });
    installGlobals(dom1.window);
    sockets.length = 0;
    await import(`../app.js?recover=first-${Date.now()}`);
    dom1.window.document.dispatchEvent(new dom1.window.Event("DOMContentLoaded"));
    await tick(20);

    dom1.window.document.querySelector("#gen-btn").click();
    await tick();
    dom1.window.document.querySelector("#backup-done").click();
    await tick(160);

    dom1.window.document.querySelector("#new-list-btn").click();
    await tick();
    dom1.window.document.querySelector("#ask-input").value = "Relay shop";
    dom1.window.document
      .querySelector("#ask-form")
      .dispatchEvent(new dom1.window.Event("submit", { bubbles: true, cancelable: true }));
    await tick(40);

    dom1.window.document.querySelector("#add-input").value = "eggs";
    dom1.window.document
      .querySelector("#add-form")
      .dispatchEvent(new dom1.window.Event("submit", { bubbles: true, cancelable: true }));
    await tick(900);

    identity = dom1.window.localStorage.getItem("gl_sk");
    assert.ok(identity, "session 1 should have persisted an identity");
    relayEvents = publishedEvents();
    assert.ok(relayEvents.length >= 2, "session 1 should have published the list + key grant");
    for (const s of sockets) { try { s.close(); } catch (_) {} }
    dom1.window.close();

    /* ---- session 2: reopen with only the identity, no cached lists ---- */
    const dom2 = new JSDOM(html, { url: "https://grocery.test/", pretendToBeVisual: true });
    installGlobals(dom2.window);
    dom2.window.localStorage.setItem("gl_sk", identity); // only the identity survives
    sockets.length = 0;
    await import(`../app.js?recover=second-${Date.now()}`);
    dom2.window.document.dispatchEvent(new dom2.window.Event("DOMContentLoaded"));
    await tick(160);

    // Feed the relays' stored events into the app's subscription.
    const socket = sockets.find((s) => s.sent.some((m) => m.includes("REQ")));
    assert.ok(socket, "session 2 should subscribe to the relays");
    const req = socket.sent.map((m) => JSON.parse(m)).find((m) => m[0] === "REQ");
    const subId = req[1];
    for (const ev of relayEvents) socket.emit(["EVENT", subId, ev]);
    socket.emit(["EOSE", subId]);
    await tick(200);

    const card = dom2.window.document.querySelector("#lists-grid .list-card");
    assert.ok(card, "the list should be recovered from the relays after reopening");
    assert.match(card.textContent, /Relay shop/);

    card.click();
    await tick(20);
    const items = [...dom2.window.document.querySelectorAll("#items .item .text")].map(
      (n) => n.textContent
    );
    assert.deepEqual(items, ["eggs"]);

    for (const s of sockets) { try { s.close(); } catch (_) {} }
    dom2.window.close();
  } finally {
    for (const id of intervals) clearInterval(id);
  }
});
