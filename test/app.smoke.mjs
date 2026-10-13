/* Headless smoke test for the browser app: loads index.html in jsdom, stubs
 * WebSockets, signs in, then plays back events from a second npub through the
 * mocked relays to verify the full share -> decrypt -> render path.
 *
 * WebSocket must be stubbed *before* the app's modules are imported, because
 * nostr-tools captures the global WebSocket at module-load time — hence the
 * dynamic imports below. */
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
    // Acknowledge published events so pool.publish() resolves, like a real relay.
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

test("browser app boots, signs in, and ingests a shared list", async () => {
  const html = fs.readFileSync(new URL("../index.html", import.meta.url), "utf8");
  const dom = new JSDOM(html, { url: "https://grocery.test/", pretendToBeVisual: true });
  const { window } = dom;

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
  })) {
    setGlobal(name, value);
  }
  globalThis.btoa = (s) => Buffer.from(s, "binary").toString("base64");
  globalThis.atob = (s) => Buffer.from(s, "base64").toString("binary");

  // Track and later clear any intervals the app starts, so the process exits.
  const intervals = [];
  const realSetInterval = globalThis.setInterval;
  globalThis.setInterval = (...args) => {
    const id = realSetInterval(...args);
    intervals.push(id);
    return id;
  };

  // Import core (which pulls in the bundled nostr-tools) and then the app.
  const core = await import("../src/core.js");
  await import("../app.js");

  try {
    window.document.dispatchEvent(new window.Event("DOMContentLoaded"));
    await tick(20);

    // Login screen shows.
    assert.equal(window.document.querySelector("#login-view").hidden, false);

    // Create a fresh identity.
    window.document.querySelector("#gen-btn").click();
    await tick();
    assert.equal(window.document.querySelector("#backup-panel").hidden, false);
    assert.match(window.document.querySelector("#backup-nsec").textContent, /^nsec1/);

    // Continue -> app connects and subscribes (render is debounced).
    window.document.querySelector("#backup-done").click();
    await tick(160);
    assert.equal(window.document.querySelector("#lists-view").hidden, false);

    const mySk = JSON.parse(window.localStorage.getItem("gl_sk"));
    const me = core.createLocalIdentity(mySk);
    assert.ok(me.pubkey);

    // Find the subscription a relay opened and grab its id.
    const socket = sockets.find((s) => s.sent.some((m) => m.includes("REQ")));
    assert.ok(socket, "a relay socket should have subscribed");
    const req = socket.sent.map((m) => JSON.parse(m)).find((m) => m[0] === "REQ");
    const subId = req[1];

    // Another npub shares an encrypted list with us.
    const friend = core.newLocalIdentity();
    const listId = core.randomHex(16);
    const listKey = core.randomHex(32);
    const data = core.emptyList("Weekend shop");
    data.items.push(core.newItem("coffee"), core.newItem("oats"));
    const listEvent = await core.makeListEvent(friend, {
      listId,
      members: [friend.pubkey, me.pubkey],
      listKeyHex: listKey,
      data,
    });
    const grant = await core.makeKeyGrant(friend, { listId, recipient: me.pubkey, listKeyHex: listKey });

    socket.emit(["EVENT", subId, listEvent]);
    socket.emit(["EVENT", subId, grant]);
    socket.emit(["EOSE", subId]);
    await tick(160);

    // The list decrypted and rendered as a card.
    const card = window.document.querySelector("#lists-grid .list-card");
    assert.ok(card, "expected a rendered list card");
    assert.match(card.textContent, /Weekend shop/);
    assert.match(card.textContent, /0\/2 done/);

    // Open it and check the items rendered.
    card.click();
    await tick(20);
    assert.equal(window.document.querySelector("#detail-view").hidden, false);
    const items = [...window.document.querySelectorAll("#items .item .text")].map((n) => n.textContent);
    assert.deepEqual(items, ["coffee", "oats"]);

    // Back, then create our own list.
    window.document.querySelector("#back-btn").click();
    await tick(20);
    window.document.querySelector("#new-list-btn").click();
    await tick();
    window.document.querySelector("#ask-input").value = "Party snacks";
    window.document
      .querySelector("#ask-form")
      .dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));
    await tick(40);
    assert.equal(window.document.querySelector("#detail-view").hidden, false);
    assert.equal(window.document.querySelector("#list-title").value, "Party snacks");

    // Share it with a third npub.
    const third = core.newLocalIdentity();
    window.document.querySelector("#share-btn").click();
    await tick();
    window.document.querySelector("#share-input").value = core.hexToNpub(third.pubkey);
    window.document
      .querySelector("#share-form")
      .dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));
    await tick(60);
    const membersRow = window.document.querySelector("#members-row").textContent;
    assert.match(membersRow, /Shared with/);
    assert.ok(
      membersRow.includes(core.shortNpub(third.pubkey, 8, 4)),
      "the third npub should be listed as a member"
    );
    // A key grant for them was actually published.
    const published = sockets.flatMap((s) => s.sent).map((m) => JSON.parse(m));
    const grantSent = published.some(
      (m) => m[0] === "EVENT" && m[1].kind === 30078 && m[1].tags.some((t) => t[0] === "t" && t[1] === "grocery-key")
    );
    assert.ok(grantSent, "a key grant should have been published");
  } finally {
    for (const id of intervals) clearInterval(id);
    for (const s of sockets) {
      try {
        s.close();
      } catch (_) {}
    }
    dom.window.close();
  }
});
