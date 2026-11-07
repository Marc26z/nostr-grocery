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
  sockets.length = 0; // start each test with a clean relay ledger

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

    // Attach a note to the first item; it is stored NIP-44 encrypted.
    window.document.querySelector("#items .item .note").click();
    await tick();
    window.document.querySelector("#note-input").value = "the oat one";
    window.document
      .querySelector("#note-form")
      .dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));
    await tick(40);
    assert.equal(window.document.querySelector("#items .item .item-note").textContent, "the oat one");
    const savedMeta = JSON.parse(window.localStorage.getItem("gl_lists"));
    const savedList = Object.values(savedMeta).find((m) => m.name === "Weekend shop");
    const savedNote = savedList.data.items[0].note;
    assert.ok(savedNote && savedNote !== "the oat one", "the note should be stored encrypted");
    assert.equal(core.decryptNote(listKey, savedNote), "the oat one");
    await tick(900); // let the debounced save/publish settle before this session closes

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

test("lists persist and reappear after the app is closed and reopened", async () => {
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
  const snapshotStorage = (window) => {
    const out = {};
    for (let i = 0; i < window.localStorage.length; i++) {
      const k = window.localStorage.key(i);
      out[k] = window.localStorage.getItem(k);
    }
    return out;
  };
  const closeSockets = () => {
    for (const s of sockets) {
      try {
        s.close();
      } catch (_) {}
    }
  };

  const intervals = [];
  const realSetInterval = globalThis.setInterval;
  globalThis.setInterval = (...args) => {
    const id = realSetInterval(...args);
    intervals.push(id);
    return id;
  };

  let stored = null;
  try {
    /* ---- first session: create a list, add an item, then "close" ---- */
    const dom1 = new JSDOM(html, { url: "https://grocery.test/", pretendToBeVisual: true });
    installGlobals(dom1.window);
    sockets.length = 0;
    await import(`../app.js?persist=first-${Date.now()}`);
    dom1.window.document.dispatchEvent(new dom1.window.Event("DOMContentLoaded"));
    await tick(20);

    dom1.window.document.querySelector("#gen-btn").click();
    await tick();
    dom1.window.document.querySelector("#backup-done").click();
    await tick(160);

    dom1.window.document.querySelector("#new-list-btn").click();
    await tick();
    dom1.window.document.querySelector("#ask-input").value = "Persisted shop";
    dom1.window.document
      .querySelector("#ask-form")
      .dispatchEvent(new dom1.window.Event("submit", { bubbles: true, cancelable: true }));
    await tick(40);
    assert.equal(dom1.window.document.querySelector("#list-title").value, "Persisted shop");

    dom1.window.document.querySelector("#add-input").value = "milk";
    dom1.window.document
      .querySelector("#add-form")
      .dispatchEvent(new dom1.window.Event("submit", { bubbles: true, cancelable: true }));
    await tick(40);

    // The decrypted list must be written to storage (not just its key).
    const saved = JSON.parse(dom1.window.localStorage.getItem("gl_lists"));
    const entry = Object.values(saved)[0];
    assert.ok(entry && entry.data, "the list's decrypted data should be persisted");
    assert.equal(entry.data.name, "Persisted shop");
    assert.deepEqual(
      entry.data.items.map((i) => i.text),
      ["milk"]
    );

    stored = snapshotStorage(dom1.window);
    closeSockets();
    dom1.window.close();

    /* ---- second session: reopen with that storage but no relay data ---- */
    const dom2 = new JSDOM(html, { url: "https://grocery.test/", pretendToBeVisual: true });
    installGlobals(dom2.window);
    for (const [k, v] of Object.entries(stored)) dom2.window.localStorage.setItem(k, v);
    sockets.length = 0;
    await import(`../app.js?persist=second-${Date.now()}`);
    dom2.window.document.dispatchEvent(new dom2.window.Event("DOMContentLoaded"));
    await tick(160);

    try {
      // No relay ever emitted an event, yet the list must be visible again.
      const card = dom2.window.document.querySelector("#lists-grid .list-card");
      assert.ok(card, "the list should reappear after reopening the app");
      assert.match(card.textContent, /Persisted shop/);
      assert.match(card.textContent, /0\/1 done/);

      // And it opens with its items intact.
      card.click();
      await tick(20);
      const items = [...dom2.window.document.querySelectorAll("#items .item .text")].map(
        (n) => n.textContent
      );
      assert.deepEqual(items, ["milk"]);
    } finally {
      closeSockets();
      dom2.window.close();
    }
  } finally {
    for (const id of intervals) clearInterval(id);
  }
});
