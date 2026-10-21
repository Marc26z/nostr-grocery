/* Headless smoke test for the household (product catalog + stock) feature:
 * boots the app in jsdom, signs in, creates a household, adds a product,
 * buys and consumes stock, and checks that the right event hits the relays. */
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

const submit = (window, sel) =>
  window.document.querySelector(sel).dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));

test("household: create, catalog a product, buy and consume stock", async () => {
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
  sockets.length = 0;

  const intervals = [];
  const realSetInterval = globalThis.setInterval;
  globalThis.setInterval = (...args) => {
    const id = realSetInterval(...args);
    intervals.push(id);
    return id;
  };

  try {
    const core = await import("../src/core.js");
    await import(`../app.js?household=${Date.now()}`);
    window.document.dispatchEvent(new window.Event("DOMContentLoaded"));
    await tick(20);

    // Sign in with a fresh local identity.
    window.document.querySelector("#gen-btn").click();
    await tick();
    window.document.querySelector("#backup-done").click();
    await tick(160);
    assert.equal(window.document.querySelector("#lists-view").hidden, false);

    // Create a household from the lists header.
    window.document.querySelector("#new-household-btn").click();
    await tick();
    window.document.querySelector("#ask-input").value = "Home";
    submit(window, "#ask-form");
    await tick(160);

    assert.equal(window.document.querySelector("#household-view").hidden, false);
    assert.equal(window.document.querySelector("#h-title").value, "Home");

    // Empty household prompts for a first product.
    assert.match(window.document.querySelector("#h-stock-list").textContent, /No products yet/);

    // Add a product through the Products tab.
    window.document.querySelector('button[data-tab="products"]').click();
    await tick(20);
    window.document.querySelector("#h-new-product").click();
    await tick();
    window.document.querySelector("#p-name").value = "Milk";
    window.document.querySelector("#p-cat").value = "Dairy";
    window.document.querySelector("#p-unit").value = "l";
    window.document.querySelector("#p-min").value = "2";
    submit(window, "#prod-form");
    await tick(120);
    assert.equal(window.document.querySelector("#modal").hidden, true);
    assert.match(window.document.querySelector("#h-products-list").textContent, /Milk/);
    assert.match(window.document.querySelector("#h-products-list").textContent, /min 2/);

    // It shows up in the stock tab, flagged low with nothing in stock.
    window.document.querySelector('button[data-tab="stock"]').click();
    await tick(20);
    const rowText = () => window.document.querySelector("#h-stock-list .stock-row").textContent;
    assert.match(rowText(), /Milk/);
    assert.match(rowText(), /0 l/);
    assert.match(rowText(), /low/);

    // Buy 3 liters.
    window.document.querySelector('#h-stock-list [data-act="buy"]').click();
    await tick();
    window.document.querySelector("#b-qty").value = "3";
    submit(window, "#buy-form");
    await tick(120);
    assert.match(rowText(), /3 l/);
    assert.ok(!/low/.test(rowText()), "3 l is at/above the minimum, no low badge");

    // Consume 1 liter.
    window.document.querySelector('#h-stock-list [data-act="consume"]').click();
    await tick();
    assert.match(window.document.querySelector("#modal-body").textContent, /3 l in stock/);
    submit(window, "#eat-form");
    await tick(120);
    assert.match(rowText(), /2 l/);

    // The household event really was published, tagged as a household.
    const published = sockets
      .flatMap((s) => s.sent)
      .map((m) => JSON.parse(m))
      .filter((m) => m[0] === "EVENT" && m[1].kind === 30078);
    const householdEv = published.find((m) => m[1].tags.some((t) => t[0] === "t" && t[1] === "grocery-household"));
    assert.ok(householdEv, "a grocery-household event should have been published");

    // And the decrypted data is cached for offline reloads, with its type.
    const cached = Object.values(JSON.parse(window.localStorage.getItem("gl_lists")))[0];
    assert.equal(cached.data.type, "household");
    assert.equal(cached.data.products[0].name, "Milk");
    assert.ok(cached.data.stock.length >= 1);

    // Reopen with that cache but no relay data: the household still shows.
    const stored = {};
    for (let i = 0; i < window.localStorage.length; i++) {
      const k = window.localStorage.key(i);
      stored[k] = window.localStorage.getItem(k);
    }
    for (const s of sockets) {
      try {
        s.close();
      } catch (_) {}
    }
    const dom2 = new JSDOM(html, { url: "https://grocery.test/", pretendToBeVisual: true });
    for (const [name, value] of Object.entries({
      window: dom2.window,
      document: dom2.window.document,
      navigator: dom2.window.navigator,
      location: dom2.window.location,
      history: dom2.window.history,
      localStorage: dom2.window.localStorage,
      crypto: webcrypto,
      WebSocket: MockWebSocket,
    })) {
      setGlobal(name, value);
    }
    for (const [k, v] of Object.entries(stored)) dom2.window.localStorage.setItem(k, v);
    sockets.length = 0;
    await import(`../app.js?household-reload=${Date.now()}`);
    dom2.window.document.dispatchEvent(new dom2.window.Event("DOMContentLoaded"));
    await tick(160);

    try {
      const card2 = dom2.window.document.querySelector("#lists-grid .household-card");
      assert.ok(card2, "the household should reappear from the local cache");
      assert.match(card2.textContent, /Home/);
      card2.click();
      await tick(40);
      assert.match(dom2.window.document.querySelector("#h-stock-list").textContent, /Milk/);
      assert.match(dom2.window.document.querySelector("#h-stock-list").textContent, /2 l/);
    } finally {
      dom2.window.close();
    }
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

test("household: another npub joins by list key and sees the stock", async () => {
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
  sockets.length = 0;

  const intervals = [];
  const realSetInterval = globalThis.setInterval;
  globalThis.setInterval = (...args) => {
    const id = realSetInterval(...args);
    intervals.push(id);
    return id;
  };

  try {
    const core = await import(`../src/core.js?hh=${Date.now()}`);
    await import(`../app.js?household-join=${Date.now()}`);
    window.document.dispatchEvent(new window.Event("DOMContentLoaded"));
    await tick(20);

    window.document.querySelector("#gen-btn").click();
    await tick();
    window.document.querySelector("#backup-done").click();
    await tick(160);

    // Find our subscription so we can replay what the owner published.
    const socket = sockets.find((s) => s.sent.some((m) => m.includes("REQ")));
    assert.ok(socket, "a relay socket should have subscribed");
    const req = socket.sent.map((m) => JSON.parse(m)).find((m) => m[0] === "REQ");
    const subId = req[1];

    // An owner shares their household with us (event + key grant).
    const owner = core.newLocalIdentity();
    const householdId = core.randomHex(16);
    const householdKey = core.randomHex(32);
    const myPub = core.createLocalIdentity(JSON.parse(window.localStorage.getItem("gl_sk"))).pubkey;
    const data = core.emptyHousehold("Shared pantry");
    const p = core.newProduct({ name: "Pasta", category: "Dry goods", unit: "packs", minQty: 1 });
    data.products.push(p);
    data.stock.push(core.newStockEntry(p.id, 2, null, owner.pubkey));
    const ev = await core.makeListEvent(owner, {
      listId: householdId,
      members: [owner.pubkey, myPub],
      listKeyHex: householdKey,
      data,
    });
    const grant = await core.makeKeyGrant(owner, {
      listId: householdId,
      recipient: myPub,
      listKeyHex: householdKey,
    });

    socket.emit(["EVENT", subId, ev]);
    socket.emit(["EVENT", subId, grant]);
    await tick(160);

    const card = window.document.querySelector("#lists-grid .household-card");
    assert.ok(card, "the shared household should render as a card");
    assert.match(card.textContent, /Shared pantry/);
    assert.match(card.textContent, /1\/1 in stock/);

    // Open it: the catalog and stock are readable, and the tab shows the qty.
    card.click();
    await tick(40);
    assert.equal(window.document.querySelector("#household-view").hidden, false);
    assert.match(window.document.querySelector("#h-stock-list").textContent, /Pasta/);
    assert.match(window.document.querySelector("#h-stock-list").textContent, /2 packs/);

    // The Low filter flags it: min 1... it has 2 packs, so it should NOT be low.
    window.document.querySelector('button[data-filter="low"]').click();
    await tick(20);
    assert.match(window.document.querySelector("#h-stock-list").textContent, /No matching products/);
    window.document.querySelector('button[data-filter="all"]').click();
    await tick(20);
    assert.match(window.document.querySelector("#h-stock-list").textContent, /Pasta/);
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
