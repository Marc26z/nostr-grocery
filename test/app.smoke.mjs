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
import { getPublicKey, finalizeEvent, generateSecretKey, verifyEvent } from "nostr-tools/pure";
import * as nip44 from "nostr-tools/nip44";
import { matchFilters } from "nostr-tools/filter";

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

test("signs in with a NIP-46 mobile signer (nostrconnect QR flow)", async () => {
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

  const intervals = [];
  const realSetInterval = globalThis.setInterval;
  globalThis.setInterval = (...args) => {
    const id = realSetInterval(...args);
    intervals.push(id);
    return id;
  };

  const core = await import("../src/core.js");
  await import(`../app.js?v=${Date.now()}`);
  window.document.dispatchEvent(new window.Event("DOMContentLoaded"));
  await tick(30);
  assert.equal(window.document.querySelector("#login-view").hidden, false);

  // We play the mobile signer. The app will end up signing as `user`.
  const user = core.newLocalIdentity();
  const signerSk = generateSecretKey();
  const signerPub = getPublicKey(signerSk);
  const now = () => Math.floor(Date.now() / 1000);

  // Open the signer dialog and read the nostrconnect:// token it generated.
  window.document.querySelector("#signer-btn").click();
  await tick(30);
  assert.equal(window.document.querySelector("#modal").hidden, false);
  const link = window.document.querySelector('#modal a[href^="nostrconnect://"]');
  assert.ok(link, "signer modal should offer a nostrconnect:// link");
  const uri = link.getAttribute("href");
  const token = uri.match(/^nostrconnect:\/\/([0-9a-f]{64})\?(.*)$/);
  assert.ok(token, "token should carry a client pubkey");
  const clientPub = token[1];
  const secret = new URLSearchParams(token[2]).get("secret");
  assert.ok(secret, "token should carry a secret");

  // The app listens for a kind-24133 response on a socket+subid it opened.
  // Prefer the sub subscribed to a specific author (the BunkerSigner session)
  // over the broad "p-tag me" sub used during the initial handshake.
  const subForEvent = (ev) => {
    let fallback = null;
    for (const s of sockets) {
      for (const raw of s.sent) {
        let parsed;
        try {
          parsed = JSON.parse(raw);
        } catch (_) {
          continue;
        }
        if (parsed[0] !== "REQ") continue;
        if (!matchFilters(parsed.slice(2), ev)) continue;
        const hit = { socket: s, subId: parsed[1] };
        if (parsed.slice(2).some((f) => Array.isArray(f?.authors) && f.authors.includes(ev.pubkey))) return hit;
        fallback ||= hit;
      }
    }
    return fallback;
  };

  // Our fake signer answers a client's request, encrypted under its key.
  const signerReplyTo = async (ev) => {
    if (!ev || ev.kind !== 24133 || ev.pubkey === signerPub) return null;
    let req;
    let ck;
    try {
      ck = nip44.getConversationKey(signerSk, ev.pubkey);
      req = JSON.parse(nip44.decrypt(ev.content, ck));
    } catch (_) {
      return null;
    }
    let result;
    if (req.method === "get_public_key") result = user.pubkey;
    else if (req.method === "connect") result = "ack";
    else if (req.method === "ping") result = "pong";
    else if (req.method === "sign_event") result = JSON.stringify(finalizeEvent(JSON.parse(req.params[0]), user.secretKey));
    else return null;
    const content = await nip44.encrypt(JSON.stringify({ id: req.id, result }), ck);
    return finalizeEvent(
      { kind: 24133, created_at: now(), tags: [["p", ev.pubkey]], content },
      signerSk
    );
  };

  // Approve the handshake: a connect response carrying the secret.
  const handshake = finalizeEvent(
    {
      kind: 24133,
      created_at: now(),
      tags: [["p", clientPub]],
      content: await nip44.encrypt(JSON.stringify({ id: "gr-0", result: secret }), nip44.getConversationKey(signerSk, clientPub)),
    },
    signerSk
  );
  const target = subForEvent(handshake);
  assert.ok(target, "the app should be subscribed to signer responses");
  target.socket.emit(["EVENT", target.subId, handshake]);

  // Keep answering requests (get_public_key, sign_event…) until the app signs in.
  const answered = new Set();
  const driveUntil = async (predicate, maxMs = 6000) => {
    const start = Date.now();
    while (Date.now() - start < maxMs) {
      for (const s of sockets) {
        for (const raw of s.sent) {
          let parsed;
          try {
            parsed = JSON.parse(raw);
          } catch (_) {
            continue;
          }
          if (parsed[0] !== "EVENT") continue;
          const ev = parsed[1];
          if (answered.has(ev.id)) continue;
          const reply = await signerReplyTo(ev);
          if (!reply) continue;
          answered.add(ev.id);
          const to = subForEvent(reply);
          if (to) to.socket.emit(["EVENT", to.subId, reply]);
        }
      }
      if (predicate()) return true;
      await tick(40);
    }
    return predicate();
  };

  assert.ok(
    await driveUntil(() => window.document.querySelector("#lists-view").hidden === false),
    "the app should sign in after the signer approves"
  );

  // The session is saved so reloads restore it without re-approving.
  const saved = JSON.parse(window.localStorage.getItem("gl_nip46"));
  assert.equal(saved.remote, signerPub);
  assert.equal(saved.user, user.pubkey);
  assert.ok(saved.sk && saved.relays.length > 0);

  // A real signing action flows through the signer: create a new list.
  window.document.querySelector("#new-list-btn").click();
  await tick();
  window.document.querySelector("#ask-input").value = "Signer shop";
  window.document
    .querySelector("#ask-form")
    .dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));
  assert.ok(
    await driveUntil(() => window.document.querySelector("#detail-view").hidden === false, 4000)
  );
  assert.equal(window.document.querySelector("#list-title").value, "Signer shop");
  await tick(200);

  // The list + self-grant were published, properly signed by the user key.
  const published = sockets
    .flatMap((s) => s.sent)
    .map((m) => JSON.parse(m))
    .filter((m) => m[0] === "EVENT" && m[1].kind === 30078);
  assert.ok(published.length >= 2, "list + key grant should be published");
  for (const [, ev] of published) {
    assert.equal(ev.pubkey, user.pubkey);
    assert.equal(verifyEvent(ev), true);
  }

  // Signing out clears the nip46 session.
  window.document.querySelector("#identity-btn").click();
  await tick();
  window.document.querySelector("#id-signout").click();
  await tick();
  window.document.querySelector("#cf-yes").click();
  await tick(50);

  try {
    for (const id of intervals) clearInterval(id);
  } finally {
    for (const s of sockets) {
      try {
        s.close();
      } catch (_) {}
    }
    dom.window.close();
  }
});
