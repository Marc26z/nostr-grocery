/* =========================================================================
 * Grocery — a shared, end-to-end encrypted shopping list over Nostr.
 *
 * Everything is client-side: the list contents are AES-256-GCM encrypted
 * under a random per-list key, and that key is handed to each member
 * encrypted to their Nostr pubkey (NIP-44, or NIP-04 as a fallback). Relays
 * only ever see ciphertext.
 * ========================================================================= */

import {
  LIST_KIND,
  newLocalIdentity,
  createLocalIdentity,
  createNip07Identity,
  createNip46Identity,
  createPasskeyIdentity,
  createPasskeySecret,
  passkeySecret,
  passkeysSupported,
  createBunkerSigner,
  connectBunkerLink,
  bunkerUserPubkey,
  makeNostrConnect,
  awaitNostrConnect,
  encodeSecret,
  decodeSecret,
  npubToHex,
  hexToNpub,
  hexToBytes,
  shortNpub,
  emptyList,
  newItem,
  encryptList,
  decryptList,
  randomHex,
  makeListEvent,
  makeKeyGrant,
  parseListEvent,
  parseKeyGrant,
  openKeyGrant,
  listDTag,
} from "./src/core.js";
import { SimplePool } from "./vendor/nostr.js";
import { qrSvg } from "./vendor/qr.js";
import { createMarmotAdapter } from "./src/marmot.js";
import { wrapIdentityAsSigner } from "./src/marmot-identity.js";


/* ------------------------------- config --------------------------------- */

const RELAYS = [
  "wss://relay.damus.io",
  "wss://nos.lol",
  "wss://relay.primal.net",
  "wss://relay.nostr.band",
  "wss://nostr.mom",
  "wss://relay.snort.social",
];

// Relays used for NIP-46 signer chatter (kind 24133). They must forward
// ephemeral events addressed to us with a `p` tag.
const SIGNER_RELAYS = ["wss://nos.lol", "wss://relay.damus.io", "wss://relay.primal.net", "wss://nostr.mom"];

/* -------------------------------- dom ----------------------------------- */

const $ = (sel) => document.querySelector(sel);
const loginView = $("#login-view");
const listsView = $("#lists-view");
const detailView = $("#detail-view");
const modalEl = $("#modal");
const modalBody = $("#modal-body");
const toastEl = $("#toast");

/* ------------------------------- state ---------------------------------- */

const state = {
  identity: null,
  pool: null,
  sub: null,
  lists: new Map(), // listId -> list
  grants: new Map(), // listId -> parsed key grant (latest)
  extraFilters: [], // targeted filters for imported invite links
  openListId: null,
  publishTimers: new Map(),
  marmot: null,
  marmotGroups: new Map(),
  activeChatGroup: null,
  chatSub: null,
  chatMessages: [],
  historyGen: null,
};

/* ----------------------------- persistence ------------------------------ */

const store = {
  get: (k, d = null) => {
    try {
      const v = localStorage.getItem(k);
      return v == null ? d : JSON.parse(v);
    } catch (_) {
      return d;
    }
  },
  set: (k, v) => {
    try {
      localStorage.setItem(k, JSON.stringify(v));
    } catch (_) {}
  },
  del: (k) => {
    try {
      localStorage.removeItem(k);
    } catch (_) {}
  },
};

function loadMeta() {
  return store.get("gl_lists", {});
}

function saveMeta() {
  const out = {};
  for (const l of state.lists.values()) {
    if (!l.key) continue;
    out[l.id] = { key: l.key, name: l.data?.name || l.name || "", owner: l.owner || null };
  }
  store.set("gl_lists", out);
}

/* ------------------------------- helpers -------------------------------- */

function show(el) {
  for (const v of [loginView, listsView, detailView]) v.hidden = v !== el;
}

function toast(text, ms = 2400) {
  toastEl.textContent = text;
  toastEl.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => (toastEl.hidden = true), ms);
}

async function copy(text, msg = "Copied") {
  try {
    await navigator.clipboard.writeText(text);
    toast(msg);
  } catch (_) {
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand("copy");
      toast(msg);
    } catch (_) {
      toast("Copy failed");
    }
    ta.remove();
  }
}

function initials(hex) {
  const n = parseInt((hex || "00").slice(0, 2), 16) || 0;
  return String.fromCharCode(65 + (n % 26));
}

function avatarsHtml(members) {
  const list = [...members].slice(0, 3);
  const extra = members.size - list.length;
  return `<span class="avatars">${list
    .map((m) => `<i title="${hexToNpub(m)}">${initials(m)}</i>`)
    .join("")}${extra > 0 ? `<i>+${extra}</i>` : ""}</span>`;
}

let renderTimer = null;
function scheduleRender() {
  if (renderTimer) return;
  renderTimer = setTimeout(() => {
    renderTimer = null;
    render();
  }, 80);
}

/* ------------------------------- identity -------------------------------- */

async function boot() {
  initTheme();
  bindUI();
  state.pool = new SimplePool();

  const sk = store.get("gl_sk");
  if (sk) {
    try {
      state.identity = createLocalIdentity(sk);
    } catch (_) {
      store.del("gl_sk");
    }
  } else if (store.get("gl_nip46")) {
    state.identity = restoreNip46();
  } else if (store.get("gl_ext") === true && window.nostr) {
    state.identity = createNip07Identity();
    await state.identity.init();
  }

  if (state.identity) startApp();
  else render();

  if (window.nostr && !state.identity) {
    const slot = $("#ext-slot");
    slot.innerHTML = `<button id="ext-btn" class="btn btn-block" type="button">Continue with browser extension</button>`;
    $("#ext-btn").addEventListener("click", async () => {
      try {
        const id = createNip07Identity();
        await id.init();
        state.identity = id;
        store.del("gl_passkey");
        store.set("gl_ext", true);
        startApp();
      } catch (e) {
        loginError(e.message || "Extension refused");
      }
    });
  }

  if (!state.identity && passkeysSupported()) setupPasskeyButton();
}

/* ------------------------------- passkeys -------------------------------- */

function passkeyError(msg) {
  const el = $("#passkey-error");
  if (!el) return;
  el.textContent = msg || "";
  el.hidden = !msg;
}

function setupPasskeyButton() {
  const btn = $("#passkey-btn");
  if (!btn) return;
  const saved = store.get("gl_passkey");
  const hasKey = !!(saved && saved.id);
  btn.hidden = false;
  btn.querySelector(".passkey-label").textContent = hasKey
    ? "Unlock with your passkey"
    : "Create an identity with a passkey";
  btn.addEventListener("click", () => (hasKey ? unlockWithPasskey() : createWithPasskey()));
}

function adoptIdentity(id) {
  state.identity = id;
  store.del("gl_sk");
  store.del("gl_ext");
  store.del("gl_nip46");
  initMarmot();
  startApp();
}

async function createWithPasskey() {
  const btn = $("#passkey-btn");
  passkeyError("");
  btn.disabled = true;
  try {
    const { credentialId, secretKey } = await createPasskeySecret({ userName: "grocery-" + randomHex(4) });
    store.set("gl_passkey", { id: credentialId });
    adoptIdentity(createPasskeyIdentity(secretKey, credentialId));
    toast("Passkey identity created");
  } catch (e) {
    if (e?.name !== "NotAllowedError" && e?.name !== "AbortError") {
      passkeyError(e.message || "Could not create a passkey");
    }
  } finally {
    btn.disabled = false;
  }
}

async function unlockWithPasskey() {
  const saved = store.get("gl_passkey");
  if (!saved || !saved.id) return;
  const btn = $("#passkey-btn");
  passkeyError("");
  btn.disabled = true;
  try {
    const secretKey = await passkeySecret({ credentialId: saved.id });
    adoptIdentity(createPasskeyIdentity(secretKey, saved.id));
    initMarmot();
  } catch (e) {
    if (e?.name !== "NotAllowedError" && e?.name !== "AbortError") {
      passkeyError(e.message || "Could not unlock with your passkey");
    }
  } finally {
    btn.disabled = false;
  }
}

function loginError(msg) {
  const el = $("#login-error");
  el.textContent = msg;
  el.hidden = false;
}

function startApp() {
  state.grants = new Map();
  state.lists = new Map();
  state.extraFilters = [];

  const meta = loadMeta();
  for (const [id, m] of Object.entries(meta)) {
    if (!m || !m.key) continue;
    state.lists.set(id, newList(id, { key: m.key, name: m.name, owner: m.owner }));
  }

  importInviteFromHash();
  connect();
  startConnPoll();
  initMarmot();

  scheduleRender();
}

function newList(id, opts = {}) {
  return {
    id,
    key: opts.key || null,
    owner: opts.owner || null,
    data: null,
    payload: null,
    payloadAt: 0,
    createdAt: 0,
    author: null,
    members: new Set(),
    name: opts.name || "",
    locked: false,
  };
}

/* --------------------------- signer identity ----------------------------- */

let signerAbort = null;

function clientMetadata() {
  return { name: "Grocery", url: location.origin + location.pathname };
}

function saveNip46({ clientSecretKey, remotePubkey, relays, secret, userPubkey }) {
  store.set("gl_nip46", {
    sk: bytesToHex(clientSecretKey),
    remote: remotePubkey,
    relays,
    secret: secret || null,
    user: userPubkey,
  });
}

function restoreNip46() {
  const c = store.get("gl_nip46");
  if (!c || !c.sk || !c.remote || !c.user || !Array.isArray(c.relays)) return null;
  try {
    const signer = createBunkerSigner({
      clientSecretKey: hexToBytes(c.sk),
      remotePubkey: c.remote,
      relays: c.relays,
      secret: c.secret,
      pool: state.pool,
    });
    return createNip46Identity({ signer, pubkey: c.user });
  } catch (_) {
    store.del("gl_nip46");
    return null;
  }
}

function finishSignerLogin({ clientSecretKey, remotePubkey, relays, secret, userPubkey, signer }) {
  state.identity = createNip46Identity({ signer, pubkey: userPubkey });
  store.del("gl_sk");
  store.del("gl_ext");
  store.del("gl_passkey");
  saveNip46({ clientSecretKey, remotePubkey, relays, secret, userPubkey });
  closeModal();
  toast("Signed in with your signer");
  startApp();
}

async function connectWithBunker(input) {
  const { signer, pubkey, bp, clientSecretKey } = await connectBunkerLink({
    input,
    pool: state.pool,
    metadata: clientMetadata(),
  });
  finishSignerLogin({
    clientSecretKey,
    remotePubkey: bp.pubkey,
    relays: bp.relays,
    secret: bp.secret,
    userPubkey: pubkey,
    signer,
  });
}

/* ------------------------------ relay layer ------------------------------ */

function connect() {
  if (state.sub) state.sub.close();
  if (!state.pool) state.pool = new SimplePool();

  const me = state.identity.pubkey;
  const filters = [
    { kinds: [LIST_KIND], "#p": [me] },
    { kinds: [LIST_KIND], authors: [me] },
    // Gift-wrapped Marmot chat invites (kind 1059) addressed to us.
    { kinds: [1059], "#p": [me] },
    ...state.extraFilters,
  ];
  setConn("connecting", "Connecting…");
  state.sub = state.pool.subscribeMany(RELAYS, filters, {
    onevent: (ev) => {
      if (ev.kind === 1059) handleGiftWrap(ev);
      else ingest(ev);
    },
    onclose: () => {},
  });
}

function startConnPoll() {
  if (startConnPoll._t) return;
  startConnPoll._t = setInterval(() => {
    if (!state.pool) return;
    const status = state.pool.listConnectionStatus();
    const open = [...status.values()].filter(Boolean).length;
    if (open > 0) setConn("online", `Live · ${open}`);
    else setConn("offline", "Offline");
  }, 4000);
}

function setConn(s, text) {
  const el = $("#conn-status");
  if (el) el.dataset.state = s;
  if (text) $("#conn-text").textContent = text;
}

async function publishEvent(ev) {
  if (!state.pool) return 0;
  const results = await Promise.allSettled(state.pool.publish(RELAYS, ev));
  const ok = results.filter((r) => r.status === "fulfilled").length;
  if (ok === 0) {
    toast("No relay accepted the update");
    setConn("error", "No relays");
  } else {
    setConn("online", "Live");
  }
  return ok;
}

/* -------------------------------- ingest --------------------------------- */

async function ingest(ev) {
  const grant = parseKeyGrant(ev);
  if (grant && grant.recipient === state.identity.pubkey) {
    const prev = state.grants.get(grant.listId);
    if (!prev || grant.createdAt >= prev.createdAt) {
      state.grants.set(grant.listId, grant);
      resolveKey(grant.listId);
    }
    return;
  }

  const parsed = parseListEvent(ev);
  if (!parsed) return;

  let l = state.lists.get(parsed.listId);
  if (!l) {
    l = newList(parsed.listId);
    state.lists.set(parsed.listId, l);
  }

  if (parsed.createdAt >= l.createdAt) {
    l.createdAt = parsed.createdAt;
    l.author = parsed.author;
    l.payload = parsed.payload;
    l.payloadAt = parsed.createdAt;
    for (const m of parsed.members) l.members.add(m);
    if (!l.key) resolveKey(parsed.listId); // a grant may have arrived before the list
    await syncList(l, parsed.createdAt);
  }
  scheduleRender();
}

async function syncList(l, at) {
  if (!l.key || !l.payload) return;
  try {
    const data = await decryptList(l.key, l.payload);
    if (at != null && l.payloadAt !== at) return; // a newer event arrived meanwhile
    if (data && typeof data === "object") {
      if (!Array.isArray(data.items)) data.items = [];
      data.name = typeof data.name === "string" ? data.name : l.name || "Grocery list";
      l.data = data;
      l.name = data.name;
      l.locked = false;
      saveMeta();
    }
  } catch (_) {
    l.locked = true;
  }
}

async function resolveKey(listId) {
  const l = state.lists.get(listId);
  if (!l || l.key) return;
  const grant = state.grants.get(listId);
  if (!grant) return;
  try {
    const key = (await openKeyGrant(state.identity, grant)).trim();
    if (!/^[0-9a-f]{64}$/i.test(key)) return;
    l.key = key.toLowerCase();
    l.owner = grant.sender;
    saveMeta();
    await syncList(l, l.payloadAt || null);
    scheduleRender();
  } catch (_) {
    /* grant wasn't for us or signer couldn't decrypt */
  }
}

/* ------------------------------ rendering -------------------------------- */

function render() {
  if (!state.identity) {
    show(loginView);
    return;
  }
  updateIdentityBtn();
  if (state.openListId && state.lists.get(state.openListId)?.data) {
    show(detailView);
    renderDetail(state.lists.get(state.openListId));
  } else {
    state.openListId = null;
    show(listsView);
    renderLists();
  }
}

function updateIdentityBtn() {
  const btn = $("#identity-btn");
  btn.hidden = false;
  $("#ident-npub").textContent = shortNpub(state.identity.pubkey, 12, 4);
}

function renderLists() {
  const lists = [...state.lists.values()].sort((a, b) => b.createdAt - a.createdAt);
  const grid = $("#lists-grid");
  const empty = $("#lists-empty");
  const waiting = lists.filter((l) => l.locked || (!l.key && l.payload));
  const hint = $("#waiting-hint");
  if (waiting.length) {
    hint.hidden = false;
    hint.textContent = `${waiting.length} shared list${waiting.length > 1 ? "s" : ""} waiting for a key…`;
  } else {
    hint.hidden = true;
  }

  const ready = lists.filter((l) => l.data);
  if (ready.length === 0) {
    grid.innerHTML = "";
    grid.hidden = true;
    empty.hidden = false;
    $("#lists-sub").textContent = "";
    return;
  }

  grid.hidden = false;
  empty.hidden = true;
  $("#lists-sub").textContent = `${ready.length} list${ready.length > 1 ? "s" : ""}`;
  grid.innerHTML = ready.map(cardHtml).join("");
  grid.querySelectorAll(".list-card").forEach((el) =>
    el.addEventListener("click", () => openList(el.dataset.id))
  );
}

function cardHtml(l) {
  const items = l.data.items;
  const done = items.filter((i) => i.done).length;
  const pct = items.length ? Math.round((done / items.length) * 100) : 0;
  const count = items.length
    ? `${done}/${items.length} done`
    : "Empty";
  return `
    <article class="list-card" data-id="${l.id}" tabindex="0" role="button" aria-label="${escapeHtml(l.data.name)}">
      <h3>${escapeHtml(l.data.name)}</h3>
      <div class="count">${count}</div>
      <div class="bar"><span style="width:${pct}%"></span></div>
      <div class="foot">
        ${avatarsHtml(l.members)}
        <span class="muted small">${l.members.size} member${l.members.size > 1 ? "s" : ""}</span>
      </div>
    </article>`;
}

function openList(id) {
  const l = state.lists.get(id);
  if (!l) return;
  if (!l.data) {
    toast("Waiting for this list's key…");
    return;
  }
  state.openListId = id;
  render();
}

function renderDetail(l) {
  $("#list-title").value = l.data.name;
  const members = [...l.members];
  $("#members-row").innerHTML = members.length
    ? `<span class="muted small">Shared with</span>` +
      members
        .map(
          (m) =>
            `<span class="member-chip" title="${hexToNpub(m)}">${avatarsHtml(new Set([m]))}${shortNpub(
              m,
              8,
              4
            )}${m === state.identity.pubkey ? ' <span class="you-tag">you</span>' : ""}</span>`
        )
        .join("")
    : "";

  const items = sortItems(l.data.items);
  $("#items-empty").hidden = items.length > 0;
  $("#items").innerHTML = items.map(itemHtml).join("");
}

function sortItems(items) {
  return [...items].sort((a, b) => (a.done === b.done ? 0 : a.done ? 1 : -1));
}

function itemHtml(it) {
  return `
    <li class="item ${it.done ? "done" : ""}" data-id="${it.id}">
      <input class="check" type="checkbox" ${it.done ? "checked" : ""} aria-label="${escapeHtml(it.text)}" />
      <span class="text">${escapeHtml(it.text)}</span>
      <button class="del" type="button" aria-label="Delete item">×</button>
    </li>`;
}

/* ------------------------------- actions --------------------------------- */

async function createList(name) {
  const id = randomHex(16);
  const key = randomHex(32);
  const l = newList(id, { key, name });
  l.data = emptyList(name || "Grocery list");
  l.members.add(state.identity.pubkey);
  l.owner = state.identity.pubkey;
  state.lists.set(id, l);
  saveMeta();

  state.openListId = id;
  render(); // show it right away; sync in the background

  await publishList(l);
  await publishGrant(l, state.identity.pubkey); // self-grant: lets you re-open on other devices
}

async function publishList(l) {
  if (!l.key || !l.data) return;
  const ev = await makeListEvent(state.identity, {
    listId: l.id,
    members: [...l.members],
    listKeyHex: l.key,
    data: l.data,
  });
  l.createdAt = ev.created_at;
  l.author = state.identity.pubkey;
  l.payloadAt = ev.created_at;
  l.locked = false;
  saveMeta();
  await publishEvent(ev);
}

async function publishGrant(l, recipient) {
  if (!l.key) return;
  const ev = await makeKeyGrant(state.identity, {
    listId: l.id,
    recipient,
    listKeyHex: l.key,
  });
  await publishEvent(ev);
}

function queuePublish(l) {
  clearTimeout(state.publishTimers.get(l.id));
  state.publishTimers.set(
    l.id,
    setTimeout(() => {
      state.publishTimers.delete(l.id);
      publishList(l);
    }, 700)
  );
}

function mutate(fn) {
  const l = state.lists.get(state.openListId);
  if (!l || !l.data) return;
  fn(l.data);
  l.name = l.data.name;
  saveMeta();
  renderDetail(l);
  queuePublish(l);
}

async function shareWith(input) {
  const l = state.lists.get(state.openListId);
  if (!l) return;
  let recipient;
  try {
    recipient = npubToHex(input);
  } catch (e) {
    throw new Error(e.message);
  }
  if (recipient === state.identity.pubkey) throw new Error("That's your own key.");
  l.members.add(recipient);
  renderDetail(l); // reflect the new member immediately
  await publishGrant(l, recipient); // hand them the key
  await publishList(l); // add their p tag so they discover it
  const group = state.marmotGroups.get(l.id);
  if (group) inviteMissingMembers(l.id, group, [recipient]); // pull them into the chat if it exists
}

function inviteLink(l) {
  const payload = { o: state.identity.pubkey, l: l.id, k: l.key, n: l.data.name };
  const b64 = b64urlEncode(JSON.stringify(payload));
  return `${location.origin}${location.pathname}#invite=${b64}`;
}

function importInviteFromHash() {
  const m = location.hash.match(/^#invite=(.+)$/);
  if (!m) return;
  try {
    const inv = JSON.parse(b64urlDecode(m[1]));
    if (inv && inv.l && inv.k) {
      const l = state.lists.get(inv.l) || newList(inv.l, { key: inv.k, name: inv.n, owner: inv.o });
      l.key = inv.k;
      l.name = inv.n || l.name;
      l.owner = inv.o || l.owner;
      state.lists.set(inv.l, l);
      saveMeta();
      if (inv.o) {
        state.extraFilters.push({ kinds: [LIST_KIND], authors: [inv.o], "#d": [listDTag(inv.l)] });
      }
      toast("Invite imported");
    }
  } catch (_) {
    /* ignore malformed invite */
  }
  history.replaceState(null, "", location.pathname + location.search);
}

function b64urlEncode(str) {
  const bytes = new TextEncoder().encode(str);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(str) {
  const b = str.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b + "===".slice((b.length + 3) % 4));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

/* ------------------------------- modals ---------------------------------- */

function openModal(html, onMount) {
  modalBody.innerHTML = html;
  modalEl.hidden = false;
  document.body.style.overflow = "hidden";
  if (onMount) onMount(modalBody);
}

function closeModal() {
  if (signerAbort) {
    signerAbort.abort();
    signerAbort = null;
  }
  modalEl.hidden = true;
  modalBody.innerHTML = "";
  document.body.style.overflow = "";
}

function askText({ title, label, placeholder = "", value = "", okLabel = "Create" }) {
  return new Promise((resolve) => {
    openModal(
      `
      <h2>${escapeHtml(title)}</h2>
      <form id="ask-form">
        ${label ? `<label class="field-label">${escapeHtml(label)}</label>` : ""}
        <input id="ask-input" class="input" placeholder="${escapeHtml(placeholder)}" value="${escapeHtml(
        value
      )}" maxlength="120" />
        <div class="share-row"><button class="btn btn-primary btn-block" type="submit">${escapeHtml(
          okLabel
        )}</button></div>
      </form>`,
      () => {
        const input = $("#ask-input");
        input.focus();
        input.select();
        $("#ask-form").addEventListener("submit", (e) => {
          e.preventDefault();
          const v = input.value.trim();
          closeModal();
          resolve(v || null);
        });
      }
    );
  });
}

function confirmAction(title, body, okLabel = "Delete") {
  return new Promise((resolve) => {
    openModal(
      `
      <h2>${escapeHtml(title)}</h2>
      <p class="muted">${escapeHtml(body)}</p>
      <div class="share-row">
        <button id="cf-no" class="btn btn-block" type="button">Cancel</button>
        <button id="cf-yes" class="btn btn-danger btn-block" type="button">${escapeHtml(okLabel)}</button>
      </div>`,
      () => {
        $("#cf-no").addEventListener("click", () => {
          closeModal();
          resolve(false);
        });
        $("#cf-yes").addEventListener("click", () => {
          closeModal();
          resolve(true);
        });
      }
    );
  });
}

function openShareModal() {
  const l = state.lists.get(state.openListId);
  if (!l) return;
  const renderMembers = () => {
    const rows = [...l.members].map((m) => {
      const you = m === state.identity.pubkey;
      return `<li><span class="avatars"><i>${initials(m)}</i></span><span class="who">${hexToNpub(
        m
      )}</span>${you ? '<span class="you-tag">you</span>' : ""}</li>`;
    });
    return rows.join("");
  };
  openModal(
    `
    <h2>Share “${escapeHtml(l.data.name)}”</h2>
    <p class="muted small">
      Add someone by npub. They receive the list key encrypted to their key, so only they can read it.
    </p>
    <form id="share-form" class="share-row">
      <input id="share-input" class="input" placeholder="npub1… or nprofile…" autocomplete="off" spellcheck="false" />
      <button class="btn btn-primary" type="submit">Add</button>
    </form>
    <p id="share-error" class="error" hidden></p>
    <h3>Members</h3>
    <ul class="members-list">${renderMembers()}</ul>
    <div class="invite">
      <button id="copy-invite" class="btn btn-block" type="button">Copy invite link</button>
      <p class="muted small" style="margin-top:8px">
        Anyone with the link can read and edit this list, so share it only with people you trust.
      </p>
    </div>`,
    () => {
      $("#share-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        const input = $("#share-input");
        const err = $("#share-error");
        err.hidden = true;
        const btn = e.submitter || e.target.querySelector("button");
        btn.disabled = true;
        try {
          await shareWith(input.value);
          input.value = "";
          toast("Shared");
          openShareModal(); // re-render member list
        } catch (ex) {
          err.textContent = ex.message || "Could not share";
          err.hidden = false;
        } finally {
          btn.disabled = false;
        }
      });
      $("#copy-invite").addEventListener("click", () => copy(inviteLink(l), "Invite link copied"));
    }
  );
}

async function deleteList(l) {
  const ok = await confirmAction(
    "Delete this list?",
    "This removes the list from your device and deletes the copy you published. Other members keep their own copy."
  );
  if (!ok) return;
  const del = {
    kind: 5,
    created_at: Math.floor(Date.now() / 1000),
    tags: [
      ["a", `${LIST_KIND}:${state.identity.pubkey}:${listDTag(l.id)}`],
      ["k", String(LIST_KIND)],
    ],
    content: "deleted",
  };
  try {
    const ev = await state.identity.signEvent(del);
    await publishEvent(ev);
  } catch (_) {}
  state.lists.delete(l.id);
  state.openListId = null;
  saveMeta();
  toast("List deleted");
  render();
}

/* -------------------------------- theme ---------------------------------- */

function applyTheme(theme) {
  const next = theme === "light" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  store.set("gl_theme", next);
  syncThemeBtn();
}

function syncThemeBtn() {
  const btn = $("#theme-btn");
  if (!btn) return;
  const light = document.documentElement.getAttribute("data-theme") === "light";
  btn.querySelector(".theme-icon").textContent = light ? "☀️" : "🌙";
}

function initTheme() {
  $("#theme-btn").addEventListener("click", () => {
    applyTheme(document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light");
  });
  syncThemeBtn();
}

/* ------------------------------ escape html ------------------------------ */

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/* ------------------------------- bind ui --------------------------------- */

function bindUI() {
  document.addEventListener("click", (e) => {
    if (e.target.dataset.close !== undefined) closeModal();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { closeModal(); closeChatModal(); }
  });

  // login
  $("#signer-btn").addEventListener("click", openSignerModal);
  $("#gen-btn").addEventListener("click", () => {
    const id = newLocalIdentity();
    state.identity = id;
    store.del("gl_nip46");
    store.del("gl_passkey");
    store.set("gl_sk", bytesToHex(id.secretKey));
    const nsec = encodeSecret(id.secretKey);
    const npub = hexToNpub(id.pubkey);
    $("#backup-nsec").textContent = nsec;
    $("#backup-npub").textContent = npub;
    loginView.querySelector(".login-card").hidden = true;
    $("#backup-panel").hidden = false;
  });
  $("#backup-copy").addEventListener("click", () => copy($("#backup-nsec").textContent, "Secret key copied"));
  $("#backup-npub-copy").addEventListener("click", () => copy($("#backup-npub").textContent, "npub copied"));
  $("#backup-done").addEventListener("click", () => {
    loginView.querySelector(".login-card").hidden = false;
    $("#backup-panel").hidden = true;
    startApp();
  });
  $("#import-btn").addEventListener("click", () => {
    try {
      const sk = decodeSecret($("#nsec-input").value);
      const id = createLocalIdentity(sk);
      state.identity = id;
      store.set("gl_sk", bytesToHex(id.secretKey));
      store.del("gl_ext");
      store.del("gl_nip46");
      store.del("gl_passkey");
      startApp();
    } catch (e) {
      loginError(e.message);
    }
  });

  // lists
  $("#new-list-btn").addEventListener("click", promptNewList);
  $("#empty-new-btn").addEventListener("click", promptNewList);

  // detail
  $("#back-btn").addEventListener("click", () => {
    state.openListId = null;
    render();
  });
  $("#share-btn").addEventListener("click", openShareModal);
  // chat
  const chatBtn = $("#chat-btn");
  if (chatBtn) {
    chatBtn.addEventListener("click", () => {
      openChatModal();
    });
  }
  const chatClose = document.querySelectorAll("[data-close-chat]");
  chatClose.forEach(b => b.addEventListener("click", closeChatModal));
  const chatForm = $("#chat-form");
  if (chatForm) {
    chatForm.addEventListener("submit", (e) => {
      e.preventDefault();
      sendChatMessage();
    });
  }

  $("#list-title").addEventListener("input", (e) => {
    const l = state.lists.get(state.openListId);
    if (!l || !l.data) return;
    l.data.name = e.target.value;
    l.name = e.target.value;
    saveMeta();
    queuePublish(l);
  });

  $("#add-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const input = $("#add-input");
    const text = input.value.trim();
    if (!text) return;
    input.value = "";
    mutate((data) => data.items.push({ ...newItem(text), addedBy: state.identity.pubkey }));
    input.focus();
  });

  $("#items").addEventListener("change", (e) => {
    if (!e.target.classList.contains("check")) return;
    const li = e.target.closest(".item");
    mutate((data) => {
      const it = data.items.find((x) => x.id === li.dataset.id);
      if (it) it.done = e.target.checked;
    });
  });
  $("#items").addEventListener("click", (e) => {
    if (!e.target.classList.contains("del")) return;
    const li = e.target.closest(".item");
    mutate((data) => {
      data.items = data.items.filter((x) => x.id !== li.dataset.id);
    });
  });

  $("#clear-done-btn").addEventListener("click", () =>
    mutate((data) => {
      data.items = data.items.filter((x) => !x.done);
    })
  );
  $("#uncheck-all-btn").addEventListener("click", () =>
    mutate((data) => {
      for (const it of data.items) it.done = false;
    })
  );
  $("#delete-list-btn").addEventListener("click", () => {
    const l = state.lists.get(state.openListId);
    if (l) deleteList(l);
  });

  $("#identity-btn").addEventListener("click", openIdentityModal);
}

async function promptNewList() {
  const name = await askText({ title: "New list", label: "List name", placeholder: "Groceries", okLabel: "Create" });
  if (name) await createList(name);
}

function openSignerModal() {
  if (signerAbort) signerAbort.abort();
  const ac = new AbortController();
  signerAbort = ac;

  const { clientSecretKey, clientPubkey, secret, uri } = makeNostrConnect(SIGNER_RELAYS, clientMetadata());
  const qr = qrSvg(uri, { cellSize: 5, margin: 1 });

  openModal(
    `
    <h2>Sign in with a signer</h2>
    <p class="muted small">
      Keep your key on your phone. Scan this with <b>Amber</b> (or any NIP-46 signer),
      then approve the connection.
    </p>
    <div class="qr-wrap">${qr}</div>
    <a class="btn btn-primary btn-block" href="${uri}">Open in signer app</a>
    <p id="signer-status" class="muted small center signer-note">Waiting for approval…</p>
    <details class="import-details">
      <summary>Or paste a bunker:// link instead</summary>
      <form id="bunker-form" class="import-row">
        <input id="bunker-input" class="input" placeholder="bunker://…" autocomplete="off" spellcheck="false" />
        <button class="btn btn-primary" type="submit">Connect</button>
      </form>
    </details>
    <p id="signer-error" class="error" hidden></p>`,
    () => {
      $("#bunker-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        ac.abort();
        const err = $("#signer-error");
        const status = $("#signer-status");
        const btn = e.submitter || e.target.querySelector("button");
        btn.disabled = true;
        err.hidden = true;
        if (status) status.textContent = "Connecting…";
        try {
          await connectWithBunker($("#bunker-input").value);
        } catch (ex) {
          err.textContent = ex.message || "Could not connect";
          err.hidden = false;
          if (status) status.textContent = "Waiting for approval…";
          btn.disabled = false;
        }
      });
    }
  );

  awaitNostrConnect({
    pool: state.pool,
    clientSecretKey,
    clientPubkey,
    relays: SIGNER_RELAYS,
    secret,
    signal: ac.signal,
  })
    .then(async (remotePubkey) => {
      const status = $("#signer-status");
      if (status) status.textContent = "Approved — finishing…";
      const signer = createBunkerSigner({
        clientSecretKey,
        remotePubkey,
        relays: SIGNER_RELAYS,
        secret,
        pool: state.pool,
      });
      const userPubkey = await bunkerUserPubkey(signer);
      finishSignerLogin({
        clientSecretKey,
        remotePubkey,
        relays: SIGNER_RELAYS,
        secret,
        userPubkey,
        signer,
      });
    })
    .catch((ex) => {
      if (ac.signal.aborted) return;
      const err = $("#signer-error");
      if (err) {
        err.textContent = ex.message || "Could not connect";
        err.hidden = false;
      }
    });
}

function openIdentityModal() {
  const npub = hexToNpub(state.identity.pubkey);
  const viaSigner = state.identity.type === "nip46";
  const viaPasskey = state.identity.type === "passkey";
  openModal(
    `
    <h2>Your identity</h2>
    <p class="muted small">Share this npub so others can invite you to their lists.</p>
    <div class="copy-row">
      <code class="copy-code">${npub}</code>
      <button id="id-copy" class="btn" type="button">Copy</button>
    </div>
    ${
      viaSigner
        ? `<p class="signer-badge">📱 Signing via a remote signer (NIP-46). Your key stays on your device.</p>`
        : ""
    }
    ${
      viaPasskey
        ? `<p class="signer-badge">🔐 Signing with a passkey. Your key is derived from your passkey and never stored.</p>`
        : ""
    }
    <h3>Danger zone</h3>
    <p class="muted small">${
      viaPasskey
        ? "Signing out forgets this passkey in this browser. You can sign in again with the same passkey."
        : "Signing out forgets this key in this browser. Make sure you saved it."
    }</p>
    <button id="id-signout" class="btn btn-danger btn-block" type="button">Sign out</button>`,
    () => {
      $("#id-copy").addEventListener("click", () => copy(npub, "npub copied"));
      $("#id-signout").addEventListener("click", async () => {
        if (!(await confirmAction("Sign out?", "Your lists stay on relays; you just forget the key here.", "Sign out")))
          return;
        try {
          await state.identity.signer?.close();
        } catch (_) {}
        store.del("gl_sk");
        store.del("gl_ext");
        store.del("gl_nip46");
        store.del("gl_passkey");
        location.reload();
      });
    }
  );
}

/* ------------------------------- util ------------------------------------ */

function bytesToHex(bytes) {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

document.addEventListener("DOMContentLoaded", boot);

async function initMarmot() {
  if (!state.identity || state.marmot) return;
  const signer = wrapIdentityAsSigner(state.identity);
  state.marmot = createMarmotAdapter(signer, state.pool, RELAYS);
  pollInvites();
  // Publishing a key package signs an event, which prompts an interactive
  // signer. Keep it off the login critical path: publish it lazily, on the
  // first user interaction or when the chat is opened.
  document.addEventListener("pointerdown", scheduleKeyPackage, { once: true, capture: true });
  document.addEventListener("keydown", scheduleKeyPackage, { once: true, capture: true });
}

let keyPackageScheduled = false;

function scheduleKeyPackage() {
  if (keyPackageScheduled) return;
  keyPackageScheduled = true;
  ensureKeyPackage();
}

// Advertise this device so list owners can invite us to a chat.
async function ensureKeyPackage() {
  if (!state.marmot) return;
  try {
    const pkgs = await state.marmot.client.keyPackages.list();
    if (!pkgs.some((p) => Array.isArray(p.published) && p.published.length)) {
      await state.marmot.client.keyPackages.create({ relays: RELAYS });
    }
  } catch (e) {
    console.error("marmot key package", e);
  }
}

// A gift-wrapped Welcome (kind 1059) addressed to us: decrypt and join the group.
async function handleGiftWrap(ev) {
  if (!state.marmot) return;
  try {
    const isNew = await state.marmot.client.invites.ingestEvent(ev);
    if (!isNew) return;
    const unread = await state.marmot.client.invites.decryptGiftWraps();
    let joined = false;
    for (const inv of unread) {
      try {
        await state.marmot.client.joinGroupFromWelcome({ welcomeRumor: inv });
        joined = true;
      } catch (e) {
        console.error("join group", e);
      }
      try {
        await state.marmot.client.invites.markAsRead(inv.id);
      } catch (_) {}
    }
    if (joined && state.openListId && !$("#chat-modal")?.hidden) loadChatGroup();
  } catch (e) {
    console.error("invite", e);
  }
}

// Pull any invites we missed while offline (also covers the startup race
// before the live subscription is ready).
async function pollInvites() {
  if (!state.marmot) return;
  try {
    const evs = await state.pool.list(RELAYS, [
      { kinds: [1059], "#p": [state.identity.pubkey], limit: 20 },
    ]);
    for (const ev of evs) await handleGiftWrap(ev);
  } catch (_) {}
}

async function fetchKeyPackage(pubkey) {
  try {
    const events = await state.pool.list(RELAYS, [
      { kinds: [30443, 443], authors: [pubkey], limit: 5 },
    ]);
    const usable = events
      .filter((e) => e.tags.some((t) => t[0] === "i"))
      .sort((a, b) => b.created_at - a.created_at);
    return usable[0] || null;
  } catch (_) {
    return null;
  }
}

function readInvited(listId) {
  try {
    const raw = localStorage.getItem("gl_marmot_invited_" + listId);
    return raw ? new Set(JSON.parse(raw)) : new Set();
  } catch (_) {
    return new Set();
  }
}

function writeInvited(listId, set) {
  try {
    localStorage.setItem("gl_marmot_invited_" + listId, JSON.stringify([...set]));
  } catch (_) {}
}

// Invite any list member who isn't already in the group. Owners only — only an
// admin can commit membership changes. Members who publish their key package
// later get picked up the next time the owner opens the chat.
async function inviteMissingMembers(listId, group, members) {
  const me = state.identity.pubkey;
  const invited = readInvited(listId);
  const targets = [...new Set(members)].filter((m) => m && m !== me && !invited.has(m));
  for (const member of targets) {
    try {
      const kp = await fetchKeyPackage(member);
      if (!kp) continue;
      await group.inviteByKeyPackageEvent(kp);
      invited.add(member);
      writeInvited(listId, invited);
    } catch (e) {
      console.error("invite member", member, e);
    }
  }
}

async function getOrCreateListChatGroup(listId, members = []) {
  if (!state.marmot) return null;
  const name = "chat_" + listId;
  const l = state.lists.get(listId);
  const owner = l?.owner || l?.author || null;
  const isOwner = !owner || owner === state.identity.pubkey;
  const found = state.marmotGroups.get(listId);
  if (found) {
    if (isOwner) inviteMissingMembers(listId, found, members);
    return found;
  }
  try {
    const groups = await state.marmot.client.groups.loadAll();
    for (const g of groups) {
      if (g.groupData?.name === name) {
        state.marmotGroups.set(listId, g);
        if (isOwner) inviteMissingMembers(listId, g, members);
        return g;
      }
    }
  } catch (_) {}
  // Only the list owner starts the group; everyone else joins from the invite.
  if (!isOwner) return null;
  let group;
  try {
    group = await state.marmot.client.groups.create(name, { relays: RELAYS });
  } catch (e) {
    console.error("Failed to create chat group", e);
    return null;
  }
  state.marmotGroups.set(listId, group);
  inviteMissingMembers(listId, group, members);
  return group;
}

function nostrGroupIdHex(group) {
  const id = group?.groupData?.nostrGroupId;
  if (!id) return null;
  return bytesToHex(id instanceof Uint8Array ? id : new Uint8Array(id));
}

function formatNpubShort(hex) {
  try {
    return shortNpub(hex);
  } catch (e) {
    return (hex || "").slice(0, 8);
  }
}

function openChatModal() {
  const el = $("#chat-modal");
  if (el) el.hidden = false;
  state.chatMessages = [];
  const list = state.lists.get(state.openListId);
  if (list) {
    $("#chat-title").textContent = list.data?.name || list.name || "List chat";
  }
  ensureKeyPackage();
  renderChat();
  loadChatGroup();
}

function closeChatModal() {
  const el = $("#chat-modal");
  if (el) el.hidden = true;
  state.activeChatGroup = null;
  stopChatIngest();
}

function stopChatIngest() {
  if (state.chatSub) {
    try {
      if (typeof state.chatSub.unsubscribe === "function") state.chatSub.unsubscribe();
      else if (typeof state.chatSub.close === "function") state.chatSub.close();
    } catch (_) {}
    state.chatSub = null;
  }
  if (state.historyGen) {
    try {
      state.historyGen.return?.();
    } catch (_) {}
    state.historyGen = null;
  }
}

async function loadChatGroup() {
  if (!state.openListId || !state.marmot) return;
  const list = state.lists.get(state.openListId);
  const members = list?.members ? Array.from(list.members) : [];
  const group = await getOrCreateListChatGroup(state.openListId, members);
  if (!group) {
    state.activeChatGroup = null;
    state.chatMessages = [];
    renderChat();
    return;
  }
  state.activeChatGroup = group;

  // Receive new group messages and feed them to MLS (which also records them).
  stopChatIngest();
  const h = nostrGroupIdHex(group);
  if (h) {
    try {
      state.chatSub = state.marmot.network.subscription(group.relays || RELAYS, [
        { kinds: [445], "#h": [h] },
      ]);
      state.chatSub.subscribe({
        next: async (ev) => {
          try {
            for await (const _r of group.ingest([ev])) {
              /* the history subscription below renders */
            }
          } catch (_) {}
        },
        error: () => {},
        complete: () => {},
      });
    } catch (e) {
      console.error("chat subscription", e);
    }
  }

  renderHistory(group);
}

function renderHistory(group) {
  state.chatMessages = [];
  state.historyGen = null;
  if (!group.history) {
    renderChat();
    return;
  }
  const gen = group.history.subscribe([{ kinds: [9] }]);
  state.historyGen = gen;
  (async () => {
    try {
      for await (const rumors of gen) {
        if (state.activeChatGroup !== group) return;
        state.chatMessages = rumors
          .slice()
          .sort((a, b) => a.created_at - b.created_at)
          .map((r) => ({ from: r.pubkey, content: r.content, ts: r.created_at }));
        renderChat();
      }
    } catch (_) {}
  })();
}

async function sendChatMessage() {
  if (!state.activeChatGroup) return;
  const input = $("#chat-input");
  const text = input.value.trim();
  if (!text) return;
  input.value = "";
  try {
    await state.activeChatGroup.sendChatMessage(text);
  } catch (e) {
    console.error("send chat", e);
    toast("Failed to send message");
  }
}

function renderChat() {
  const box = $("#chat-messages");
  if (!box) return;
  box.innerHTML = "";
  if (state.chatMessages.length === 0) {
    const empty = document.createElement("div");
    empty.className = "chat-empty muted small";
    empty.textContent = state.activeChatGroup ? "No messages yet" : "Waiting for the chat to start…";
    box.appendChild(empty);
    return;
  }
  for (const m of state.chatMessages) {
    const div = document.createElement("div");
    div.className = "chat-message" + (m.from === state.identity.pubkey ? " me" : "");
    const meta = document.createElement("div");
    meta.className = "meta";
    meta.textContent = formatNpubShort(m.from || "") + " " + new Date(m.ts * 1000).toLocaleTimeString();
    const txt = document.createElement("div");
    txt.className = "text";
    txt.textContent = m.content;
    div.appendChild(meta);
    div.appendChild(txt);
    box.appendChild(div);
  }
  box.scrollTop = box.scrollHeight;
}
