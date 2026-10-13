/* =========================================================================
 * Nostr Grocery — core logic.
 *
 * A shared grocery list is:
 *   • a random 256-bit symmetric "list key" that encrypts the list contents
 *     with AES-256-GCM (WebCrypto), and
 *   • a Nostr addressable event (kind 30078, NIP-78) whose content is that
 *     ciphertext and whose `p` tags name every member.
 *
 * To let another npub in, the owner encrypts the list key to their pubkey
 * with NIP-44 (or NIP-04, if the signer only speaks that) and publishes it as
 * a small "key grant" event addressed to them. Relays only ever see cipher-
 * text; only members can read or write the list.
 *
 * This module is pure (no DOM, no network) so it can be unit-tested.
 * ========================================================================= */

import {
  generateSecretKey,
  getPublicKey,
  finalizeEvent,
  nip19,
  nip44,
  nip04,
} from "../vendor/nostr.js";

export const LIST_KIND = 30078; // NIP-78 application-specific data (addressable)
export const LIST_DATA = "grocery-list"; // `t` tag marking a list event
export const KEYGRANT_DATA = "grocery-key"; // `t` tag marking a key grant
const D_LIST = "grocery:";
const D_KEY = "grocery-key:";

/** The `d` tag value identifying a list's addressable event. */
export const listDTag = (listId) => D_LIST + listId;
const AES = { name: "AES-GCM", length: 256 };

/* ------------------------------- bytes ---------------------------------- */

export function bytesToHex(bytes) {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

export function hexToBytes(hex) {
  if (typeof hex !== "string" || hex.length % 2) throw new Error("bad hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function randomHex(bytes = 16) {
  const b = new Uint8Array(bytes);
  crypto.getRandomValues(b);
  return bytesToHex(b);
}

function b64encode(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function b64decode(str) {
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/* --------------------------- list encryption ---------------------------- */

async function importAesKey(listKeyHex) {
  return crypto.subtle.importKey("raw", hexToBytes(listKeyHex), AES, false, [
    "encrypt",
    "decrypt",
  ]);
}

/** Encrypt a plain list object to a base64 string (iv ‖ ciphertext). */
export async function encryptList(listKeyHex, data) {
  const key = await importAesKey(listKeyHex);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const pt = new TextEncoder().encode(JSON.stringify(data));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, pt));
  const joined = new Uint8Array(iv.length + ct.length);
  joined.set(iv, 0);
  joined.set(ct, iv.length);
  return b64encode(joined);
}

/** Decrypt a base64 blob produced by encryptList back to an object. */
export async function decryptList(listKeyHex, payload) {
  const raw = b64decode(payload);
  const iv = raw.subarray(0, 12);
  const ct = raw.subarray(12);
  const key = await importAesKey(listKeyHex);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return JSON.parse(new TextDecoder().decode(pt));
}

/** A brand new, empty list object (the plaintext shape). */
export function emptyList(name = "Groceries") {
  return { v: 1, name, items: [], updatedAt: Math.floor(Date.now() / 1000) };
}

export function newItem(text) {
  return {
    id: randomHex(8),
    text: String(text).trim(),
    done: false,
    addedBy: null,
    addedAt: Math.floor(Date.now() / 1000),
  };
}

/* ---------------------------- key grants -------------------------------- */

function splitPayload(payload) {
  const i = payload.indexOf(":");
  if (i < 0) return ["glk44", payload];
  return [payload.slice(0, i), payload.slice(i + 1)];
}

/**
 * Build a signed "key grant": the list key encrypted to `recipient`.
 * Uses NIP-44 when available, else NIP-04 (tagged in the payload).
 */
export async function makeKeyGrant(identity, { listId, recipient, listKeyHex, createdAt }) {
  const encrypted = await identity.encryptTo(recipient, listKeyHex);
  const at = createdAt ?? Math.floor(Date.now() / 1000);
  const template = {
    kind: LIST_KIND,
    created_at: at,
    tags: [
      ["d", `${D_KEY}${listId}:${recipient}`],
      ["t", KEYGRANT_DATA],
      ["list", listId],
      ["p", recipient],
      ["p", identity.pubkey],
    ],
    content: encrypted,
  };
  return identity.signEvent(template);
}

export function parseKeyGrant(event) {
  if (!event || event.kind !== LIST_KIND) return null;
  const d = event.tags.find((t) => t[0] === "d");
  if (!d || !d[1].startsWith(D_KEY)) return null;
  const rest = d[1].slice(D_KEY.length);
  const sep = rest.lastIndexOf(":");
  if (sep < 0) return null;
  const listId = rest.slice(0, sep);
  const recipient = rest.slice(sep + 1);
  return { listId, recipient, sender: event.pubkey, encrypted: event.content, createdAt: event.created_at };
}

/** Recover a list key that someone granted us. */
export async function openKeyGrant(identity, grant) {
  const plaintext = await identity.decryptFrom(grant.sender, grant.encrypted);
  return plaintext.trim();
}

/* ---------------------------- list events ------------------------------- */

export async function makeListEvent(identity, { listId, members, listKeyHex, data, createdAt }) {
  const at = createdAt ?? Math.floor(Date.now() / 1000);
  data.updatedAt = at;
  const payload = await encryptList(listKeyHex, data);
  const tags = [
    ["d", `${D_LIST}${listId}`],
    ["t", LIST_DATA],
  ];
  for (const m of [...new Set(members)].sort()) tags.push(["p", m]);
  const template = { kind: LIST_KIND, created_at: at, tags, content: payload };
  return identity.signEvent(template);
}

export function parseListEvent(event) {
  if (!event || event.kind !== LIST_KIND) return null;
  const d = event.tags.find((t) => t[0] === "d");
  if (!d || !d[1].startsWith(D_LIST)) return null;
  const t = event.tags.find((t) => t[0] === "t" && t[1] === LIST_DATA);
  if (!t) return null;
  const members = event.tags.filter((x) => x[0] === "p").map((x) => x[1]);
  return {
    listId: d[1].slice(D_LIST.length),
    members,
    payload: event.content,
    createdAt: event.created_at,
    author: event.pubkey,
  };
}

/* ---------------------------- identities -------------------------------- */

/** An in-app identity holding a raw secret key. */
export function createLocalIdentity(secretKeyBytes) {
  const sk = secretKeyBytes instanceof Uint8Array ? secretKeyBytes : hexToBytes(secretKeyBytes);
  return {
    type: "local",
    secretKey: sk,
    pubkey: getPublicKey(sk),
    async signEvent(template) {
      return finalizeEvent(template, sk);
    },
    async encryptTo(pubHex, plaintext) {
      const ck = nip44.getConversationKey(sk, pubHex);
      return "glk44:" + nip44.encrypt(plaintext, ck);
    },
    async decryptFrom(pubHex, payload) {
      const [tag, ct] = splitPayload(payload);
      if (tag === "glk04") return nip04.decrypt(sk, pubHex, ct);
      const ck = nip44.getConversationKey(sk, pubHex);
      return nip44.decrypt(ct, ck);
    },
  };
}

export function newLocalIdentity() {
  return createLocalIdentity(generateSecretKey());
}

/** A NIP-07 browser-extension identity (window.nostr). */
export function createNip07Identity() {
  const provider = window.nostr;
  return {
    type: "nip07",
    pubkey: null,
    async init() {
      this.pubkey = await provider.getPublicKey();
      return this.pubkey;
    },
    async signEvent(template) {
      return provider.signEvent(template);
    },
    async encryptTo(pubHex, plaintext) {
      if (provider.nip44?.encrypt) return "glk44:" + (await provider.nip44.encrypt(pubHex, plaintext));
      if (provider.nip04?.encrypt) return "glk04:" + (await provider.nip04.encrypt(pubHex, plaintext));
      throw new Error("Your signer supports neither NIP-44 nor NIP-04 encryption");
    },
    async decryptFrom(pubHex, payload) {
      const [tag, ct] = splitPayload(payload);
      if (tag === "glk04") {
        if (!provider.nip04?.decrypt) throw new Error("Your signer cannot decrypt NIP-04");
        return provider.nip04.decrypt(pubHex, ct);
      }
      if (!provider.nip44?.decrypt) throw new Error("Your signer cannot decrypt NIP-44");
      return provider.nip44.decrypt(pubHex, ct);
    },
  };
}

/* ------------------------------ npub utils ------------------------------- */

export function npubToHex(input) {
  const v = (input || "").trim();
  if (/^[0-9a-f]{64}$/i.test(v)) return v.toLowerCase();
  if (/^(npub|nprofile)1/i.test(v)) {
    const { data } = nip19.decode(v);
    return typeof data === "string" ? data : data.pubkey;
  }
  throw new Error("Enter an npub, nprofile or 64-char hex pubkey");
}

export function hexToNpub(hex) {
  return nip19.npubEncode(hex);
}

export function shortNpub(hex, head = 10, tail = 4) {
  const npub = hexToNpub(hex);
  return `${npub.slice(0, head)}…${npub.slice(-tail)}`;
}

export function decodeSecret(input) {
  const v = (input || "").trim();
  if (/^nsec1/i.test(v)) {
    const { data } = nip19.decode(v);
    return data;
  }
  if (/^[0-9a-f]{64}$/i.test(v)) return hexToBytes(v);
  throw new Error("Enter an nsec (or 64-char hex secret key)");
}

export function encodeSecret(sk) {
  return nip19.nsecEncode(sk);
}
