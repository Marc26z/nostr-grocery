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
  BunkerSigner,
  parseBunkerInput,
} from "../vendor/nostr.js";

export const LIST_KIND = 30078; // NIP-78 application-specific data (addressable)
export const NOSTR_CONNECT_KIND = 24133; // NIP-46 remote-signer messages
/** Permissions we ask a remote signer to approve on connect. */
export const NIP46_PERMS = [
  "get_public_key",
  "sign_event",
  "nip44_encrypt",
  "nip44_decrypt",
  "nip04_encrypt",
  "nip04_decrypt",
].join(",");
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

/* ------------------------------ passkeys --------------------------------- */

/* A passkey can back a Nostr identity instead of an exported nsec. A WebAuthn
 * credential's PRF extension yields a stable 32-byte secret for a fixed salt,
 * so hashing it gives the same secp256k1 key every time. Because passkeys sync
 * through the user's provider (Google Password Manager, iCloud Keychain, …),
 * the same npub comes back on every device — there is no nsec to back up. */

const PRF_SALT = new TextEncoder().encode("nostr-grocery-passkey-v1");

/** Whether this browser can create/unlock a passkey-backed identity. */
export function passkeysSupported() {
  return (
    typeof navigator !== "undefined" &&
    !!navigator.credentials &&
    typeof navigator.credentials.create === "function" &&
    typeof navigator.credentials.get === "function" &&
    typeof globalThis.PublicKeyCredential === "function"
  );
}

function toB64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromB64url(str) {
  const b = str.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b + "===".slice((b.length + 3) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** SHA-256(prf ‖ salt): maps any authenticator PRF output to one key. */
async function secretFromPrf(prfBytes, salt) {
  const joined = new Uint8Array(prfBytes.length + salt.length);
  joined.set(prfBytes, 0);
  joined.set(salt, prfBytes.length);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", joined));
}

function prfFirst(credential) {
  const first = credential?.getClientExtensionResults?.()?.prf?.results?.first;
  return first ? new Uint8Array(first) : null;
}

/** Ask an existing passkey for its PRF output (prompts the user). */
export async function passkeySecret({ credentialId, salt = PRF_SALT } = {}) {
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: credentialId ? [{ type: "public-key", id: fromB64url(credentialId) }] : [],
      userVerification: "preferred",
      extensions: { prf: { eval: { first: salt } } },
    },
  });
  const first = prfFirst(assertion);
  if (!first) {
    throw new Error("This passkey can't derive your key (PRF extension unsupported by your browser or provider).");
  }
  return secretFromPrf(first, salt);
}

/**
 * Create a passkey-backed identity. Returns the derived secret key plus the
 * credential id — persist the latter to re-derive the same key later.
 */
export async function createPasskeySecret({ rpName = "Grocery", userName = "grocery", salt = PRF_SALT } = {}) {
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { name: rpName },
      user: { id: crypto.getRandomValues(new Uint8Array(16)), name: userName, displayName: userName },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      authenticatorSelection: { residentKey: "required", userVerification: "preferred" },
      extensions: { prf: { eval: { first: salt } } },
    },
  });
  const credentialId = toB64url(new Uint8Array(credential.rawId));
  const prf = prfFirst(credential);
  // Most authenticators only return the PRF result on assertion, not creation.
  const secretKey = prf ? await secretFromPrf(prf, salt) : await passkeySecret({ credentialId, salt });
  return { credentialId, secretKey };
}

/** A local identity backed by a passkey (secret held in memory this session). */
export function createPasskeyIdentity(secretKey, credentialId) {
  const id = createLocalIdentity(secretKey);
  id.type = "passkey";
  id.credentialId = credentialId;
  return id;
}

/* ------------------------- remote signers (NIP-46) ----------------------- */

function withTimeout(promise, ms, message) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(message || "Timed out")), ms);
    promise.then(
      (v) => {
        clearTimeout(t);
        resolve(v);
      },
      (e) => {
        clearTimeout(t);
        reject(e instanceof Error ? e : new Error(String(e)));
      }
    );
  });
}

/**
 * Build the `nostrconnect://` token a client shows to a mobile signer.
 * Returns the disposable client key, the shared secret and the URI to scan.
 */
export function makeNostrConnect(relays, { name = "Grocery", url = "", perms = NIP46_PERMS } = {}) {
  const clientSecretKey = generateSecretKey();
  const clientPubkey = getPublicKey(clientSecretKey);
  const secret = randomHex(8);
  const qs = new URLSearchParams();
  for (const r of relays) qs.append("relay", r);
  qs.set("secret", secret);
  qs.set("perms", perms);
  if (name) qs.set("name", name);
  if (url) qs.set("url", url);
  return { clientSecretKey, clientPubkey, secret, uri: `nostrconnect://${clientPubkey}?${qs.toString()}` };
}

/** Decrypt a NIP-46 message with the client key (NIP-44, then NIP-04). */
async function decryptNip46(clientSecretKey, senderPubkey, content) {
  try {
    const ck = nip44.getConversationKey(clientSecretKey, senderPubkey);
    return JSON.parse(nip44.decrypt(content, ck));
  } catch (_) {
    return JSON.parse(await nip04.decrypt(clientSecretKey, senderPubkey, content));
  }
}

/**
 * Wait for the signer to answer a `nostrconnect://` handshake. Resolves with
 * the remote-signer pubkey once a response carries our secret.
 */
export function awaitNostrConnect({
  pool,
  clientSecretKey,
  clientPubkey,
  relays,
  secret,
  timeout = 120000,
  signal,
}) {
  return new Promise((resolve, reject) => {
    let sub;
    const finish = (fn) => {
      clearTimeout(timer);
      try {
        sub?.close();
      } catch (_) {}
      signal?.removeEventListener("abort", onAbort);
      fn();
    };
    const onAbort = () => finish(() => reject(new Error("Cancelled")));
    const timer = setTimeout(() => finish(() => reject(new Error("Timed out waiting for the signer"))), timeout);
    sub = pool.subscribeMany(relays, [{ kinds: [NOSTR_CONNECT_KIND], "#p": [clientPubkey] }], {
      onevent: async (ev) => {
        try {
          const msg = await decryptNip46(clientSecretKey, ev.pubkey, ev.content);
          if (msg && msg.result === secret) finish(() => resolve(ev.pubkey));
        } catch (_) {
          /* not a message we can read */
        }
      },
    });
    if (signal) {
      if (signal.aborted) onAbort();
      else signal.addEventListener("abort", onAbort);
    }
  });
}

/** Create a BunkerSigner that talks to `remotePubkey` over `relays`. */
export function createBunkerSigner({ clientSecretKey, remotePubkey, relays, secret = null, pool }) {
  const bp = { pubkey: remotePubkey, relays, secret: secret || null };
  return new BunkerSigner(clientSecretKey, bp, pool ? { pool } : {});
}

/** Learn the user pubkey a signer signs for (asks it to sign nothing). */
export function bunkerUserPubkey(signer, timeout = 60000) {
  return withTimeout(signer.getPublicKey(), timeout, "The signer did not respond");
}

/**
 * Connect to a signer from a `bunker://…` link (signer-initiated flow).
 * Sends the connect request with our perms + metadata, then learns the user
 * pubkey. Returns a ready BunkerSigner.
 */
export async function connectBunkerLink({
  input,
  pool,
  clientSecretKey = generateSecretKey(),
  metadata = null,
  perms = NIP46_PERMS,
  timeout = 120000,
}) {
  const bp = await parseBunkerInput(String(input || "").trim());
  if (!bp) throw new Error("Enter a valid bunker:// connection string");
  if (!bp.relays || bp.relays.length === 0) throw new Error("That bunker link has no relay");
  const signer = createBunkerSigner({
    clientSecretKey,
    remotePubkey: bp.pubkey,
    relays: bp.relays,
    secret: bp.secret,
    pool,
  });
  try {
    const params = [bp.pubkey, bp.secret || ""];
    if (metadata || perms) params.push(perms || "");
    if (metadata) params.push(JSON.stringify(metadata));
    await withTimeout(
      signer.sendRequest("connect", params),
      timeout,
      "The signer did not approve the connection"
    );
    const pubkey = await bunkerUserPubkey(signer, timeout);
    return { signer, pubkey, bp, clientSecretKey };
  } catch (e) {
    try {
      await signer.close();
    } catch (_) {}
    throw e;
  }
}

/** A NIP-46 (remote signer) identity: signs and encrypts via the BunkerSigner. */
export function createNip46Identity({ signer, pubkey }) {
  return {
    type: "nip46",
    pubkey,
    signer,
    async signEvent(template) {
      return signer.signEvent(template);
    },
    async encryptTo(pubHex, plaintext) {
      try {
        return "glk44:" + (await signer.nip44Encrypt(pubHex, plaintext));
      } catch (e) {
        try {
          return "glk04:" + (await signer.nip04Encrypt(pubHex, plaintext));
        } catch (_) {
          throw e;
        }
      }
    },
    async decryptFrom(pubHex, payload) {
      const [tag, ct] = splitPayload(payload);
      if (tag === "glk04") return signer.nip04Decrypt(pubHex, ct);
      return signer.nip44Decrypt(pubHex, ct);
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
