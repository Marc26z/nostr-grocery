import { test } from "node:test";
import assert from "node:assert/strict";
import {
  newLocalIdentity,
  encryptList,
  decryptList,
  emptyList,
  newItem,
  randomHex,
  makeKeyGrant,
  parseKeyGrant,
  openKeyGrant,
  makeListEvent,
  parseListEvent,
  npubToHex,
  hexToNpub,
  decodeSecret,
  encodeSecret,
  shortNpub,
  makeNostrConnect,
  createNip46Identity,
  NIP46_PERMS,
} from "../src/core.js";
import { getPublicKey, finalizeEvent, verifyEvent } from "nostr-tools/pure";
import * as nip44 from "nostr-tools/nip44";
import * as nip04 from "nostr-tools/nip04";

test("list content round-trips through AES-GCM", async () => {
  const key = randomHex(32);
  const data = emptyList("Costco run");
  data.items.push(newItem("milk"), newItem("eggs"));
  const payload = await encryptList(key, data);
  const back = await decryptList(key, payload);
  assert.equal(back.name, "Costco run");
  assert.deepEqual(back.items.map((i) => i.text), ["milk", "eggs"]);
});

test("a different key cannot decrypt", async () => {
  const payload = await encryptList(randomHex(32), emptyList("secret"));
  await assert.rejects(() => decryptList(randomHex(32), payload));
});

test("npub <-> hex and nsec round-trip", () => {
  const id = newLocalIdentity();
  const npub = hexToNpub(id.pubkey);
  assert.equal(npubToHex(npub), id.pubkey);
  assert.match(npub, /^npub1/);
  const nsec = encodeSecret(id.secretKey);
  assert.deepEqual(decodeSecret(nsec), id.secretKey);
  assert.match(shortNpub(id.pubkey), /…/);
});

test("owner shares an encrypted list with another npub", async () => {
  const alice = newLocalIdentity();
  const bob = newLocalIdentity();
  const listId = randomHex(16);
  const listKey = randomHex(32);

  const aliceData = emptyList("Shared list");
  aliceData.items.push(newItem("bread"));
  const listEvent = await makeListEvent(alice, {
    listId,
    members: [alice.pubkey, bob.pubkey],
    listKeyHex: listKey,
    data: aliceData,
  });

  const parsed = parseListEvent(listEvent);
  assert.equal(parsed.listId, listId);
  assert.deepEqual(parsed.members.sort(), [alice.pubkey, bob.pubkey].sort());

  const grant = await makeKeyGrant(alice, {
    listId,
    recipient: bob.pubkey,
    listKeyHex: listKey,
  });
  const parsedGrant = parseKeyGrant(grant);
  assert.equal(parsedGrant.listId, listId);
  assert.equal(parsedGrant.recipient, bob.pubkey);

  // Bob recovers the key and can read the owner's list.
  const recovered = await openKeyGrant(bob, parsedGrant);
  assert.equal(recovered, listKey);
  const bobView = await decryptList(recovered, parsed.payload);
  assert.equal(bobView.name, "Shared list");
  assert.equal(bobView.items[0].text, "bread");

  // Bob edits and republishes; Alice can read the change.
  bobView.items.push(newItem("jam"));
  const bobEvent = await makeListEvent(bob, {
    listId,
    members: parsed.members,
    listKeyHex: recovered,
    data: bobView,
    createdAt: parsed.createdAt + 10,
  });
  const aliceView = await decryptList(listKey, parseListEvent(bobEvent).payload);
  assert.deepEqual(aliceView.items.map((i) => i.text), ["bread", "jam"]);
  assert.equal(bobEvent.pubkey, bob.pubkey);
});

test("NIP-44 conversation keys are symmetric across identities", async () => {
  const a = newLocalIdentity();
  const b = newLocalIdentity();
  const ct = await a.encryptTo(b.pubkey, "hello world");
  assert.equal(await b.decryptFrom(a.pubkey, ct), "hello world");
  // and each can talk to itself (cross-device backup grants)
  const self = await a.encryptTo(a.pubkey, "to self");
  assert.equal(await a.decryptFrom(a.pubkey, self), "to self");
});

test("makeNostrConnect builds a scannable nostrconnect:// token", () => {
  const { clientSecretKey, clientPubkey, secret, uri } = makeNostrConnect(
    ["wss://a.example", "wss://b.example"],
    { name: "Grocery", perms: NIP46_PERMS }
  );
  const m = uri.match(/^nostrconnect:\/\/([0-9a-f]{64})\?(.*)$/);
  assert.ok(m, "uri should be nostrconnect://<client-pubkey>?…");
  assert.equal(m[1], clientPubkey);
  assert.equal(getPublicKey(clientSecretKey), clientPubkey);
  const qs = new URLSearchParams(m[2]);
  assert.equal(qs.getAll("relay").length, 2);
  assert.equal(qs.get("secret"), secret);
  assert.equal(qs.get("name"), "Grocery");
  assert.equal(qs.get("perms"), NIP46_PERMS);
});

test("NIP-46 identity signs and encrypts via the remote signer", async () => {
  const user = newLocalIdentity();
  const friend = newLocalIdentity();
  const signer = {
    async signEvent(t) {
      return finalizeEvent(t, user.secretKey);
    },
    async nip44Encrypt(pub, pt) {
      const ck = nip44.getConversationKey(user.secretKey, pub);
      return nip44.encrypt(pt, ck);
    },
    async nip44Decrypt(pub, ct) {
      const ck = nip44.getConversationKey(user.secretKey, pub);
      return nip44.decrypt(ct, ck);
    },
    async nip04Encrypt(pub, pt) {
      return nip04.encrypt(user.secretKey, pub, pt);
    },
    async nip04Decrypt(pub, ct) {
      return nip04.decrypt(user.secretKey, pub, ct);
    },
  };
  const id = createNip46Identity({ signer, pubkey: user.pubkey });
  assert.equal(id.type, "nip46");

  // sign_event delegates to the signer
  const ev = await id.signEvent({ kind: 30078, created_at: 1, tags: [], content: "encrypted" });
  assert.equal(ev.pubkey, user.pubkey);
  assert.equal(verifyEvent(ev), true);

  // key grants handed out by a signer-backed identity open on the other side
  const ct = await id.encryptTo(friend.pubkey, "secret-list-key");
  assert.equal(await friend.decryptFrom(id.pubkey, ct), "secret-list-key");
  const back = await id.decryptFrom(friend.pubkey, "glk44:" + (await nip44.encrypt("reply", nip44.getConversationKey(friend.secretKey, user.pubkey))));
  assert.equal(back, "reply");
});

test("NIP-46 identity falls back to NIP-04 when the signer lacks NIP-44", async () => {
  const user = newLocalIdentity();
  const friend = newLocalIdentity();
  const signer = {
    async signEvent() {
      throw new Error("n/a");
    },
    async nip44Encrypt() {
      throw new Error("unsupported");
    },
    async nip44Decrypt() {
      throw new Error("unsupported");
    },
    async nip04Encrypt(pub, pt) {
      return nip04.encrypt(user.secretKey, pub, pt);
    },
    async nip04Decrypt(pub, ct) {
      return nip04.decrypt(user.secretKey, pub, ct);
    },
  };
  const id = createNip46Identity({ signer, pubkey: user.pubkey });
  const ct = await id.encryptTo(friend.pubkey, "list-key");
  assert.match(ct, /^glk04:/);
  assert.equal(await friend.decryptFrom(id.pubkey, ct), "list-key");
  const enc = await nip04.encrypt(friend.secretKey, user.pubkey, "reply");
  assert.equal(await id.decryptFrom(friend.pubkey, "glk04:" + enc), "reply");
});
