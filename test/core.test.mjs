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
} from "../src/core.js";

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
