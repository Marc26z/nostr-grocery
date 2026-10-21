import { test } from "node:test";
import assert from "node:assert/strict";
import {
  newLocalIdentity,
  emptyHousehold,
  emptyList,
  newProduct,
  newStockEntry,
  productQty,
  isLowStock,
  consumeStock,
  encryptList,
  decryptList,
  randomHex,
  makeListEvent,
  parseListEvent,
  makeKeyGrant,
  parseKeyGrant,
  openKeyGrant,
  HOUSEHOLD_DATA,
  LIST_DATA,
} from "../src/core.js";

test("household contents round-trip through AES-GCM", async () => {
  const key = randomHex(32);
  const h = emptyHousehold("Home");
  const milk = newProduct({ name: "Milk", category: "Dairy", unit: "l", minQty: 2 });
  h.products.push(milk);
  h.stock.push(newStockEntry(milk.id, 3, "2026-11-01"));
  const payload = await encryptList(key, h);
  const back = await decryptList(key, payload);
  assert.equal(back.type, "household");
  assert.equal(back.name, "Home");
  assert.equal(back.products[0].name, "Milk");
  assert.equal(productQty(back, milk.id), 3);
});

test("a household event is tagged grocery-household and parses with its type", async () => {
  const id = newLocalIdentity();
  const listId = randomHex(16);
  const key = randomHex(32);
  const data = emptyHousehold("Pantry");

  const ev = await makeListEvent(id, { listId, members: [id.pubkey], listKeyHex: key, data });
  const parsed = parseListEvent(ev);
  assert.equal(parsed.type, "household");
  assert.equal(parsed.listId, listId);
  assert.ok(ev.tags.some((t) => t[0] === "t" && t[1] === HOUSEHOLD_DATA));
  assert.equal(ev.tags.find((t) => t[0] === "t")[1], HOUSEHOLD_DATA);

  // A normal list still parses as a list.
  const listEv = await makeListEvent(id, {
    listId: randomHex(16),
    members: [id.pubkey],
    listKeyHex: key,
    data: emptyList("Groceries"),
  });
  assert.equal(parseListEvent(listEv).type, "list");
  assert.ok(listEv.tags.some((t) => t[0] === "t" && t[1] === LIST_DATA));
});

test("a member recovers the household key via a key grant and reads the stock", async () => {
  const alice = newLocalIdentity();
  const bob = newLocalIdentity();
  const id = randomHex(16);
  const key = randomHex(32);

  const h = emptyHousehold("Shared home");
  const eggs = newProduct({ name: "Eggs", unit: "pcs", minQty: 6 });
  h.products.push(eggs);
  h.stock.push(newStockEntry(eggs.id, 12, null, alice.pubkey));

  const ev = await makeListEvent(alice, {
    listId: id,
    members: [alice.pubkey, bob.pubkey],
    listKeyHex: key,
    data: h,
  });
  const grant = await makeKeyGrant(alice, { listId: id, recipient: bob.pubkey, listKeyHex: key });

  const parsedGrant = parseKeyGrant(grant);
  const recovered = await openKeyGrant(bob, parsedGrant);
  assert.equal(recovered, key);

  const bobView = await decryptList(recovered, parseListEvent(ev).payload);
  assert.equal(bobView.type, "household");
  assert.equal(productQty(bobView, eggs.id), 12);
});

test("product qty sums live stock entries", () => {
  const h = emptyHousehold();
  const p = newProduct({ name: "Rice", unit: "g" });
  h.products.push(p);
  assert.equal(productQty(h, p.id), 0);
  h.stock.push(newStockEntry(p.id, 500));
  h.stock.push(newStockEntry(p.id, 250));
  h.stock.push(newStockEntry(randomHex(8), 999)); // someone else's product
  assert.equal(productQty(h, p.id), 750);
});

test("isLowStock compares the total against the minimum", () => {
  const h = emptyHousehold();
  const p = newProduct({ name: "Butter", unit: "pcs", minQty: 2 });
  h.products.push(p);
  assert.equal(isLowStock(p, h), true);
  h.stock.push(newStockEntry(p.id, 1));
  assert.equal(isLowStock(p, h), true);
  h.stock.push(newStockEntry(p.id, 1));
  assert.equal(isLowStock(p, h), false); // exactly at the minimum is fine
  const noMin = newProduct({ name: "Spices" });
  h.products.push(noMin);
  assert.equal(isLowStock(noMin, h), false); // 0 = no minimum
});

test("consumeStock empties the soonest-expiring entries first (FEFO)", () => {
  const h = emptyHousehold();
  const p = newProduct({ name: "Yogurt", unit: "pcs" });
  h.products.push(p);
  const undated = newStockEntry(p.id, 2); // oldest, but no date
  undated.addedAt = 100;
  const later = newStockEntry(p.id, 3, "2026-01-01");
  const soonest = newStockEntry(p.id, 1, "2025-12-01");
  h.stock.push(undated, later, soonest);
  const other = newProduct({ name: "Bread" });
  h.products.push(other);
  const otherEntry = newStockEntry(other.id, 1, "2025-01-01");
  h.stock.push(otherEntry);

  const consumed = consumeStock(h, p.id, 4);
  assert.equal(consumed, 4);
  // 1 soonest + 3 later used up; the undated lot survives untouched.
  assert.equal(productQty(h, p.id), 2);
  assert.deepEqual(h.stock.filter((e) => e.productId === p.id).map((e) => e.qty), [2]);
  // Other products are never touched.
  assert.ok(h.stock.includes(otherEntry));
});

test("consumeStock never takes more than what's in stock", () => {
  const h = emptyHousehold();
  const p = newProduct({ name: "Coffee", unit: "pcs" });
  h.stock.push(newStockEntry(p.id, 2));
  const consumed = consumeStock(h, p.id, 5);
  assert.equal(consumed, 2);
  assert.equal(productQty(h, p.id), 0);
  assert.equal(h.stock.length, 0); // empty entries are dropped
  assert.equal(consumeStock(h, p.id, -3), 0);
});
