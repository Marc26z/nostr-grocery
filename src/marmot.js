/* Builds a Marmot client for the current identity: MLS group chat (list chat)
 * over Nostr. The client persists its group state, key packages and message
 * history locally so chats survive reloads. */
import { MarmotClient } from "../vendor/marmot.js";
import { SimplePool } from "../vendor/nostr.js";
import {
  SimplePoolNetworkAdapter,
  createLocalStorageStore,
  historyFactory,
} from "./marmot-adapter.js";

export const DEFAULT_RELAYS = [
  "wss://relay.damus.io",
  "wss://nos.lol",
  "wss://relay.primal.net",
  "wss://relay.nostr.band",
  "wss://nostr.mom",
  "wss://relay.snort.social",
];

/** A stable per-device slot id for this client's addressable key package. */
export function deviceClientId() {
  try {
    let id = localStorage.getItem("gl_marmot_client");
    if (!id) {
      id = "grocery-" + Math.random().toString(16).slice(2, 10);
      localStorage.setItem("gl_marmot_client", id);
    }
    return id;
  } catch (_) {
    return "grocery-web";
  }
}

/** @param signer an EventSigner (see wrapIdentityAsSigner). */
export function createMarmotAdapter(signer, pool = null, relays = DEFAULT_RELAYS) {
  const netPool = pool || new SimplePool();
  const network = new SimplePoolNetworkAdapter(netPool, relays);
  const client = new MarmotClient({
    signer,
    network,
    clientId: deviceClientId(),
    groupStateStore: createLocalStorageStore("marmot_gs_"),
    keyPackageStore: createLocalStorageStore("marmot_kp_"),
    inviteStore: createLocalStorageStore("marmot_inv_"),
    historyFactory: historyFactory(),
  });
  return { client, network, pool: netPool, relays };
}
