// Bundle entry: re-exports just what the app needs from nostr-tools so the
// browser loads one self-contained file (vendor/nostr.js) with no CDN needed.
export {
  generateSecretKey,
  getPublicKey,
  finalizeEvent,
  verifyEvent,
} from "nostr-tools/pure";
export { SimplePool } from "nostr-tools/pool";
export * as nip19 from "nostr-tools/nip19";
export * as nip44 from "nostr-tools/nip44";
export * as nip04 from "nostr-tools/nip04";
export { BunkerSigner, parseBunkerInput } from "nostr-tools/nip46";
