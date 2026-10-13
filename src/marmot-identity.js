/* Adapts a Grocery identity (local / NIP-07 / NIP-46 / passkey) into the
 * `EventSigner` shape the Marmot client expects. The identity already exposes
 * a plain NIP-44 implementation, which Marmot needs for MLS gift wrapping. */
export function wrapIdentityAsSigner(identity) {
  return {
    getPublicKey: async () => identity.pubkey,
    signEvent: async (draft) => identity.signEvent(draft),
    nip44: identity.nip44 || {
      encrypt: async (pubkey, plaintext) => identity.encryptTo(pubkey, plaintext),
      decrypt: async (pubkey, ciphertext) => identity.decryptFrom(pubkey, ciphertext),
    },
    nip04: identity.nip04,
  };
}
