# 🧺 Grocery

*I vibe-coded a simple grocery list app that I can share with my household. I used open-code on an Omarchy Android app that basically turns your phone into an arch linux computer.  It's the free version. I had to ask Deepseek Pro to fix some bugs, but it was able to fix the bugs based on that information. It was also able to bpush it to github and host it on a github domain. Then I heard Max Hillebrand suggest we should try adding Marmot Protocol messages. Like a famous genie once said, "your wish is my command." Now I can talk about my grocery list in private because... Why not? I can ask my wife to pick up some raw milk our milk dealer. Just kidding. Buying raw milk may or may not be a crime in your area. Check with the local milk police. Please follow all milk laws.*

A **shared, end-to-end encrypted shopping list** that lives on Nostr and run
entirely in the browser. Create a list, invite other npubs, and everyone sees
live updates — without any server, account, or database. Relays only ever store
ciphertext.

Live: `https://marc26z.github.io/nostr-grocery/` _(once GitHub Pages is enabled)_

## How sharing works

The hard part of a shared list is letting several npubs read and write the same
data while keeping it private from the relays. This app does it with two layers:

1. **A random list key encrypts the contents.**
   Each list gets a fresh 256-bit key. The whole list (name + items) is
   serialized to JSON and encrypted with **AES-256-GCM** (WebCrypto), then
   published as the content of a kind `30078` ([NIP-78] app data) addressable
   event whose `d` tag is `grocery:<listId>`. The event carries a `p` tag for
   every member.

2. **The list key is handed to each member, encrypted to their key.**
   To add an npub, the owner encrypts the list key to that member with
   **NIP-44** (falling back to NIP-04 for signers that only speak that) and
   publishes it as a small "key grant" event addressed to them. The member's
   client discovers it, decrypts the key, and can now read and edit the list.

Members find their lists by subscribing to the events tagged with their own
`p` key. Edits are last-write-wins by `created_at`, which is plenty for a
grocery list. Metadata (which npubs share a list) is visible to relays; the
contents never are.

```
owner ── AES-GCM(list, K) ──► relay           (kind 30078, d=grocery:<id>, p=members)
owner ── NIP-44(K, member) ─► relay           (kind 30078, d=grocery-key:<id>:<member>)
member ◄─ decrypt K ── read/edit list ────────► relay
```

## Using it

- **Create an identity** in the app (a new key is generated in your browser), or
  import an existing `nsec`, use a NIP-07 browser extension, or back it with a
  **passkey** (see below). Your key never leaves the browser.
- **New list** → add items, tick them off, **Clear checked**.
- **Share** → paste someone's `npub`/`nprofile`. They receive the encrypted key
  and the list appears on their side.
- **List key** → the Share dialog also shows a paste-able **list key**
  (a `grocery1:…` string packing the owner, list id and the list's 256-bit
  key). Anyone who has it can read and edit the list, so only share it with
  people you trust. On another device, **Join** and paste the key to open the list.
- The self-grant means signing in with the same `nsec` on another device
  restores your lists.

## Signing in with a mobile signer (NIP-46)

Your key doesn't have to live in the browser. **Sign in with a signer app**
shows a QR code for a `nostrconnect://` token — scan it with
[Amber](https://github.com/greenart7c3/Amber) (or any NIP-46 signer) and approve.
You can also paste a `bunker://…` connection string instead. Signing and key
granting then happen on your device, so the browser never holds your key. The
disposable client key used for the session is stored locally so a reload keeps
you signed in.

## Signing in with a passkey (WebAuthn)

You can create an identity backed by a **passkey** instead of an exported `nsec`.
The browser creates a WebAuthn credential and reads its [PRF extension] output —
a stable 32-byte secret for a fixed salt — which is hashed (SHA-256) into your
Nostr key. The same passkey always derives the same npub, so there is no secret
to write down: it comes back on every device where the passkey is available
(Google Password Manager, iCloud Keychain, a security key, …).

- **Create an identity with a passkey** on the login screen. Nothing is stored
  but the credential id; the derived key lives only for the session.
- On a later visit, **Unlock with your passkey** re-derives the same key after
  the usual passkey prompt.
- Requires a browser and passkey provider that support the WebAuthn `prf`
  extension. If it's missing, the app says so and you can use an `nsec` instead.

[PRF extension]: https://w3c.github.io/webauthn/#prf-extension

## Files

| file | purpose |
|---|---|
| `index.html`, `styles.css`, `app.js` | the app (no build step needed at runtime) |
| `src/core.js` | the protocol: crypto, event building/parsing, identities incl. NIP-46 (pure, unit-tested) |
| `src/vendor.js` → `vendor/nostr.js` | `nostr-tools` (incl. `nip46`) bundled into one self-contained file |
| `src/qr.js` → `vendor/qr.js` | QR rendering for the `nostrconnect://` login (bundled) |
| `test/` | Node tests: crypto round-trips **and** jsdom smoke tests of the whole app incl. the signer and passkey flows |
| `manifest.webmanifest`, `icons/` | PWA manifest + icons (used when wrapping for Zapstore) |
| `scripts/build-apk.sh` | wrap the web app into an APK with `zapstore/goapk` |

## Development

Requires Node (for the bundler/tests) and Perl (for the dev server).

```sh
npm install          # nostr-tools + esbuild + jsdom (+ qrcode-generator)
npm run build        # rebuild vendor/nostr.js and vendor/qr.js after changing src/
npm test             # crypto tests + headless app smoke test (both sign-in paths)
npm run serve        # http://localhost:8000
```

`vendor/nostr.js` and `vendor/qr.js` are committed, so the deployed site needs
no build step.

## Deploying the web app

It is a static site. Publish the repo with GitHub Pages (branch `main`, root),
or any static host. `.nojekyll` is included so asset paths are served as-is.

## Publishing to Zapstore

[Zapstore](https://zapstore.dev) is an open Android app store. Web apps are
wrapped into an APK with [`zapstore/goapk`](https://github.com/zapstore/goapk),
which needs no Android SDK, JDK or Gradle.

1. **Build a signed APK**

   ```sh
   go install github.com/zapstore/goapk@latest
   ./scripts/build-apk.sh          # -> dist/grocery.apk, keystore.p12 created once
   ```

   Reuse the same `keystore.p12` for every release so devices update in place.
   Bind the keystore to your Nostr key with `goapk` when it prompts you
   (one-time, NIP-C1).

2. **Host the APK.** Attach `dist/grocery.apk` to a GitHub release.

3. **Publish the catalog event**

   ```sh
   go install github.com/zapstore/zsp@latest
   SIGN_WITH=nsec1... zsp publish -r github.com/Marc26z/nostr-grocery
   ```

   The first publish runs the linker; `zapstore.yaml` (committed here) lets the
   relay auto-whitelist the `pubkey`. Replace the placeholder `pubkey` with
   yours if you publish under a different identity.

## Protocol notes

- List + key-grant events are kind `30078` ([NIP-78]) so they are addressable
  (one live version per author per list) and namespaced by their `d` tag.
- Symmetric content: AES-256-GCM, `iv ‖ ciphertext`, base64.
- Key transport: NIP-44 v2, tagged `glk44:`; NIP-04 fallback, tagged `glk04:`.
- Data deletion uses a kind `5` ([NIP-09]) event pointing at your own copy.

[NIP-78]: https://github.com/nostr-protocol/nips/blob/master/78.md
[NIP-09]: https://github.com/nostr-protocol/nips/blob/master/09.md

## License

MIT

