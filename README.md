# 🧺 Grocery

A **shared, end-to-end encrypted shopping list** that lives on Nostr and runs
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
  import an existing `nsec`, or use a NIP-07 browser extension if you have one.
  Your key never leaves the browser.
- **New list** → add items, tick them off, **Clear checked**.
- **Share** → paste someone's `npub`/`nprofile`. They receive the encrypted key
  and the list appears on their side. You can also copy an **invite link**
  (anyone holding it can read and edit, so only share it with people you trust).
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

## Files

| file | purpose |
|---|---|
| `index.html`, `styles.css`, `app.js` | the app (no build step needed at runtime) |
| `src/core.js` | the protocol: crypto, event building/parsing, identities incl. NIP-46 (pure, unit-tested) |
| `src/vendor.js` → `vendor/nostr.js` | `nostr-tools` (incl. `nip46`) bundled into one self-contained file |
| `src/qr.js` → `vendor/qr.js` | QR rendering for the `nostrconnect://` login (bundled) |
| `test/` | Node tests: crypto round-trips **and** a jsdom smoke test of the whole app incl. the signer flow |
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
