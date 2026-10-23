# Passkey-held keys

Experimental NIP proposals for recovering the same Nostr identity across compatible passkey clients. These drafts have no assigned NIP numbers and have not been accepted by `nostr-protocol/nips`. Relay kind `31778` is provisional and requires coordination before broad deployment.

## Read the proposal

- [Core: Passkey-Held Keys](XX.md) distinguishes deriving a key from a passkey from unlocking an encrypted stored key.
- [Optional companion: Vault Recovery](YY.md) adds seed and account recovery without requiring every core client to implement a vault.
- [Best practices](passkey-held-keys/BEST-PRACTICES.md) covers clear consent, one-time use, optional migration, recovery and retiring credentials.
- [Interoperability guide](passkey-held-keys/INTEROPERABILITY.md) explains source registration, origin authorization and implementation checks.

These are passkey interoperability proposals, separate from this repository’s post-quantum proposals. They do not make Nostr keys or signatures quantum-resistant.

## Implementation status

The experimental SDK candidate is published as [`@nostr-wot/identity@1.1.0-next.0`](https://www.npmjs.com/package/@nostr-wot/identity/v/1.1.0-next.0). [keytr integration is under review](https://github.com/SovereignTechnology/keytr/pull/38). Client integration, independent interoperability testing and device testing remain in progress; publication of these drafts does not establish production readiness or standard adoption.

## Verify the fixtures

From this repository’s root, with Node.js 22 or newer:

```sh
node nip-drafts/passkeys/passkey-held-keys/checks/vectors.mjs
```

The [public test vectors](passkey-held-keys/vectors.json) and their [checksum](passkey-held-keys/vectors.sha256) cover the core and vault companion. The checker requires no package installation; its arithmetic is for test fixtures, not production signing.

## Review

Please discuss protocol feedback on this repository’s pull request or open an issue. In particular, review mode recognition, authenticated record precedence, overwrite protection, cross-origin authorization and compatibility with existing credentials.

[All proposals](../README.md)
