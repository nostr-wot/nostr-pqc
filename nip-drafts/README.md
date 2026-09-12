# NIP proposals

Draft specifications for implemented post-quantum messaging and proposed relay migration.

These drafts document the Nostr WoT extension and SDK's experimental formats and proposals for incremental relay migration. They are maintained here so clients, signers and relay implementations can discuss the same specification. No official NIP number is claimed.

Moved from [nostr-wot-extension/nips at 36596f9](https://github.com/nostr-wot/nostr-wot-extension/tree/36596f9/nips). The former file paths retain compatibility pointers. Source history before the move remains in that repository.

Read the [complexity, sizing and interoperability audit](AUDIT.md) before implementing the relay proposals. Reproduce the payload calculations with `node scripts/nip-payload-sizes.mjs` from this repository's root.

Start with the [illustrated suite-evolution guide](07-suite-evolution-and-relay-flows.md) for examples of how clients and relays cooperate.

For the relationship to existing encryption, read [why the experimental envelope differs from NIP-44 v2](03-pq-nip44-envelope.md#relationship-to-nip-44). NIP-44 already supports versioning and does not block PQ extensions; the current DM path still uses it for the outer gift wrap.

## The drafts

| Draft | What it covers | Depends on |
|---|---|---|
| [01 — Key derivation](01-pq-key-derivation.md) | Deriving ML-KEM and ML-DSA keys from the BIP-39 seed a Nostr identity already has | NIP-06 |
| [02 — Key attestation](02-pq-key-attestation.md) | `kind:10203`, how a pubkey publishes its post-quantum keys and proves it holds them | NIP-01, 01 |
| [03 — NIP-44 post-quantum envelope](03-pq-nip44-envelope.md) | The hybrid ML-KEM + NIP-44 payload format | NIP-44, 02 |
| [04 — Signer capability](04-nip07-encryption-capability.md) | `window.nostr.nip44.schemes`, so a client can ask a signer instead of guessing | NIP-07, 03 |
| [05 - Relay crypto-agility](05-relay-crypto-agility.md) | Compact envelope selectors, opaque transport, NIP-11 discovery and relay policy | NIP-01, NIP-11, NIP-17, 03 |
| [06 - Hybrid event authentication](06-hybrid-event-authentication.md) | Candidate dual-signature public events, trust pinning and downgrade handling | NIP-01, 02, 05 |
| [07 - Suite evolution and flows](07-suite-evolution-and-relay-flows.md) | Adding suites, relay admission parameters, worked examples and SVG diagrams | 03, 04, 05, 06 |

Drafts 01-04 describe existing work. Drafts 05-07 propose the next migration stage.

## Status

**None of these has a NIP number.** They are not submitted to [nostr-protocol/nips](https://github.com/nostr-protocol/nips) yet, and the numbers in the filenames are reading order, nothing more. The one number that is claimed in the wild is the event kind `10203`, which is in use on relays today and would need to change if it collides with something in flight.

Implementation status (05-07 are proposals, not shipped capabilities):

| Draft | Implementation |
|---|---|
| 01, 02 | [extension crypto](https://github.com/nostr-wot/nostr-wot-extension/blob/main/src/lib/crypto/pq.ts), [extension PQ handlers](https://github.com/nostr-wot/nostr-wot-extension/blob/main/src/services/background/pqc-handlers.ts) |
| 03 | [extension crypto](https://github.com/nostr-wot/nostr-wot-extension/blob/main/src/lib/crypto/pq.ts) (envelope section), [`@nostr-wot/pq`](https://github.com/nostr-wot/nostr-wot-sdk/tree/main/packages/pq) |
| 04 | [extension provider](https://github.com/nostr-wot/nostr-wot-extension/blob/main/inject.ts), [extension signer](https://github.com/nostr-wot/nostr-wot-extension/blob/main/src/services/signing/signer.ts), [`@nostr-wot/signers`](https://github.com/nostr-wot/nostr-wot-sdk/tree/main/packages/signers) |

Drafts 05-07 have no implementation or independent interoperability results yet.

[Obelisk](https://github.com/obelisk-app/obelisk) consumes these formats through the shared SDK. This demonstrates integration, not independent wire-format interoperability. Independent conformance vectors remain necessary.

## Migration boundaries

Start with message confidentiality using the existing compact envelope. Relays can carry it without understanding its encryption; legacy recipients still need an upgraded decryptor. The classical outer gift wrap also means metadata is not post-quantum protected. Draft 05 makes these boundaries explicit.

Event authentication needs separate verifier support and durable trusted key bindings. Draft 06 explores an additive public proof while retaining NIP-01's outer fields. It is not a completed protocol-wide identity migration. Encryption and signature suite identifiers have separate namespaces and purposes.

No new byte is imposed on every Nostr event. Draft 03 already has a version byte and an algorithm byte, and keeps its existing wire format. New signatures add substantial proof bytes only to events that opt in.

## Feedback

Open an issue on this repository. Disagreement about the wire format is more useful now than after a second client ships against it.
