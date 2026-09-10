# Implementations

[Overview](../README.md) · [Implementations](implementations.md) · [FAQ](faq.md) · [Backup guide](key-backups.md)

### nostr-wot-extension

**[github.com/nostr-wot/nostr-wot-extension](https://github.com/nostr-wot/nostr-wot-extension)** · MIT · TypeScript · Chrome / Firefox / Safari

The documented **v0.4.0** feature set includes the following. For pending **0.7.0** import/export support, see the [backup guide](key-backups.md).

- **Derives ML-KEM-1024 and ML-DSA-87 keys from your existing BIP-39 seed** — not from your Nostr private key. The two are *siblings*, derived independently from the same mnemonic via domain-separated HKDF (`nip-pqc/v1/<alg>/<account>`). This is the security property the whole design rests on: an adversary who breaks secp256k1 and recovers your `nsec` cannot walk *back* to the seed, and therefore cannot reach your post-quantum keys. Seed-derived keys use the existing mnemonic; independent keys require a separate backup.
- **Publishes a `kind:10203` attestation** advertising the public keys, which is how anyone discovers that you can receive post-quantum messages at all.
- **Counter-signs the attestation with the ML-DSA key** (proof of possession) over a message binding the npub to both public keys — so advertising a key you cannot actually decrypt with is detectable. ML-KEM cannot sign, which is why the DSA key is also what proves possession of the encryption key.
- **Sends and receives post-quantum DMs** over NIP-44 + NIP-59. Decryption routes automatically because the payload is self-describing; encryption is an explicit opt-in so a message can never be silently downgraded.
- **Extends the NIP-07 surface** additively: `encrypt(pubkey, plaintext, { scheme: 'pq', recipientKemKey })`. Omit the options and you get classic NIP-44.
- **Ships an offline CLI** (`npm run pqc:keygen`) that derives the keys and prints the signed attestation without a browser, reading the mnemonic from stdin and never writing it to disk.
- **Generates new identities with 24 words instead of 12.** BIP-39 expands any mnemonic to a 64-byte seed, so 12 words *would* derive working post-quantum keys — carrying only 128 bits of real entropy, which would make the seed, not the lattice, the weakest link. The keygen tool refuses 12-word mnemonics rather than quietly producing something that looks post-quantum and is not.

### @nostr-wot/pq

**[github.com/nostr-wot/nostr-wot-sdk/tree/main/packages/pq](https://github.com/nostr-wot/nostr-wot-sdk/tree/main/packages/pq)** · MIT · TypeScript · [npm](https://www.npmjs.com/package/@nostr-wot/pq)

The reference library the extension is built on, usable independently. Key derivation, `kind:10203` attestation build/parse/verify, the hybrid message envelope, and gift-wrapped post-quantum DMs.

```bash
npm install @nostr-wot/pq
```

**The message envelope** is a self-describing, version-prefixed payload carrying an ML-KEM-1024 ciphertext and an XChaCha20-Poly1305-sealed message:

```
version   1 byte    0x01
alg       1 byte    0x01 = ML-KEM-1024 + NIP-44 conversation key, XChaCha20-Poly1305
kem_ct    1568      ML-KEM-1024 ciphertext
nonce     24        XChaCha20-Poly1305 nonce
sealed    variable  AEAD(padded plaintext), includes the 16-byte tag
```

Design decisions worth borrowing:

- **Hybrid, never bare.** The KEM secret is combined with the classic NIP-44 conversation key through HKDF, so the result is no weaker than either input. A flaw in a comparatively young lattice scheme must not be able to make Nostr messaging *worse* than it is today.
- **Its own version byte, not NIP-44's**, so it can be adopted, renumbered or superseded without squatting a number in a registry its authors own.
- **The framing is authenticated.** Version, algorithm and both pubkeys go into the AEAD's associated data, so a ciphertext cannot be replayed into another conversation, have its direction swapped, or have its algorithm byte downgraded.
- **Length is padded** with NIP-44's scheme, so ciphertext size does not leak message size on a public relay.
- **One generic error** for every decryption failure — distinguishing bad padding from a bad tag from a wrong key hands an attacker an oracle.
- **It rides inside NIP-59 gift wrap unchanged.** To a relay, and to any client that has not implemented it, a post-quantum DM is an ordinary `kind:1059` gift wrap. **No relay changes are required.**

**Measured cost** on the complete `kind:1059` event as a relay sees it:

| message | classic NIP-17 | post-quantum | overhead | ratio |
|---|---|---|---|---|
| "hi" (2 chars) | 1,533 B | 4,605 B | +3,072 B | 3.0x |
| chat line (32) | 1,701 B | 4,605 B | +2,904 B | 2.7x |
| a tweet (280) | 2,213 B | 5,285 B | +3,072 B | 2.4x |
| a paragraph (1 KB) | 3,921 B | 7,333 B | +3,412 B | 1.9x |
| a long note (4 KB) | 11,429 B | 14,161 B | +2,732 B | 1.2x |
| a document (16 KB) | 38,737 B | 44,197 B | +5,460 B | 1.1x |

**~3 KB constant overhead**, almost all of it the 1,568-byte ML-KEM ciphertext, which base64 expands at every NIP-59 layer. About 2.4x on a typical chat message — roughly +107 MB/year per conversation at 100 messages a day. That is the number relay operators will care about, and the strongest argument anyone will make against adopting this. Worth noting that NIP-59 is *already* expensive: a classic two-character "hi" costs 1,533 bytes. Post-quantum raises that floor; it does not create it.

Placing the envelope at the **seal** layer rather than inside the rumor saves 16–28%, by removing one of the three base64 expansions the ML-KEM ciphertext would otherwise pass through.

### Dart NDK — quantum-secure signer

[Source](https://github.com/relaystr/ndk) · Dart / Rust

NDK now includes hybrid ML-KEM-1024 DM encryption through its Rust FFI and a
PqEncryption Dart API. [PR #713](https://github.com/relaystr/ndk/pull/713), merged
August 18, 2026, includes a test opening a TypeScript @nostr-wot/pq envelope.
[PR #712](https://github.com/relaystr/ndk/pull/712), merged the same day, replaced
round-3 Dilithium with FIPS 204 ML-DSA (44/65/87) for its experimental signer.
Both changes were contributed by leonacostaok.

This establishes a shared implementation with a cross-language test vector,
not a ratified Nostr standard. The [identity-key proposal](https://github.com/nostr-protocol/nips/pull/2434)
remains open. Ordinary event signatures are not made quantum-safe by adding PQ DMs.

### Nymchat

[Source](https://github.com/Spl0itable/NYM) · [Whitepaper](https://nymchat.app/whitepaper/)

A Nostr messaging client with hybrid ML-KEM-768 private/group messages. Its newer
pq2 format places a KEM-derived ChaCha20-Poly1305 layer around NIP-44 ciphertext;
public keys are discovered through kind:30078, d=nym-pq announcements.

[Encryption code](https://github.com/Spl0itable/NYM/blob/main/android-ios-app/lib/core/crypto/pq.dart),
[key registry](https://github.com/Spl0itable/NYM/blob/main/android-ios-app/lib/features/identity/pq_registry.dart)
and [messaging tests](https://github.com/Spl0itable/NYM/blob/main/android-ios-app/test/pq_gift_wrap_test.dart)
are public. The protocol differs from the ML-KEM-1024 / kind:10203 approach above;
compatibility needs explicit agreement, not just a shared algorithm family.
Nostr event signatures remain classical. Group confidentiality depends on all
copies being protected. The whitepaper describes the current independent-root
scheme; legacy derivation paths also remain in the source.

### Claudeway

[Source](https://github.com/JordanNewell/claudeway) · Python · MIT

Implements an optional ML-DSA-65 backend for signed consensus receipts, using
dilithium-py. Receipts can be transported inside kind:30078 Nostr events.
This protects the application receipt's authenticity; it does not encrypt DMs
or replace the outer event's BIP-340 signature. Verification still needs a trusted
receipt public key — a valid signature alone does not establish the signer's identity.

Evidence: [PQ backend](https://github.com/JordanNewell/claudeway/blob/main/claudeway/signing_pq.py),
[transport](https://github.com/JordanNewell/claudeway/blob/main/claudeway/transports.py),
[tests](https://github.com/JordanNewell/claudeway/blob/main/tests/test_signing_pq.py).
The tests cover round trips, tampering and wrong keys; they skip when the optional
PQ dependency is absent. Included as an application implementation, not an audited
production cryptography recommendation.

### x0x Nostr bridge

[Bridge source](https://github.com/saorsa-labs/x0x-nostr-bridge) · Rust · MIT / Apache-2.0

An experimental relay facade that sends Nostr events through a local x0xd daemon
and the x0x mesh. The [underlying x0x project](https://github.com/saorsa-labs/x0x)
documents ML-KEM-768 transport and ML-DSA-65 identities/signatures. Those algorithms
belong to the mesh layer; the bridge continues to accept classical Nostr signatures.
It does not upgrade an existing NIP-44 ciphertext to end-to-end PQ encryption.

Evidence: [transport adapter](https://github.com/saorsa-labs/x0x-nostr-bridge/blob/main/src/transport.rs),
[protocol handling](https://github.com/saorsa-labs/x0x-nostr-bridge/blob/main/src/proto.rs),
[adversarial transport tests](https://github.com/saorsa-labs/x0x-nostr-bridge/blob/main/tests/adversarial_transport.rs).
Useful for studying transport interoperability and preserving signed payloads across
meshes. This listing does not certify the bridge, daemon, or a deployment as secure.

*Entries reviewed against public source on September 10, 2026. This review checked
implementation scope and inspected tests; it did not execute upstream suites or
perform a full security audit.*
