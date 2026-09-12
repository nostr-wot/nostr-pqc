# 03 — Post-quantum envelope for NIP-44 payloads

`draft` `optional`

A payload format that combines an ML-KEM-1024 encapsulation with the NIP-44 conversation key, so that a message stays confidential against an adversary recording it today and decrypting it after secp256k1 falls.

## Motivation

NIP-44's conversation key is a secp256k1 ECDH product. Every message encrypted under it is recoverable by anyone who can solve discrete log on that curve, which is what Shor's algorithm does. Traffic captured now is decryptable then, and no change made later helps the messages already recorded.

## Relationship to NIP-44

**NIP-44 does not prevent post-quantum messaging.** [NIP-44 already defines versioned encryption](https://github.com/nostr-protocol/nips/blob/master/44.md), explicitly allowing different constructions to coexist. A version selector is existing protocol machinery, not a new contribution of these drafts. The open question is whether to standardize a hybrid construction as a future NIP-44 version or continue maintaining a separate experimental envelope.

### Where NIP-44 is still used

The current hybrid DM path reuses the NIP-44 v2 conversation key in its combiner and uses NIP-44 v2 for the outer gift wrap. It changes the encryption of the rumor inside the seal:

| Layer | Current hybrid DM path |
|---|---|
| Rumor | Unsigned application event, serialized before encryption |
| Kind-13 seal `content` | This draft's local hybrid envelope, rather than a NIP-44 v2 payload |
| Kind-1059 gift-wrap `content` | NIP-44 v2 encryption of the seal |
| Seal and gift-wrap signatures | Existing classical BIP-340 signatures |

This reuses the [NIP-17](https://github.com/nostr-protocol/nips/blob/master/17.md) / [NIP-59](https://github.com/nostr-protocol/nips/blob/master/59.md) structure with an experimental change to seal encryption. It is not an unchanged, fully interoperable NIP-17/NIP-59 encryption path: a standard recipient can unwrap the outer layer but needs this envelope's decryptor and matching key material to read the rumor. The outer layer and signatures remain classical, so the hybrid inner payload does not provide post-quantum protection for every layer or for metadata.

### What v2 does not supply

NIP-44 v2 specifies secp256k1 ECDH, its KDF, padding, ChaCha20 and HMAC-SHA256. It does not supply a post-quantum KEM, recipient PQ-key discovery or the signer operations needed by this construction. Adding ML-KEM ciphertext, changing the combiner and using XChaCha20-Poly1305 changes that construction. Those bytes cannot be labeled `0x02` and treated as conforming v2 ciphertext.

These are gaps in the currently specified construction and surrounding key-management interfaces, not a restriction against extending NIP-44. A reviewed future NIP-44 version could define a hybrid construction. It would still need compatible implementations, authenticated recipient keys, signer support and explicit downgrade policy.

### Why document a separate envelope, and what does it cost?

This draft records the experimental format already implemented by the extension and SDK so that its exact bytes can be reviewed and reproduced without claiming an official NIP-44 version allocation. That is the practical reason to document it separately; it is not evidence that a separate format is necessary or preferable for long-term standardization.

The tradeoff is additional format dispatch, a local version/suite registry and compatibility work for each independent implementation. Our local `0x01` is **not an allocated NIP-44 version**; upstream NIP-44 lists `0x01` as deprecated and undefined. Only explicitly supported experimental decoding may interpret it as this envelope. An ordinary NIP-44 decoder must not be expected to recognize it, and arbitrary unknown payloads must not be guessed into this format.

Most of this profile's additional bytes come from its chosen PQ construction, especially the 1568-byte ML-KEM ciphertext. The local version and suite selectors occupy two bytes. The [size audit](AUDIT.md) measures the complete construction, including wrapping and padding; it does not show that crypto-agility itself requires the whole PQ size increase.

### Path toward a future NIP-44 version

A standardization proposal should first evaluate expressing the reviewed hybrid construction through NIP-44's existing version mechanism, and justify any separate suite selector rather than assuming one is needed. This repository cannot assign that future version. No specific future allocation or acceptance is implied.

If such a version is adopted, ship and verify readers before enabling writers, explicitly select a mutually supported method that satisfies user policy, and retain the historical decoder and keys needed for old messages. Do not relabel existing local envelopes as the new format, reinterpret existing selectors, or silently fall back to classical encryption. Relay carriage generally remains opaque; recipient compatibility and key lifecycle still require coordination.

## Hybrid first

The ML-KEM shared secret is mixed **with** the NIP-44 conversation key, never used instead of it.

```
shared_secret   = ML-KEM-1024.Encapsulate(recipient_kem_pk)      # 32 bytes
conversation_key = NIP-44 v2 conversation key                    # 32 bytes

PRK = HKDF-Extract(SHA-256, salt = "", IKM = shared_secret || conversation_key)
key = HKDF-Expand(SHA-256, PRK, info = "nip-pqc/v1/hybrid", L = 32)
```

An implementation of **this profile** MUST NOT use either input alone.

That is a property of this profile. Future encryption suites can be adopted by participating senders, recipients and signers without teaching opaque relays to decrypt. Event-signature migration is a separate coordination problem; see [draft 05](05-relay-crypto-agility.md).

The hybrid aims to retain confidentiality if one key-agreement component remains secure, subject to the combiner and symmetric construction assumptions. It is not literally NIP-44 after a KEM break: this profile uses a different KDF composition and AEAD. Independent cryptographic review is still required. The size cost is material for short messages; see the [audit](AUDIT.md).

A future profile that drops the classic input is expected, and the version and algorithm bytes exist so it can be introduced without breaking this one.

The ordering `shared_secret || conversation_key` is fixed and MUST be preserved.

## Wire format

```
+---------+-----+------------------+-----------+---------------------------+
| version | alg |  KEM ciphertext  |   nonce   |  XChaCha20-Poly1305 output |
|  1 byte | 1 B |    1568 bytes    |  24 bytes |     padded plaintext + tag |
+---------+-----+------------------+-----------+---------------------------+
```

Base64 encoded for transport, exactly like a NIP-44 payload.

| Field | Value |
|---|---|
| `version` | `0x01` |
| `alg` | `0x01`, meaning ML-KEM-1024 with XChaCha20-Poly1305 |
| KEM ciphertext | Output of `ML-KEM-1024.Encapsulate`, 1568 bytes |
| nonce | 24 random bytes, fresh per message |
| ciphertext | AEAD output over the padded plaintext, including the 16-byte tag |

The header is 1594 bytes. With the smallest padded plaintext (34 bytes) and the tag, the shortest possible envelope is 1644 bytes before base64.

### Self-describing on purpose

The version and algorithm bytes lead the payload so that a decrypting signer can route on the payload itself rather than being told which scheme was used. This is why decryption in draft 04 takes no flag and cannot be got wrong by a caller.

It follows that any future scheme MUST be distinguishable by these two leading bytes. A new scheme that reuses `0x01 0x01` with different semantics breaks every existing reader.

A NIP-44 v2 payload begins with `0x02`, which distinguishes that version from this local envelope. This does not establish compatibility with every historical or future NIP-44 version. Implementations MUST dispatch only explicitly supported formats and reject unknown selectors; they SHOULD test that ordinary v2 traffic is never routed into the experimental decoder.

### Associated data

```
AD = "nip-pqc/v1/env:" || version || ":" || alg || ":" || sender || ":" || recipient || ":" || kem_ciphertext
```

`version` and `alg` are decimal integers, so version 1 with algorithm 1 gives the prefix `nip-pqc/v1/env:1:1:`. `sender` and `recipient` are 64-character lowercase x-only pubkey hex.

Binding both pubkeys means a ciphertext cannot be replayed into a different conversation. Binding the version and algorithm means it cannot be presented as having used a weaker scheme. Binding the KEM ciphertext means the encapsulation cannot be swapped for another.

**Both pubkeys MUST be validated as 64 lowercase hex characters before use.** The fields are joined with `:`, so unvalidated input allows two different party pairs to produce identical associated data: a sender of `aaaa:bbbb` with recipient `cccc` yields the same string as a sender of `aaaa` with recipient `bbbb:cccc`. This was a real defect in an early implementation of this format, fixed in `@nostr-wot/pq@0.2.1`.

### Padding

This profile uses NIP-44 short-message padding with a two-byte big-endian length prefix. Minimum padded body length is 32 bytes and the profile maximum plaintext is 65535 bytes. Current NIP-44 additionally specifies an extended length prefix for larger messages; this experimental profile does not implement that extension. Its maximum applies to serialized rumor bytes, not just the chat text.

Reusing NIP-44's scheme rather than inventing one keeps the length leakage characteristics identical to what Nostr clients already accept, and means one padding implementation serves both paths.

The KEM ciphertext occupies 1568 bytes. Relative to a classical envelope, the binary difference is 1545 bytes for the same short-message plaintext; nested base64 and padding buckets make the final gift-wrap difference variable. The [reproducible audit](AUDIT.md) separates binary overhead from final wire size.

## Decryption

```
1. Base64 decode. Reject if shorter than the minimum length.
2. Reject if version != 0x01 or alg != 0x01.
3. shared_secret = ML-KEM-1024.Decapsulate(kem_ciphertext, our_kem_sk)
4. key = hybrid(shared_secret, conversation_key)
5. Verify and decrypt with AD rebuilt from the sender and recipient.
6. Unpad.
```

Cryptographic failures MUST produce a generic decryption error without exposing secret-dependent details. Use constant-time primitives and avoid secret-dependent early exits. Public framing and resource-limit checks can reject before expensive operations; this does not establish whole-call constant-time behavior in JavaScript. An unsupported format may be reported as unsupported without trying another scheme.

Note that ML-KEM decapsulation does not fail on a bad ciphertext; it returns an unrelated shared secret by design. The failure therefore surfaces at the AEAD tag check, which is the intended behaviour and not something to special-case.

## Key material requirements

Encryption needs the raw NIP-44 conversation key. Decryption needs the ML-KEM secret key. Neither is exposed by NIP-07 or by NIP-46, which return finished ciphertext and nothing else.

**This construction can therefore only be performed by the component that holds the key material.** In a browser extension that is the signer, not the page. A client library cannot implement this on top of a signer's public interface, no matter how it is layered, and an architecture that tries will end up either exporting the conversation key or reimplementing the signer.

This is the constraint that produces draft 04: since the page cannot do the work itself, the signer has to do it, and the page has to be able to find out whether this particular signer will.

## Reference implementation

[extension crypto](https://github.com/nostr-wot/nostr-wot-extension/blob/main/src/lib/crypto/pq.ts) in the extension repository, and [`@nostr-wot/pq`](https://github.com/nostr-wot/nostr-wot-sdk/tree/main/packages/pq), which is the normative one for the wire format.

## Relay migration

[Draft 05](05-relay-crypto-agility.md) preserves these bytes and specifies transport and discovery boundaries. The two-byte prefix is local to this envelope, not an allocated NIP-44 version. Legacy relays can carry it; legacy recipients cannot necessarily decrypt it.
