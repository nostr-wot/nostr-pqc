# Nostr Quantum

**An index of post-quantum cryptography (PQC) work in the [Nostr](https://github.com/nostr-protocol/nostr) protocol — every project, what it actually protects, and how it is implemented.**

Nostr identities are secp256k1 keys, and every Nostr public key is published to every relay it touches. A cryptographically relevant quantum computer running Shor's algorithm recovers a private key from a public key. Unlike Bitcoin — where an unspent output can hide behind a hash — a Nostr `npub` is *always* exposed by design. That makes Nostr unusually exposed to the quantum transition, and it makes the work catalogued here worth tracking.

This is a living index. If something is missing or wrong, [open an issue or a PR](#contributing).

---

## Contents

- [The two problems](#the-two-problems)
- [The index](#the-index)
- [Implementations](#implementations)
- [Specifications and discussion](#specifications-and-discussion)
- [Cryptographic primitives](#cryptographic-primitives)
- [Adjacent work (not post-quantum)](#adjacent-work-not-post-quantum)
- [FAQ](#faq)
- [Glossary](#glossary)
- [Contributing](#contributing)

---

## The two problems

Post-quantum Nostr is not one problem. It is two, with very different deadlines, and almost every disagreement in the ecosystem comes from conflating them.

### 1. Confidentiality — fixable *in advance*

[NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md) derives its conversation key from an ECDH shared secret between two secp256k1 keys. Anyone archiving encrypted Nostr events **today** can decrypt all of them the day secp256k1 falls. This is the **harvest now, decrypt later** attack, and it is the only part of the problem that can be pre-empted — a message encrypted with post-quantum protection today is confidential permanently, no matter when the break arrives.

Because of this, the confidentiality side is where most shipped work is concentrated, and it is solved with a **KEM** (key encapsulation mechanism), typically ML-KEM.

### 2. Authenticity — *not* fixable in advance

Once secp256k1 breaks, an adversary can forge any Nostr event and sign as any user. This is worse in impact, but it cannot be pre-empted: publishing post-quantum signatures today does nothing until the ecosystem stops accepting secp256k1 signatures. It is fixed only by migrating signatures *before* the break, which is a protocol-wide coordination problem rather than a library problem.

This side is solved with a post-quantum **signature scheme** — ML-DSA (CRYSTALS-Dilithium), SLH-DSA (SPHINCS+), or Falcon.

> **The practical consequence:** encryption work can ship unilaterally and helps immediately. Signature work needs a NIP and ecosystem-wide agreement, and helps only at cutover. Both are catalogued below.

---

## The index

| Project | Type of implementation | PQC algorithms | Hybrid | Layer | Status |
|---|---|---|---|---|---|
| [nostr-wot-extension](#nostr-wot-extension) | Key derivation + attestation publishing + post-quantum DMs, in a browser signer | ML-KEM-1024, ML-DSA-87 | Yes | Client / NIP-07 signer | **Shipped** (v0.4.0) |
| [@nostr-wot/pq](#nostr-wotpq) | Reference library: derivation, `kind:10203` attestation, hybrid message envelope, PQ DMs over NIP-17/59 | ML-KEM-1024, ML-DSA-87 | Yes | Library (TypeScript) | **Published** (v0.2.0) |
| [Dart NDK — quantum-secure signer](#dart-ndk--quantum-secure-signer) | Post-quantum event **signer and verifier** via native Rust FFI | CRYSTALS-Dilithium (2 / 3 / 5) | No (replacement) | Library (Dart) | Experimental |
| [nips#1971](#nips1971--post-quantum-nip-44) | Spec discussion: hybrid KEM for NIP-44 | ML-KEM, sntrup761, HQC | Yes | Specification | Open discussion |
| [NIP-101 (nips#391)](#nip-101--algorithm-transition-nips391) | Spec proposal: generic algorithm-transition framework | Falcon, SPHINCS+ | — | Specification | Closed |
| [@noble/post-quantum](#noblepost-quantum) | Underlying primitives used by the JS implementations | ML-KEM, ML-DSA, SLH-DSA | — | Primitives | Maintained |

**Legend — "type of implementation":**
`KEM` protects confidentiality (harvest-now-decrypt-later). `Signature` protects authenticity (forgery). `Hybrid` means the post-quantum secret is combined with the existing classical secret so the result is never weaker than today. `Replacement` means the classical scheme is swapped out entirely.

---

## Implementations

### nostr-wot-extension

**[github.com/nostr-wot/nostr-wot-extension](https://github.com/nostr-wot/nostr-wot-extension)** · MIT · TypeScript · Chrome / Firefox / Safari

The first Nostr signer to ship post-quantum keys to end users. As of **v0.4.0** it:

- **Derives ML-KEM-1024 and ML-DSA-87 keys from your existing BIP-39 seed** — not from your Nostr private key. The two are *siblings*, derived independently from the same mnemonic via domain-separated HKDF (`nip-pqc/v1/<alg>/<account>`). This is the security property the whole design rests on: an adversary who breaks secp256k1 and recovers your `nsec` cannot walk *back* to the seed, and therefore cannot reach your post-quantum keys. Your words do not change and there is nothing new to back up.
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

**[github.com/relaystr/ndk](https://github.com/relaystr/ndk)** · Dart · [pub.dev/packages/ndk](https://pub.dev/packages/ndk)

The Dart Nostr Development Kit ships an experimental **quantum-secure event signer and verifier** (`QsRustEventSigner` / `QsRustEventVerifier`), implemented over native Rust FFI using the `crystals-dilithium` crate. Security levels 2, 3 and 5 are selectable (~AES-128 / ~AES-192 / ~AES-256 equivalent).

This is the **signature** side of the problem rather than the KEM side, and it is a *replacement* rather than a hybrid: events are signed with Dilithium instead of BIP-340 Schnorr. It is published as a demo to provoke ecosystem discussion about what Nostr would need if quantum resistance becomes practically urgent — not as a production identity scheme. NDK is in use across downstream apps including Camelus, YANA, Zapstore and Zapstream, so it is a realistic place for such an experiment to live.

Complementary to the KEM work above: together they cover both halves of [the two problems](#the-two-problems).

---

## Specifications and discussion

### nips#1971 — post-quantum NIP-44

**[nostr-protocol/nips#1971](https://github.com/nostr-protocol/nips/issues/1971)** — opened by [paulmillr](https://github.com/paulmillr), July 2025. Open.

The canonical discussion thread. Argues for **hybrid** constructions that combine existing ECDH with a post-quantum KEM, rather than outright replacement — the same path Signal, WhatsApp and Apple's iMessage took. Names ML-KEM (lattice, broad adoption), sntrup761 (lattice, adopted by OpenSSH) and HQC (conservative, limited adoption) as candidates, with key sizes in the 1–2 KB range.

Open questions raised there and still unresolved: where post-quantum public keys are *stored* and discovered, and how any of this applies outside DMs. `@nostr-wot/pq` and the `kind:10203` attestation are a direct response to this thread.

### NIP-101 — algorithm transition (nips#391)

**[nostr-protocol/nips#391](https://github.com/nostr-protocol/nips/pull/391)** — by [eznix86](https://github.com/eznix86). **Closed** (May 2025).

Proposed a generic framework for transitioning Nostr's cryptographic algorithms without breaking compatibility, naming Falcon and SPHINCS+. Closed, but the discussion is the useful artifact: contributor [mikedilger](https://github.com/mikedilger) argued that post-quantum *signatures* are not urgent because nobody can forge signatures today, while *encryption* warrants concern because of harvest-now-decrypt-later — and suggested keeping SHA-256 IDs and secp256k1 signatures while optionally adding new algorithm fields alongside them. That framing has largely held.

> **There is no assigned NIP for post-quantum Nostr yet.** The `kind:10203` attestation used by the implementations above is an unregistered kind chosen by those projects, not a ratified standard. Treat every wire format on this page as provisional.

---

## Cryptographic primitives

### @noble/post-quantum

**[github.com/paulmillr/noble-post-quantum](https://github.com/paulmillr/noble-post-quantum)** · MIT · TypeScript

Auditable, dependency-light implementations of the NIST post-quantum standards — ML-KEM (FIPS 203), ML-DSA (FIPS 204) and SLH-DSA (FIPS 205). This is what the JavaScript Nostr implementations above are built on, from the same author who opened nips#1971.

### Parameter sets, and why the big ones

The implementations above use **ML-KEM-1024 and ML-DSA-87** — NIST Category 5, the sets mandated by NSA **CNSA 2.0**. Australia's ISM withdraws approval for ML-KEM-768 and ML-DSA-65 after 2030, so shipping the smaller sets would mean shipping parameters already scheduled for withdrawal. The cost is size, which is why the overhead tables above matter.

Reference standards:

- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) — ML-KEM (Module-Lattice Key Encapsulation)
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) — ML-DSA (Module-Lattice Digital Signature, formerly CRYSTALS-Dilithium)
- [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) — SLH-DSA (Stateless Hash-Based Signature, formerly SPHINCS+)

---

## Adjacent work (not post-quantum)

Listed because it is frequently — and incorrectly — cited as post-quantum protection.

- **[nostr-double-ratchet](https://github.com/mmalmi/nostr-double-ratchet)** (Martti Malmi, used by Iris and Damus) implements Signal's double ratchet over NIP-44, giving **forward secrecy** and post-compromise recovery. It is entirely classical elliptic-curve cryptography. Forward secrecy limits the blast radius of a *key compromise*; it does not help against an adversary who breaks the underlying curve, because that adversary can derive every ratchet key from the public transcript. Valuable, orthogonal, and not a substitute for a KEM.

---

## FAQ

### Is Nostr quantum-safe today?

No. Nostr identities are secp256k1 keys, event signatures are BIP-340 Schnorr, and NIP-04/NIP-44 encryption derives from secp256k1 ECDH. All three are broken by a sufficiently large quantum computer running Shor's algorithm. The projects indexed here are early, partial mitigations — none of them makes Nostr as a whole quantum-safe.

### Can a quantum computer steal my nsec from my npub?

Yes, in principle — that is exactly what Shor's algorithm does to elliptic-curve keys. Nostr is more exposed than most systems here because a public key is not optional: your `npub` is broadcast to every relay you touch, so there is no version of Nostr usage in which your public key stays private. No such quantum computer is known to exist today.

### What is "harvest now, decrypt later"?

An adversary archives encrypted traffic today and decrypts it years later once the underlying cryptography breaks. It is the reason encrypted DMs are the urgent part of the problem: every NIP-44 message sitting on a public relay right now is already collectable, and its confidentiality expires the day secp256k1 does. Messages sent with post-quantum protection today are not retroactively exposed.

### Which is more urgent, post-quantum signatures or post-quantum encryption?

Encryption. Not because forgery is less damaging — it is worse — but because encryption is the only half that can be fixed *in advance*. Protecting a message today protects it forever. A post-quantum signature published today prevents no forgery until the ecosystem stops accepting secp256k1 signatures, which is a coordination problem, not a cryptography problem.

### Do I need a new seed phrase or a new npub?

Under the derivation scheme used by `@nostr-wot/pq`, no: post-quantum keys come from the BIP-39 seed you already have, alongside your Nostr key rather than from it, so one mnemonic still restores everything. The caveat is entropy — a 12-word mnemonic carries 128 bits, which would make the seed the weakest link rather than the lattice, so 24 words are required for derived keys. 12-word identities can still publish an independently generated key pair, backed up separately.

### Why derive post-quantum keys from the seed instead of from the Nostr private key?

Because that would be circular. An adversary who recovers `nsec` from `npub` would simply run the same derivation and obtain the post-quantum keys too. BIP-32 and HKDF are one-way, so deriving both keys independently from the same seed means breaking secp256k1 reveals nothing about the seed and therefore nothing about the post-quantum keys.

### Does post-quantum Nostr require relay changes?

Not for the KEM-based DM implementations indexed here. The post-quantum payload rides inside an ordinary NIP-59 gift wrap, so relays see a normal `kind:1059` event and clients that have not implemented it are unaffected. Post-quantum *signatures* are a different story — those cannot be adopted without protocol-level agreement.

### How much bigger are post-quantum Nostr events?

About **3 KB of constant overhead** per direct message — roughly 2.4x a typical chat message — almost all of it the 1,568-byte ML-KEM-1024 ciphertext, amplified by NIP-59's base64 layers. The `kind:10203` key attestation is roughly 12 KB, but it is a replaceable event published once per identity and rewritten only on key rotation. See the [measured table](#nostr-wotpq).

### Which NIP covers post-quantum Nostr?

None yet. [nips#1971](https://github.com/nostr-protocol/nips/issues/1971) is the live discussion; [NIP-101](https://github.com/nostr-protocol/nips/pull/391) was proposed and closed. The `kind:10203` attestation used in practice is an unregistered kind chosen by the implementing projects.

### Is ML-KEM the same as Kyber? Is ML-DSA the same as Dilithium?

Effectively yes. ML-KEM (FIPS 203) is the NIST-standardised form of CRYSTALS-Kyber, and ML-DSA (FIPS 204) is the standardised form of CRYSTALS-Dilithium. The standardised versions differ from the original submissions in some details, so they are not wire-compatible — an implementation targeting "Kyber" and one targeting "ML-KEM" will not interoperate.

---

## Glossary

| Term | Meaning |
|---|---|
| **PQC** | Post-quantum cryptography — classical algorithms believed secure against quantum attack |
| **KEM** | Key encapsulation mechanism; establishes a shared secret. Protects confidentiality |
| **ML-KEM** | FIPS 203, lattice-based KEM, formerly CRYSTALS-Kyber |
| **ML-DSA** | FIPS 204, lattice-based signature scheme, formerly CRYSTALS-Dilithium |
| **SLH-DSA** | FIPS 205, hash-based signature scheme, formerly SPHINCS+ |
| **Hybrid** | Combining a post-quantum secret with a classical one so the result is no weaker than either |
| **HNDL** | Harvest now, decrypt later |
| **Attestation** | A signed Nostr event advertising an identity's post-quantum public keys (`kind:10203`) |
| **Proof of possession** | A counter-signature proving the publisher actually holds the advertised keys |
| **CNSA 2.0** | NSA's Commercial National Security Algorithm Suite 2.0, which mandates Category 5 parameters |

---

## Contributing

Additions are welcome, including projects that compete with the ones listed here — the point of an index is to be complete, not flattering.

To add a project, open a PR editing both [`README.md`](README.md) and [`projects.json`](projects.json), and include:

1. A link to source code (not just a website).
2. Which of [the two problems](#the-two-problems) it addresses — confidentiality, authenticity, or both.
3. The specific algorithms and parameter sets.
4. Whether it is hybrid or a replacement.
5. Honest status: shipped, experimental, or proposal.

Claims should be checkable against the source. Entries that overstate what a project protects will be corrected — an index that lets a reader believe they are protected when they are not is worse than no index.

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## License

[MIT](LICENSE). Maintained by [nostr-wot](https://github.com/nostr-wot) · [nostr-wot.com](https://nostr-wot.com)
