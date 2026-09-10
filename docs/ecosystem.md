# Specifications and primitives

[Overview](../README.md) · [Implementations](implementations.md) · [FAQ](faq.md) · [Backup guide](key-backups.md)

Project statuses below reflect the existing index; follow the source links for current discussion.

## nips#1971 — post-quantum NIP-44

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
