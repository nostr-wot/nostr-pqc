# FAQ and glossary

[Overview](../README.md) · [Implementations](implementations.md) · [FAQ](faq.md) · [Backup guide](key-backups.md)

## Encryption and signatures

Encryption protects message confidentiality, including against harvest-now-decrypt-later attacks. Signatures protect identity and event authenticity. Hybrid DM encryption can be added by compatible clients; changing the signatures accepted by the network requires coordinated adoption.

### Is Nostr quantum-safe today?

No. Nostr identities are secp256k1 keys, event signatures are BIP-340 Schnorr, and NIP-04/NIP-44 encryption derives from secp256k1 ECDH. All three are broken by a sufficiently large quantum computer running Shor's algorithm. The projects indexed here are early, partial mitigations — none of them makes Nostr as a whole quantum-safe.

### Can a quantum computer steal my nsec from my npub?

Yes, in principle — that is exactly what Shor's algorithm does to elliptic-curve keys. Nostr is more exposed than most systems here because a public key is not optional: your `npub` is broadcast to every relay you touch, so there is no version of Nostr usage in which your public key stays private. No such quantum computer is known to exist today.

### What is "harvest now, decrypt later"?

An adversary archives encrypted traffic today and decrypts it years later once the underlying cryptography breaks. It is the reason encrypted DMs are the urgent part of the problem: every NIP-44 message sitting on a public relay right now is already collectable, and its confidentiality expires the day secp256k1 does. Post-quantum encryption aims to resist this attack, subject to its security assumptions and implementation.

### Which is more urgent, post-quantum signatures or post-quantum encryption?

Encryption can protect newly sent messages against future decryption attempts. Signature migration also needs preparation now, but its protection depends on clients and relays enforcing the new authentication rules. Neither makes the entire protocol quantum-safe by itself.

### Do I need a new seed phrase or a new npub?

Under the derivation scheme used by `@nostr-wot/pq`, no: post-quantum keys come from the BIP-39 seed you already have, alongside your Nostr key rather than from it, so one mnemonic still restores everything. The caveat is entropy — a 12-word mnemonic carries 128 bits, which would make the seed the weakest link rather than the lattice, so 24 words are required for derived keys. 12-word identities can still publish an independently generated key pair, backed up separately.

### Why derive post-quantum keys from the seed instead of from the Nostr private key?

Because that would be circular. An adversary who recovers `nsec` from `npub` would simply run the same derivation and obtain the post-quantum keys too. BIP-32 and HKDF are one-way, so deriving both keys independently from the same seed means breaking secp256k1 reveals nothing about the seed and therefore nothing about the post-quantum keys.

### Does post-quantum Nostr require relay changes?

Not for the KEM-based DM implementations indexed here. The post-quantum payload rides inside an ordinary NIP-59 gift wrap, so relays see a normal `kind:1059` event and clients that have not implemented it are unaffected. Post-quantum *signatures* are a different story — those cannot be adopted without protocol-level agreement.

### How much bigger are post-quantum Nostr events?

About **3 KB of constant overhead** per direct message — roughly 2.4x a typical chat message — almost all of it the 1,568-byte ML-KEM-1024 ciphertext, amplified by NIP-59's base64 layers. The `kind:10203` key attestation is roughly 12 KB, but it is a replaceable event published once per identity and rewritten only on key rotation. See the [measured table](implementations.md#nostr-wotpq).

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
