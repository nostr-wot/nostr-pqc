# Nostr Quantum

An index of post-quantum cryptography work in Nostr: what each project protects,
which algorithms it uses, and where to find the implementation.

Nostr's classical keys and signatures are vulnerable to a sufficiently capable
quantum computer. The projects below address parts of that problem; none makes
Nostr as a whole quantum-safe.

## Projects

| Project | Focus | Algorithms | Details |
|---|---|---|---|
| Nostr WoT Extension | Hybrid encrypted DMs and PQ key management | ML-KEM-1024, ML-DSA-87 | [Browser signer](docs/implementations.md#nostr-wot-extension) |
| @nostr-wot/pq | Hybrid DM and key-attestation library | ML-KEM-1024, ML-DSA-87 | [TypeScript SDK](docs/implementations.md#nostr-wotpq) |
| Dart NDK | Hybrid DMs and experimental signing | ML-KEM-1024, ML-DSA | [Signer and verifier](docs/implementations.md#dart-ndk--quantum-secure-signer) |
| Nymchat | Hybrid private/group messages | ML-KEM-768 | [Client](docs/implementations.md#nymchat) |
| Claudeway | PQ-signed receipts carried by Nostr | ML-DSA-65 | [Application signatures](docs/implementations.md#claudeway) |
| x0x Nostr bridge | Nostr over a PQ mesh transport | ML-KEM-768, ML-DSA-65 (x0x) | [Infrastructure](docs/implementations.md#x0x-nostr-bridge) |
| nips#1971 | Hybrid KEM discussion for NIP-44 | ML-KEM, sntrup761, HQC | [Discussion](docs/ecosystem.md#nips1971--post-quantum-nip-44) |
| NIP-101 / nips#391 | Algorithm-transition proposal | Falcon, SPHINCS+ | [Proposal history](docs/ecosystem.md#nip-101--algorithm-transition-nips391) |
| @noble/post-quantum | Cryptographic primitives | ML-KEM, ML-DSA, SLH-DSA | [Library and standards](docs/ecosystem.md#noblepost-quantum) |

Encryption protects message confidentiality. Signatures protect identity and event
authenticity. These need different migration strategies; see the
[short explanation](docs/faq.md#encryption-and-signatures).

## NIP drafts

Protocol proposals live in [nip-drafts/](nip-drafts/README.md), including the [complexity, payload-size and interoperability audit](nip-drafts/AUDIT.md). Drafts 05-06 are unimplemented designs for review.

## Guides

- [Implementations](docs/implementations.md) — capabilities, wire format and size measurements.
- [Key backups](docs/key-backups.md) — plain and encrypted files, account import and PQ restoration.
- [Specifications and primitives](docs/ecosystem.md) — proposals, standards and related work.
- [FAQ and glossary](docs/faq.md) — security assumptions and common questions.
- [Machine-readable index](projects.json) — project metadata and recorded release status.

**Extension 0.7.0 is pending store publication.** Its new backup/import behavior is
marked separately from the previously documented release features.

## Contributing

Missing a project or spotted an error? Open an issue or PR. Update this overview,
the relevant detail page and [projects.json](projects.json). Include source links,
algorithms, protection scope and an accurate implementation status.
See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE). Maintained by [nostr-wot](https://github.com/nostr-wot).
