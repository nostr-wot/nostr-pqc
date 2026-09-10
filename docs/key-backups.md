# Key backup and restoration

[Overview](../README.md) · [Implementations](implementations.md) · [FAQ](faq.md) · [Backup guide](key-backups.md)

The following behavior is implemented for **0.7.0, pending store publication**.
It does not change the message or attestation protocol.

- Independently generated ML-KEM-1024 / ML-DSA-87 pairs can be imported into an
  existing account. Unlike seed-derived keys, an independent pair cannot be
  recovered from the account's mnemonic or nsec; retain its separate backup.
- In Settings → Post-quantum key, export either a plain key file or a
  password-encrypted backup. The same screen imports both, asking for the export
  password when needed and validating both key pairs before storing them.
- In the create/add-account wizard, Import Key accepts ordinary account secrets
  (mnemonic, nsec/hex, ncryptsec) and password-encrypted JSON seed backups, either
  pasted or selected as a file. A PQ-only file cannot create a classical Nostr
  identity: create/import that account first, then restore its PQ file in Settings.

A plain PQ key file contains Base64 public and secret keys:

```json
{
  "v": "nip-pqc/v1",
  "alg": { "kem": "ml-kem-1024", "dsa": "ml-dsa-87" },
  "kem": { "public": "<base64>", "secret": "<base64>" },
  "dsa": { "public": "<base64>", "secret": "<base64>" }
}
```

The CLI also writes an `origin` field (`derived` or `independent`); the extension's
plain export currently omits it. Import validates the key material rather than
relying on this descriptive field. The placeholders above are not valid keys.

The extension's password-encrypted backup is a **separate, extension-specific
envelope**, not a PQ key file or a NIP-49 ncryptsec:

```json
{ "v": 1, "salt": "<base64>", "iv": "<base64>", "ct": "<base64>" }
```

It encrypts the UTF-8 seed phrase or complete PQ JSON with AES-256-GCM. The key is
derived using PBKDF2-SHA-256, 210,000 iterations and a random 16-byte salt; the
random IV is 12 bytes. `ct` includes the GCM authentication tag. These parameters
describe the current backup format, not the vault's encryption settings.
Use the password chosen at export; a wrong password or damaged ciphertext fails
authentication. An encrypted ncryptsec wrapped inside this format still requires
its separate ncryptsec password after the outer file is decrypted.

Implementation: [backup encryption](https://github.com/nostr-wot/nostr-wot-extension/blob/main/src/lib/crypto/keyBackup.ts),
[PQ import](https://github.com/nostr-wot/nostr-wot-extension/blob/main/src/screens/Settings/PqcImportPanel.tsx),
[account import](https://github.com/nostr-wot/nostr-wot-extension/blob/main/src/screens/Wizard/ImportStep.tsx).

