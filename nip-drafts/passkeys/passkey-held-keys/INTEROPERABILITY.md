# Enabling another client or passkey source

Operational guide, 23 October 2026. Applies equally to every provider. Protocol compatibility, origin authorization and proven recovery are separate requirements. Being listed in a chooser does not satisfy the other two.

## Two sides of an integration

The source owns the RP domain and the credentials created under it. The receiving client wants its users to unlock those credentials. For direct web access using Related Origin Requests, the source explicitly authorizes the receiving origin; the client separately configures the source and understands its recovery records. This is directional: authorizing client B at source A does not authorize A at B.

A single WebAuthn request uses one RP. A source chooser selects that RP; it cannot discover every passkey in the user’s password manager. A new source must not be enabled through an arbitrary URL entry without the same review.

## Integration procedure

| Step | Responsible role | Action | Evidence required to close |
|---|---|---|---|
| 1. Identify | Receiving-client maintainer | Supply exact HTTPS origins for each environment, application/platform versions, technical contact and intended user flow. | Reviewed request with production and staging origins separately identified. |
| 2. Declare scope | Both maintainers | Decide signer-only access versus direct key/vault recovery. State what secrets the receiving client can see and whether it persists them. | Explicit scope and user consent text; no claim that account selection prevents access to an already-decrypted vault. |
| 3. Match the contract | Both implementers | Agree draft/package versions, handle modes, parameter sets, legacy formats, optional vault support, storage/relay locations and error behavior. | Shared fixtures pass in both actual implementations; incompatible modes are visibly rejected. |
| 4. Review trust | Source owner | Review receiving-origin ownership, client security, secret storage, dependencies, consent, incident contact and deployment controls. | Named approval for exact origins and capabilities. Registration is not automatic. |
| 5. Authorize web origin | Source operator | Publish/merge approved origins into https://<source-rp>/.well-known/webauthn as application/json over HTTPS. Preserve existing approved origins; do not replace the file blindly. | HTTP 200 valid JSON plus successful origin validation in each supported browser. |
| 6. Configure receiving client | Client operator | Add source name, RP ID and supported relay configuration to its reviewed catalog; enable only after the checks above. | Config validation, source chooser test, source removal disables remembered shortcuts. |
| 7. Verify recovery | Both QA owners | Use disposable identities on real supported devices, including fresh-browser recovery and cancellation/failure paths. | Same expected public key recovered; no silent new identity; no unwanted persistent secret or token. |
| 8. Pilot and release | Both release owners | Start with a limited cohort and named compatible versions; publish supported platforms, failure paths and support contacts. | Pilot results, rollback instructions and released-version evidence. |
| 9. Maintain and retire | Both operators | Recheck after origin, package, credential-format or platform changes; disable unsupported entries and warn affected users before planned removal. | Dated matrix and documented incident/retirement procedure. |

No actual user seed, private key, PRF output or exported personal vault is needed for onboarding review. Use public fixtures and disposable test identities only.

## Example: request access to Nostr WoT’s RP

A LaWallet operator first supplies the actual deployed LaWallet origins. Do not assume that every self-hosted LaWallet instance is authorized. Different deployments require explicit review; authorizing one hosted origin does not authorize all installations.

If Nostr WoT approves direct recovery access for an illustrative client origin, its RP endpoint would include:

```json
{
  "origins": [
    "https://wallet.example.org"
  ]
}
```

This is an example, not a proposed production deployment or an instruction to overwrite existing origins. Paths are not origins; list the exact scheme, hostname and port where applicable. Do not treat this as a per-account or read-only permission: the approved origin may request credentials for the RP and, following the ceremony, obtain PRF-derived secret access. Creation capabilities must also be considered in the trust review.

The receiving LaWallet deployment then adds a source to its existing PASSKEY_IMPORT_SOURCES configuration, for example:

```json
[
  {
    "label": "Nostr WoT",
    "rpId": "passkeys.nostrwot.com"
  }
]
```

Source names belong inside this chooser; the main action remains “Continue with passkey.” Relay configuration must match tested recovery locations; do not invent relay URLs. Core/vault/legacy capability support is currently an implementation agreement, not an automatically discovered standardized manifest.

Verified on 23 October 2026: https://passkeys.nostrwot.com/.well-known/webauthn returned HTTP 404 with text/html. Direct related-origin browser requests are not ready through that endpoint. Existing native association endpoints are separate and do not establish web permission. Enabling this requires exact destination origins, trust approval and a hosting change followed by browser tests; this guide has not deployed that change.

## Native and unsupported-platform cases

Apple associated domains and Android Digital Asset Links bind native applications to domains using their platform-specific identifiers and signatures. They are separate from the web origins list. Request those integrations separately and verify actual app entitlements/certificates; never add a native application identifier to the origins array.

Browser/platform support varies. If direct related-origin recovery is unsupported or the source declines to trust the receiving origin, keep a generic supported signer route available. A source-hosted broker or redirect can be designed separately, but it needs its own origin checks, request binding, consent and output-scope review; it is not implemented by this protocol draft and must not be advertised as an existing fallback. Do not solve unsupported access by forcing migration or raw-key export.

## Scaling beyond a handful of sources

A receiving client can maintain a reviewed, searchable catalog with per-source status. WebAuthn’s related-origin limit applies at each source RP and counts registrable origin labels; it is not a universal five-source limit on the client’s catalog. The standard requires supporting clients to handle at least five such labels and permits limits. This makes a shared RP for arbitrary thousands of unrelated clients unsuitable as an assumed baseline.

The current LaWallet schema independently limits configured sources to five. Review that application cap as part of chooser implementation, rather than confusing it with the source RP’s browser limit. A large catalog needs bounded search, enable/disable state, ownership and versioned configuration, but does not need to probe every source at login. Prefer normal signer interoperability for broad ecosystem access where direct RP sharing cannot scale safely.

## Request template — prepared, not sent

Subject: Passkey interoperability support request for [client name]

We would like users of [source name / RP ID] to open their existing identity in [client name] without mandatory migration. Our exact production origin is [origin]; staging is [origin, separately approved or omitted]. The integration requests [signer operations / direct selected-key recovery / full-vault recovery], and the receiving client can access [precise secret scope].

Our implementation uses [protocol draft revision and package versions], supports [modes and legacy formats], and stores [session/public metadata policy]. Here are the consent flow, source code, security review and shared-fixture results: [links]. Our supported and tested browsers/devices are [matrix]; our technical and security contact is [contact].

Please confirm compatible credential formats and recovery locations, your origin-approval process and whether direct access is appropriate. If approved, please add the exact agreed web origins to your RP’s /.well-known/webauthn, preserving existing entries. We propose a disposable-identity pilot before public availability. If native access is needed, we will provide platform identifiers and certificate evidence separately. We will not ask for users’ secrets or treat listing as permission to access accounts without consent.

## References

[WebAuthn related origins](https://www.w3.org/TR/webauthn-3/#sctn-related-origins), [core draft](../XX.md), [vault companion](../YY.md), [best practices](BEST-PRACTICES.md).
