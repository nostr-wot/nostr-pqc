# Passkey-held keys: implementation and user-experience guidance

Status: proposed companion guidance, 23 October 2026. This document is not an adopted industry standard. The wire-format and security requirements are in [NIP-XX](../XX.md) and [NIP-YY](../YY.md); recommendations here do not change their requirements. General passkey guidance is attributed below. Recommendations specific to encrypted Nostr recovery are this proposal’s design guidance.

## One identity, more than one recovery route

Keep the user’s identity stable when adding a passkey. A Nostr private key identifies an account; a seed can derive multiple accounts; a passkey protects access to a recovery record. These are different objects. Creating another passkey does not require creating another Nostr identity.

Recommend one convenient everyday sign-in method and an independently recoverable backup. Do not force a new passkey at every app, but do not make a single credential or provider the only recovery route. Multiple devices using the same synced credential are convenient, but remain dependent on that provider account. Additional credentials increase availability and also add access paths that need protection and management.

A newly created credential has its own PRF output. Protecting an existing identity with it requires re-encrypting the existing secret according to the protocol; deriving a new identity from the new credential would change the account. Do not silently substitute derivation when stored recovery fails. The [WebAuthn PRF explainer](https://github.com/w3c/webauthn/blob/main/explainers/prf-extension.md) describes per-credential secrets and the need to accommodate multiple credentials when encrypting data.

## Simple first-use and repeat-use flows

Keep shared guidance provider-neutral. Use generic actions such as “Continue with passkey” and, where supported, “Connect a signer.” Integrate with the host client’s existing login hierarchy and signer chooser rather than requiring a button for one vendor. Show concrete provider names only to identify available or selected sources, with the same compatibility and trust checks for all providers. Discovery is not authorization; an arbitrary source is not automatically trusted or compatible.

Offer “Continue with passkey” and a visible “Use another passkey” fallback. Continue with the last successfully used source only if remembrance was chosen; otherwise use the current client’s RP. The fallback opens a compact, searchable list of configured compatible sources, labelled by name and domain. These are credential origins, not credential managers. Let the platform choose the password manager/device. Do not enumerate credentials across RPs or automatically chain prompts. A cancellation or timeout is not evidence that a passkey does not exist. One request targets one RP ID, subject to origin authorization and browser support.

After recovery, show the account’s name and profile image, with a shortened public identifier available for checking. Show an account picker only when multiple usable accounts exist. Explain the access being granted before releasing key material to another app. On later visits, remember public routing information and the chosen account, not decrypted secrets merely to avoid a prompt.

Keep optional credential changes out of the critical sign-in path. After successful access, offer “Add another way to recover” in security settings. Use clear labels, such as “Use existing passkey” and “Add a passkey for this app,” rather than asking users to choose protocol modes. Google’s [passkey user journeys](https://developers.google.com/identity/passkeys/ux/user-journeys) recommend contextual enrollment, recovery preparation, and recognizable credential labels.

## Occasional use without migration

Support temporary access without creating a destination passkey. Keep decrypted secrets in memory for that session, with explicit expiry and logout cleanup; do not persist them in localStorage, sessionStorage or IndexedDB as an implementation shortcut. Remembering public account and RP routing details is a separate choice and should not confer silent signing access. Document the lifetime and permissions of any server session separately. Memory cleanup in garbage-collected runtimes is best effort, not guaranteed erasure.

Offer additional recovery methods in security settings after successful use. Make clear that session-only import still exposes the key to the receiving client; a signer connection is preferable when the receiving client should never possess it. Verify the implemented storage behavior before labeling a mode “Use this time.”

## Sharing an identity is a trust decision

Importing a key lets the receiving client use that key. Keeping the original passkey as the unlocking method does not turn import into remote signing. A client that decrypts a whole vault may access more than the account selected in its interface; disclose the actual scope, not just what is displayed.

Prefer a signer connection when an app only needs signing or encryption operations. For recovery/import, minimize the secret scope: a selected account key where sufficient; a whole seed or vault only for an explicit full recovery or backup operation. Never describe a single-account key copy as a seed backup. A host’s “seed backup” policy and a protocol’s support for single-key records are separate product decisions.

Protect authorized RP origins, hosting, native association files and cross-origin message handlers as key-access infrastructure. Verify exact origins and bind requests and responses to the initiating session. Do not send PRF outputs, seeds or private keys to analytics, logs, error reports, or ordinary backend authentication endpoints.

## Migration is optional and verified

Use “Add” or “Copy access” when the old credential remains usable. Reserve “Move” for a process that explains what is being retired. Keep/copy choices should state whether they cover one account or the entire vault and whether future vault changes will propagate. Independent copies do not automatically stay synchronized.

Recommended sequence:

1. Unlock the existing recovery method and identify the intended account or vault.
2. Explain the destination, scope and continued access through the original method; obtain confirmation.
3. Create the destination credential, encrypt the existing material, and confirm durable storage. Do not overwrite an unrelated non-empty provider record silently.
4. Start a fresh retrieval and decrypt using the destination credential. Compare the recovered public key, or all expected vault accounts, with the source. A successful credential-creation dialog alone is insufficient.
5. Test another device/provider path before claiming cross-device recovery, and establish an independent backup before retiring the only known working route.
6. Offer retirement separately, after checking dependencies on the original credential. On failure or cancellation, preserve the original and provide a clear retry path.

A legacy credential-derived identity needs its existing private key recovered and protected by the destination credential before the original is removed. Recreating a passkey with the same display name does not recreate that identity.

## Removal, retirement and compromise

Do not automatically delete the original passkey after a copy. It may still protect other accounts, other apps, or the only full seed/vault backup. Explain the scope and consequences of each removal action.

| Action | What it means |
|---|---|
| Forget this account on this device | Remove local remembered routing or session state; the passkey still exists. |
| Remove a service’s sign-in registration | Prevent that service from accepting the credential for authentication; this does not erase the credential from its provider. |
| Delete a passkey from its provider | Remove that provider-managed credential; assess effects on all dependent recovery records and accounts. |
| Remove an encrypted recovery copy | Remove a particular stored copy where supported; do not promise erasure of relay replicas or cached data. |
| Replace the Nostr private key | Change the identity; this is not merely replacing a passkey. |

FIDO’s [passkey management guidance](https://www.passkeycentral.org/launch-and-grow/troubleshooting-guidance/passkey-management-and-removing-passkeys) documents confusion between service-side removal and credentials retained by a provider. Applications should guide both sides rather than claim one action always completes both.

Adding a new passkey does not revoke an old party’s knowledge of the Nostr private key. Even deleting the original credential cannot retract previously decrypted secrets or guaranteed copies. If compromise is suspected, follow an explicit identity/key-compromise process; do not present passkey replacement as sufficient remediation.

## Recovery and storage durability

Authentication recovery and decryption recovery are different. Email verification or an administrator resetting a login cannot recover encrypted material without a valid decryption route. Say this clearly before the user relies on the system as their sole backup.

Do not assume that synced passkeys imply synced provider largeBlob data or available relay records. Test the exact credential manager, browser, OS and storage combination. Keep independent encrypted recovery copies where the protocol supports them, verify writes and subsequent reads, and expose degraded recovery without blocking a valid alternate source. Never fall back to an older vault against the protocol’s selection rules merely to make a login succeed.

Preserve unknown vault fields and unusable accounts when rewriting. A successful recovery of one account does not authorize discarding the rest. A seed-based backup must cover the actual derivation information; a standalone imported key requires its own backup. An ordinary login success is not proof that a recovery record remains usable.

Settings should show an understandable label, originating service, scope, last verified recovery date where known, and whether a method has actually been tested. Do not invent provider identity or claim “safe on all devices” from backup flags alone. Encourage an independently protected method and periodic recovery checks without making every login a setup wizard.

## Release acceptance

Before general availability, verify real-device recovery with the supported Apple, Google and other credential managers, browsers and hardware authenticators. Publish a dated support matrix instead of claiming universal passkey support. Test unavailable PRF, unsupported storage, provider-account loss, cancellation, stale or malformed relay copies, partial vault recovery, interrupted enrollment, fresh-browser recovery, and voluntary retirement using disposable test identities.

A staged release should deploy compatible readers before enabling new writes, preserve legacy recovery, and avoid automatic destructive conversion. Monitor aggregate failure categories without collecting secrets or unnecessary stable identifiers. Rollback should disable new enrollment if necessary while preserving the ability to read already-created records. Protocol fixtures and unit tests do not replace these acceptance checks.
