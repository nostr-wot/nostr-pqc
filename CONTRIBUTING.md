# Contributing

This is an index of post-quantum cryptography work in Nostr. It aims to be **complete and accurate**, not promotional. Projects that compete with the maintainers' own are welcome and will be listed on the same terms.

## Adding a project

Open a pull request editing `README.md`, the relevant page under `docs/`, and `projects.json`. An entry needs:

1. **A link to source code.** A website or a blog post is not enough — an entry nobody can check is not an entry.
2. **Which problem it addresses.** Confidentiality (a KEM, protecting against harvest-now-decrypt-later), authenticity (a signature scheme, protecting against forgery), or both. This is the single most important field, because the two have completely different deadlines.
3. **Specific algorithms and parameter sets.** "Post-quantum" is not an algorithm. `ML-KEM-1024` is; `ML-KEM` alone is ambiguous about security level, and `Kyber` is not wire-compatible with `ML-KEM`.
4. **Hybrid or replacement.** Whether the post-quantum secret is combined with the classical one, or swapped in for it.
5. **Honest status.** `shipped`, `published`, `experimental`, `discussion`, or `closed`. Experimental work is welcome — mislabelled work is not.

## What gets rejected

- **Overstated protection.** Claiming a project protects against quantum attack when it only provides forward secrecy, key rotation, or a longer classical key. An index that lets a reader believe they are protected when they are not is worse than no index.
- **Unverifiable claims.** If the README says ML-KEM-1024 and the source imports ML-KEM-768, the source wins.
- **Vapourware.** A design document with no implementation belongs in the specifications section, clearly labelled, not in the implementations table.

## Corrections

If an entry misrepresents your project — in either direction — open an issue. Corrections from maintainers of the listed projects take precedence over third-party descriptions.

## Style

Describe what a project *does*, not how impressive it is. Prefer measured numbers over adjectives: "3 KB constant overhead" is useful, "lightweight" is not.
