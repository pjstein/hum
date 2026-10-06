# W0-03 · Verifiers, trust lists and the verifier runtime

**Owns:** `docs/specs/verifier.md`, `docs/specs/trust-list.md`, `docs/specs/verifier-runtime.md`

Verifiers are a protocol, not a plugin store: anyone can run one, including a context's administrators from day one, and the platform's own district verifier speaks the same protocol. Specify it.

## Read first

- `docs/design.md`: "Verifiers" and "Open questions and risks" (identity)
- `docs/specs/manifest.md`: the `verifier` and `trust-list` rows of the type registry, and security considerations
- `docs/specs/credentials.md` as W0-02 drafts it (issuance and presentation live there; you define what a verifier declares and runs)
- `docs/ux/screens/P-Verify.png`

## Verifier manifest (`verifier.md`)

- Body fields: issuer public keys, attributes issued (names, types, value sets), the evidence it collects and how long it keeps it, deduplication method, revocation method (short-lived credentials re-issued on a schedule, or a published accumulator), declared assurance level, and the hash of its code.
- What the phone shows before anyone submits evidence, generated from the manifest alone.
- Profiles for the first verifiers: **invite** (an organizer-issued link or code), **approved list**, **district** (a core verifier: proves residence in a ward without revealing the address), **age band**, and **uniqueness**. The district and uniqueness verifiers are core infrastructure but earn trust the same way as any other.
- Attributes that gate entry versus attributes that can appear in breakdowns, and how the 300-voter cell gate applies (a unit number can gate entry but never appears in a breakdown).

## Trust lists (`trust-list.md`)

- Who can publish one, its scope, the verifier authorities and attributes it accepts, and how contexts reference lists or single issuers in their entry policy.

## Runtime (`verifier-runtime.md`)

- Where custom verifier code runs (a WebAssembly sandbox is the leading option), its host interface, resource limits, and what it can never reach (nothing that could link a credential to a later presentation).
- How reproducible builds tie the running code to the hash in the manifest, and who can check that.
- Custom code can over-collect evidence; the defense is transparency. Spell out what's visible to whom.

## Done when

Three specs exist, the five verifier profiles are concrete enough to build, the runtime's host interface is fully listed, vectors are listed, and the `spec-reviewer` subagent has no blockers left.
