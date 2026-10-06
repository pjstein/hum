# W0-07 · Service APIs and the threat model

**Owns:** `docs/specs/services.md`, `docs/threat-model.md`

Wave 1 builds services and apps in parallel, so every boundary between them needs a fixed API. Write those APIs in one place, and write the threat model every reviewer will check against.

## Read first

- `docs/design.md`: "Protocol stack", "Privacy model and trust", "Open data platform"
- `docs/specs/manifest.md`: transparency logs, references and resolution, verification, security considerations
- The other wave-0 specs as they land (link to them; don't duplicate their formats)
- C2SP tlog-tiles, tlog-checkpoint, tlog-cosignature and tlog-witness (c2sp.org), as implemented by Tessera

## Services (`services.md`)

For each service, define endpoints, request and response formats, authentication (anonymous tokens wherever a person is involved), errors, rate limits, and what's logged:

- **Ledger and log:** submitting a manifest bundle, the checks it runs before appending (verification steps 1–6 and 8, plus 10 for releases), tiles, checkpoints, inclusion and consistency proofs, lineage lookup.
- **Witness:** cosigning checkpoints, compatible with the C2SP witness protocol so independent witnesses can join.
- **Aggregator:** opening a deck, ballot intake per release round, the noised daily count, publishing a release, and phase 2 (DAP Leader and Helper).
- **Issuer and verifier host:** issuance, evidence submission, re-issuance and revocation.
- **Delivery service and blob store:** link to `chat.md` and `storage.md`.
- **Resolver and mirrors:** serving bytes by CID, location hints, mirroring.
- **Gallery index:** listing and ranking takes; reading releases as Parquet.
- **OHTTP relay:** which requests must go through it, and who runs it.

## Threat model (`threat-model.md`)

- Adversaries from the design doc: the operator, a breach or subpoena, organizers, other members who know you, the public, and also a malicious verifier, a malicious or compromised agent, a compromised phone, and colluding servers.
- Assets: votes, hands, shields, the link between identities, membership, chat content, files, metadata.
- For every party: what it sees, what it must never see, and the mechanism that keeps it that way, with the spec section that guarantees it.
- Assumptions (non-colluding aggregators in phase 2, honest-but-curious operator in phase 1, at least one honest witness) and what breaks if each fails.
- Out-of-scope threats, stated plainly.
- The seam list from `CLAUDE.md`, mapped to the specs that define each seam.

## Done when

Every boundary that wave 1 workstreams share has an API here, the threat model covers every party and asset, and the `spec-reviewer` subagent has no blockers left.
