# W0-02 · Ballots, pseudonyms and the shield

**Owns:** `docs/specs/credentials.md`, `docs/specs/ballot.md`, `docs/specs/shield.md`

Specify how a person gets the right to vote in a context without being identifiable, how a phone casts a deck's votes, and how the phone tracks its own privacy budget. This is the most security-critical spec in the project. Be precise, cite the drafts you build on, and don't invent cryptography.

## Read first

- `docs/design.md`: "Privacy model and trust" (the who-sees-what table and three identities), "Verifiers", "Differential privacy design", "Deliberation layer (IBIS)"
- `docs/specs/manifest.md`: floors, verification, the `verifier`, `context`, `deck` and `release` types
- Your sibling specs as they land: `context.md`, `deck.md`, `release.md` (W0-01), `verifier.md` (W0-03)
- `docs/ux/screens/P-Verify.png`, `P-Join.png`, `P-Budget.png`, `Swipe-Deck.png`, `Swipe-End.png`, `IBIS-Card.png`

## Credentials (`credentials.md`)

- **Resident card:** a BBS credential (draft-irtf-cfrg-bbs-signatures) with selective disclosure, issued blind so the issuer never sees the credential it will later be shown. Attributes, issuance flow, expiry and re-issuance.
- **Per-context voting pseudonym:** a stable pseudonym per person per context with a nullifier, so one person can't vote twice and two contexts can't link the same person. Compare BBS with pseudonyms against Semaphore-style group proofs on phone cost, proof size, library maturity and how revocation works, and recommend one in `docs/decisions/`.
- **Policy presentation:** a zero-knowledge proof that the phone's credentials satisfy a context's entry policy, plus the nullifier. Unlinkable across contexts and to the issuer.
- **Chat name:** an MLS credential that signs what you say. State plainly that nothing connects it to the other two.
- **Agent sponsor credentials:** of a type no voting policy accepts.
- Every identifier any of these produce, where it's stored, and who can see it. This list is what the reviewers check.

## Ballots (`ballot.md`)

- What a phone submits for each release round (see W0-01's rounds): agree, disagree or unsure per card, bounded to the contribution cap K and encoded so every release part is a sum of bounded per-person vectors.
- Phase 1 (central DP): ballots under the voting pseudonym through an OHTTP relay (RFC 9458). Phase 2: the same values as Prio3 shares under DAP (draft-ietf-ppm-dap, draft-irtf-cfrg-vdaf). The phase 1 encoding must map onto a Prio3 type without changing what's measured.
- Re-votes after the IBIS card flips: how movement is recorded and capped.
- Receipts: what the phone keeps so it can check its ballot is under the release's receipt root, without the receipt identifying it to anyone else.
- What the aggregator learns in each phase, matching the design doc's who-sees-what table.

## Shield (`shield.md`)

- The yearly budget per person, tracked only on the phone (placeholder ε 20; the target is an open decision).
- Charge before sending: the phone charges the plan's maximum ρ when it votes, so an unused tier never costs more than declared.
- Composition under zCDP across releases and contexts; what happens when the shield runs out (the phone sits decks out and says why).
- Re-votes and IBIS parts cost more; how that's charged.
- Phone loss and restore: whether shield state is backed up, and how without weakening the guarantee.

## Done when

The three specs exist with byte-level formats where bytes cross a boundary, every identifier is listed with who can see it, the pseudonym recommendation is filed, the vector list is complete, and the `spec-reviewer` subagent has no blockers left. Mark the whole spec `seam:` in your summary.
