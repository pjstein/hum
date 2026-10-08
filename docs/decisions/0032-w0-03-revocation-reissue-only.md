# 0032 · Credential revocation in draft 0.1 is re-issuance only

**Status:** proposed (W0-03, 2026-10-06)

## Context

The design doc allows two revocation methods: short-lived credentials re-issued on a schedule, or an accumulator the issuer publishes. An accumulator needs a scheme choice that depends on W0-02's credential recommendation (BBS with pseudonyms versus a group-proof scheme), a publication channel (a new verifier version per update, or a new manifest type), and a phone-side non-membership proof. None of that is needed to launch.

## Decision

`revocation.method` is `reissue` in draft 0.1. Cards live one epoch of `V = floor(validity / 28 days)` periods aligned to the Unix epoch (`validity` between 28 and 366 days), and renewal is an evidence session during the epoch's last two periods that issues the next epoch's card (`credentials.md` ADR 0026). There is no evidence-free renewal. `accumulator` is reserved in the schema with no defined scheme, and a manifest naming it fails validation rule 15. The emergency path is removing an issuer key from `issuerKeys`, which revokes every credential under that key for new presentations.

## Consequences

- Core verifiers set `validity` around six months (the district example gives 168-day epochs); a card issued mid-epoch is shorter, and people repeat the evidence step during handover.
- Revoking one person's card without rotating a key is not possible in draft 0.1. A verifier that needs that must shorten `validity`.
- Age bands stay honest through expiry rather than revocation.
- Revisit when W0-02's scheme is fixed and before federation, when re-issuance load on small verifiers may matter.
