# 0021 · The voting nullifier is per deck, not per context

**Status:** proposed (W0-02, 2026-10-06) · `seam:` pseudonyms and nullifiers

## Context

`docs/design.md` calls the voting identity "a per-context voting pseudonym". `services.md` and `release.md` ask for one nullifier per (context, deck) that stays the same across a deck's rounds. The scope string decides which it is.

## Decision

The ballot scope is `hum/ballot/1 ‖ deck lineage CID`. One person has one nullifier per deck, the same in every round and every version of that deck (a `closes` extension is a new version of the same lineage). Two decks of one context yield unlinkable nullifiers.

## Why

- A phase-1 aggregator holds pseudonymous votes. With a per-context pseudonym it could build one person's raw voting profile across every deck of the context for as long as it liked; with per-deck pseudonyms it holds a profile for one deck, and `services.md` AG-5 deletes it 24 hours after the final version.
- Nothing needs cross-deck stability. Duplicate checks, replacements and later rounds are per deck. The daily count is per deck. Rating decks use a group the phone computed locally. The shield is on the phone.
- Composition across releases is a property of the noise, not of the pseudonym, so the DP accounting is unchanged.

The design doc's wording is a disagreement with the spec; the spec wins and this ADR flags it. Suggested wording: "a per-deck voting pseudonym derived from the resident card".

## Consequences

- `verifier.md`'s per-issuer uniqueness still bounds sybils: the per-deck nullifier comes from the context's designated credential, one per person per issuer.
- A context cannot count "distinct voters across the year" from nullifiers. That number is a release part if ever wanted.
- Re-issuance of a card changes its nym secret and therefore every nullifier; phones defer renewal while a deck they voted in is open (`credentials.md`).
