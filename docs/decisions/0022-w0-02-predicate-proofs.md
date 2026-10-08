# 0022 · Hidden-attribute predicates: not in draft 0.1; disclosure-only policies and a disclosed issuance period

**Status:** proposed, revised after review (W0-02, 2026-10-06) · `seam:` credential presentation

## Context

`context.md` policies carry three predicates: present, value in a set of up to 64, and value in a range. `verifier.md` wanted expiry proven and never disclosed. BBS selective disclosure proves "I hold a signature on these messages, and here are some of them"; it has no predicate over a hidden message, and the BBS drafts define none. `CLAUDE.md` says never hand-roll cryptography. The first draft of `credentials.md` specified a set-membership extension and claimed a fallback that needed none; the review found the fallback could not be configured and the extension was underspecified.

## Decision

1. **Draft 0.1 uses selective disclosure only.** A leaf is satisfied by disclosing the message when disclosure reveals nothing beyond "the leaf holds": `[0]` on a bool, a single-valued set, a range with `lo = hi`. Multi-valued sets, ranges with `lo < hi`, and `[0]` on an enum, band or uint are **not satisfiable in draft 0.1**. `context.md` is asked to reject them at validation so phones never meet them. A context that wants "wards 1 to 3" uses an attribute the verifier already coarsened (the district profile's `area`) or a verifier that issues the predicate as a bool.
2. **Expiry is a disclosed epoch, equal across every valid card.** Message 1 is the card's epoch, `floor(period / V)` with `V = floor(validity / 28 days) ≥ 1`, and a card is valid in that epoch only. Because every valid card from an issuer carries the same epoch (and the same `kid` and layout, ADR 0026), the disclosure forms no cohort below the issuer; the re-review's cell-count concern (up to 78 cells of 1,000 voters with per-card periods) is closed by construction rather than accepted. For ballots the epoch is that of the deck's original `closes` (ADR 0026). `verifier.md`'s "never disclosed" becomes "disclosed and identical for all valid cards".
3. **The hidden-predicate extension is described, not specified.** `credentials.md` "Future: hidden predicates" gives the shape (a linked Pedersen commitment plus a Cramer–Damgård–Schoenmakers OR-proof, folded into the BBS challenge as the pseudonym draft folds its own extension) and the open points: scalar mapping of set values, generator derivation, transcript order, verifier-version binding, and a library that exposes the per-message blinding without a fork in a seam. No vectors are generated for it. The outside review chooses among this, a range-proof system, and expiry by issuer-key rotation.

## Alternatives considered

- **Specify the extension now.** Rejected: two implementers would produce different bytes from the first draft, and no library exposes the linking step without a fork.
- **Disclose multi-valued attributes.** Tells the phase-1 aggregator every voter's ward. Rejected; a consented version is the same question as the phase-1 breakdown (`ballot.md`) and waits for the owner.
- **One-hot attributes at issuance.** Proof size grows with the attribute's value count. Rejected.
- **Expiry by issuer-key rotation with no period message.** Needs no disclosure and no extension, leaks the issuance window as a `kid` cohort instead of a period cohort, and constrains `verifier.md`'s key schedule. Kept as the review's alternative.

## Also for the outside review (from the library pass, 2026-10-06)

- **Single nym secret and quantum adversaries.** The pseudonym draft §9.1 promises cross-scope unlinkability against a cryptographically relevant quantum computer only while a prover uses fewer distinct `context_id`s than the length of the nym-secret vector, and marks its proof as to-do. Hum uses `N` = 1 and one scope per deck, day, join and object, so that promise does not apply; today's unlinkability is DDH in G1. The review should say whether a larger `N` (more committed scalars per card, each proof growing by one scalar per extra secret) is worth it, given that every other pairing-based piece of the stack has the same exposure and a card lives one epoch.
- **The alternative renewal in ADR 0026** reuses `signer_nym_entropy` as §6.1.2 allows and needs only the equality proof described there.

## Consequences

- Draft 0.1 policies: bools, single values, and conjunctions and disjunctions of them. The `context.md` example changes `ward ∈ {1,2,3}` to `area = 1`.
- `verifier.md`: `validity ≥ 28 days`; lifetime between `28(V − 1) + 1` and `28V` days; one `active` issuing key (cohort bound); `valid-for` has no effect; `max` below 2⁶⁴ − 1.
- `credentials.md` isolates predicate satisfaction behind one table, so a reviewed hidden predicate can be added without touching ballots, policies or scopes.
- Presentation sizes are small (about 0.6 KiB per card); `chat.md`'s `TICKET_BYTES` of 4,096 holds with room.
