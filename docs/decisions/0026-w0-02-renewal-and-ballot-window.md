# 0026 · Cards live one epoch, renewal is a session with evidence, and a ballot's card is the one of the deck's original close

**Status:** proposed, revised after re-review (W0-02, 2026-10-06) · `seam:` credential issuance and presentation, pseudonyms and nullifiers · **the alternative needs the owner and the outside review**

## Context

A renewed card has a new nym secret, so every pseudonym changes. Two reviews found three routes to one person holding two valid cards and casting two counted ballots in one deck: an evidence-free renewal chain within one period; evidence-free renewal plus a fresh enrolment after the issuer's dedup record expired; and a `closes` extension that moved a deck's validity window across a renewal boundary. A third finding: disclosing a per-card issuance period split presentations into cohorts small enough to join a chat identity to a voting pseudonym through public map-object bundles, which is an invariant 2 problem.

## Decision (draft 0.1, drafts only)

1. **Epochs.** A verifier's cards live in epochs of `V = floor(validity / 28 days)` periods, aligned to the Unix epoch. A card carries its epoch as a disclosed message and is valid in that epoch's periods only. A card issued mid-epoch is shorter-lived; nothing lives past `validity`.
2. **Same public fields for every valid card.** All cards of one epoch share one `kid` (a new key signs only epochs whose handover starts after it became `active`) and one message layout (fixed at handover start). So issuer, `kid`, `len` and `epoch` identify the issuer and nothing finer; the disclosed epoch is not a cohort.
3. **Renewal is a session with evidence** in the last two periods of an epoch (handover), which issues the next epoch's card, post-dated. There is no evidence-free renewal, no renewal presentation, no `POST /v1/verifier/reissue`, no `hum/reissue/1` scope and no V-3.
4. **Dedup outlives every card.** The issuer's dedup row stores `lastEpoch` and the request hash and lives until 30 days after that epoch ends. A session issues the current epoch (no row, or a dead card), the current and next epoch (first card in handover), the next epoch only (renewal), or is refused. One dedup key yields at most one card per epoch.
5. **Lost responses.** The signer's nym share is a deterministic function of a host secret and the request, so an identical retry gets the identical card instead of a dedup refusal.
6. **Ballot window.** A ballot's cards must be of the epoch of `period(closes)` of the deck lineage's **version 1**, and must have started. One person has one card per issuer per epoch, so one deck nullifier per policy slot; a `closes` extension cannot move the epoch, so an old card and its successor can never both act in one deck.

District example (`validity` 180 days, `V` = 6, epochs of 168 days): a card issued in period 2 of epoch 0 lives periods 2 to 5; the person renews with evidence in periods 4 or 5 and gets the epoch-1 card for periods 6 to 11; the row says `lastEpoch = 1` until 30 days after period 11; a fresh session in period 7 is refused. Cell count of the public card fields: one per issuer (two for one hour at a boundary).

## Cost

- A deck whose original `closes` falls in an issuer's epoch `E + 1` counts only that epoch's cards, which nobody holds as a started card until `E + 1` begins. The wait is from `opens` to that start, which for a long deck can be most of an epoch (up to `V` periods), not 56 days. Epoch grids are public, so organizers can deal around them, and the deck card says when counting starts. Two organizer levers follow, both visible in the log and neither able to single out a person: an original `closes` just after a boundary makes the electorate the members who renewed in handover; an original `closes` on an epoch's last day, extended afterwards, freezes the electorate to that epoch's holders.
- A card pinned to a deck is kept past its epoch until the deck is final, for later rounds and extensions.
- `validity` must be frozen within a verifier lineage, since the epoch grid depends on it; a `credential` dedup item is never the only one; several dedup rows resolve to the largest `lastEpoch` (`verifier.md`).
- Every nullifier a person has changes at each epoch: join, token and authorship nullifiers included. `chat.md`'s one-chat-identity-per-card rule holds per epoch.
- Renewal needs evidence every epoch (every 168 days for the district profile). The re-enrolment burden is the price of needing no cryptography beyond the drafts.

## Alternative for the owner and the review

**Evidence-free renewal with a stable nym secret.** Part of this is inside the pseudonym draft: its §6.1.2 says `signer_nym_entropy` "can be reused for the same prover" on re-issuance so a holder keeps the same pseudonymous identity, and Hum's deterministic derivation of that value already reuses it. What the draft does not give is the check that the holder's new `prover_nyms[0]` equals the one in the presented card: an honest holder recommits the same share and keeps every nullifier, but a dishonest one commits a fresh share and obtains a second identity, which is exactly the double-vote route. Closing it needs an equality proof between the hidden last message of the presented card and the new `commitment_with_proof`, a construction outside the drafts, which belongs with the hidden-predicate review in ADR 0022. With that proof, nullifiers never change, renewal needs no evidence, and the ballot window could relax to "valid now". It would also need the dedup row to outlive the chain, which item 4 already gives.

## Consequences

- `verifier.md`, `verifier-runtime.md`: dedup retention and row contents; the epoch-issuing rule; key rotation and layout aligned to epochs; the deterministic nym share; no renewal nullifier rows.
- `services.md`: issue body carries one or two commitments and returns a `cards` array; reissue endpoint, V-3 and reissue registry rows withdrawn; `hum/nym-share/1` added.
- `ballot.md` B2, `shield.md` `cards`: the window and the pinned card set.
- Failing vectors: a fresh session against a live row; a handover session against `lastEpoch = E_now + 1`; a ballot from the previous epoch's card; a ballot from the next epoch's card in an extended deck; a post-dated card before it starts.
