# 0101 · Presentations that are logged must not be checked against the reader's clock

**Status:** accepted by the owner 2026-10-07, as applied; the seam diff still gets the owner's read before merge · `seam:` credential presentation, log proof verification

*2026-10-07:* The owner accepted the recommendation. The cosignature-timestamp option below stays open. Previous status: Applied 2026-10-06 on the owner's go-ahead; seam, pending owner review of the diff (W0-10).

## Context

`credentials.md` checks every presentation except a ballot with `epoch = E_now` on the verifier's own clock (rule P5), and reads the issuer `kid` from the verifier version in force "when the presentation is verified" (rule P3). That fits a join ticket or a token request, which is verified once.

Three presentations are stored in the log and verified again later:

- the membership proof in a signed issue-map object (`hum/author-once/1`);
- the membership proof in an unsigned one (`hum/author-slot/1`);
- the `sponsorProof` in an agent-sponsor manifest (`hum/sponsor/1`).

`issue-map.md` says "a phone runs every rule when it syncs", and IM-6 includes the membership proof. `manifest.md` step 9 has phones and aggregators verify every manifest a deck references, and a deck references positions and arguments. `agent-sponsor.md` has phones verify the sponsor manifest at an Add commit.

Read literally, a phone that syncs after the author's issuer has turned an epoch rejects every older object. A deck that pins a position written in the previous epoch fails step 9 on every phone and at both aggregators, so nobody can vote. A sponsor manifest with a 90-day `expires` stops verifying at the agent verifier's next epoch boundary. Two phones that read the rule differently hold different maps.

`verifier.md` and `trust-list.md` already use a different rule: the verifier version in force "at the presentation's log position".

## Decision (proposed)

Add a third row to the "Validity" table in `credentials.md` for logged presentations:

1. **At submission** the log applies today's rule with its own clock: `epoch = E_now`, with the first-hour grace. It also requires the envelope's `issued` to be within one hour of its clock for these three uses. `issue-map.md` already bounds the unsigned window this way.
2. **At any later verification** the verifier does not consult a clock. It checks that the disclosed epoch equals `epoch(period(issued − 7200))` or `epoch(period(issued + 3600))` for the object's `issued`. (As applied; the first wording here allowed the whole previous period, which was wider than the one-hour grace plus the one-hour `issued` bound needs.) It reads the issuer `kid`, the layout length and the trust-list rows from the verifier version in force at the object's log position, as `verifier.md` and `trust-list.md` already say.
3. A `kid` removed or retired after the object's log position does not invalidate the object. A `kid` removed before it does. This is the keyset revocation rule of `manifest.md` applied to issuer keys.

`credentials.md` P3 and its definition of "in force" change to say "at the log position, for a logged presentation". `issue-map.md` IM-6 and `agent-sponsor.md` AS-8 point at the new row.

## Alternatives

- Phones never re-verify logged presentations and trust the log's check. This breaks invariant 6: a phone would accept membership on a server's word.
- Authors re-prove each epoch. Objects would need a new version every epoch, and dealt objects are frozen.

## Consequences

- The log's clock check is the only clock in the path, as it already is for slot windows.
- **Corrected after review (AS9).** `issued` is chosen by the author and bounded only by one log's clock at submission. Witnesses check consistency and never times, and later verifiers use no clock. A log of record that skips the check admits a proof from an expired card with a back-dated `issued` for as long as the `kid` stays in `issuerKeys`, which since ADR 0104 is the epoch plus `KEY_TAIL` (520 days, not 30), and unlimited unsigned slots back-dated into old windows. That is wider than the one-hour grace, which an earlier version of this line claimed it equalled. It is now a stated assumption in `docs/threat-model.md`.
- **Log of record (AS11).** As applied, "the log" is the first entry of the context's `logs`. Other listed logs accept an object on proof of inclusion there.
- **Layout without a clock (AS10).** As applied, `verifier.md` attributes carry `fromEpoch`, so a later verifier computes the message count of an epoch from any manifest version.

## Open option, not specified

Require of a later verifier that `issued` is at most 3,600 seconds after the earliest witness cosignature timestamp on the checkpoint that proves the object. That bounds forward-dating without a clock of the verifier's own, using timestamps `services.md` today calls informational. A lower bound (against back-dating) would need an earlier checkpoint carried in the bundle. Needs the owner; it changes what a cosignature means.
- Vectors: one object verified in a later epoch (accepted), one whose disclosed epoch does not match `issued` (rejected), one whose `kid` was removed before its log position (rejected) and one removed after (accepted).
