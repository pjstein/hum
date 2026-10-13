# 0115 · Consensus tables across release stages

2026-10-13 · proposed; owner clarification required

## Conflict exposed by R15 integration

The existing release rules do not give one implementable answer for two vote-deck
paths. This predates the seven-lane integration; rating decks forbid consensus.

1. `release.md` Tables assigns consensus to part 3 at stage 4. R6 locks that part
   when its own noised count is below the gate, and R7 forbids locked-part tables.
   Yet R7's common-count wording and the existing `required_tables` function can
   require consensus at stage 4 solely from unlocked tallies and `nHat`.
2. `required_tables` permits optional part-0 consensus in nonfinal stages 1–3.
   R8 freezes its table CID. At stage 4, the same table must instead carry part-3
   metadata and noise parameters. The frozen bytes cannot satisfy both contracts.

The new `release_tables.contract_for` follows the table mapping and refuses a
locked part. Relaxing this check, consuming locked group data, or substituting
part 0 at stage 4 would silently choose protocol behavior. None was done.
Independent review confirmed the baseline contradiction in `required_tables`
was already present at commit `0ae01ca`.

## Recommendation

Reserve consensus publication for final versions. When the common-count gate is
met, use part 0 for a final version before stage 4; at stage 4 require consensus
only when part 3 is unlocked. Otherwise omit consensus. Do not allow early optional
consensus on a lineage that can proceed to stage 4.

After owner approval, revise R7, the computation prose and `required_tables`
together, then generate locked-part-3 stage-4, early-consensus transition and
final-stage-2/3 cases. R8 continues to freeze every previously published table.
An alternative is a separately named stable tallies-consensus table or an explicit
origin-based contract; either is a larger protocol choice.

## Present boundary

No normative rule or code was changed for this question. The passing public and
sealed four-stage fixtures cover unlocked part 3 and no early consensus; they do
not resolve these contradictory transitions. This remains a conformance gap.

`seam:` release tiers, privacy floors, table metadata and frozen publication state.
