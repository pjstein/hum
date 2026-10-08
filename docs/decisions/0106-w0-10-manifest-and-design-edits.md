# 0106 · Edits the cross-spec review asks of `manifest.md`, `design.md` and the threat model

**Status:** the `manifest.md` items 2 to 7 and the threat-model items are accepted by the owner 2026-10-07, as applied. Still open: `manifest.md` item 1 (envelope keys for the retired marker and successor pointers), the rest of the `manifest.md` list, and every `design.md` edit · `seam:` signing, canonical encoding (the manifest spec)

*2026-10-07:* The owner accepted the applied edits. Previous status: the `manifest.md` items 2 to 7 and the threat-model items are Applied 2026-10-06 on the owner's go-ahead; seam, pending owner review of the diff (W0-10). Still open: `manifest.md` item 1 (envelope keys for the retired marker and successor pointers; this ADR names no keys, so none were assigned), the rest of the `manifest.md` list in `cross-spec.md` section 10, and every `design.md` edit.

## Context

W0-10 may not edit `docs/specs/manifest.md` or `docs/design.md`. Both now disagree with the type specs in places the type specs recorded as proposals. `CLAUDE.md` says the spec wins over the design doc and the disagreement is flagged. This ADR is the flag. The full lists, with the section of each edit, are in `docs/specs/reviews/cross-spec.md`, "Edits needed in files this review does not own".

## Decision (proposed)

Apply the listed edits. The ones that block work:

**`manifest.md`**

1. Assign envelope keys for the retired marker and the successor and superseded lineage pointers. Until then a scheduled deck cannot be withdrawn (`deck.md`), a verifier lineage cannot retire (`verifier.md`), and `take.md` and `agent-sponsor.md` each carry their own body field `retired`.
2. Say how the domain string enters a signature: COSE `external_aad`, detached payload equal to the CID (ADR 0082). Apply the rename if ADR 0105 item 1 is accepted.
3. Adopt or point to the bundle wire format in `services.md` (map keys 0 to 4, the proof map, the media type, rules B-1 to B-4).
4. Keyset version 1 carries no `authority` field and is signed by its own `rotate` threshold (ADR 0082).
5. Type registry: add `service` with its kinds and retire `blob-store` (ADR 0072); state the two-signer rule for `release` with the Helper in the body (ADR 0010 item 5); correct the rows for `deck`, `take`, `verifier`, `agent-sponsor` and the participant-authored types.
6. Replace the deck example (no `aggregators` or `statements` ref, `rho` as a `rat`, per-part ρ).
7. Verification: step 6 has two variants (authorship for participant-authored types, two keysets for a release); logs run the step-9 reference rule and step 10 for every type; `issued` is load-bearing in `release.md` R10, R13 and R14.

**`design.md`**

1. The voting pseudonym is per deck and comes from a BBS credential, not a Semaphore-style per-context group proof (ADRs 0020, 0021).
2. The resident card is issued once per issuer epoch, with evidence at each renewal (ADR 0026). The issuer sees the attributes and the signature and never the pseudonym secret.
3. The delivery-service row of the who-sees-what table gains what `chat.md` §12.10 lists: the context of a channel, the message class, the epoch rate, Welcome and ticket counts and token issuance counts.
4. A release has up to three post-close rounds and is published as up to four versions of one lineage (ADR 0014).

**`docs/threat-model.md`**

The edits that follow from ADR 0100, three stale references, and one new row for the timing of a first ballot.

## Consequences

- No behavior changes. These edits make the two owner-controlled documents say what the specs already say.
- Item 1 of the manifest list changes envelope bytes for retired versions only, and no retired version exists yet.
