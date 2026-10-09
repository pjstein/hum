# Wave 0 handoff

Written 2026-10-08 at the end of the orchestration session. Read this before continuing wave 0 or starting wave 1.

## State in one paragraph

Wave 0 is written, reviewed and committed on branch `wave-0/contracts` (12 commits on top of `main`, last one `882810d`, not pushed, not merged). At that commit `just check` exited 0 with 268 reference tests and 794 accepting plus 752 rejecting vectors, and `just sim-fast` passed 5 scenarios with 4 adversarial hooks pending. After that commit the owner approved three more decision records. Their spec edits are in the working tree, uncommitted and not yet verified. The reference implementation and vectors do not follow them yet.

## What is committed (`wave-0/contracts`)

- 17 specs in `docs/specs/` plus `docs/threat-model.md`. Per-spec reviews are in `docs/specs/reviews/`.
- The cross-spec review `docs/specs/reviews/cross-spec.md`. Section 12 lists every decision applied after review, by file and section.
- `docs/specs/reviews/applied-decisions.md`: the review of the applied decisions.
- `reference/` and `vectors/`: the Python reference and 1,546 vectors. Coverage, gaps and resolved disagreements are in `docs/specs/conformance.md`.
- `sim/`: the simulator skeleton.
- `docs/research/seam-libraries.md`: library research.
- `docs/DECISIONS.md` and `docs/decisions/`: the decision log. Owner decisions are under "Accepted by the owner on 2026-10-07".
- `CLAUDE.md`: the hand-roll rule was reworded on the owner's approval so that a protocol construction from a published draft may be built in-house.

## What is in the working tree, uncommitted

Applied on 2026-10-08 on the owner's answer "apply all recommended". The record is `docs/specs/reviews/cross-spec.md` section 12.9.

- Decision records 0103, 0104 and 0107 applied across 14 specs and the threat model.
- The two-phone shield risk recorded as accepted for draft 0.1 (record 0023).
- The independent check for the in-house BBS crate recorded as a second implementation in the Python reference (record 0110).
- `docs/DECISIONS.md` gained "Accepted by the owner on 2026-10-08".
- `sim/`: the leak checker change for record 0107. Verified with the Rust gates and `just sim-fast`; not committed.

## What was running when the session ended

These agents do not survive the session. Check for their output files before redoing the work.

1. **Review of the 0103, 0104, 0107 edits.** If it finished, `docs/specs/reviews/applied-decisions.md` has a section titled "ADRs 0103, 0104, 0107". If that section is missing, run the review again.
2. **Simulator change.** Done and verified at the end of the session, uncommitted: `sim/src/leak.rs` and `sim/src/world.rs` follow the new allow table. The format check and clippy were clean, `cargo test --workspace --locked` passed 47 tests, and `just sim-fast` passed 5 scenarios. One stale line remains in `docs/specs/simulator.md`: the W1-05 plug-in row still says chat registers "device keys as MLS leaves", which the new table forbids at the delivery service. Fix that row.
3. **BLS12-381 library research.** If it finished, `docs/research/bls12-381-libraries.md` exists.

## Remaining steps to close wave 0

1. Finish or redo the three items above.
2. Fix whatever the review of 0103, 0104, 0107 finds. Earlier rounds each found one or two real blockers, so expect some.
3. Bring the reference and vectors in line with section 12.9. Byte-level changes: `join-record` key 1 becomes an array `nullifiers` with a new key 5 `day`; the `authorship` map loses key 4; `context` gains optional keys 20 `resolvers` and 21 `relays`; every `services.md` body gets integer keys and the receipt gains `kid`; evidence is sealed under `hum/evidence/1`; a below-minimum release has no receipt root and no part 8. The new vector names are listed in section 12.9.
4. Run `just check` and `just sim-fast` yourself. Do not accept an agent's report of a green gate.
5. Commit on `wave-0/contracts`. The owner reviews the seam diffs before merging to `main`.

## Decisions waiting on the owner

- **`CLAUDE.md` invariant 3 wording.** Record 0103 asks to replace "at least 100 noised voters to publish," with "at least 100 noised voters to publish anything except the organizer's noised daily count, which is served while a deck is open and is inside the deck's declared ρ,". Not applied. Ask before editing.
- **BLS12-381 library** for the in-house BBS crate, Rust and Python sides. Research was running.
- **Privacy targets.** ε 4 per release and ε 20 per year are placeholders. The rating-deck budget depends on them.
- **Receipt clamp δ** (record 0102 items 2 and 3). Adopting it changes every reported ε.
- **Outside cryptography reviewer.** Scope so far: records 0022 and 0026, and the BBS crate.
- **One chat identity per resident card** (`chat.md` open question 16) and **whether a context can forbid agents**.
- **`docs/design.md` edits.** The list is in `cross-spec.md` section 10. The specs win where they differ.
- **Operator, Helper, relay and witness operators, hosting, licenses, first contexts.**
- Remaining parts of record 0105 (signature convention, media types) and the retired and successor markers in `manifest.md`.

## Vector gaps that libraries now unblock

The owner approved the libraries in `docs/DECISIONS.md` ("Libraries" table). Not started: HPKE-sealed formats (`pyhpke`), Argon2id (`cryptography`), Parquet tables and release rule R15 (`pyarrow`), verifier-runtime rules (`wasmtime-py`), 14 chat sets that need MLS (`mls-rs` through its uniffi bindings), Privacy Pass tokens (RFC 9578 vectors), and BBS proofs (the in-house implementation).

## What this session learned the hard way

- **Verify relayed claims.** Agents reported green gates that were not green, and reported fixes that had not landed. Re-run the gate and read the spec text.
- **Reviews find real problems late.** The shield bound was broken three separate ways after it was first "fixed". Every applied decision got a review, and each review found something.
- **Session limits kill agents silently.** An agent that stops mid-task leaves the tree half edited. Ask for a return to green after each step.
- **Regenerating vectors.** The generator now writes to a temporary directory and swaps it in, so a crash no longer empties `vectors/`. Before that fix, a failed `just vectors` did empty it.
- **The reference test suite takes about 22 minutes.** Run `just check` in the background.
- **Agents edit each other's assumptions.** After any spec change, tell the reference author the byte-level changes explicitly.
