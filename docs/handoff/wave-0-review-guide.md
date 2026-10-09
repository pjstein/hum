# Wave 0 owner review guide

W0-11 · 2026-10-09 · `wave-0/contracts`

This is a contracts closeout, not a claim that the network or applications are implemented. The owner must review the seams before merge. No wave 1 work is included.

## Read the seams in this order

Line numbers refer to this closeout tree. Each entry names the section as well so the guide survives later edits.

| Order | File and line | What changed / what to check |
| --- | --- | --- |
| 1 | `docs/specs/context.md:211`, C16 at line 287; `docs/specs/reviews/cross-spec.md:820` | One public issuer-and-branch cell per context. No `any` policy, no multi-issuer leaf, no fallback issuer or overlapping verifier migration in draft 0.1. These are the lost policy choices the owner should see. |
| 2 | `docs/specs/credentials.md:71` (Validity) | Stored proofs use the log's clock at submission, then the object's `issued` and verifier version at its log position. A later reader does not re-expire history against its own clock. |
| 3 | `docs/specs/shield.md:23` (Window); `docs/specs/release.md:204` (R5–R6) | Shield lifetime follows final release/expiry, with the deck and release clock bounds. Rating releases omit `groupsK` below minimum; part 3 unlocks with part 0 and carries its own `n` without using it as an unlock gate. The noised daily count remains the declared minimum-voter exception. |
| 4 | `docs/specs/context.md:282` (C11); `docs/specs/services.md:789` (O-6) | The first log is frozen. Context relays are narrower than the original option: every aggregator request, every log submission and the authored-blob/token path use shipped relays only. Each eligible relay authority counts once; deterministic vector picks are illustrative, not required network behavior. |
| 5 | `docs/specs/services.md:667` (V-4), line 264 (L-6) | Evidence is bound to verifier/item/session/request; all opening failures issue nothing and use V-4 without a mandated detail string. Logging domains are explicit; malformed encodings and incomplete host/count lines are rejected. Field validity does not authorize private values or exact accepted-ballot counts. |
| 6 | `docs/specs/chat.md:195` (§2.5), line 539 (§5.17) | Sequence numbers order admissions; receive time measures pending intervals. Every Add requires its record age to be below 3,600 seconds. The no-record backstop starts at a fetch boundary of 600 seconds, only for Adds observed after current state/snapshot acquisition. Pruning old records cannot retrospectively remove an established member. |
| 7 | `docs/specs/reviews/wave-0-closeout.md`; `docs/specs/conformance.md:244` (Gaps), line 288 (Disagreements) | Read the independent review, boundary vectors and remaining limits. Tail items 20, 26–29 and 31–33 are closed. Cryptographic and MLS placeholders remain explicit. |

`seam:` canonical encoding and validation; credential admission and nullifiers; release tiers and floor checks; logging and what leaves the phone; relay selection; evidence binding. Earlier wave-0 signing, key derivation, DP sampling/accounting and witnessed-log changes also remain in the owner review scope.

## Owner questions — recommendations, not applied decisions

Please answer by number. An unanswered question remains open; these recommendations do not amend the accepted owner decisions or Open section of `docs/DECISIONS.md`. The separate Adopted entry for ADR 0111 records the reviewed closeout clarifications, not answers to these questions.

| # | Question | Recommendation |
| --- | --- | --- |
| 1 | What are the release and yearly privacy targets, including rating decks' ρ 0.05, cap 20 and two releases per source/year? | Keep ε 4 / ε 20 explicitly provisional for the contracts and simulator; commission a joint DP utility/accounting review before calling them launch guarantees. Decide the rating budget with those targets. |
| 2 | Count receipt-clamp δ inside the declared δ (ADR 0102 items 2–3)? | Yes. Have the reviewer establish the discrete tail bound, use a proved conservative bound until then, and regenerate all reported ε/accounting vectors after acceptance. Do not silently retain the unverified 10⁻⁹ claim. |
| 3 | Who should perform the outside cryptography review, and when? | Appoint an independent reviewer before real-user deployment. Include ADRs 0022/0026, BBS/blind issuance/pseudonyms, the `blst` unsafe wrapper and subgroup checks, HPKE bindings, and sampler/receipt accounting. Named reviewer and engagement remain owner choices. |
| 4 | Confirm one chat identity per resident card per context per issuer epoch (chat open question 16)? | Keep this draft rule and disclose that renewal can add another identity; it is a rate bound, not lifetime uniqueness. |
| 5 | May contexts forbid agents or restrict sponsor classes? | Allow an explicit context policy, defaulting to the present agent-enabled behavior. Apply only after a field/validation proposal is reviewed; no new policy field is added here. |
| 6 | Reconcile `docs/design.md` with the specs (cross-spec review §10)? | Yes, in a dedicated wording pass. Show the exact replacement text before changing this protected file; approve that text separately. The specs continue to govern meanwhile. |
| 7 | Who runs the Operator and independent Helper? | Separate administrative control and failure domains; choose named parties before deployment. |
| 8 | Who runs the two relays and launch witnesses; are two witness cosignatures enough? | Use two relay operators independent of the Operator, plus independently operated witnesses and at least the existing two-cosignature baseline. Review availability and collusion assumptions before choosing operators/threshold changes. |
| 9 | Where should services be hosted? | Use managed infrastructure with separate accounts/control for Operator, Helper, relays and witnesses; select regions and providers with those operators. No provider is selected here. |
| 10 | Which code/spec/data licenses should ship? | Apache-2.0 for Hum-authored code and CC BY 4.0 for specs and releasable datasets, subject to dependency/license review, including hpke-rs MPL-2.0. This is a proposal, not a license change. |
| 11 | Which first contexts should launch? | Small, opt-in pilots with accountable organizers and one verifier source per policy leaf, after privacy and security review. Select named communities rather than opening an unrestricted network first. |
| 12 | Accept ADR 0105 items 2–5 (COSE convention, enums, media types and registry)? | Use domain strings as COSE external AAD with detached hash/CID payloads; retain the three existing text-enum exceptions; standardize the proposed media types and explicit registry rules. These change signed bytes and require a separately reviewed regeneration after approval. |
| 13 | Assign retired/successor/superseded envelope markers now? | Settle the field numbers, signed semantics and relation to body-level retirement before implementing lineage retirement. Request a concrete schema proposal; do not allocate bytes implicitly in this closeout. |
| 14 | How should `sessionCap` work without device evidence? | Keep the drafted host-internal address counter, memory only, discarded within 24 hours and never logged; disclose NAT sharing and address rotation limits. No new stable identity or dedup linkage. |
| 15 | Any change to the already deferred two-device/transfer/restore controls or phase-1 breakdowns? | Keep them off in draft 0.1 as accepted; retain the disclosed two-phone residual risk and reopen only with a reviewed design. |
| 16 | Pursue the two-post-close-round covariance alternative now? | Defer it pending a simulator/math comparison; keep the current three-round contract for this merge. |
| 17 | When should Android `blst`/uniffi compatibility be proved? | Make the cross-build and wrapper checks an early wave-1 prerequisite before app integration, without starting them in this closeout. |

## Readiness and next work

The gate record is in `wave-0-closeout.md`. Green checks make this ready for owner seam review, not an automatic merge or production deployment. The receipt δ decision and signature/retirement formats remain explicitly unresolved and must be settled before dependent implementation or guarantees.

Approved dependencies unblock the next vector work: the independent Python BBS implementation over `py_ecc`, checked against the pinned draft fixtures, then HPKE seals using `pyhpke`. Follow with Parquet tables/R15, verifier runtime, MLS and Privacy Pass coverage. These are recommendations only; W0-11 does not start them. Wave 1 should begin from reviewed contracts and these independent cryptographic vectors, with Android `blst` feasibility established early.

`just sim-full` has not completed; release rounds, receipts, issuer epochs, relays and daily counts are not yet modeled end to end. Four adversarial fast scenarios remain pending. Six service response bodies remain provisional. None of these gaps is made green by the closeout wording fixes.

## Publication

At the owner's later request, existing local `main` commit `f8f76d3` (authored October 6) was pushed to `origin/main` on October 9. Wave-0 work remains on `wave-0/contracts`; this operation did not merge it into `main`.
