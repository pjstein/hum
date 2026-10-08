# Decisions

The decision log for Hum. **Accepted** decisions came from the project owner and aren't relitigated without them. **Adopted in the docs** decisions are written into `docs/design.md` or a spec; change them with a spec change, not in code. **Proposed** decisions are recommendations waiting for the owner's approval in wave 0. **Open** decisions block something and need the owner.

New decisions go in `docs/decisions/NNNN-short-title.md` (context, decision, consequences, status), with a line added here.

## Accepted

1. **Name: Hum.** From IETF humming (RFC 7282): a chair reads the room's hum, and nobody is singled out.
2. **A chat app with superpowers.** Conversation ratchets into structure and back: chat → issue map → deck → release → chat. Things shouldn't get lost in chat; they should ratchet up into decisions.
3. **No vote is ever attributable to a person.** The public dataset is the releases, never the votes. Anyone can explore releases in a studio and a Kaggle-like gallery.
4. **Native apps only** (iOS and Android), for the device-level security a native app allows.
5. **UX direction B:** dark, editorial, data-first, played like a card game (Tinder-style swipe, *Reigns*-style card sorting). Fun is a feature.
6. **Contexts:** anyone can create one, configure permissions and membership, and deal statement sets; there is also a Global context.
7. **IBIS deliberation** (issues, positions, pro and con arguments) generates what people vote on; some statements are artifacts presenting a case.
8. **Chat is end-to-end encrypted** and Discord/Slack-shaped (channels, roles), beyond simple groups.
9. **Agents are first-class participants** in every process and conversation.
10. **Protocol-first.** Everything is an open protocol. Launch on one reference network, designed to federate; federation itself comes later.
11. **Verifiers are extensible from day one.** Some (like district) are core infrastructure; context administrators can run their own from the start.
12. **Context-level shared file storage,** which also backs chat.
13. **Built by one person directing agents, at full scope,** in three waves: contracts, parallel build, integrate and attack.

### Accepted by the owner on 2026-10-07

The owner reviewed the wave 0 breakdowns and accepted every recommendation made in them ("I go with all your recs for sure"). The items below that touch seams are accepted as decisions; their spec diffs still get the owner's read before merge.

14. **One cell per context (ADR 0100, as applied).** In draft 0.1 neither `entry` nor `vote` has an `any` node and every policy leaf resolves to exactly one verifier authority (`context.md` C16), so every member's presentation shows the same public fields. Accepted with the lost expressiveness listed in `docs/specs/reviews/cross-spec.md` section 12.7: no two-ways-in policies, no multi-verifier trust list as a leaf source, no fallback issuer, no overlap when moving to a new verifier. See `docs/decisions/0100-w0-10-issuer-and-branch-cells.md`.
15. **Logged presentations (ADR 0101, as applied).** The log of record checks a membership or sponsor proof against its own clock at submission, with `issued` within one hour; every later verifier checks against `issued` and the verifier version at the object's log position, with no clock. See `docs/decisions/0101-w0-10-logged-presentations-and-time.md`.
16. **Shield window anchor (ADR 0102, item 1, as applied).** An entry stays in the window until 365 days after the final release version was seen, capped at the deck's `expires`, or after `expires` when there is none. With it: no release version after a deck's `expires` (`release.md` R13), `expires` bounded above (`deck.md` D13), no deck version after `closes` (`deck.md` D16). See `docs/decisions/0102-w0-10-shield-window-and-padding-delta.md`.
17. **Domain strings renamed (ADR 0105, item 1).** `manifest/1` → `hum/manifest/1`, `keyring/1` → `hum/keyring/1`, `delivery/1` → `hum/delivery/1`. See `docs/decisions/0105-w0-10-names-and-encodings.md`.
18. **`manifest.md` brought in line with the type specs (ADR 0106, as applied):** the `service` type, the two-signer release rule, the deck example, keyset version 1 without `authority`, the bundle format pointer, the domain string as COSE `external_aad`. The fixes from the two reviews of these changes are in `cross-spec.md` sections 12.6 and 12.8. See `docs/decisions/0106-w0-10-manifest-and-design-edits.md`.
19. **BBS in-house (ADR 0110).** Hum implements the BBS, blind-issuance and pseudonym drafts itself in a core crate, over a vetted BLS12-381 library, with `zkryptium` as a reference to compare against. `CLAUDE.md`'s hand-roll rule now allows a protocol construction from a published draft with owner approval, the draft's vectors and outside review (follow-up 1, done). Open under it: the BLS12-381 library, and an independent check for composite vectors. See `docs/decisions/0110-owner-bbs-in-house.md`.
20. **Sampler input: option B (ADR 0010).** The discrete Gaussian sampler is called with a rational upper bound σ_r on σ, and the part is charged at the plan's ρ. W0-01 is making this normative in `release.md`. See `docs/decisions/0010-w0-01-body-conventions.md`.
21. **Two OHTTP relays that phones rotate between, never run by the operator (ADR 0073).** Who runs them is open. See `docs/decisions/0073-w0-07-ohttp-relay-operator.md`.
22. **The host holds the issuer key for platform-hosted verifiers (ADR 0035).** See `docs/decisions/0035-w0-03-hosted-issuer-key-custody.md`.
23. **Confirmed off in draft 0.1:** phone-to-phone transfer of hand and shield, and two voting devices (ADR 0023); the "I did not vote in this deck" control after a restore (ADR 0025); breakdowns (part 7) in phase 1. The alternatives stay open for a later decision, and the two-phone residual risk of ADR 0023 is not yet explicitly accepted; both are listed under "Open".
24. **Libraries, approved as seam dependencies** (from `docs/research/seam-libraries.md`, versions as found on 2026-10-06). Nothing is adopted for Prio3 or DAP.

| Use | Rust (core and services) | Python reference | Stated risk |
| --- | --- | --- | --- |
| MLS (ADR 0050) | OpenMLS 0.9.0, with the pure-ciphertext wire format policy. Not an earlier version: 0.9.0 fixes a commit-acceptance bug | `mls-rs` 0.56.0 through its uniffi bindings (`mls-rs-uniffi`, built from git), for reference vectors | No public audit of OpenMLS was found, and its API breaks between minor versions. `mls-rs` says it has had no full third-party audit; nobody has checked that the bindings expose authenticated data, exporters and private-use extensions |
| HPKE | `hpke-rs` 0.7.0 | `pyhpke` 0.6.5 | Neither is audited. `hpke-rs` recently moved repositories and is MPL-2.0, which matters for the license decision |
| Argon2id | `argon2` 0.6.0 (RustCrypto) | `cryptography` 50.0.2, already a dependency | No audit on record for the Rust crate. The 64 MiB setting is untested on a low-end phone |
| Privacy Pass | `privacypass` 0.2.0-pre.3, pinned to the exact pre-release | No library: the RFC 9578 vectors | Pre-release, unaudited, one author, on a pre-release fork of the VOPRF crate. Nobody has checked that it exposes RFC 9497 `DeriveKeyPair`. Type 0x0001 issuance stays a gap in the reference |
| DP noise | OpenDP 0.16.0, its exact discrete Gaussian sampler (`sample_discrete_gaussian`), with Hum's own ρ accounting | Draws no noise (ADR 0081) | The sampler takes σ, not σ², which item 20 settles. It cannot be seeded, so the statistical harness is the only test |
| WebAssembly components | `wasmtime` 49.x | `wasmtime` (wasmtime-py) 49.x, same major | Audit status not researched. Fuel counts may differ between wasmtime majors, so fuel vectors may pin one version |
| Parquet | `parquet` 60.0.0 (arrow-rs) | `pyarrow` 25.0.1, dev dependency | Audit status not researched. Bytes differ between writers, so tables are compared row-wise |
| BBS | In-house (item 19); `zkryptium` 0.7.1 only as a comparison | — | `zkryptium` is unaudited research code and tracks blind issuance -02, not -03 |

## Adopted in the docs

- Manifest envelope: deterministic CBOR, CIDs (0x01 + SHA-256), detached COSE_Sign with Ed25519 under the `hum/manifest/1` domain string, keyset lineages with pre-rotation, pinning by CID, transparency logs with witness cosignatures. See `docs/specs/manifest.md`.
- Differential privacy: user-level ρ-zCDP Gaussian mechanism, δ = 10⁻⁶; one release per deck; every release is a sum, so central DP ships first and two-server aggregation (DAP, Prio3) replaces it later without changing the math.
- Size gates: tallies 100 voters, common ground 300, map and groups 800, breakdown cells 300, real-data checks 5,000.
- Three identities, never linked: resident card, per-context voting pseudonym, chat name.
- Agents never vote; agent content is labeled; adding a shared agent is a visible membership event.
- Each channel is its own MLS group; message franking for moderation.
- Storage: sealed (encrypted, content-addressed) and public blobs; keys travel in references, never in manifests, logs or store requests; a folder is a channel of file operations.
- Floors are enforced at the edges (phones, aggregators, ledgers) and can only get stricter.


## Proposed (approve or replace in wave 0)

- **One Cargo workspace at the repo root** for `core/crates/*`, the Rust services and `sim/`; Go ledger as its own module; `uv` project in `reference/`. See `docs/decisions/0001-repo-layout.md`.
- **Rust core** shared by phones and services, exposed to the apps through uniffi; **SwiftUI** and **Jetpack Compose** apps on top. Over-the-air code updates stay off.
- **Python reference implementation** that generates every test vector, independently of the Rust code.
- **Go ledger on Tessera,** which also serves as the second, independent implementation of manifest verification.
- Libraries: `coset`; others chosen per workstream and recorded here. The seam libraries the owner approved on 2026-10-07 are listed under "Accepted".
- **Voting pseudonyms are BBS with the CFRG pseudonym extension,** not Semaphore-style group proofs: one credential system for cards, votes, membership, tokens and authorship; no trusted setup and no per-member group state. See `docs/decisions/0020-w0-02-pseudonyms-bbs-not-semaphore.md`.
- **The voting nullifier is per deck** (scope `hum/ballot/1 ‖ deck lineage CID`), not per context; disagrees with the design doc's wording and is strictly less linkable. See `docs/decisions/0021-w0-02-per-deck-nullifier.md`.
- **Draft 0.1 policies use selective disclosure only** (bools, single values); multi-valued leaves are not satisfiable until the outside review clears a hidden predicate; expiry is a disclosed epoch that every valid card of an issuer shares, so it forms no cohort. See `docs/decisions/0022-w0-02-predicate-proofs.md`.
- **Per-person sealed backup (chat key, edit root, cards, context list; never a hand, shield or receipt) under a recovery phrase, in the platform backup; one voting device per person; no transfer of hand or shield off the phone in 0.1.** See `docs/decisions/0023-w0-02-backup-and-voting-device.md`.
- **Round-0 ballots may be replaced until close; the counted hand is the first K cards cast; one DAP task per (round, part); every ballot padded to 48 KiB; `covStatements` ≤ 128.** See `docs/decisions/0024-w0-02-ballot-replacement-and-tasks.md`.
- **Shield: tracked in ρ (`SHIELD_RHO` 2201/500 for ε 20), sliding 365-day window, reserved at open and charged at the plan's total before the first ballot, never refunded after a send, never backed up, restored as an upper bound.** See `docs/decisions/0025-w0-02-shield-window-and-restore.md`.
- **Cards live one issuer epoch; renewal is a session with evidence in the last two periods; the dedup row outlives every card; a ballot's cards are those of the epoch of the deck's original `closes`,** so one person has one deck nullifier per policy slot and no extension or re-enrolment can add one. See `docs/decisions/0026-w0-02-renewal-and-ballot-window.md`.
- **Verifier modules are WebAssembly components** with a closed host interface (manifest body, declared evidence and datasets, one-key dedup, day-granular time; no network, signing, randomness or fine time). See `docs/decisions/0031-w0-03-verifier-sandbox-wasm.md`.
- **Credential revocation in draft 0.1 is re-issuance only;** the accumulator method is reserved. Emergency path: remove an issuer key. See `docs/decisions/0032-w0-03-revocation-reissue-only.md`.
- **Attributes declare `gate` or `breakdown` exposure;** `uint` and large enums are gate-only, so a unit number can never form a breakdown cell. See `docs/decisions/0033-w0-03-attribute-exposure.md`.
- **Trust lists name verifier authorities, not versions,** pin nothing, and must record removals with a reason. See `docs/decisions/0034-w0-03-trust-lists-name-authorities.md`.

- **Sealed blob format details:** self-delimiting Padmé pad (`0x80` then zeros), nonce `000000 || last-flag || uint64_be(index)`, AAD `hum/sealed/1` + header, AES-128 keys; format 1 (random key in the reference) and format 2 (16-byte salt in the header, key by HKDF from the keyring epoch secret); plaintext digest in CID form; delete commitment `SHA-256("hum/delete/1" || secret)`; domain strings namespaced under `hum/`. See `docs/decisions/0060-w0-06-sealed-format.md`.
- **Blob-store tokens are Privacy Pass type 0x0002** (publicly verifiable, blind RSA) with one issuer key per context, so the context is in the key and not in token metadata; members gossip the key id in the all-members channel; public GETs need no token. See `docs/decisions/0061-w0-06-blob-tokens.md`.
- **Re-keying after a removal is lazy by default;** folders marked sensitive are re-keyed eagerly by the removing member's phone, bounded by a context size cap. See `docs/decisions/0062-w0-06-rekeying-default.md`.

- **Chat MLS profile:** ciphersuite 0x0001, `basic` credentials carrying only the chat identity key, a device ID, a name and a binding; every handshake message a `PrivateMessage`; no external commits; KeyPackages and large ratchet trees as sealed blobs; exporter labels `hum/keyring/1` and `hum/delivery/1`; MIMI content pinned at draft 09 (no byte change from 08); MLS implementation proposed as OpenMLS 0.9.0 for the core and `mls-rs` via uniffi for reference vectors, owner's choice. See `docs/decisions/0050-w0-05-mls-profile.md`.
- **Delivery service authorization:** a non-validating service that sequences every message and never picks a commit (phones take the first valid one per epoch); commits carry an HMAC under a per-epoch delivery secret the service already holds; per-channel Privacy Pass tokens (type 0x0001) whose issuer key is published in the channel directory and checked by every phone; one token per send; an organizer-signed reset as the backstop; context tokens for registration and join tickets; everything through OHTTP. See `docs/decisions/0051-w0-05-delivery-authorization.md`.
- **Message franking:** a keyed commitment in the MLS authenticated data (`hum/frank/1`), a delivery-service stamp (`hum/stamp/1`), and the MLS signature as attribution; reports carry the epoch's GroupContext and go to the organizers group; the map's `origin` is the message ID, never the tag. See `docs/decisions/0052-w0-05-franking.md`.
- **Admission to a context:** a join ticket holding the joiner's KeyPackage handles, HPKE-sealed to a per-context greeting key (`chat.greeting`, requested from `context.md`) and posted to a per-context inbox at the delivery service with a context token; organizers and greeter agents open it and commit the Add. A handle never passes through a verifier. See `docs/specs/chat.md` §2.5.
- **One reference log is also the release ledger;** release entries are `type: release` leaves, leaf = CBOR `[cid, type, authority, lineage, version]`, origin `hum/log/<cid>`, C2SP tiles, checkpoints, cosignatures and witness protocol under `/v1/log/`. See `docs/decisions/0071-w0-07-one-log.md`.
- **A `service` manifest type with a `kind` field** for every service, blob stores included: common fields at keys 0–15, kind-specific fields from 16 (storage.md §7 defines the store's); the `blob-store` registry row becomes `kind: blob-store`. See `docs/decisions/0072-w0-07-service-manifest-type.md`.

- **Every issue-map object version is its own log entry;** no per-context batch roots. The log then proves inclusion, order and non-equivocation per object, and a phone lists a map straight from the log. See `docs/decisions/0041-w0-04-log-every-authored-object.md`.
- **Positions and arguments are revisable by version until a deck pins them, then frozen;** new words after that are withdraw-and-replace. Authorship of later versions is proven by a per-object edit key committed in version 1. See `docs/decisions/0042-w0-04-revise-until-dealt.md`.
- **Take ratings are decks** (`kind` 1): cards are take versions, the release has tallies plus group tallies with the groups taken from the source release, ρ ≤ 0.05, cap 20, at most two per source release per year. No gallery server ever sees a rating. See `docs/decisions/0043-w0-04-ratings-are-decks.md` and `0015-w0-01-rating-decks.md`.

- **Body conventions for context, deck and release:** rationals as `[num, den]` in lowest terms, `RHO_MAX` = 127/500, σ as micro-units with a fixed binary64 formula, Parquet tables with `hum.` metadata, the Helper as a body field with step 6 requiring both aggregator keysets, decks inherit aggregators from the context. See `docs/decisions/0010-w0-01-body-conventions.md`.
- **Members-only results:** the release manifest is logged in the clear, tables are sealed, and the table keys reach members through an HPKE keybox sealed to a context `resultsKey` derived by HKDF from the keyring epoch secret (info `hum/results-key/1`); organizers-only results deferred; `nHat` stays public. See `docs/decisions/0011-w0-01-members-only-results.md`.
- **Organizer daily count:** noised daily increments (sensitivity 1 for the whole series) as release part `count`, at most ρ 1/200 by default, inside the deck's budget and published with the release. See `docs/decisions/0012-w0-01-daily-count.md`.
- **IBIS release parts:** movement (3 × 3 transitions plus "moved me" for one argument, cap 10, sensitivity √(2·K_m)) and argument ratings (cap 10, by group in the group round), both gated at 300; recommended split 0.13/0.30/0.13/0.30/0.08/0.06. See `docs/decisions/0013-w0-01-ibis-parts.md`.
- **Release rounds as versions:** three post-close rounds (covariance, map cell, group tallies); each publication is a logged version of one release lineage, parts noised once and frozen; discrete Gaussian noise drawn with the rational upper bound σ_r = n/2²⁰ (owner-accepted 2026-10-07); receipt trees padded to a noised size under a `receipts` part; the Helper attests parameters in phase 1. See `docs/decisions/0014-w0-01-release-rounds.md`.
- **Rating decks are `deck` kind 1** with take cards, a source release, parts tallies and groups only, groups fixed from the source, no post-close rounds. See `docs/decisions/0015-w0-01-rating-decks.md`.

- **Simulator dependencies and fakes:** `sim/` adds `rand`, `rand_chacha`, `rand_distr`, `serde`, `serde_json`, `csv` and `anyhow` for itself only; its fakes may use floating-point Gaussian noise (the research oracle) and a labelled non-cryptographic hash for fake CIDs, neither of which may leave `sim/`. See `docs/decisions/0090-w0-09-simulator-dependencies.md`.
- **Simulator data and gates:** Polis open data is fetched, never vendored; `just sim-fast` runs a seeded synthetic fixture offline; gates are per source and per size tier, calibrated against the research means with slack for seed spread. See `docs/decisions/0091-w0-09-fixture-and-thresholds.md`.

- **Reference libraries:** `cryptography` for Ed25519 and AES-GCM, standard-library HMAC for HKDF, a hand-written deterministic CBOR codec and COSE_Sign structure (encoding only), RFC 9162 trees checked against the Certificate Transparency known answers, `numpy` as a dev dependency for the ranking oracle test. See `docs/decisions/0081-w0-08-reference-libraries.md`.
- **Manifest format details the spec leaves open,** chosen provisionally by the reference: `hum/manifest/1` as COSE `external_aad`, protected header `{alg, kid}`, a keyset body layout with a sorted-list pre-rotation commitment, no `authority` field on a keyset's first version, keysets signed by the previous version's `rotate` threshold (version 1 by its own), revocations by log position across the lineage, reference depth counted per hop, checkpoints held once per session. See `docs/decisions/0082-w0-08-manifest-format-details.md`.
- **Reference choices from the second vector run:** per-type verification hooks, misbehaving-log test worlds, a synthetic attestation report, MIMI and KeyConfig readings, the receipt root blob, seed expansions for ratings selection and send schedule, placeholders where a library is missing (Parquet, HPKE, BBS, Argon2id), one task-id form, rating-deck parts, log-side clock checks as log-admission callables, the R2 reading. See `docs/decisions/0083-w0-08-run-2-reference-choices.md`.


- **Issuer epochs across decks:** an issuer key stays listed for a fixed tail so pinned cards still verify in later rounds; an emergency key removal ends later rounds for affected voters; `services.md` V-2 allows two cards in handover; uses that prove `entry` record every nullifier of the proof. See `docs/decisions/0104-w0-10-epochs-across-decks.md`.
- **Discovery and wire-format gaps:** `resolvers` and `relays` fields in the context manifest, bootstrap `service` bundles shipped with the app, integer keys for `services.md` API bodies, an HPKE `info` for evidence, rules for the `delivery` service kind, and nine smaller alignments. See `docs/decisions/0107-w0-10-discovery-and-wire-gaps.md`.


## Open

- **Operator and Helper:** who runs the reference network, and which independent party runs the second aggregator.
- **OHTTP relay operators:** the arrangement is accepted (two relays, never the operator); who runs them is open. See `docs/decisions/0073-w0-07-ohttp-relay-operator.md`.
- **Under ADR 0110:** which BLS12-381 library the in-house BBS crate is built on, and how composite vectors (issuance, presentation with pseudonym) get a check that is independent of the code under test.
- **Privacy targets:** ε per release (drafted at ε 4 / ρ 0.254) and the yearly shield (placeholder ε 20).
- **Witnesses at launch:** who runs them, and whether two cosignatures is enough.
- **Licenses:** code (AGPL-3.0 or Apache-2.0), specs and release data (CC BY 4.0 suggested).
- **Outside cryptography review:** who, and when before real users. Its first questions are filed by W0-02: the hidden-predicate extension (ADR 0022) and carrying the nym secret across renewal (ADR 0026). The in-house BBS crate is in its scope (ADR 0110).
- **The two-phone residual risk (ADR 0023):** a person who restores the full backup onto a second phone while still voting from the first can spend up to twice one shield across different decks. Not yet explicitly accepted by the owner. The alternatives the owner kept off in draft 0.1 on 2026-10-07 stay open for a later decision: direct phone-to-phone transfer of hand and shield and two voting devices (ADR 0023), the "I did not vote in this deck" control after a restore (ADR 0025), and breakdowns (part 7) in phase 1 (`ballot.md`). The design doc's "per-context pseudonym", "Semaphore-style" and "issuer never sees the credential" wording is in the `design.md` edit list below (ADRs 0020, 0021).
- **Hosting** for the reference services.
- **First contexts** to launch with.
- **Rating deck budget:** ρ 0.05 per round, cap 20, two rounds per source release per year adds about ε 1.8 to a context's yearly total. Decide with the privacy targets. See `docs/decisions/0043-w0-04-ratings-are-decks.md`.
- **Context agent policy:** whether a context can forbid agents or restrict sponsors to `agent`-class trust lists; today any valid sponsor's proposals reach any public map. Raised in `docs/specs/issue-map.md` and `docs/specs/agent-sponsor.md`, needs a `context.md` field.
- **Covariance round:** whether a normalize-then-center estimator lets the covariance ride in the vote ballot (two post-close rounds instead of three). Needs a simulator run. See `docs/decisions/0014-w0-01-release-rounds.md`.
- **Floor exceptions and `closes`:** whether the daily count and the receipt count may be published below the voter minimum, a rule that `closes` cannot move after it has passed, the rating-deck minimum under a tightened context floor, and the ledger of record when a context names two logs. See `docs/decisions/0103-w0-10-floor-exceptions-and-closes.md`.
- **Receipt clamp δ:** whether the clamp's δ is counted inside the plan's δ (changes every reported ε). See items 2 and 3 of `docs/decisions/0102-w0-10-shield-window-and-padding-delta.md`.
- **Encodings left from ADR 0105:** one placement for the domain string in COSE signatures (chat `roles`, delete orders), the enumeration rule, and `application/vnd.hum.*` for every media type. See `docs/decisions/0105-w0-10-names-and-encodings.md`.
- **Retired and successor markers, and `design.md`:** envelope keys for retiring a lineage and naming a successor are still unassigned; the `design.md` edit list and the rest of the `manifest.md` list are in `docs/specs/reviews/cross-spec.md` section 10. See `docs/decisions/0106-w0-10-manifest-and-design-edits.md`.
