# Hum Verifier Runtime Spec — Draft 0.1

Oct 6, 2026 · W0-03 · revised after review

## Scope

This spec says where a verifier's code runs, what it can and can't reach, how its hash in the manifest ties to the code that runs, and who can see what. It covers the five profile binaries and any custom module. `verifier.md` defines what a verifier declares; `credentials.md` defines the issuance cryptography the host performs around the module.

The design goal is narrow: a module decides whether evidence earns which attribute values. It never signs, never talks to the network, and never sees anything that appears later in a context presentation.

## Where code runs

A verifier's module runs inside a **host**. A host is a server that holds the verifier's issuer key and host transport keys, runs issuance sessions with phones, and executes the module inside a sandbox.

Two kinds of host exist, and they are the same code:

| Host | Runs modules for | Issuer key held by |
| --- | --- | --- |
| The platform host (the `issuer` service in `services.md`) | Core verifiers, and any context whose organizers chose hosted mode | The platform host |
| A self-run host | One organization's verifiers | That organization |

A verifier's manifest doesn't say which kind hosts it. The host is named by the `hostKeys` in the manifest and reached through unsigned location hints. Every session payload (each evidence body and the blind issuance request) is HPKE-sealed by the phone to one of those keys; TLS is transport only, so an edge or load balancer in front of the host sees ciphertext. In hosted mode the organizer's authority signs the manifest, and the platform host generates the issuer key and hands back the public key to put in it (decision 0035, open).

Modules never run on phones. The phone's job is to show the disclosure summary, collect exactly the declared evidence, seal it to a host key, and run the credential protocol from `credentials.md`. The phone checks that the `code` blob hashes to the manifest's CID when it fetches it, as the resolver rules require, and does not instantiate it.

## The sandbox

Modules are WebAssembly components (the WASI 0.2 component model). A host runs them in an engine with these settings. Each is checkable by the conformance harness.

| Limit | Value |
| --- | --- |
| Module size | At most 16 MiB |
| Linear memory | At most 64 MiB |
| CPU time | At most 10 seconds of wall clock per `decide` call, including host imports. This is the normative limit, because instruction-count (fuel) accounting differs between engines and between versions of one engine. A host SHOULD also meter fuel and stop early; the fuel budget is the host's choice and is not part of conformance. The conformance vector is an unbounded loop, which must be terminated under any budget. |
| Stack | At most 1 MiB |
| Threads, relaxed SIMD, shared memory | Disabled |
| NaN canonicalization | Enabled |
| WASI interfaces | None beyond the `hum:verifier/host` world below. No filesystem, sockets, clocks, random, environment or stdio. |

A module that imports anything outside the host world fails to instantiate. A module that exceeds a limit is terminated and the session fails closed with reason `module-limit`, which the phone sees as a retryable failure, not a rejection.

Determinism follows from the import set. Every import is a pure function of the session's declared inputs, the session's opening day and the manifest, so two hosts running the same module on the same inputs that both finish reach the same decision. That is what makes dual-run audits possible (see "Checking the host").

**Resource limits are outside that claim.** Whether a module finishes within the memory, stack and wall-clock limits depends on the host, so a `module-limit` outcome is never evidence of anything about the evidence or the person: it is logged as `module-limit`, issues nothing, writes no dedup row, and the phone may retry. A replay that finishes is authoritative over a timeout. Nothing in this spec can make the limit itself deterministic, because no instruction cost model is shared across engines or engine versions; the five profile binaries are required to finish every conformance decision vector in under 1 second on the reference host, so a limit on them indicates a host problem, not an input.

## The host interface

The module world is `hum:verifier/module@0.1`. The host world it may import is `hum:verifier/host@0.1`. This is the complete list. Nothing else is available, and nothing here may be added without a new world name and a new `code.abi` value in the manifest.

### Imports (what the module may call)

| Function | Signature | Returns | Notes |
| --- | --- | --- | --- |
| `manifest.body` | `() -> list<u8>` | The verifier's own body, canonical CBOR | So the module reads its configuration: value sets, bands, evidence and dataset names |
| `manifest.version` | `() -> u64` | The version number | |
| `evidence.get` | `(name: string) -> option<evidence-value>` | The submitted evidence item, or none if not submitted | Only names declared in `evidence`. Undeclared names trap. |
| `evidence.credential` | `(name: string) -> option<list<attribute-claim>>` | The disclosed attributes of a card submitted as evidence of kind `credential` | The host has already verified the presentation under the issuance scope. The module sees `(verifier authority, attribute name, value)` triples, never the proof or nullifier. |
| `evidence.device` | `(name: string) -> option<device-claim>` | Platform and attestation level | Only for evidence of kind `device`. The device key hash is not given to the module; the host uses it for dedup itself. |
| `dataset.lookup` | `(name: string, key: list<u8>) -> option<dataset-record>` | A record and its Merkle inclusion proof | Only names declared in `datasets`. Same behavior for `public` and `private`. |
| `dataset.root` | `(name: string) -> list<u8>` | The commitment from the manifest | A convenience; the same bytes are in `manifest.body` |
| `time.day` | `() -> u32` | The UTC day, as days since the Unix epoch, on which the session was opened | Fixed for the session and written to the session log, so a replay uses the same value |

Types:

```
record evidence-value { schema: string, text: option<string>, number: option<s64>, day: option<u32>, image: option<list<u8>> }
record attribute-claim { authority: list<u8>, name: string, value: u64 }
record device-claim { platform: string, level: u8 }
record dataset-record { fields: list<tuple<string, string>>, salt: list<u8>, proof: list<list<u8>>, index: u64 }
```

An `image` is JPEG or PNG bytes, at most 4 MiB, with EXIF stripped by the phone before upload. The host rejects larger or unstripped images before the module runs. There is no normalizer import: name, address and email normalization ships inside the module, so it is pinned by the code hash like everything else.

### Exports (what the host calls)

| Function | Signature | Meaning |
| --- | --- | --- |
| `decide` | `() -> result<decision, rejection>` | Run once per issuance session, after all required evidence has arrived |

```
record decision {
  attributes: list<tuple<string, u64>>,   // attribute name, value; bool is 1 and present only when true
  dedup-keys: list<list<u8>>,             // one raw key per dedup item of method `evidence`, in manifest order
}
record rejection { code: u16, retry: bool }
```

Rejection codes 0–99 are reserved by this spec: 0 no match, 1 duplicate, 2 missing evidence, 3 malformed evidence, 4 dataset proof failed, 5 outside scope. Codes 100–999 are module-defined and listed in the build recipe, in the manifest's `lang`, so the phone can show a sentence. The phone shows the sentence and nothing else; evidence never comes back.

**Duplicate is an oracle.** For a district verifier the evidence is a name and address. Anyone can submit a neighbor's details, and a visible "duplicate" tells them the neighbor holds a card and so uses Hum. The host therefore sends the phone code 0 in place of code 1 unless every required evidence item has kind `document`, `selfie`, `credential` or `device`, which bind the submitter. The true code goes to the session log only.

### What the host does with a decision

In order. Every step is a conformance rule.

1. Every attribute name in `decision.attributes` is declared in the manifest with status `active`. Otherwise the session fails with `host-invalid-attribute`.
2. Every value is in the attribute's declared set: 1 for `bool`, a declared `v` for `enum`, a position for `band`, at most `max` for `uint`. Otherwise `host-invalid-value`.
3. Every attribute the profile requires is present. Otherwise `host-missing-attribute`.
4. The host assembles the full dedup key list: the module's `dedup-keys`, whose length must equal the number of `evidence`-method dedup items, plus one key per `credential` item (the issuance-scope nullifier of the presented card) and one per `device` item (the per-verifier device key hash). A wrong count fails with `host-invalid-dedup`. The host hashes each key with its secret and reads its row, which holds `lastEpoch`, the signing `kid` and the issuance request hash. A row whose `kid` is no longer in the manifest's `issuerKeys` counts as no row. Across all matched rows the largest `lastEpoch` governs, and whatever the session issues is written back to every row. With `E_now` the current epoch and handover its last two periods:
   - no row, or `lastEpoch < E_now`: issue `E_now`, plus `E_now + 1` during handover;
   - `lastEpoch = E_now` during handover: issue `E_now + 1` only (this is renewal);
   - `lastEpoch = E_now` outside handover, or `lastEpoch = E_now + 1`: if the request hash equals the governing row's, return the identical response (a lost-response retry); otherwise fail with `host-duplicate` and issue nothing.
5. The host computes `E_now = floor(floor(session day / 28) / V)` from the logged session day, with `V` from the manifest. A module can't shorten or extend a card's life.
6. For every dedup key the host writes `lastEpoch` (the newest epoch issued), the `kid` that signed it and the request hash, with the row expiring 30 days after that epoch ends.
7. The host issues one card per epoch decided, with the decided attributes, in that epoch's message layout (the attributes with `fromEpoch ≤ E`, `verifier.md` "Attribute"), under that epoch's key (the listed key with the largest `fromEpoch ≤ E` in that same version, or in the current version if that key was removed), per `credentials.md`. Each card's response names its `kid`. The host signs with the pseudonym draft's `BlindSignWithNym`; its `signer_nym_entropy` is `HKDF-SHA256(host secret, salt "hum/nym-share/1", info = SHA-256(request plaintext) ‖ uint64be(epoch))`, so the same request always yields the same card. The response is sealed back to the phone inside the request's HPKE context. The module is already unloaded.
8. The host discards every evidence item whose `kept` is 0, and stores the rest only as declared (`hash` or `raw`), with its expiry, in its own storage. It never writes evidence, dedup rows or session data to a blob store or any context store.

The host never passes the module's decision to the phone except as success or a rejection code. The attribute values reach the phone inside the credential.

### What the module can never reach

Listed plainly, because this list is what reviewers check:

- The network, the filesystem, environment variables, fine-grained time, randomness.
- The issuer signing key, or any signing operation. The host signs after the module exits.
- The phone's blind credential request, the issued credential, the pseudonym, any context nullifier, or any context-scoped presentation. For a `credential` evidence item the module sees the disclosed claims only, never the proof or the issuance-scope nullifier.
- Evidence from any other session. Each `decide` call runs in a fresh instance with fresh memory.
- The dedup table. There is no dedup import: the host reads every row after the module exits, so a decision never depends on host state and a duplicate rejection replays exactly.
- Device identifiers. `evidence.device` gives platform and level; the keyed device hash stays with the host.
- The phone's IP address, user agent, or transport metadata. Evidence travels over TLS to the host, so the host sees a transport address; the module sees nothing about transport.
- Any way to write. The only output is the `decide` result, which the host validates against the manifest.

A module can over-collect only by declaring more evidence in the manifest, where the phone shows it. A module cannot link an issuance to a later vote, because nothing it touches appears in a context presentation. That is the "custom code can't break unlinkability" property from the design doc, made concrete.

## Datasets

A module may read reference data. Every dataset is fixed by a commitment in the manifest, so the data a module decided against is as auditable as the code. Public and private datasets share one format.

**Records.** A record is `[key, fields]` where `key` is a byte string and `fields` is an array of `[name, value]` text pairs, in canonical CBOR. Records are sorted by `key` bytewise; duplicate keys are invalid.

**Tree.** A binary Merkle tree over the records in order, with RFC 9162 hashing: a leaf is `SHA-256(0x00 ‖ salt ‖ record bytes)`, an interior node is `SHA-256(0x01 ‖ left ‖ right)`, and a non-power-of-two size splits at the largest power of two less than the size. The `salt` is 32 random bytes per dataset version, held by the host and given to auditors with the records, so a small roster of emails can't be confirmed by guessing against the root. The empty tree's root is `SHA-256()`. `commitment` is the root.

**Lookup.** `dataset.lookup(name, key)` returns the record's `fields`, the dataset's `salt`, the audit path from leaf to root as `proof`, and the leaf position as `index`. The module rebuilds the record bytes from the key it asked for and the returned fields, computes the salted leaf hash itself, and verifies the path against `dataset.root` using the manifest's `records` as the tree size. Because the key in the leaf is the one the module chose, a host can't substitute a different record under a valid proof. The salt reaching the module is harmless because the module has no write path: its only outputs are `attributes`, which the credential carries as declared values, and `dedup-keys`, which stay with the host and are never disclosed.

**Public datasets.** The blob at `refs["dataset.<name>"]` is the canonical CBOR array of records plus the salt as its first element: `[salt, record, record, …]`. Anyone can recompute the root and compare it to `commitment`; that is validation rule 15.

**Private datasets.** Only the host holds the records and salt. A new extract is a new commitment, which is a new verifier version. Replacing data without telling anyone is not possible.

What a commitment proves: that the host used one fixed dataset for every session under that version. What it does not prove: that the dataset is the real voter file. Dataset attestation by an auditor is an open question in `trust-list.md`.

## Reproducible builds

The manifest's `code` ref pins the module bytes by CID. The `build` ref pins a build recipe. Together they let anyone rebuild the module from source and check that the bytes match.

**One binary per profile.** Each of the five named profiles is a single module built once by the reference operator. It takes no build-time parameters; it reads its configuration from `manifest.body` and its secret inputs (codes, rosters, voter files) from datasets. Every invite verifier in the network therefore has the same `code` CID, which is the CID the core trust list attests, and `verifier.md` rule 20e can hold.

The build recipe is a public blob in canonical CBOR with the integer keys below, like every other body in the protocol:

| Key | Name | Type | Meaning |
| --- | --- | --- | --- |
| 0 | source | bytes | Commit hash, equal to `code.source` in the manifest |
| 1 | repository | text | Where the source is. Informational; the hash is what binds. |
| 2 | image | text | Build container image as `registry/name@sha256:…` |
| 3 | command | array of text | The build command inside the image |
| 4 | output | text | Path of the built module inside the image |
| 5 | toolchain | text | Equal to `code.toolchain` |
| 6 | lang | text | BCP 47 tag of the rejection sentences; equal to the manifest's `lang` |
| 7 | rejections | array of `{code: uint, text ≤ 140}` | Sentences for module-defined rejection codes 100–999 |

A rebuild succeeds when running `command` in `image` at `source` yields bytes whose CID equals the `code` ref. The reference modules are built with a pinned `rustc` for the `wasm32-wasip2` target, which emits a component directly, in a pinned image; the build is deterministic (no timestamps, sorted inputs, `--remap-path-prefix`). `cargo-component` is not used: it has been experimental and unmaintained since 2025 (`docs/research/seam-libraries.md`).

Who can check:

| Who | What they check | How it is recorded |
| --- | --- | --- |
| Anyone | Rebuild and compare the CID | Nothing required; a trust-list publisher may record it |
| A trust-list publisher | Rebuild, then list the CID in the entry's `attested` | In their trust list, in the log |
| The platform host | Refuses to instantiate a module whose bytes don't hash to the manifest's `code` ref | Rule 1 |
| A phone | That the fetched `code` blob hashes to the CID; it does not rebuild or instantiate | Resolver rules in `manifest.md` |

## Checking the host

A reproducible build proves what the manifest's code is. It does not prove a host runs it. Three things bound a dishonest host:

1. **The phone sends only declared evidence.** Over-collection is limited by the manifest, whatever the host runs.
2. **Dual-run audit.** Because `decide` is deterministic given the inputs and the logged session day, an auditor who obtains a session's inputs (with the person's consent, as part of a complaint) can re-run the pinned module and compare. A host that issued a credential the module would reject, or refused one it would accept, is caught. A logged `module-limit` is compared against nothing: if the auditor's replay finishes, the replay's decision is what the module says, and the host's timeout is a host fault, not a contradiction.
3. **Attestation later.** Remote attestation of the host (a TEE quote naming the module hash) is the path to a stronger guarantee. It is not in draft 0.1; a later world can add an attestation field beside `hostKeys`.

A host cannot, honest or not, learn who a credential holder votes as. That property comes from `credentials.md`, not from this spec.

## Transparency: who sees what

| Party | Sees | Never sees |
| --- | --- | --- |
| The person | The disclosure summary before submitting; success or a rejection sentence after | The module's internals, the dedup table, whether a duplicate was the reason (for unbound evidence) |
| The public | Every verifier version, its code, its build recipe, its datasets' commitments and public blobs, trust-list attestations, and the log | Any evidence, any session |
| The host operator | Declared evidence for its declared retention; the keyed dedup table; the session log; at renewal, the same evidence again, since renewal is an ordinary session in handover | Which context a card is used in; any context presentation; who the person votes as |
| Context organizers | For a verifier they run themselves (invite, approved list): session outcomes, because they supplied the codes or roster and already know whom they invited. For a verifier they merely accept, such as a core one: nothing. | Who holds a core card; what anyone does with any card |
| The platform's attestation vendor (Apple, Google) | That an app instance requested an attestation, when a `device` item is used | Which verifier, the evidence, the outcome. The host sends the attestation nowhere else. |
| A trust-list publisher | What everyone sees, plus whatever review it does out of band | Anything from sessions |

Host logging rules, checked by conformance where testable:

- A host's session log line has exactly these fields: a random 16-byte session ID (for abuse handling), the verifier authority, the version, the session's opening day (the `time.day` value), the true outcome (`issued`, a rejection code including code 1 even when the phone saw 0, or `module-limit`), and the module's resource use rounded to buckets (memory in 8 MiB steps, CPU time in 500 ms steps) so it doesn't echo an input's size. Never evidence, never a dedup key or its hash, never a transport address. `services.md`'s logging table points here.
- A host reports session outcomes only to the verifier's own authority. A context that accepts a verifier it doesn't run learns nothing about its sessions.
- A host keeps no join between a session log line and a dedup table row, and writes neither to a blob store.

## Validation rules

For conformance. Rules 1–3 are checked by instantiating a module; 4–12 by running a module or the host-side checks; 13–16 on artifacts.

1. A module whose bytes don't hash to the manifest's `code` ref is not instantiated.
2. A module importing any function outside `hum:verifier/host@0.1` is not instantiated.
3. A module larger than 16 MiB is not instantiated.
4. `evidence.get` with an undeclared name traps.
5. `dataset.lookup` with an undeclared name traps.
6. A `decide` call that never returns is terminated with `module-limit` within the wall-clock limit; the session issues nothing, writes no dedup row, and reports a retryable failure to the phone.
7. An undeclared attribute name in a decision fails with `host-invalid-attribute`.
8. An out-of-set value fails with `host-invalid-value`.
9. A missing profile-required attribute fails with `host-missing-attribute`.
10. A `dedup-keys` list whose length differs from the count of `evidence`-method dedup items fails with `host-invalid-dedup`; a governing row at `lastEpoch = E_now` outside handover, or at `E_now + 1`, with a different request hash fails with `host-duplicate` and nothing is issued; the same request hash returns the identical response; a row with an unlisted `kid` is ignored; the largest `lastEpoch` across matched rows governs and is written to all.
11. The epochs issued follow step 4 for the logged session day: `E_now` outside handover, `E_now` and `E_now + 1` for a first session in handover, `E_now + 1` only for renewal.
12. A duplicate outcome reaches the phone as code 0 unless every required evidence item binds the submitter.
13. Evidence with `kept` 0 is absent from host storage after the session.
14. The host's session log line has exactly the fields listed above.
15. A public dataset blob's recomputed root equals the manifest's `commitment`.
16. The build recipe's `source`, `toolchain` and `lang` equal the manifest's `code.source`, `code.toolchain` and `lang`.

## Vectors

W0-08 generates these from `reference/`. Modules in vectors are the five profile binaries built by the pinned recipe. They are too large for JSON with hex, so they ship as separate files under `vectors/verifier-runtime/modules/<cid>.wasm`, referenced by CID from the JSON cases. The Python reference needs a component-model runtime (`wasmtime` with component support) to run them; W0-08 records that dependency.

- **Decisions:** for each of the five profiles, a manifest, an evidence bundle, dataset fixtures (a small synthetic voter file and roster with salts and trees), the session day, and the expected decision. No real personal data; names and addresses are generated.
- **Rejections:** one per reserved code 0–5, including a dataset record with a bad proof (code 4) and a substituted record under a valid proof (code 4).
- **Duplicate masking:** a district manifest with a duplicate decision, expected phone-visible code 0 and logged code 1 (rule 12); a uniqueness manifest of the `device` plus `document` plus `selfie` variant with a duplicate, expected phone-visible code 1 (the `device` plus `phone` variant masks to 0, because `phone` doesn't bind the submitter).
- **Host checks:** one per rule 7–11, as a decision, a session day and a dedup row state with the expected epochs or refusal; the retry case (same request hash, identical response); the uniqueness profile with two dedup keys where only the device key's row is spent (refused, and the document row is written to match); a row whose `kid` was removed (treated as no row); a first session in handover issuing two cards under two different epoch keys; the uniqueness profile with two dedup keys where only the device key is seen.
- **Running module:** a module calling `evidence.get("undeclared")` (rule 4) and `dataset.lookup("undeclared")` (rule 5).
- **Instantiation:** a module with a stray `wasi:sockets` import (rule 2), a module with the wrong hash (rule 1), an oversized module (rule 3), and an unbounded loop (rule 6, run by the harness).
- **Replay:** an age-band session with two different session days, decisions differing only through `time.day`, and the logged day reproducing each; a logged `module-limit` session whose replay finishes, with the replay's decision as the expected authoritative outcome and no dedup row written by the original.
- **Profile performance:** every decision vector for the five profile binaries completes in under 1 second on the reference host; the harness fails if one doesn't.
- **Storage and log:** a session with `kept` 0 evidence and the expected empty host store (rule 13); a log line with an extra field expected to fail (rule 14).
- **Datasets:** a public dataset blob and its root (rule 15); inclusion proofs for the synthetic voter file, valid and tampered.
- **Build:** for each profile binary, the recipe blob and the CID a rebuild must produce; one recipe with a mismatched `toolchain` (rule 16). CI rebuilds and compares.

## Open questions

- **Hosted mode and issuer key custody.** Decision 0035, open. Default: the host holds the key.
- **Remote attestation.** Whether to require a TEE quote for core hosts before launch, or leave it for the outside cryptography review to weigh.
- **Image evidence.** Document and selfie checks in a pure-function module without network access mean the matcher ships inside the module. Model size against the 16 MiB limit is untested. The alternative is a host-provided `match.document` import in a later world, which widens the interface.
- **Rate limits (owner decision).** `services.md` counts `sessionCap` by the per-verifier device key hash when the profile requires a `device` item, and otherwise by an in-memory counter keyed by client address, discarded after 24 hours and never logged. This spec accepts that for draft 0.1: the counter is a host-internal abuse control that never reaches the session log or the dedup table. The alternative is to drop `sessionCap` for profiles without `device`. Filed for the owner alongside `services.md`'s open question.
- **Resolved with W0-07 (2026-10-06): evidence item key.** `services.md` keys submitted evidence by the item's unique `name`.
- **Vector modules.** Shipping binaries beside JSON vectors and running them from Python is a new shape for `vectors/`; W0-08 should confirm.

Assumptions about sibling specs:

- `credentials.md` (W0-02, confirmed 2026-10-06, after its re-review): issuance is one session over a host key; the host blind-signs after the module exits, using the BBS blind-signature and pseudonym drafts, and the module never sees the request; the response is sealed back inside the request's HPKE context; a card required at issuance is presented under `hum/issuance/1 ‖ authority`; cards live one epoch of `V = floor(validity / 28 days)` periods aligned to the Unix epoch, and the epoch is disclosed at every presentation; renewal is an evidence session in handover, with no renewal nullifier and no `/v1/verifier/reissue`; credential message layout is index 0 epoch, 1 + i for attribute position i in manifest order, and the nym secret last at L − 1 with L = A + 2 (the pseudonym draft orders signer messages, then committed messages, then nym secrets), where epoch E's attributes are those with `fromEpoch ≤ E`; the host's HPKE suite stays ChaCha20-Poly1305.
- `services.md` (W0-07): the `issuer` service is this host; sessions, evidence and the blind issue call go over TLS with HPKE-sealed payloads; the revocation publication goes through the relay and `/v1/verifier/reissue` is withdrawn by `credentials.md`; the session call returns only an ID and expiry, so the host never sends its own list of asks; the issue response carries the masked code with the true code kept separately for the log; its logging table lists this spec's exact fields. Confirmed on disk.
