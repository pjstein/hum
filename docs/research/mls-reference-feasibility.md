# MLS reference bindings: executed coverage and gaps

2026-10-13 · transactional receive and replay follow-up to the 2026-10-09 probe · approved reference stack from ADR 0050 / `docs/DECISIONS.md`

**mls-rs 0.56.0 works through actual generated Python UniFFI bindings for live
MLS group operations, exporter agreement and opaque GroupInfo extension
transport.** A small wrapper patch was necessary. The raw provider path still reproduces an authentication-failure state-consumption issue.
A reviewed wrapper transaction now preserves state on failure; exact synthetic-state
replay proves the fix and required control AAD/public-control rejection. Full Hum-profile
conformance is still not claimed.

## 2026-10-13: transactional receive, replay, franking and stamps

The parent reviewed the wrapper design before implementation. The new
`process_incoming_message_transactional(message, hum_policy)` holds the original
mutex, clones the existing `Group`, processes and converts the result on the
candidate, and replaces the original only after all checks succeed. The raw
`process_incoming_message` remains available so the original failure stays
reproducible. The patch calls existing APIs and changes no MLS or crypto primitive.

This boundary is justified for the pinned provider by inspecting its source:
[`ciphertext_processor.rs`](https://github.com/awslabs/mls-rs/blob/8f1b43f447a792ff9307f1c2c7f54da63914870e/mls-rs/src/group/ciphertext_processor.rs)
obtains a mutable decryption key before authenticating ciphertext;
[`Group`](https://github.com/awslabs/mls-rs/blob/8f1b43f447a792ff9307f1c2c7f54da63914870e/mls-rs/src/group/mod.rs)
derives `Clone`; and
[`state_repo.rs`](https://github.com/awslabs/mls-rs/blob/8f1b43f447a792ff9307f1c2c7f54da63914870e/mls-rs/src/group/state_repo.rs)
keeps inserted/updated epochs in owned pending buffers until explicit
`write_to_storage`. Storage handles are shared by clones, so this is **not** a
general transaction over arbitrary callback side effects. The read-only storage
callbacks and stock Basic/OpenSSL providers used here are in scope; provider
changes require re-review. No persistence write runs during tested receive failures.

With `hum_policy=True`, the channel boundary refuses any non-PrivateMessage
before processing (Welcome remains a separate join operation). It then checks
application AAD is 33 bytes starting with `0x01`, or proposal/commit AAD is exactly
`0x00`, before publishing candidate state. Added send methods expose control AAD
for Add, proposal and commit. Default upstream methods retain their old behavior.
This boundary enforces format and AAD **shape**, not complete roles, credentials,
franking verification or the other Hum edge rules.

A new 9.7 KB [synthetic replay fixture](../../tools/mls-reference/fixtures/synthetic-replay.json)
contains deliberately public synthetic private keys, complete receiver group/
epoch state, real serialized frames and exact expected exporter/plaintext/stamp
bytes. It is generated once with real MLS randomness using the explicit
`transaction_checks.py --capture` mode. Normal runs restore those fixed inputs
and replay twice with identical expectations. This is deterministic **replay**,
not a claim that random group setup is deterministic; the main `vectors/` tree
is untouched and no fake MLS bytes are used.

Twelve checks per replay now establish:

- Failed ciphertext authentication, empty control AAD, public control and invalid
  application AAD leave both exporter state and serialized persistent group state
  unchanged; storage callback write counts remain unchanged during each failure.
- The original authentic message decrypts after the tampered one; accepted-message
  replay still fails, including after persisting and reloading the receiver.
- A valid private commit with `0x00` AAD advances to the exact expected exporter
  once, and a private proposal with `0x00` AAD is accepted.
- The same failure preservation holds when decrypting a delayed message through
  the past-epoch persistent storage/cache path.
- The decrypted MIMI bytes contain a synthetic `hum.frank` key and verify the
  §11.1 HMAC over domain/group/epoch/exact bytes. Group, epoch and content changes
  fail. An actual Ed25519 DS stamp over the resulting AAD verifies; changed
  sequence or AAD fails. These use Python's standard HMAC and the repository's
  vetted `cryptography` provider, with existing reference CBOR.

The [transaction result snapshot](../../tools/mls-reference/evidence/transaction-results.json)
is separate from the original 26 primitive checks. The latter still assert the
raw upstream limitation. The transactional wrapper is a **reference adapter**,
not production approval: clone memory cost, secret-copy lifetime, concurrency,
crash atomicity of a future persistent backend, full report attribution and
custom provider side effects remain outside this proof. Franking/stamp checks
are composed in the replay harness; they are not part of the Rust AAD-shape
transaction and do not establish delivery-keyset or witnessed-log trust.

## Pinned implementation and executed checks

[`tools/mls-reference`](../../tools/mls-reference/README.md) fetches upstream tag
`0.56.0`, commit `8f1b43f447a792ff9307f1c2c7f54da63914870e`, from
[awslabs/mls-rs](https://github.com/awslabs/mls-rs/tree/8f1b43f447a792ff9307f1c2c7f54da63914870e).
The checked-in lockfile resolves `mls-rs-uniffi` 0.13.0, UniFFI 0.31.2,
`mls-rs-crypto-openssl` 0.21.0 and the Rust OpenSSL binding 0.10.81. The actual
run used Rust 1.99.0 on Apple Silicon macOS and Homebrew OpenSSL. It did not
modify Hum's root dependencies, reference registry or generated vectors.

Before patching, upstream `cargo test -p mls-rs-uniffi --lib --test scenarios`
passed **3 Rust unit tests and 6 generated-Python-binding scenarios**. After
patching, the same tests passed. The checked-in run script then built the shared
library, generated fresh Python bindings from its metadata, loaded that library,
and passed **26 live checks**. The final script exited 0. These tests execute
MLS, OpenSSL and UniFFI; they are not structural mocks.

The [result snapshot](../../tools/mls-reference/evidence/profile-results.json)
lists each assertion. The
[provenance snapshot](../../tools/mls-reference/evidence/provenance.json) records
source and patch/lockfile/test hashes. The original upstream APIs did not expose
an exporter, discarded decrypted authenticated data, forced empty authenticated
data when encrypting, and kept extension lists opaque.

The [patch](../../tools/mls-reference/uniffi-hum-profile.patch) only changes the
upstream UniFFI wrapper. It exposes existing library functions for:

- Serialized `MLSMessage` input/output, including provider validation on parsing.
- Application-message authenticated data on both encryption and receipt.
- `export_secret(label, context, length)` using the library RFC 9420 exporter.
- Opting into private control messages while preserving the original constructor.
- Sending an opaque GroupInfo extension in encrypted Welcome, and reading its
  bytes after joining. The tested private-use type is `0xF001`.

No MLS, hash, KDF, curve, AEAD, or signature primitive is implemented by the patch.
The wrapper uses the upstream Basic identity provider; that provider does not
implement Hum's credential or role policy.

## What the live run establishes

| Boundary | Executed evidence | Limit |
| --- | --- | --- |
| Ciphersuite and framing | Suite 0x0001, MLS1.0, private Add/proposal/epoch/removal commits, private application traffic, Welcome type3 | Sender configuration only; no Hum receiver policy rejecting all public controls |
| Exporters | Both members agree on `hum/keyring/1` length16 and `hum/delivery/1` length32; label/context separation; delivery rotates on commit; remaining members agree on a new keyring export after removal | Does not implement the Hum rule that keyring export happens only for removal commits in the all-members group |
| Authentication | 33-byte AAD transported intact; altered AAD and truncated frames rejected; message replay rejected | The 32-byte test suffix is synthetic, not a verified franking tag |
| Membership | Add via Welcome, proposal/commit, removal; removed member cannot decrypt subsequent traffic while remaining member can | No Hum admission proof, device binding, capability matrix or organizer policy |
| Tree extension | Omitted inline ratchet tree, out-of-band tree supplied to join, `0xF001` opaque bytes returned from Welcome | The extension fixture is not a sealed-reference encoding or a tree-hash-checked blob fetch |

One additional one-byte application-AAD case deliberately tests the general
library transport API, **not valid Hum application traffic**. Hum §4.2 requires
33 bytes (`0x01` plus a verified franking tag) for every application message,
and `0x00` for proposals/commits. The original upstream control helpers still send empty
AAD; the new opt-in control helpers and policy transaction enforce the required form. Private ciphertext alone does not satisfy that profile. The generic wrapper
must not be mistaken for the Hum edge validator.

## Reproduced state-consumption finding

The test sends a fresh private application frame with a 33-byte authenticated-data
field. Before the receiver processes it, the test flips one byte of that field
and delivers the altered frame. MLS correctly rejects it. Delivering the original
unaltered bytes to the same receiver then fails with:

```text
key not available, invalid generation 2
```

This repeats with fresh random group keys. The receive generation has been
consumed during the failed-authentication path. An attacker capable of altering
and preempting delivery can therefore make that original frame unavailable to
this receiver. No confidentiality break or group-wide compromise is claimed.

`profile_checks.py` asserts and reports this as a **known limitation**, separately
from the passing primitive checks. It will fail if behavior changes, requiring a
review of the finding. No primitive patch was made to suppress it; the new separate wrapper transaction prevents this failure from publishing candidate state.
The pinned source analysis and transactional reference adapter above address the observed in-memory failure. Production integration still needs the stated storage/provider and outside-review work. This finding is not a new accepted protocol rule.

## What remains before chat conformance vectors

All fourteen complete suites listed under `conformance.md`'s MLS gap still need
Hum-specific generators and tests. Some now have functioning library primitives:

- `chat/exporter`: live exporter agreement exists, but deterministic world inputs,
  keyring scheduling, contexts and negative Hum policy cases remain.
- `chat/credential`, `chat/join`, `chat/roles`: the library has real member changes;
  Hum CBOR credentials, key bindings, 90-day lifetime, admission proofs, role
  authorization and cross-channel subset policy are not implemented here.
- `chat/frank`, `chat/stamp`, `chat/tokens`: private serialized frames and AAD are
  available; franking, delivery stamps and token protocol composition remain.
- `chat/ignore`, `chat/promote`, `chat/directory`, `chat/agent-limits`,
  `chat/history`, `chat/ds-api`, `chat/no-votes`: application state and rejection
  rules remain beyond the real-group foundation demonstrated here.

Exact Hum size buckets, previous-epoch acceptance bounds beyond the tested delayed message,
valid sealed tree-reference contents, serialization
validation beyond the tested cases, crash atomicity beyond the tested orderly persist/reload,
and full role/agent scenarios also remain. Upstream storage and tree scenarios
passed, but they do not prove these Hum-specific rules.

The provider uses fresh randomness and time during setup. The original live harness
records check names only; the new explicitly synthetic fixture records complete
reproducible state inputs and expected bytes for exact replay. Neither emits
nondeterministic files into `vectors/`. Promoting these into the canonical corpus
needs the usual coverage/registry review and regeneration conventions. Synchronous bindings were
executed; the asynchronous configuration remains untested.
