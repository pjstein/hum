# MLS reference bindings: executed coverage and gaps

2026-10-09 · approved reference stack from ADR 0050 / `docs/DECISIONS.md`

**mls-rs 0.56.0 works through actual generated Python UniFFI bindings for live
MLS group operations, exporter agreement and opaque GroupInfo extension
transport.** A small wrapper patch was necessary. The probe also reproduces an
authentication-failure state-consumption issue. This is usable integration
infrastructure for further reference work, not full Hum-profile conformance.

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
and `0x00` for proposals/commits. The upstream control helpers still send empty
AAD: private ciphertext alone does not satisfy that profile. The generic wrapper
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
review of the finding. No primitive/state-machine patch was made to suppress it.
Before production use, investigate upstream's intended failure-state semantics
and decide whether a reviewed transactional processing boundary or another
upstream remedy is needed. This finding is not a new accepted protocol rule.

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

Exact Hum size buckets, previous-epoch acceptance bounds, explicit public-message
rejection, control AAD, valid sealed tree-reference contents, serialization
validation beyond the tested cases, crash/reload behavior under the added APIs,
and full role/agent scenarios also remain. Upstream storage and tree scenarios
passed, but they do not prove these Hum-specific rules.

The provider uses fresh randomness and time; the harness records check names,
not random secrets or output bytes. It deliberately does not emit nondeterministic
files into `vectors/`. A deterministic reference adapter must control the
library's randomness/time or commit complete reproducible state inputs before
these become the repository's canonical byte vectors. Synchronous bindings were
executed; the asynchronous configuration remains untested.
