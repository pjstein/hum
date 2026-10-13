# ADR 0113 · BBS errata profile and backup envelope proposals

2026-10-13 · **Proposed; owner acceptance required before normative integration.**

`seam:` credential issuance, proofs and nullifiers; recovery-key derivation and
sealed backups. This document does not change the normative specs, accept an
open decision, approve a library, or authorize production use.

## Two concrete owner choices

1. **BBS E1 — recommended:** adopt the explicitly versioned, N=1 profile
   `hum-bbs-nym-03-errata-1` below for reference implementation, including the
   blinding scalar in the signed layout and backup, the fixture-supported signing
   transcript, and an explicit 48-byte deterministic entropy derivation. Require
   independent fixture comparison before replacing Hum P4 placeholders. The
   alternative is to retain current base/verification coverage and wait for a
   corrected published upstream draft; there is no newer published version now.
2. **Backup B1 — recommended:** adopt the canonical English phrase input and
   strict version-1 CBOR envelopes below, retaining all current Argon2id, X25519,
   HPKE and sealed-blob algorithms. The alternative is to defer portable backup
   files and retain tested encryption components only.

Either choice can be accepted independently. B1 can seal an empty-card backup
before E1 is accepted; it cannot make a blind-issued card restorable without its
blinding scalar. Both choices remain subject to the existing outside review.

## Primary sources and new evidence

On 2026-10-13, IETF Datatracker still lists
[blind -03](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-blind-signatures/)
and [pseudonym -03](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-per-verifier-linkability/)
as latest. This proposal keeps
[base -12](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-12.txt),
[blind -03](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-03.txt)
and [pseudonym -03](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-per-verifier-linkability-03.txt)
pinned. It is a named local errata profile, not a claim that their published
pseudocode already says all of the following.

The existing reference reproduces base fixtures and verifies two commitment and
seven pseudonym proof fixtures. Additional read-only fixture analysis on October
13 reconstructed **all four** pseudonym -03 SHA-256 signatures (§12.1.4.1–4) from
their published issuer inputs and commitments. Their bytes match
`e = hash_to_scalar(serialize(SK, B_full), api_id || "H2S_")`, where `B_full`
already includes the domain term. None matches the printed blind -03 transcript
`serialize(SK, B_full, domain)`. Reconstructed domains match all four fixtures.
This evidence uses existing reference/vetted group helpers, not the Rust BBS code;
the later executable proposal below implements this explicitly named erratum,
without relabeling it as a passing test of the printed blind -03 procedure.

The published fixture inputs suffice for signer-side generation despite missing
private `proverNym` fields. A subsequent read-only checkout of the
[CFRG author-maintained repository](https://github.com/cfrg/draft-irtf-cfrg-bbs-pseudonyms/tree/fcbba956b7f8ed573c7589192f10decd3d2b8fc4/fixtures/fixture_data/bls12-381-sha-256)
at commit `fcbba956b7f8ed573c7589192f10decd3d2b8fc4` supplied the missing private
inputs and randomness. They are preserved unmodified with source hashes under
`reference/tests/fixtures/bbs/upstream-nym-sha256/`; outputs are first checked
against the published draft. The tests then reproduce **both commitments, all
four signatures/finalizations and all seven proofs** byte for byte, without
recovering private inputs from expected responses. This closes the private-input
fixture gap identified in [prior findings](../research/bbs-pinned-draft-findings.md);
it does not resolve the printed draft contradictions by itself.

## E1: exact proposed N=1 profile

### Fixed scope and identifiers

Hum continues to use BLS12-381-SHA-256, with:

```
api_id = ASCII("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_PSEUDONYM_")
blind_generator_api_id = ASCII("BLIND_") || api_id
N = 1
committed_messages = []
```

The profile identifier is an implementation/spec revision label, **not** another
byte silently appended to the existing draft transcripts. No multi-secret
pseudonym, committed-disclosure extension or hidden-predicate construction is
included. Existing unapproved predicate designs stay out of scope.

### Generators, signed layout and retained secrets

Let `A` be the attribute count for the credential epoch; let `S = A + 1` be the
number of issuer-known messages. Their octets are the existing eight-byte epoch
and attribute/absent encodings. Map those messages to scalars with the existing
draft `messages_to_scalars(..., api_id)`.

```
(Q1, H0, ..., H[S-1]) = create_generators(S + 1, api_id)
(Q2, J) = create_generators(2, blind_generator_api_id)
core_generators = (Q1, H0, ..., H[S-1], Q2, J)
core_messages = (m0, ..., m[S-1], s, n)
```

Here `s` is `secret_prover_blind`, `p` the prover's nym share, `t` the signer's
entropy and `n = (p + t) mod r`. Neither `s` nor `n` is passed through
`messages_to_scalars`. The holder retains `s` with the signature and nym secret;
without it the holder cannot reconstruct B or make a proof after restore.
The canonical retained blind has **0 <= s < r**: base -12 §4.2.1 reduces random
draws modulo r without rejecting individual zero draws, and nym -03's finalizer
explicitly permits a default-zero blind. Commitment nonce scalars likewise allow
zero individually, but an identity C or temporary commitment is rejected. A
zero serialized response/challenge is also rejected, preserving blind -03
§5.4.2 step 12 (for example s=0 together with its tilde=0). The prover share p also ranges over Z_r and may be zero; the
completed n must remain nonzero because an identity pseudonym is unusable.

**Explicit Hum spec correction:** `credentials.md` currently says `L = A + 2`
and omits `s`. E1 changes the actual signed length to **`L = A + 3`**, places
`s` at index `A + 1 = L - 2` and `n` at `A + 2 = L - 1`, and forbids disclosure
of both. Attribute indexes `1..A` and epoch index 0 remain unchanged. The
presentation `len`, P3 layout check, P5/P6 index bounds and relevant structural
vectors must change together. No implementation may guess that the extra proof
response represents an attribute, omit the blinding term, or silently use the old
L with the new group equations.

For the sealed backup card map, propose required key **6** = `s` as 32-byte
big-endian scalar. Key 5 remains `n`, also explicitly 32-byte big-endian. The
messages field contains exactly the S issuer-known message byte strings, each
eight bytes; the two retained scalar fields are not duplicated there. `len`
records S+2. Reject unknown card keys and missing blind on E1 restore. Existing
opaque/pre-issuance fixture cards are not evidence of a migratable real format;
no silent conversion or guessed scalar is allowed.

### Domain and blind signing

The base header remains `hum/credential/1 || authority_CID || kid`. Define once:

```
combined_header = header || I2OSP(1, 8)
domain = calculate_domain(PK, Q1, (H0,...,H[S-1],Q2,J),
                          combined_header, api_id)
C = Q2*s + J*p
B_full = P1 + Q1*domain + sum(H[i]*m[i]) + C + J*t
e = hash_to_scalar(I2OSP(SK,32) || point_to_octets(B_full), api_id || "H2S_")
A_sig = B_full * inverse(SK + e mod r)
signature = point_to_octets(A_sig) || I2OSP(e,32)
```

The commitment proof is the draft CoreCommit group equation with exactly two
blind generators, one message p and a fresh s: serialized C (48 bytes), the
blind response (32), p response (32), challenge (32), **144 bytes total**.
Verify that proof before signing; require precisely one nym and no additional
committed messages for Hum. Correct blind -03 §4.3.2's generator count to M+1,
consistent with its explicit tuple and CoreCommit.

This replaces the undefined `domain` input in `B_calculate` with an explicit
precomputed domain and includes Q1*domain exactly once. The e transcript above
is an **explicit deviation from the printed blind -03 §4.3.3**, supported by all
four published pseudonym signatures. It must be accepted as such, not described
as mere variable renaming. Reject identity/out-of-subgroup inputs, noncanonical
encodings, zero signature scalars and a noninvertible SK+e as the base draft
requires. Recompute the issuer public key from SK on the signer side.

### Finalization and proof interfaces

- `CommitWithNym(p)` returns `(commitment_with_proof, s)`. A production caller
  supplies fresh cryptographic randomness; deterministic randomness is fixture
  input only. It retains p and s privately until finalization.
- `BlindSignWithNym(SK, PK, commitment, t, header, issuer_messages)` enforces the
  fixed N=1/no-other-committed-message profile and returns the 80-byte signature.
- `VerifyFinalizeWithNym(PK, signature, p, t, s, header, issuer_messages)` computes
  n, verifies the signature under the exact combined generator/message vectors
  above and combined_header, then returns n. An identity pseudonym secret n=0
  is unusable and is rejected; no partial card is stored.
- `ProofGenWithNym` takes the completed card including s and n, the raw header,
  Hum's existing presentation header, scope and permitted disclosure indexes.
  It adds the N suffix **once**, builds core vectors once and executes base -12
  ProofInit/ProofFinalize with the pseudonym -03 challenge. There is no second
  append of an undefined `blind_generators` vector.
- `ProofVerifyWithNym` receives S (derived from L-2), creates the same generators,
  derives hidden indexes as the sorted complement, and checks the last response
  against the N=1 pseudonym equation. It uses base -12's full proof tuple:
  `(Abar,Bbar,D,e_hat,r1_hat,r3_hat,message_responses,challenge)`.
  Proof length is `272 + 32*U`, where U includes both hidden s and n; disclosure
  of either is invalid. Missing/extra responses are rejected.

For N=1, `OP = hash_to_curve_g1(scope, api_id)`, `nym = OP*n`, and the verifier's
pseudonym commitment is `OP*n_hat - nym*challenge`. Challenge serialization is
pseudonym -03 §7.3.3: disclosure count and interleaved indexes/scalars, five base
proof points, nym, its temporary commitment, domain, length-prefixed ph, then
length-prefixed scope. Hum nullifier hashing remains unchanged.

### Deterministic signer entropy: resolve the missing length

The existing spec names HKDF-SHA256 and reduction but not HKDF output length.
The structural reference currently emits 32 raw bytes; that is not a completed
scalar definition. E1 proposes:

```
uniform = HKDF-SHA256(IKM=host_secret, salt=ASCII("hum/nym-share/1"),
                     info=SHA-256(request_plaintext) || I2OSP(epoch,8), L=48)
t = OS2IP(uniform) mod r
```

Forty-eight bytes matches the base SHA-256 suite's wide reduction width. No
additional hash-to-scalar DST or second expansion is inserted. This preserves
identical-request/epoch determinism but **changes the structural reference's
current raw nym-share outputs**; update those fixtures only after owner acceptance.
A zero final n still fails finalization, not a silently selected replacement
scalar. This proposal does not redefine session retry or dedup policy.

### Independent fixture acceptance plan

Before Hum P4 is marked complete:

1. Preserve byte-exact base -12 tests, both commitment verification fixtures and
   all seven published N=1 pseudonym proof verifications unchanged.
2. Add all four published nym §12.1.4 signer fixtures using their published
   commitments and issuer inputs. Record the printed transcript mismatch as an
   errata assertion, alongside positive byte-exact E1 signatures. Do not derive
   expected signatures from the implementation under test.
3. Obtain complete private commitment/proof fixture inputs from a pinned upstream
   author-maintained fixture corpus, recording immutable source commit and hashes;
   verify correspondence to the published output before claiming reproduction.
   Alternatively commission a second implementation from this approved profile,
   with no shared helpers/code and a distinct vetted group backend. Recovered
   secrets calculated from expected responses are not independent generation inputs.
4. Compare independently produced commitment, signature, completed n, scope point,
   domain, challenge and proof bytes for full disclosure, partial disclosure and
   no attribute disclosure. Run altered issuer, header, ph, scope, scalar range,
   subgroup, secret-index disclosure and proof-length refusals. Include two scopes
   for one card and multiple cards/epochs; no user data.
5. Only then wire real P4 into credentials, ballot, issue-map, sponsor and host
   vectors, including restore using retained s. Python outputs remain the source
   of Hum vectors; the Rust crate is a consumer, not the vector oracle.

The pinned author-maintained corpus now supplies the private inputs for this
acceptance plan, as recorded above. No upstream email or issue has been sent.
Any future source mismatch remains an explicit gap rather than an invented fixture.

## B1: exact proposed backup encoding

### Phrase-to-Argon2 input

Use the [BIP-39 English list](https://github.com/bitcoin/bips/blob/927b6de9915c9262615a6399de51b200f81e5aa4/bip-0039/english.txt)
pinned at commit `927b6de9915c9262615a6399de51b200f81e5aa4` (2,048 words; raw-file
SHA-256 `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`).
[BIP-39](https://github.com/bitcoin/bips/blob/927b6de9915c9262615a6399de51b200f81e5aa4/bip-0039.mediawiki)
defines the entropy/checksum-to-word mapping; Hum keeps its already specified
Argon2id KDF, not BIP-39's wallet PBKDF2 seed derivation.

Proposed entry canonicalization is fully specified: Unicode NFKD normalization;
convert ASCII A–Z to a–z; split on ASCII whitespace U+0009–000D and U+0020;
reject any remaining non-ASCII character, punctuation, abbreviation or word not
in the list. Require exactly twelve words and a valid BIP-39 128-bit entropy /
4-bit checksum. Join the resulting full words with exactly one ASCII space,
without leading/trailing space, newline, NUL or BOM. The resulting ASCII bytes
are the direct Argon2id password. No BIP-39 passphrase is accepted. Wallet seed
bytes, decoded entropy bytes and locale-dependent case folding are not KDF inputs.

Argon2id remains version 0x13, t=3, m=65536 KiB, p=1, output=32 bytes, with the
16-byte envelope salt. Clamp byte 0 with 248 and byte 31 with 127 then 64 for
X25519, exactly as the current helper does. Example canonical password is eleven
`abandon` words and `about`, separated by single spaces. Phrase generation uses
128 fresh random bits and the BIP-39 checksum; an arbitrary user-created sentence
is not accepted as equivalent entropy.

### Outer envelope

Encode one deterministic CBOR map with no tag and no trailing object, using the
existing Hum canonical CBOR rules. No keys other than those listed are permitted.

| Key | Meaning | Full recovery backup (mode 1) | Chat-only export (mode 2) |
| --- | --- | --- | --- |
| 0 | envelope version | uint 1 | uint 1 |
| 1 | mode | uint 1 | uint 2 |
| 2 | recovery salt | bytes(16), fresh per backup | absent |
| 3 | wrapped content key | bytes(64) | bytes(64) |
| 4 | sealed contents | bytes: existing format-1 sealed blob | bytes: existing format-1 sealed blob |

The wrapped content key is exactly `enc(32) || ct(32)`: the existing 16-byte fresh
content key plus its 16-byte AES-GCM tag. Use HPKE base X25519/HKDF-SHA256/AES128GCM,
info `hum/backup/1`, empty AAD, no extra framing byte. The inner blob keeps storage
format 1, Padmé padding, fresh independent 16-byte key, existing chunk nonces and
AAD. The outer envelope contains no public key, card metadata, CID, plaintext
hash, locator or keyring secret. Store it only in the platform-backed-up container
or explicitly exported local file, as currently specified.

Mode 1 derives the recipient key from phrase/salt. Mode 2 uses the already
specified one-time recipient public key and never accepts a phrase or salt. This
proposal does not assign QR payload fields or alter which device displays it;
that pairing-channel detail stays outside the backup-file format.

Unknown versions/modes, duplicate/unknown keys, noncanonical CBOR, wrong types,
wrong salt/wrap lengths or a non-format-1 blob reject before decryption. Enforce
existing receive/storage resource policy before allocating; this proposal adds
no new universal size cap. A wrong phrase/salt, substituted wrap or modified blob
must fail authentication. After opening, apply the existing strict plaintext
allowlist: mode 1 requires the complete recovery-backup schema; mode 2 accepts
exactly `{0:1,1:chat_identity_private_key,2:edit_root}` and never a full card backup.
The envelope mode alone is not authorization to accept the decrypted contents.

The existing constant HPKE info is preserved. Unknown-version rejection plus
strict per-mode inner validation is mandatory; do not silently reinterpret an
old envelope as a newer format or a full backup as a chat-only export. Failed
restore installs no partial state. Authenticate/decode fully before committing
keys or context membership; rebuild shield state under the existing restore rule.
No hand, shield entry, receipt, card order or selection enters any envelope.

### B1 vectors after acceptance

- Pin BIP-39's independent English entropy/mnemonic vectors; use their twelve-word
  rows to check checksum and canonical text. Do not use their wallet seed output
  as Hum's expected Argon2 input.
- Freeze canonical phrase bytes, salt, clamped X25519 key, deterministic test HPKE
  wrap, storage blob and outer CBOR. Cross-check primitive known answers already
  in the repository; compare phrase derivation with a second library before
  calling the whole backup independently verified.
- Cover ASCII capitalization/whitespace normalization, NFKD, unknown/non-ASCII
  words, checksum error, 11/13/24 words, unknown fields/mode/version, salt/wrap
  lengths, ciphertext mutation, swapped components, forbidden plaintext fields,
  and full-backup-to-chat-export substitution.
- With E1 accepted, restore a signed card including s, then generate and verify a
  new scoped proof. Without E1, keep the card-restoration part explicitly pending.


## Executable review artifacts, still unadopted

`reference/src/hum_reference/proposed_bbs.py` implements the candidate E1
commitment, blind signature, verified finalization, selective proof generation,
proof verification and explicit wide entropy derivation. It is separate from
`credentials.py` and never replaces P4. It enforces the two hidden scalars and
fixed commitment size; absent scope cannot disable pseudonym verification.
No production randomness API or app integration is provided. A private low-level
signer helper accepts the extra committed-message shape solely to check the
published draft fixtures; the E1 public interface rejects it.

`reference/tests/test_proposed_bbs.py` checks immutable primary fixtures and
synthetic E1 all/partial/no disclosure, binding to issuer/header/ph/scope,
malformed encodings, zero/canonical scalar boundaries, wrong retained secrets,
secret-index disclosure and truncated/extra proof responses.
`vectors/proposed_bbs_vectors.py` produces **3 accepting and 18 rejecting** review
cases under `experimental/proposed-bbs`. These bytes are not normative Hum
conformance obligations. The normative layout, backup format and structural
nym-share outputs remain unchanged pending owner acceptance.

The new corpus supplies the independent generation evidence requested above;
owner acceptance of the explicit E1 profile, coordinated normative edits and
real Hum P4 integration are still required. The entropy-length choice is Hum's
proposed derivation and has no matching upstream BBS fixture; its cryptographic
operations use the approved HKDF implementation. None of these artifacts is an
outside cryptography review.
