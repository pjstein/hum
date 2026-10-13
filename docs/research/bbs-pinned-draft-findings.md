# Independent BBS reference: pinned-draft findings

2026-10-09 · ADR 0110 follow-up · `seam:` credential issuance and presentation,
pseudonyms and nullifiers. This records evidence and recommendations, not an
accepted change to the protocol.

The Python oracle in `reference/src/hum_reference/bbs.py` is written from the
published drafts independently of the Rust implementation. Curve operations,
compressed point parsing, subgroup arithmetic, pairings, and hash-to-curve use
owner-approved `py_ecc` 8.0.0. It is a variable-time test oracle and must not handle
production secrets. Inputs and explicit deterministic randomness in generated
vectors are public synthetic data.

## October 13 follow-through

[ADR 0113](../decisions/0113-bbs-and-backup-proposals.md) adds the explicit E1
proposal and a pinned upstream corpus containing the private inputs omitted from
the published text. The proposed implementation independently reproduces two
commitments, four signatures and seven complete proofs. These results resolve
the missing generation-input evidence, while the draft contradictions and owner
adoption of the errata remain separate questions. No normative P4 path is changed.

## Verified scope

The SHA-256 base implementation reproduces both signature fixtures and all three
proof fixtures in [base -12 §8.4](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-12.txt).
Tests also check its key derivation, public key and eleven message generators.
Proof checking rejects changed headers, presentation headers, malformed encodings,
non-subgroup points and invalid disclosure indexes.

The [pseudonym -03](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-per-verifier-linkability-03.txt)
SHA-256 commitment fixtures (§12.1.3) verify against the commitment group equation.
All seven SHA-256 pseudonym proof fixtures (§12.1.5) verify against the base proof
and N=1 pseudonym equations with the specified combined header. Changing the scope,
presentation header or pseudonym rejects them. The missing private values do not
prevent verification of these public proofs. They do prevent byte-for-byte
regeneration of the issuance and pseudonym proof fixtures.

`bbs_commit.py` implements the commitment equations and a synthetic generation /
verification check. The generator count follows the explicit tuple Q2,J1,...,JM
and the generation algorithm; blind -03 §4.3.2's contradictory count assertion
is not treated as normative for this low-level equation test.

The base vector generator emits real base signatures and selective-disclosure
proofs. It does not convert a base signature into a Hum resident card. Existing
Hum composite P4 placeholders remain visibly pending. No high-level blind
issuance / finalization / pseudonym adapter is claimed complete.

## Pinned text conflicts requiring a reviewed resolution

1. [Blind -03 §5.1](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-03.txt)
   `B_calculate` uses `Q_1 * domain`, but has no domain, public key, header or
   interface identifier input and does not calculate domain. §4.3.3 calculates
   domain after receiving B. Issuance cannot be implemented literally.
2. Blind -03 §4.3.2 sets M to the number of message responses, requires M
   generators, then destructures M+1 generators as Q2,J1,...,JM. §4.3.1 uses M+1.
3. Blind -03 §10 provides no test vectors: they are being revised for committed
   disclosure. Older blind-draft fixtures must not be relabeled as -03 coverage.
4. Pseudonym -03 §6.1.3 and §6.2.1 call `Blind.prepare_parameters`, absent from
   the pinned blind -03 document. §6.2.1 additionally appends `blind_generators`,
   not defined in that procedure, to the already returned generators.
5. Pseudonym -03 §7.1 names `length_nym_secrets` but refers to
   `length_nym_vector`; §7.2's proof destructuring omits fields present in the
   pinned base -12 proof. The independently tested core uses the actual base
   -12 proof serialization and the N=1 public fixtures; this is not approval of
   a generalized multi-secret adapter.
6. Pseudonym -03 §12.1.3–§12.1.5 includes literal `undefined` for the private
   nym and several generation trace values. Verification is possible, but the
   drafts do not supply all private inputs required to reproduce these fixtures.

Header handling itself is **not** a conflict: §7.1 and §7.2 append N to the
header inside the core pseudonym operations. An interface passes the original
header; low-level base proof calls in the reference tests receive the already
combined header exactly once.

As of 2026-10-09 the IETF Datatracker still lists
[blind -03](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-blind-signatures/)
and [pseudonym -03](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-per-verifier-linkability/)
as the latest published versions. A later published corrected draft is not an
available migration option at this check.

## Recommendation for owner review

Keep base -12 coverage and externally checked N=1 verification now. Require a
versioned, reviewed errata profile identifying the precise domain calculation,
generator/message layout, N binding, proof serialization and interface adapters,
plus complete independently sourced generation fixtures, before replacing Hum's
P4 placeholders or implementing blind issuance. Prefer a corrected published
upstream revision; if the owner chooses a local errata profile, record approval
and put it explicitly within the outside cryptography review. Do not infer
approval from a same-code round trip or claim an older draft is the pinned one.
