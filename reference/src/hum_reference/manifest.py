"""The manifest envelope, keysets, bundles and the eleven verification steps.

Everything here follows ``docs/specs/manifest.md``. Where that spec leaves a
byte-level detail open (the keyset body, how a keyset's first version names
its authority) this module uses the provisional choices in ADR 0082-w0-08 and
says so at the point of use.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from . import cbor, cose, log, merkle
from .cid import cid as compute_cid
from .cid import parse_cid
from .keys import SigningKey

__all__ = [
    "Bundle",
    "KeysetKey",
    "LogProof",
    "Rejection",
    "Resolved",
    "VerificationContext",
    "World",
    "count_valid_signatures",
    "decode_bundle",
    "encode_bundle",
    "keyset_in_force",
    "register",
    "build_keyset_body",
    "decode_envelope",
    "encode_envelope",
    "envelope",
    "envelope_cid",
    "next_commitment",
    "verify_bundle",
]

# ---------------------------------------------------------------- envelope keys

SPEC, TYPE, AUTHORITY, LINEAGE, VERSION, PREV, ISSUED, EXPIRES, REFS, BODY = range(10)
ENVELOPE_KEYS = {SPEC, TYPE, AUTHORITY, LINEAGE, VERSION, PREV, ISSUED, EXPIRES, REFS, BODY}

MAX_ENVELOPE_BYTES = 64 * 1024
MAX_REFS = 1024
MAX_REF_DEPTH = 16
WITNESS_THRESHOLD = 2

TYPES = {
    "keyset",
    "verifier",
    "trust-list",
    "context",
    "deck",
    "release",
    "issue",
    "position",
    "argument",
    "take",
    "agent-sponsor",
    "service",
}

# Keyset body (provisional; ADR 0082-w0-08).
KS_KEYS, KS_THRESHOLDS, KS_NEXT, KS_REVOCATIONS = 0, 1, 2, 3
KEY_ID, KEY_ALG, KEY_PUBLIC, KEY_ROLES = 0, 1, 2, 3
ROLE_SIGN, ROLE_ROTATE = "sign", "rotate"
ROLES = {ROLE_SIGN, ROLE_ROTATE}


class Rejection(Exception):
    """A verification failure: which step stopped and why. ``rule`` is the type rule id, if any."""

    def __init__(self, step: int, reason: str, rule: str | None = None) -> None:
        super().__init__(f"step {step}: {reason}")
        self.step = step
        self.reason = reason
        self.rule = rule


# ---------------------------------------------------------------- building


def envelope(
    type_: str,
    body: dict[int, Any],
    *,
    authority: bytes | None,
    version: int = 1,
    issued: int,
    refs: dict[str, bytes] | None = None,
    lineage: bytes | None = None,
    prev: bytes | None = None,
    expires: int | None = None,
) -> dict[int, Any]:
    """An unsigned envelope as a map with integer keys."""
    env: dict[int, Any] = {SPEC: 1, TYPE: type_, VERSION: version, ISSUED: issued}
    if authority is not None:
        env[AUTHORITY] = authority
    if lineage is not None:
        env[LINEAGE] = lineage
    if prev is not None:
        env[PREV] = prev
    if expires is not None:
        env[EXPIRES] = expires
    env[REFS] = dict(refs or {})
    env[BODY] = body
    return env


def encode_envelope(env: dict[int, Any]) -> bytes:
    return cbor.encode(env)


def decode_envelope(data: bytes) -> dict[int, Any]:
    return cbor.decode(data)


def envelope_cid(env_or_bytes: dict[int, Any] | bytes) -> bytes:
    data = env_or_bytes if isinstance(env_or_bytes, bytes) else encode_envelope(env_or_bytes)
    return compute_cid(data)


@dataclass(frozen=True)
class KeysetKey:
    kid: bytes
    public: bytes
    roles: tuple[str, ...]
    alg: int = cose.ALG_EDDSA


def build_keyset_body(
    keys: list[KeysetKey],
    sign_threshold: int,
    rotate_threshold: int,
    next_keys: list[KeysetKey] | None = None,
    revocations: list[tuple[bytes, int]] | None = None,
) -> dict[int, Any]:
    body: dict[int, Any] = {
        KS_KEYS: [
            {KEY_ID: k.kid, KEY_ALG: k.alg, KEY_PUBLIC: k.public, KEY_ROLES: list(k.roles)}
            for k in keys
        ],
        KS_THRESHOLDS: {ROLE_SIGN: sign_threshold, ROLE_ROTATE: rotate_threshold},
    }
    if next_keys is not None:
        body[KS_NEXT] = next_commitment(next_keys)
    if revocations:
        body[KS_REVOCATIONS] = [[kid, pos] for kid, pos in revocations]
    return body


def next_commitment(keys: list[KeysetKey]) -> bytes:
    """Pre-rotation commitment: SHA-256 of the CBOR list of [kid, public], sorted by kid."""
    import hashlib

    pairs = sorted(([k.kid, k.public] for k in keys), key=lambda p: p[0])
    return hashlib.sha256(cbor.encode(pairs)).digest()


# ---------------------------------------------------------------- bundles


@dataclass
class LogProof:
    """One inclusion proof (services.md, "The bundle": ``{0 log, 1 index, 2 checkpoint, 3 path}``).

    ``consistency`` is not part of the wire proof: it is the proof the phone fetched from its
    own held checkpoint to the proof's checkpoint, carried here so a vector can supply it.
    """

    log: bytes  # the log authority CID
    position: int
    checkpoint_note: str  # signed note text with log and witness signatures
    inclusion: list[bytes]
    consistency: list[bytes] | None = None


@dataclass
class Bundle:
    envelope: bytes
    signatures: bytes | None  # one COSE_Sign; None for participant-authored types (B-4)
    cid: bytes  # as claimed by whoever handed over the bundle
    proof: LogProof | None = None
    authorship: bytes | None = None  # issue-map.md / take.md authorship proof


@dataclass
class VerificationContext:
    """What a phone holds: cached bundles by CID, log keys, witnesses, a checkpoint, the clock."""

    resolver: dict[bytes, Bundle]
    log_authority: bytes  # the accepted log, as the context names it
    log_public: bytes  # the log's sign key in force (resolved through its keyset lineage)
    witness_keys: list[bytes]  # the context's listed witness keys for this log
    held_checkpoint: tuple[int, bytes] | None  # (size, root) the phone already trusts
    now: int
    min_witnesses: int = WITNESS_THRESHOLD
    verified: dict[bytes, dict[int, Any]] = field(default_factory=dict)
    accepted_checkpoints: set[tuple[int, bytes]] = field(default_factory=set)
    consistency_proofs: dict[tuple[int, bytes], list[bytes]] = field(default_factory=dict)
    blobs: dict[bytes, bytes] = field(default_factory=dict)  # public blobs the phone fetched
    global_context: bytes | None = None  # the Global context lineage CID (protocol constant)
    decoded: dict[bytes, dict[int, Any] | None] = field(default_factory=dict)  # decode cache


# ---------------------------------------------------------------- type registry


@dataclass
class Resolved:
    """What a type's step-10 rules may read: the envelope, its predecessor, the log position,
    the resolver (decoded, not re-verified) and the blobs the phone holds."""

    ctx: VerificationContext
    bundle: Bundle
    env: dict[int, Any]
    position: int | None

    @property
    def body(self) -> dict[int, Any]:
        return self.env[BODY]

    @property
    def refs(self) -> dict[str, bytes]:
        return self.env[REFS]

    def bundle_of(self, cid: bytes) -> Bundle | None:
        return self.ctx.resolver.get(cid)

    def manifest(self, cid: bytes) -> dict[int, Any] | None:
        b = self.ctx.resolver.get(cid)
        if b is None:
            return None
        cache = self.ctx.decoded
        if cid in cache:
            return cache[cid]
        try:
            env = cbor.decode(b.envelope)
        except cbor.CborError:
            env = None
        env = env if isinstance(env, dict) else None
        cache[cid] = env
        return env

    def position_of(self, cid: bytes) -> int | None:
        b = self.ctx.resolver.get(cid)
        return b.proof.position if b is not None and b.proof is not None else None

    @property
    def prev_env(self) -> dict[int, Any] | None:
        return self.manifest(self.env[PREV]) if PREV in self.env else None

    def lineage(self, lineage_cid: bytes) -> list[tuple[int, dict[int, Any], Bundle]]:
        """Every logged version of a lineage (its version 1 is ``lineage_cid``), by position."""
        out = []
        for b in self.ctx.resolver.values():
            if b.proof is None:
                continue
            env = self.manifest(b.cid)
            if env is None:
                continue
            if b.cid == lineage_cid or env.get(LINEAGE) == lineage_cid:
                out.append((b.proof.position, env, b))
        out.sort(key=lambda t: t[0])
        return out

    def lineage_of(self, cid: bytes) -> bytes | None:
        """The lineage CID (version 1) of the manifest ``cid`` names."""
        env = self.manifest(cid)
        if env is None:
            return None
        return env.get(LINEAGE, cid)

    def latest_before(self, lineage_cid: bytes, position: int | None) -> dict[int, Any] | None:
        """The highest version of a lineage logged before ``position`` (any, when None)."""
        best = None
        for pos, env, _ in self.lineage(lineage_cid):
            if position is not None and pos >= position:
                continue
            if best is None or env[VERSION] > best[VERSION]:
                best = env
        return best

    def blob(self, cid: bytes) -> bytes | None:
        return self.ctx.blobs.get(cid)

    def all_of_type(self, type_: str) -> list[tuple[int, dict[int, Any], Bundle]]:
        out = []
        for b in self.ctx.resolver.values():
            env = self.manifest(b.cid)
            if env is not None and env.get(TYPE) == type_ and b.proof is not None:
                out.append((b.proof.position, env, b))
        out.sort(key=lambda t: t[0])
        return out


# Per-type hooks. Body modules register themselves on import (see ``bodies/__init__``).
TYPE_SCHEMAS: dict[str, Callable[[dict[int, Any]], None]] = {}
TYPE_RULES: dict[str, Callable[[Resolved], None]] = {}
# Step-6 replacements: (view, decoded COSE signatures or None, keyset body, revoked) -> None.
SIGNATURE_CHECKS: dict[str, Callable[..., None]] = {}
# Step-7 ledger-of-record hooks: (view) -> the log authority the inclusion proof must be
# against, or None when the context cannot be read yet (steps 8 and 9 then report that).
# `deck` and `release` manifests must be proven in the context's ledger of record whichever
# log the phone fetched the bundle from (services.md "Submitting a manifest"; release.md R10;
# context.md "Log entries"; ADR 0103).
RECORD_LOGS: dict[str, Callable[[Resolved], bytes | None]] = {}


def register(
    type_: str,
    *,
    schema: Callable[[dict[int, Any]], None] | None = None,
    rules: Callable[[Resolved], None] | None = None,
    signatures: Callable[..., None] | None = None,
    record_log: Callable[[Resolved], bytes | None] | None = None,
) -> None:
    if schema is not None:
        TYPE_SCHEMAS[type_] = schema
    if rules is not None:
        TYPE_RULES[type_] = rules
    if signatures is not None:
        SIGNATURE_CHECKS[type_] = signatures
    if record_log is not None:
        RECORD_LOGS[type_] = record_log


# ---------------------------------------------------------------- verification


def _check_cid_field(value: Any, name: str) -> None:
    if not isinstance(value, bytes):
        raise Rejection(4, f"{name} must be a CID byte string")
    try:
        parse_cid(value)
    except ValueError as e:
        raise Rejection(4, f"{name}: {e}") from e


def _schema(env: Any) -> dict[int, Any]:
    """Step 4: envelope shape, known type and spec version, body shape."""
    if not isinstance(env, dict) or not all(isinstance(k, int) for k in env):
        raise Rejection(4, "envelope must be a map with integer keys")
    unknown = set(env) - ENVELOPE_KEYS
    if unknown:
        raise Rejection(4, f"unknown envelope keys {sorted(unknown)}")
    for required in (SPEC, TYPE, VERSION, ISSUED, REFS, BODY):
        if required not in env:
            raise Rejection(4, f"missing envelope key {required}")
    if env[SPEC] != 1:
        raise Rejection(4, f"unknown spec version {env[SPEC]!r}")
    if not isinstance(env[TYPE], str) or env[TYPE] not in TYPES:
        raise Rejection(4, f"unknown type {env[TYPE]!r}")
    if not isinstance(env[VERSION], int) or env[VERSION] < 1:
        raise Rejection(4, "version must be a positive integer")
    if not isinstance(env[ISSUED], int) or env[ISSUED] < 0:
        raise Rejection(4, "issued must be an unsigned integer")
    if EXPIRES in env and (not isinstance(env[EXPIRES], int) or env[EXPIRES] < 0):
        raise Rejection(4, "expires must be an unsigned integer")
    is_keyset = env[TYPE] == "keyset"
    if AUTHORITY in env:
        _check_cid_field(env[AUTHORITY], "authority")
    elif not (is_keyset and env[VERSION] == 1):
        raise Rejection(4, "authority is required")
    if env[VERSION] == 1:
        if LINEAGE in env or PREV in env:
            raise Rejection(4, "version 1 must not carry lineage or prev")
    else:
        if LINEAGE not in env or PREV not in env:
            raise Rejection(4, "versions after 1 must carry lineage and prev")
        _check_cid_field(env[LINEAGE], "lineage")
        _check_cid_field(env[PREV], "prev")
    refs = env[REFS]
    if not isinstance(refs, dict) or not all(isinstance(k, str) for k in refs):
        raise Rejection(4, "refs must be a map from text to CID")
    if len(refs) > MAX_REFS:
        raise Rejection(4, f"more than {MAX_REFS} references")
    for name, value in refs.items():
        _check_cid_field(value, f"refs[{name!r}]")
    if not isinstance(env[BODY], dict):
        raise Rejection(4, "body must be a map")
    if is_keyset:
        _keyset_schema(env[BODY])
    hook = TYPE_SCHEMAS.get(env[TYPE])
    if hook is not None:
        from .bodies import TypeRule

        try:
            hook(env)
        except TypeRule as e:
            raise Rejection(4, str(e), e.rule) from e
    return env


def _keyset_schema(body: dict[Any, Any]) -> None:
    if set(body) - {KS_KEYS, KS_THRESHOLDS, KS_NEXT, KS_REVOCATIONS}:
        raise Rejection(4, "keyset body has unknown keys")
    keys = body.get(KS_KEYS)
    if not isinstance(keys, list) or not keys:
        raise Rejection(4, "keyset must list at least one key")
    seen: set[bytes] = set()
    for k in keys:
        if not isinstance(k, dict) or set(k) != {KEY_ID, KEY_ALG, KEY_PUBLIC, KEY_ROLES}:
            raise Rejection(4, "keyset key entry shape")
        if not isinstance(k[KEY_ID], bytes) or not k[KEY_ID]:
            raise Rejection(4, "key id must be a non-empty byte string")
        if k[KEY_ID] in seen:
            raise Rejection(4, "duplicate key id")
        seen.add(k[KEY_ID])
        if k[KEY_ALG] != cose.ALG_EDDSA:
            raise Rejection(4, "only EdDSA (-8) keys are defined in draft 0.1")
        if not isinstance(k[KEY_PUBLIC], bytes) or len(k[KEY_PUBLIC]) != 32:
            raise Rejection(4, "Ed25519 public key must be 32 bytes")
        roles = k[KEY_ROLES]
        if not isinstance(roles, list) or not roles or not set(roles) <= ROLES:
            raise Rejection(4, "key roles must be a non-empty subset of {sign, rotate}")
    th = body.get(KS_THRESHOLDS)
    if not isinstance(th, dict) or set(th) != ROLES:
        raise Rejection(4, "thresholds must name sign and rotate")
    for role, n in th.items():
        if not isinstance(n, int) or n < 1:
            raise Rejection(4, f"{role} threshold must be at least 1")
    if KS_NEXT in body and not (isinstance(body[KS_NEXT], bytes) and len(body[KS_NEXT]) == 32):
        raise Rejection(4, "next-keyset commitment must be 32 bytes")
    if KS_REVOCATIONS in body:
        rev = body[KS_REVOCATIONS]
        ok = isinstance(rev, list) and all(
            isinstance(r, list)
            and len(r) == 2
            and isinstance(r[0], bytes)
            and isinstance(r[1], int)
            and r[1] >= 0
            for r in rev
        )
        if not ok:
            raise Rejection(4, "revocations must be [kid, from position] pairs")


def _keyset_keys(body: dict[int, Any]) -> dict[bytes, KeysetKey]:
    return {
        k[KEY_ID]: KeysetKey(k[KEY_ID], k[KEY_PUBLIC], tuple(k[KEY_ROLES]), k[KEY_ALG])
        for k in body[KS_KEYS]
    }


def count_valid_signatures(
    keyset_body: dict[int, Any],
    role: str,
    sigs: list[cose.Signature],
    cid: bytes,
    revoked_before: dict[bytes, int] | None = None,
    position: int | None = None,
) -> int:
    """Distinct ``role`` keys of ``keyset_body`` with a valid signature over ``cid``."""
    return _count_valid(keyset_body, role, sigs, cid, revoked_before or {}, position)


def keyset_in_force(ctx: VerificationContext, authority: bytes, position: int | None):
    """Public wrapper for step 5 lookups from type rules (release R9, take TK-5)."""
    return _keyset_in_force(ctx, authority, position, 0)


def _count_valid(
    keyset_body: dict[int, Any],
    role: str,
    sigs: list[cose.Signature],
    cid: bytes,
    revoked_before: dict[bytes, int],
    position: int | None,
) -> int:
    keys = _keyset_keys(keyset_body)
    signers: set[bytes] = set()
    for s in sigs:
        k = keys.get(s.kid)
        if k is None or role not in k.roles:
            continue
        if s.kid in revoked_before and position is not None and position >= revoked_before[s.kid]:
            continue
        if cose.verify_signature(k.public, s, cid):
            signers.add(s.kid)
    return len(signers)


def _lineage_chain(ctx: VerificationContext, lineage: bytes) -> list[tuple[Bundle, dict[int, Any]]]:
    """Bundles in the resolver whose lineage is ``lineage`` (or are its version 1), by version."""
    out = []
    for b in ctx.resolver.values():
        try:
            env = cbor.decode(b.envelope)
        except cbor.CborError:
            continue
        if not isinstance(env, dict):
            continue
        if b.cid == lineage or env.get(LINEAGE) == lineage:
            out.append((b, env))
    out.sort(key=lambda be: (be[1].get(VERSION, 0), be[0].proof.position if be[0].proof else 0))
    return out


def _revocations(ctx: VerificationContext, authority: bytes) -> dict[bytes, int]:
    """Every revocation declared anywhere in a keyset lineage, keyed by kid, earliest position."""
    revoked: dict[bytes, int] = {}
    for _, env in _lineage_chain(ctx, authority):
        if env.get(TYPE) != "keyset" or not isinstance(env.get(BODY), dict):
            continue
        for kid, pos in env[BODY].get(KS_REVOCATIONS, []):
            revoked[kid] = min(pos, revoked.get(kid, pos))
    return revoked


def _keyset_in_force(
    ctx: VerificationContext, authority: bytes, position: int | None, depth: int
) -> tuple[dict[int, Any], dict[bytes, int]]:
    """Step 5: the keyset version logged before ``position``, plus revocations from the lineage."""
    if authority not in ctx.resolver:
        raise Rejection(5, "authority keyset lineage cannot be resolved")
    chain = _lineage_chain(ctx, authority)
    in_force = None
    revoked: dict[bytes, int] = {}
    for b, env in chain:
        if env.get(TYPE) != "keyset":
            continue
        if b.proof is None:
            continue
        if position is None or b.proof.position < position:
            _verify(ctx, b, depth, for_action=False)
            in_force = env[BODY]
        for kid, pos in env[BODY].get(KS_REVOCATIONS, []):
            revoked[kid] = min(pos, revoked.get(kid, pos))
    if in_force is None:
        raise Rejection(5, "no keyset version logged before this manifest")
    return in_force, revoked


def _verify_log(ctx: VerificationContext, bundle: Bundle, env: dict[int, Any]) -> None:
    """Step 7: inclusion in a witnessed checkpoint consistent with the held one."""
    proof = bundle.proof
    if proof is None:
        raise Rejection(7, "no log inclusion proof")
    try:
        note = log.parse_note(proof.checkpoint_note)
    except ValueError as e:
        raise Rejection(7, f"malformed checkpoint: {e}") from e
    cp = note.checkpoint
    if proof.log != ctx.log_authority or cp.origin != log.log_origin(ctx.log_authority):
        raise Rejection(7, "proof is not from the accepted log")
    record_of = RECORD_LOGS.get(env[TYPE])
    if record_of is not None:
        record = record_of(Resolved(ctx, bundle, env, proof.position))
        if record is not None and proof.log != record:
            raise Rejection(7, "proof is not against the context's ledger of record")
    leaf = log.entry_leaf(
        bundle.cid, env[TYPE], env.get(AUTHORITY, bundle.cid), env.get(LINEAGE), env[VERSION]
    )
    if (cp.size, cp.root) in ctx.accepted_checkpoints:
        # A checkpoint the phone already accepted in this session: only inclusion is left.
        if not merkle.verify_inclusion(leaf, proof.position, cp.size, proof.inclusion, cp.root):
            raise Rejection(7, "inclusion proof does not verify")
        return
    if not any(log.verify_log_signature(cp, s, ctx.log_public) for s in note.signatures):
        raise Rejection(7, "checkpoint is not signed by the log")
    cosigners = log.cosigners(note, ctx.witness_keys)
    if len(cosigners) < ctx.min_witnesses:
        raise Rejection(7, f"{len(cosigners)} witness cosignatures, need {ctx.min_witnesses}")
    if not merkle.verify_inclusion(leaf, proof.position, cp.size, proof.inclusion, cp.root):
        raise Rejection(7, "inclusion proof does not verify")
    if ctx.held_checkpoint is not None:
        held_size, held_root = ctx.held_checkpoint
        if cp.size < held_size:
            raise Rejection(7, "checkpoint is older than the one held")
        if cp.size == held_size:
            if cp.root != held_root:
                raise Rejection(7, "checkpoint root differs from the held checkpoint")
        else:
            consistency = proof.consistency or ctx.consistency_proofs.get((cp.size, cp.root))
            if consistency is None or not merkle.verify_consistency(
                held_size, cp.size, held_root, cp.root, consistency
            ):
                raise Rejection(7, "checkpoint is not consistent with the held checkpoint")
    # The phone now holds this checkpoint and remembers it was witnessed and consistent.
    ctx.accepted_checkpoints.add((cp.size, cp.root))
    ctx.held_checkpoint = (cp.size, cp.root)


def _verify_lineage(
    ctx: VerificationContext, bundle: Bundle, env: dict[int, Any], depth: int
) -> None:
    """Step 8: prev is a logged version one lower with the same authority; no earlier fork."""
    if env[VERSION] == 1:
        return
    prev = ctx.resolver.get(env[PREV])
    if prev is None:
        raise Rejection(8, "prev cannot be resolved")
    try:
        prev_env = _verify(ctx, prev, depth, for_action=False)
    except Rejection as e:
        raise Rejection(8, f"prev does not verify ({e})") from e
    if prev_env[VERSION] != env[VERSION] - 1:
        raise Rejection(8, "prev version is not exactly one lower")
    if prev_env[TYPE] != env[TYPE]:
        raise Rejection(8, "prev has a different type")
    if prev_env.get(AUTHORITY) != env.get(AUTHORITY) and not (
        env[TYPE] == "keyset" and prev_env[VERSION] == 1 and env[AUTHORITY] == env[LINEAGE]
    ):
        raise Rejection(8, "authority changed within the lineage")
    expected_lineage = env[PREV] if prev_env[VERSION] == 1 else prev_env[LINEAGE]
    if env[LINEAGE] != expected_lineage:
        raise Rejection(8, "lineage does not point at version 1")
    if bundle.proof is not None:
        for other, other_env in _lineage_chain(ctx, env[LINEAGE]):
            if other.cid == bundle.cid or other.proof is None:
                continue
            if (
                other_env.get(VERSION) == env[VERSION]
                and other.proof.position < bundle.proof.position
            ):
                raise Rejection(8, "another version with this number was logged first")


def _type_rules(ctx: VerificationContext, env: dict[int, Any]) -> None:
    """Step 10: frozen fields and type rules. Only keyset rules exist until the type specs land."""
    if env[TYPE] != "keyset":
        return
    body = env[BODY]
    keys = _keyset_keys(body)
    for role, n in body[KS_THRESHOLDS].items():
        holders = sum(1 for k in keys.values() if role in k.roles)
        if n > holders:
            raise Rejection(10, f"{role} threshold {n} exceeds the {holders} keys holding it")
    if env[VERSION] > 1:
        prev_env = cbor.decode(ctx.resolver[env[PREV]].envelope)
        commitment = prev_env[BODY].get(KS_NEXT)
        if commitment is not None and next_commitment(list(keys.values())) != commitment:
            raise Rejection(10, "keys do not match the previous version's next-keyset commitment")


def _verify(
    ctx: VerificationContext, bundle: Bundle, depth: int, *, for_action: bool
) -> dict[int, Any]:
    if depth > MAX_REF_DEPTH:
        raise Rejection(9, f"reference depth exceeds {MAX_REF_DEPTH}")
    if bundle.cid in ctx.verified:
        env = ctx.verified[bundle.cid]
        if for_action and EXPIRES in env and ctx.now >= env[EXPIRES]:
            raise Rejection(11, "expired")
        return env

    # 1. size
    if len(bundle.envelope) > MAX_ENVELOPE_BYTES:
        raise Rejection(1, f"envelope is {len(bundle.envelope)} bytes, limit {MAX_ENVELOPE_BYTES}")
    # 2. canonical form
    try:
        env = cbor.decode(bundle.envelope)
    except cbor.CborError as e:
        raise Rejection(2, f"not deterministic CBOR: {e}") from e
    if cbor.encode(env) != bundle.envelope:
        raise Rejection(2, "re-encoding does not reproduce the bytes")
    # 3. CID
    cid = compute_cid(bundle.envelope)
    if cid != bundle.cid:
        raise Rejection(3, "computed CID differs from the CID the bundle was presented under")
    # 4. type and schema
    _schema(env)
    # 5. keyset in force
    is_genesis_keyset = env[TYPE] == "keyset" and env[VERSION] == 1
    position = bundle.proof.position if bundle.proof else None
    if is_genesis_keyset:
        keyset_body, revoked = env[BODY], {}
    elif env[TYPE] == "keyset":
        # Keyset version N is signed by the rotate threshold of version N-1.
        prev = ctx.resolver.get(env[PREV])
        if prev is None:
            raise Rejection(5, "previous keyset cannot be resolved")
        keyset_body = cbor.decode(prev.envelope)[BODY]
        revoked = _revocations(ctx, env[AUTHORITY])
    else:
        keyset_body, revoked = _keyset_in_force(ctx, env[AUTHORITY], position, depth)
    # 6. signatures
    sigs: list[cose.Signature] | None = None
    if bundle.signatures is not None:
        try:
            sigs = cose.decode_cose_sign(bundle.signatures)
        except (ValueError, cbor.CborError) as e:
            raise Rejection(6, f"malformed COSE_Sign: {e}") from e
    check = SIGNATURE_CHECKS.get(env[TYPE])
    if check is not None:
        from .bodies import TypeRule

        view = Resolved(ctx, bundle, env, position)
        try:
            check(view, sigs, keyset_body, revoked)
        except TypeRule as e:
            raise Rejection(6, str(e), e.rule) from e
    else:
        if sigs is None:
            raise Rejection(6, "no signatures")
        role = ROLE_ROTATE if env[TYPE] == "keyset" else ROLE_SIGN
        need = keyset_body[KS_THRESHOLDS][role]
        have = _count_valid(keyset_body, role, sigs, cid, revoked, position)
        if have < need:
            raise Rejection(6, f"{have} valid {role} signatures, threshold {need}")
    # 7. log
    _verify_log(ctx, bundle, env)
    # 8. lineage
    _verify_lineage(ctx, bundle, env, depth)
    # 9. references
    for name, ref in env[REFS].items():
        target = ctx.resolver.get(ref)
        if target is None:
            if ref in ctx.blobs:
                continue  # a blob the phone fetched and checked against its CID
            raise Rejection(9, f"reference {name!r} cannot be resolved")
        try:
            _verify(ctx, target, depth + 1, for_action=False)
        except Rejection as e:
            if e.step == 9 and e.reason.startswith("reference depth"):
                raise
            raise Rejection(9, f"reference {name!r} fails verification ({e})") from e
    # 10. type rules
    _type_rules(ctx, env)
    hook = TYPE_RULES.get(env[TYPE])
    if hook is not None:
        from .bodies import TypeRule

        try:
            hook(Resolved(ctx, bundle, env, position))
        except TypeRule as e:
            raise Rejection(10, str(e), e.rule) from e
    ctx.verified[bundle.cid] = env
    # 11. expiry, for a new action
    if for_action and EXPIRES in env and ctx.now >= env[EXPIRES]:
        raise Rejection(11, "expired")
    return env


def verify_bundle(ctx: VerificationContext, bundle: Bundle, *, for_action: bool = True) -> dict:
    """Run the eleven steps. Returns the decoded envelope or raises ``Rejection``.

    A consistency proof in the bundle is a proof for its checkpoint, from the phone's held
    checkpoint; it is used the first time that checkpoint is checked, whichever bundle
    (a keyset, a prev, a reference, or this one) gets there first.
    """
    from .bodies import registry  # noqa: F401  (registers every type's hooks)

    if bundle.proof is not None and bundle.proof.consistency:
        try:
            note = log.parse_note(bundle.proof.checkpoint_note)
            key = (note.checkpoint.size, note.checkpoint.root)
            ctx.consistency_proofs.setdefault(key, bundle.proof.consistency)
        except ValueError:
            pass
    return _verify(ctx, bundle, 0, for_action=for_action)


# ---------------------------------------------------------------- a test world


@dataclass
class World:
    """A deterministic log plus the bundles logged in it, used by the vector generator and tests."""

    log_authority: bytes  # CID of the log's keyset version 1
    log_key: SigningKey
    witnesses: dict[bytes, SigningKey]  # witness authority CID -> cosigning key
    leaves: list[bytes] = field(default_factory=list)
    bundles: dict[bytes, Bundle] = field(default_factory=dict)
    blobs: dict[bytes, bytes] = field(default_factory=dict)
    global_context: bytes | None = None

    @property
    def log_public(self) -> bytes:
        return self.log_key.public

    def origin(self) -> str:
        return log.log_origin(self.log_authority)

    def witness_keys(self) -> list[bytes]:
        return [k.public for k in self.witnesses.values()]

    def checkpoint(self, size: int | None = None) -> log.Checkpoint:
        n = len(self.leaves) if size is None else size
        return log.Checkpoint(self.origin(), n, merkle.root_hash(self.leaves[:n]))

    def note(self, size: int | None = None, timestamp: int = 1_791_259_200) -> log.Note:
        cp = self.checkpoint(size)
        sigs = [log.sign_checkpoint(cp, self.log_key)]
        for authority, key in self.witnesses.items():
            sigs.append(log.cosign_checkpoint(cp, log.witness_name(authority), key, timestamp))
        return log.Note(cp, sigs)

    def append(
        self,
        env: dict[int, Any],
        signers: list[tuple[bytes, SigningKey]] | None = None,
        *,
        authorship: Callable[[bytes], bytes] | bytes | None = None,
    ) -> Bundle:
        """Sign ``env`` with ``signers`` (kid, key), or attach ``authorship`` (bytes, or a
        function of the CID), and append it to the log."""
        data = encode_envelope(env)
        cid = compute_cid(data)
        position = len(self.leaves)
        self.leaves.append(
            log.entry_bytes(cid, env[TYPE], env.get(AUTHORITY, cid), env.get(LINEAGE), env[VERSION])
        )
        signatures = None
        if signers:
            signatures = cose.encode_cose_sign([cose.sign_cid(k, kid, cid) for kid, k in signers])
        if callable(authorship):
            authorship = authorship(cid)
        bundle = Bundle(
            data, signatures, cid, LogProof(self.log_authority, position, "", []), authorship
        )
        self.bundles[cid] = bundle
        return bundle

    def put_blob(self, data: bytes) -> bytes:
        """Store a public blob the phones in this world have fetched. Returns its CID."""
        self.blobs[compute_cid(data)] = data
        return compute_cid(data)

    def finalize(self, held_size: int = 0) -> None:
        """Fill every bundle's proof against the current checkpoint."""
        note_text = self.note().text()
        n = len(self.leaves)
        consistency = (
            merkle.consistency_proof(self.leaves, held_size) if 0 < held_size < n else None
        )
        for b in self.bundles.values():
            assert b.proof is not None
            b.proof.checkpoint_note = note_text
            b.proof.inclusion = merkle.inclusion_proof(self.leaves, b.proof.position)
            b.proof.consistency = consistency

    def context(self, now: int, held_size: int = 0) -> VerificationContext:
        held = (held_size, merkle.root_hash(self.leaves[:held_size])) if held_size else None
        return VerificationContext(
            resolver=dict(self.bundles),
            log_authority=self.log_authority,
            log_public=self.log_public,
            witness_keys=self.witness_keys(),
            held_checkpoint=held,
            now=now,
            blobs=dict(self.blobs),
            global_context=self.global_context,
        )


# ---------------------------------------------------------------- bundle wire format

BUNDLE_ENVELOPE, BUNDLE_SIGNATURES, BUNDLE_PROOFS, BUNDLE_HINTS, BUNDLE_AUTHORSHIP = range(5)
PROOF_LOG, PROOF_INDEX, PROOF_CHECKPOINT, PROOF_PATH = range(4)
MAX_BUNDLE_BYTES = 96 * 1024


def encode_bundle(bundle: Bundle, hints: list[str] | None = None) -> bytes:
    """services.md "The bundle": ``{0 envelope, 1 signatures, 2 [proofs], 3 hints, 4 authorship?}``.

    ``signatures`` is one COSE_Sign (bstr) holding every signer's COSE_Signature; it is absent
    for participant-authored types, which carry ``authorship`` instead (B-4).
    """
    proofs = []
    if bundle.proof is not None:
        proofs.append(
            {
                PROOF_LOG: bundle.proof.log,
                PROOF_INDEX: bundle.proof.position,
                PROOF_CHECKPOINT: bundle.proof.checkpoint_note,
                PROOF_PATH: list(bundle.proof.inclusion),
            }
        )
    item: dict[int, Any] = {
        BUNDLE_ENVELOPE: bundle.envelope,
        BUNDLE_PROOFS: proofs,
        BUNDLE_HINTS: list(hints or []),
    }
    if bundle.signatures is not None:
        item[BUNDLE_SIGNATURES] = bundle.signatures
    if bundle.authorship is not None:
        item[BUNDLE_AUTHORSHIP] = bundle.authorship
    return cbor.encode(item)


def decode_bundle(data: bytes) -> Bundle:
    """Parse the wire bundle. The claimed CID is the hash of the envelope bytes."""
    if len(data) > MAX_BUNDLE_BYTES:
        raise ValueError("bundle over 96 KiB")
    item = cbor.decode(data)
    if not isinstance(item, dict) or not {BUNDLE_ENVELOPE, BUNDLE_PROOFS, BUNDLE_HINTS} <= set(
        item
    ):
        raise ValueError("bundle shape")
    if set(item) - {0, 1, 2, 3, 4}:
        raise ValueError("bundle has unknown keys")
    sigs = item.get(BUNDLE_SIGNATURES)
    authorship = item.get(BUNDLE_AUTHORSHIP)
    if (sigs is None) == (authorship is None):
        raise ValueError("B-4: exactly one of signatures and authorship")
    if sigs is not None and not isinstance(sigs, bytes):
        raise ValueError("signatures must be one COSE_Sign byte string")
    if authorship is not None and not isinstance(authorship, bytes):
        raise ValueError("authorship must be a byte string")
    proofs = item[BUNDLE_PROOFS]
    proof = None
    if proofs:
        p = proofs[0]
        proof = LogProof(p[PROOF_LOG], p[PROOF_INDEX], p[PROOF_CHECKPOINT], list(p[PROOF_PATH]))
    env = item[BUNDLE_ENVELOPE]
    return Bundle(env, sigs, compute_cid(env), proof, authorship)
