"""The ``agent-sponsor`` body: docs/specs/agent-sponsor.md.

Step 4 checks shapes only (rule id ``schema``); AS-1 to AS-9 run at step 10 as the spec's
table says. AS-2b never decides manifest validity: ``check_report`` is the phone's check
at the Add commit, against a synthetic report format this reference defines for vectors::

    report = CBOR {0: platform (uint), 1: measurement (bstr), 2: report_data (bstr 32)}
    report_data = SHA-256("hum/attest/1" ‖ agentKey ‖ sponsor authority CID)

``sponsorProof`` (AS-8) is a credential presentation ``credentials.md`` has not defined.
This reference checks a provisional structure
``CBOR {0: scope (bstr), 1: disclosed ([]), 2: proof (bstr)}``
for the right scope and no disclosed attribute, and marks the proof itself pending.

seam: credential presentation (``hum/sponsor/1``), domain string ``hum/attest/1``.
"""

from __future__ import annotations

import hashlib
from typing import Any

from .. import cbor
from .. import credentials as cr
from .. import manifest as m
from . import TypeRule, is_bytes, is_text, is_uint, no_unknown_keys, require, require_keys
from . import verifier as vfspec

__all__ = [
    "ATTEST_DOMAIN",
    "SPONSOR_SCOPE",
    "body",
    "check_report",
    "log_submission_check",
    "report_data",
    "rules",
    "schema",
    "sponsor_proof",
    "synthetic_report",
    "verify_sponsor_proof",
]

(
    AGENT_KEY, TIER, RUNTIME, ATTESTATION, CODE_HASH, CAPABILITIES, RATE_LIMITS, LABEL,
    DESCRIPTION, SPONSOR_KIND, SPONSOR_PROOF, RETIRED,
) = range(12)  # fmt: skip
REQUIRED = {AGENT_KEY, TIER, RUNTIME, CAPABILITIES, RATE_LIMITS, LABEL, DESCRIPTION, SPONSOR_KIND}
ALL_KEYS = set(range(12))
TIER_SHARED, TIER_PUBLIC = 0, 1
RT_MEMBER, RT_ENCLAVE, RT_ANYWHERE = 1, 2, 3
RUNTIMES_FOR_TIER = {TIER_SHARED: {RT_MEMBER, RT_ENCLAVE}, TIER_PUBLIC: {RT_ANYWHERE}}
CAP_POST, CAP_GREETER, CAP_HISTORY, CAP_AUTHOR_MAP, CAP_TAKE = range(5)
CAPS_FOR_TIER = {TIER_SHARED: {0, 1, 2, 3, 4}, TIER_PUBLIC: {CAP_TAKE}}
RL_WINDOW, RL_MAP_OBJECTS, RL_MESSAGES, RL_TAKES = range(4)
AT_PLATFORM, AT_MEASUREMENT, AT_ISSUED_AT, AT_POLICY = range(4)
PLATFORMS = {0: "SEV-SNP", 1: "TDX", 2: "Nitro", 3: "Apple PCC"}
MAX_EXPIRY = 7_776_000
ATTEST_DOMAIN = b"hum/attest/1"
SPONSOR_SCOPE = b"hum/sponsor/1"
VERIFIER_CLASS_KEY = 4  # verifier.md body key 4: class


# ---------------------------------------------------------------- builders


def body(
    *,
    agent_key: bytes,
    tier: int,
    runtime: int,
    capabilities: list[int],
    label: str,
    description: str,
    sponsor_kind: int,
    rate_limits: dict[int, int] | None = None,
    attestation: dict[int, Any] | None = None,
    code_hash: bytes | None = None,
    sponsor_proof: bytes | None = None,
    retired: bool | None = None,
) -> dict[int, Any]:
    out: dict[int, Any] = {
        AGENT_KEY: agent_key,
        TIER: tier,
        RUNTIME: runtime,
        CAPABILITIES: capabilities,
        RATE_LIMITS: rate_limits
        or {RL_WINDOW: 86_400, RL_MAP_OBJECTS: 10, RL_MESSAGES: 50, RL_TAKES: 2},
        LABEL: label,
        DESCRIPTION: description,
        SPONSOR_KIND: sponsor_kind,
    }
    for k, v in (
        (ATTESTATION, attestation),
        (CODE_HASH, code_hash),
        (SPONSOR_PROOF, sponsor_proof),
        (RETIRED, retired),
    ):
        if v is not None:
            out[k] = v
    return out


def report_data(agent_key: bytes, authority: bytes) -> bytes:
    return hashlib.sha256(ATTEST_DOMAIN + agent_key + authority).digest()


def synthetic_report(platform: int, measurement: bytes, data: bytes) -> bytes:
    return cbor.encode({0: platform, 1: measurement, 2: data})


def sponsor_proof(
    issuer: bytes,
    kid: bytes,
    epoch: int,
    proof: bytes,
    pseudonym: bytes,
    *,
    length: int = 3,
    disclosed: dict[int, int] | None = None,
    context: bytes | None = None,
) -> bytes:
    """A ``sponsorProof``: a credentials.md presentation with one card from the agent-class
    verifier ``issuer`` (its authority CID), disclosing the epoch and nothing else. The BBS
    proof and pseudonym are inputs (pending a library)."""
    card = cr.CardProof(issuer, kid, length, {0: epoch, **(disclosed or {})}, proof, pseudonym)
    return cr.Presentation([card], [], context).encode()


def verify_sponsor_proof(
    proof: bytes,
    *,
    authority: bytes,
    agent_key: bytes,
    verifier_env: dict[int, Any],
    issued: int,
    position: int | None,
) -> dict[str, Any]:
    """AS-8's presentation check: P1 to P8 of credentials.md for the sponsor row (scope
    ``hum/sponsor/1`` ‖ authority, bound message ``agentKey``, no context, the possession leaf
    ``[4, A]`` with ``A`` the agent-class verifier the manifest names, epoch only) as a logged
    presentation verified against ``issued`` and the verifier version in force at ``position``.
    Raises ``PresentationError``."""
    pres = cr.Presentation.decode(proof)
    vb, vauth = verifier_env[m.BODY], verifier_env[m.AUTHORITY]
    keys = vb[vfspec.ISSUER_KEYS]
    info = cr.IssuerInfo(
        authority=vauth,
        class_=vb[vfspec.CLASS],
        retired=False,
        kids={k[vfspec.IK_KID] for k in keys},
        retired_kids=set(vb.get(vfspec.RETIRED_KIDS, [])),
        attributes=[(a[vfspec.AT_NAME], a.get(7, 0)) for a in vb[vfspec.ATTRIBUTES]],
        since={k[vfspec.IK_KID]: k[vfspec.IK_SINCE] for k in keys},
    )
    scope, bound = cr.scopes.sponsor(authority, agent_key)
    return cr.verify_presentation(
        pres,
        use="sponsor",
        policy=cr.possession_leaf(vauth),
        scope=scope,
        bound=bound,
        expected_context=None,
        issuers={vauth: info},
        rows_for_source={},
        now=None,
        v_of={vauth: cr.validity_periods(vb[vfspec.VALIDITY])},
        issued=issued,
        object_position=position,
    )


def log_of_record(bundle: m.Bundle) -> bytes | None:
    """AS-8 (credentials.md "in force", RS6): a sponsor manifest pins no context, so its log
    of record is the log whose inclusion proof its bundle carries. That log made the clock
    check at submission, and the verifier version in force is read at the manifest's position
    in it, whichever context later uses the manifest."""
    return bundle.proof.log if bundle.proof is not None else None


def context_accepts_log(ctx_logs: list[bytes], bundle: m.Bundle) -> bool:
    """A context accepts a sponsor manifest when its log of record is any entry of the
    context's ``logs`` (not only the first), so AS-8 gives one answer everywhere."""
    record = log_of_record(bundle)
    return record is not None and record in ctx_logs


def log_submission_check(proof: bytes, issued: int, log_now: int, v: int) -> str | None:
    """The log of record's clock check on a ``sponsorProof`` at submission (AS-8, credentials.md
    "Validity"): the disclosed epoch is current and ``issued`` is within 3,600 s of ``log_now``.
    Returns the reason for a ``rejected`` under rule P5, or None."""
    try:
        pres = cr.Presentation.decode(proof)
    except cr.PresentationError as e:
        return f"{e.rule}: {e.reason}"
    for cp in pres.creds:
        reason = cr.log_submission_check(cp.disclosed.get(0, -1), v, log_now, issued)
        if reason is not None:
            return reason
    return None


# ---------------------------------------------------------------- step 4: shapes


def schema(env: dict[int, Any]) -> None:
    b = env[m.BODY]
    require_keys(b, REQUIRED, "schema")
    no_unknown_keys(b, ALL_KEYS, "schema")
    require(is_bytes(b[AGENT_KEY], 32), "schema", "agentKey must be 32 bytes")
    require(is_uint(b[TIER]), "schema", "tier")
    require(is_uint(b[RUNTIME]), "schema", "runtime")
    require(
        isinstance(b[CAPABILITIES], list) and all(is_uint(c) for c in b[CAPABILITIES]),
        "schema",
        "capabilities",
    )
    rl = b[RATE_LIMITS]
    require(
        isinstance(rl, dict) and all(is_uint(k, 0, 3) and is_uint(v) for k, v in rl.items()),
        "schema",
        "rateLimits",
    )
    require(
        isinstance(b[LABEL], str) and isinstance(b[DESCRIPTION], str),
        "schema",
        "label and description are text",
    )
    require(is_uint(b[SPONSOR_KIND], 0, 1), "schema", "sponsorKind")
    if ATTESTATION in b:
        at = b[ATTESTATION]
        require(
            isinstance(at, dict) and {AT_PLATFORM, AT_MEASUREMENT, AT_ISSUED_AT} <= set(at),
            "schema",
            "attestation shape",
        )
        no_unknown_keys(
            at, {AT_PLATFORM, AT_MEASUREMENT, AT_ISSUED_AT, AT_POLICY}, "schema", "attestation"
        )
        require(
            is_uint(at[AT_PLATFORM]) and is_bytes(at[AT_MEASUREMENT]) and is_uint(at[AT_ISSUED_AT]),
            "schema",
            "attestation types",
        )
        if AT_POLICY in at:
            require(is_text(at[AT_POLICY], 256), "schema", "attestation.policy")
    if CODE_HASH in b:
        require(is_bytes(b[CODE_HASH], 32), "schema", "codeHash must be 32 bytes")
    if SPONSOR_PROOF in b:
        require(is_bytes(b[SPONSOR_PROOF]), "schema", "sponsorProof must be bytes")
    if RETIRED in b:
        require(isinstance(b[RETIRED], bool), "schema", "retired must be a bool")
    for name in env[m.REFS]:
        require(name in ("verifier", "report"), "schema", f"unknown ref {name!r}")


# ---------------------------------------------------------------- step 10: AS-1 to AS-9


def rules(view: m.Resolved) -> None:
    env, b, refs = view.env, view.body, view.refs
    tier, runtime = b[TIER], b[RUNTIME]
    # AS-1
    require(tier in (TIER_SHARED, TIER_PUBLIC), "AS-1", "tier must be 0 or 1")
    require(
        runtime in RUNTIMES_FOR_TIER[tier], "AS-1", f"runtime {runtime} not allowed for tier {tier}"
    )
    # AS-2a
    enclave = runtime == RT_ENCLAVE
    present = (ATTESTATION in b, CODE_HASH in b, "report" in refs)
    require(
        all(present) if enclave else not any(present),
        "AS-2a",
        "attestation, codeHash and report present iff runtime 2",
    )
    if enclave:
        at = b[ATTESTATION]
        require(at[AT_PLATFORM] in PLATFORMS, "AS-2a", "unknown attestation platform")
        require(
            hashlib.sha256(at[AT_MEASUREMENT]).digest() == b[CODE_HASH],
            "AS-2a",
            "codeHash is not SHA-256(measurement)",
        )
    # AS-3
    caps = b[CAPABILITIES]
    require(len(set(caps)) == len(caps), "AS-3", "duplicate capability")
    require(
        set(caps) <= CAPS_FOR_TIER[tier], "AS-3", f"capabilities {caps} not allowed for tier {tier}"
    )
    if tier == TIER_PUBLIC:
        require(caps == [CAP_TAKE], "AS-3", "a public agent's capabilities are exactly [4]")
    # AS-4
    rl = b[RATE_LIMITS]
    require(
        set(rl) == {RL_WINDOW, RL_MAP_OBJECTS, RL_MESSAGES, RL_TAKES},
        "AS-4",
        "rateLimits needs all four fields",
    )
    require(3_600 <= rl[RL_WINDOW] <= 604_800, "AS-4", "rateLimits.window out of range")
    # AS-5
    keyset = view.latest_before(env[m.AUTHORITY], None)
    if keyset is not None and keyset.get(m.TYPE) == "keyset":
        publics = {k[m.KEY_PUBLIC] for k in keyset[m.BODY][m.KS_KEYS]}
        require(b[AGENT_KEY] not in publics, "AS-5", "agentKey is a key of the sponsor's keyset")
    # AS-6
    require(m.EXPIRES in env, "AS-6", "expires is required")
    require(
        env[m.EXPIRES] - env[m.ISSUED] <= MAX_EXPIRY,
        "AS-6",
        "expires more than 90 days after issued",
    )
    # AS-7
    require(
        is_text(b[LABEL], 64, min_bytes=1), "AS-7", "label must be 1..64 bytes, NFC, no controls"
    )
    require(is_text(b[DESCRIPTION], 560), "AS-7", "description over 560 bytes or malformed")
    # AS-8
    has_proof, has_verifier = SPONSOR_PROOF in b, "verifier" in refs
    require(has_proof == has_verifier, "AS-8", "sponsorProof present iff refs.verifier present")
    if has_proof:
        ver = view.manifest(refs["verifier"])
        require(
            ver is not None and ver.get(m.TYPE) == "verifier",
            "AS-8",
            "refs.verifier is not a verifier",
        )
        require(
            ver[m.BODY].get(VERIFIER_CLASS_KEY) == "agent", "AS-8", "verifier class is not agent"
        )
        # the version in force: the lineage's highest log index below this manifest's, in
        # the manifest's log of record (the log whose proof the bundle carries; RS6)
        record = log_of_record(view.bundle)
        require(
            record is None or record == view.ctx.log_authority,
            "AS-8",
            "the bundle's proof is not from the log being read",
        )
        in_force = view.latest_before(view.lineage_of(refs["verifier"]), view.position) or ver
        try:
            verify_sponsor_proof(
                b[SPONSOR_PROOF],
                authority=env[m.AUTHORITY],
                agent_key=b[AGENT_KEY],
                verifier_env=in_force,
                issued=env[m.ISSUED],
                position=view.position,
            )
        except cr.PresentationError as e:
            raise TypeRule("AS-8", f"sponsorProof fails {e.rule}: {e.reason}") from e
    # AS-9
    prev = view.prev_env
    if prev is not None:
        pb = prev[m.BODY]
        for key, name in ((AGENT_KEY, "agentKey"), (TIER, "tier"), (SPONSOR_KIND, "sponsorKind")):
            require(b[key] == pb[key], "AS-9", f"{name} changed")
        require(not pb.get(RETIRED, False), "AS-9", "no version follows a retired one")


# ---------------------------------------------------------------- AS-2b (phone, at the Add commit)


def check_report(report: bytes, b: dict[int, Any], authority: bytes) -> list[str]:
    """Return the AS-2b failures for a synthetic report, empty when it binds."""
    problems = []
    try:
        item = cbor.decode(report)
    except cbor.CborError:
        return ["report is not deterministic CBOR"]
    if not (isinstance(item, dict) and set(item) == {0, 1, 2}):
        return ["report shape"]
    at = b.get(ATTESTATION, {})
    if item[0] != at.get(AT_PLATFORM):
        problems.append("platform differs")
    if item[1] != at.get(AT_MEASUREMENT):
        problems.append("measurement differs from attestation.measurement")
    if item[2] != report_data(b[AGENT_KEY], authority):
        problems.append("report data is not bound to agentKey and the sponsor authority")
    return problems


m.register("agent-sponsor", schema=schema, rules=rules)
