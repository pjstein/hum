"""Vectors for docs/specs/agent-sponsor.md: sponsor manifests, AS-1 to AS-9, the synthetic
attestation report (AS-2b) and the cross-spec cases that live here.

Pending: `as-x-take-authority` (needs the take body) and verifying `sponsorProof` against an
issuer key (needs credentials.md). The AS-8 cases pin real custom-profile verifiers built with
the verifier body's builders.
"""

from __future__ import annotations

import hashlib
from typing import Any

from .. import cbor, fixtures
from .. import credentials as cr
from .. import manifest as m
from ..bodies import agent_sponsor as sp
from ..bodies import registry  # noqa: F401  (registers every type's hooks)
from ..keys import key_from_label
from . import File, hexify, jsonable
from .issue_map_vectors import bundle_json

SPEC = "agent-sponsor"
S_RULES = "Validation rules"
S_ATTEST = "Attestation"
DAY = 86_400
ISSUED = fixtures.ISSUED + DAY
NOW = ISSUED + 3600
AGENT_VALIDITY = 2_419_200  # one period per epoch for the agent-class verifier (V = 1)
AGENT_EPOCH = cr.epoch_now(ISSUED, 1)
NEXT_EPOCH_NOW = (AGENT_EPOCH + 1) * cr.PERIOD + 7200  # a phone syncing in the next epoch
LOG_SKEW_T = ISSUED + 7200
VERIFY_AT = {"as-ok-proof-after-epoch": NEXT_EPOCH_NOW}


class World:
    def __init__(self) -> None:
        self.fx = fixtures.build()
        self.w = self.fx.world
        self.named: dict[str, m.Bundle] = {}
        self.keys: dict[str, Any] = {}
        self._build()

    def authority(self, label: str) -> tuple[bytes, Any]:
        keys = {label: key_from_label(label), f"{label}-rotate": key_from_label(f"{label}-rotate")}
        self.keys.update(keys)
        ks = self.w.append(
            fixtures.service_keyset(label, f"{label}-rotate", keys),
            [(f"{label}-rotate".encode(), keys[f"{label}-rotate"])],
        )
        self.named[f"keyset-{label}"] = ks
        return ks.cid, keys[label]

    def manifest(
        self,
        name: str,
        auth: bytes,
        signer,
        body: dict,
        *,
        refs=None,
        version=1,
        v1=None,
        prev=None,
        expires: int | None = ISSUED + 60 * DAY,
        issued: int = ISSUED,
        label: str | None = None,
    ):
        env = m.envelope(
            "agent-sponsor",
            body,
            authority=auth,
            version=version,
            issued=issued,
            expires=expires,
            refs=refs or {},
            lineage=v1.cid if v1 else None,
            prev=prev.cid if prev else None,
        )
        b = self.w.append(env, [((label or "k").encode(), signer)])
        self.named[name] = b
        return b

    def _verifier_env(self, auth: bytes, class_: str, name: str, validity: int = 7_776_000) -> dict:
        """A valid custom-profile verifier of the given class (verifier.md builders)."""
        from ..bodies import verifier as vf

        label = class_
        code_blob = self.w.put_blob(fixtures.fixed_bytes(f"module-{label}", 64))
        build_blob = self.w.put_blob(fixtures.fixed_bytes(f"build-{label}", 64))
        body = vf.body(
            name=name,
            operator="Hum reference operator",
            profile="custom",
            class_=class_,
            issuer_keys=[
                vf.issuer_key(
                    fixtures.fixed_bytes(f"kid-{label}", 8),
                    fixtures.fixed_bytes(f"bbs-{label}", 96),
                    0,
                    1,
                )
            ],
            host_keys=[
                vf.host_key(
                    fixtures.fixed_bytes(f"hkid-{label}", 8),
                    fixtures.fixed_bytes(f"hpke-{label}", 32),
                )
            ],
            attributes=[
                vf.attribute(
                    "agent-sponsor" if class_ == "agent" else "approved",
                    "bool",
                    "gate",
                    "Sponsored agent" if class_ == "agent" else "Approved",
                )
            ],
            evidence_=[
                vf.evidence(
                    "org",
                    "other",
                    "text",
                    "Something else: the sponsoring organization's registration",
                )
            ],
            dedup_=[],
            code_=vf.code(fixtures.fixed_bytes(f"source-{label}")),
            assurance=1,
            validity=validity,
        )
        return m.envelope(
            "verifier",
            body,
            authority=auth,
            issued=ISSUED,
            refs={"code": code_blob, "build": build_blob},
        )

    def _build(self) -> None:
        w = self.w
        agent = key_from_label("agent-key").public
        self.agent_key = agent

        def base(**kw) -> dict:
            args = dict(
                agent_key=agent,
                tier=0,
                runtime=1,
                capabilities=[0, 3],
                label="millbrook-facilitator",
                description="Proposes issues from long threads and drafts the strongest pro and con.",
                sponsor_kind=1,
            )
            args.update(kw)
            return sp.body(**args)

        auth, key = self.authority("sponsor")
        self.auth, self.key = auth, key
        enc = key_from_label("agent-key-enclave").public
        measurement = fixtures.fixed_bytes("sev-snp-measurement", 48)
        self.report = sp.synthetic_report(0, measurement, sp.report_data(enc, auth))
        report_cid = w.put_blob(self.report)
        att = {sp.AT_PLATFORM: 0, sp.AT_MEASUREMENT: measurement, sp.AT_ISSUED_AT: ISSUED - 600}
        code_hash = hashlib.sha256(measurement).digest()
        mf = self.manifest
        mf("as-ok-shared-hardware", auth, key, base(), label="sponsor")
        self.enclave = mf(
            "as-ok-shared-enclave",
            auth,
            key,
            base(
                agent_key=enc,
                runtime=2,
                attestation=att,
                code_hash=code_hash,
                label="facilitator-enclave",
            ),
            refs={"report": report_cid},
            label="sponsor",
        )
        self.enclave_body = base(agent_key=enc, runtime=2, attestation=att, code_hash=code_hash)
        mf(
            "as-ok-public",
            auth,
            key,
            base(
                agent_key=key_from_label("agent-key-public").public,
                tier=1,
                runtime=3,
                capabilities=[4],
                label="studio-writer",
            ),
            label="sponsor",
        )
        mf(
            "as-ok-empty-capabilities",
            auth,
            key,
            base(
                agent_key=key_from_label("agent-key-reader").public, capabilities=[], label="reader"
            ),
            label="sponsor",
        )
        v1 = mf(
            "renewable-v1",
            auth,
            key,
            base(agent_key=key_from_label("agent-key-renew").public, label="renewable"),
            label="sponsor",
        )
        mf(
            "as-ok-renew",
            auth,
            key,
            base(agent_key=key_from_label("agent-key-renew").public, label="renewable"),
            version=2,
            v1=v1,
            prev=v1,
            expires=ISSUED + 80 * DAY,
            issued=ISSUED + 1,
            label="sponsor",
        )
        r1 = mf(
            "retirable-v1",
            auth,
            key,
            base(agent_key=key_from_label("agent-key-retire").public, label="retirable"),
            label="sponsor",
        )
        retired = mf(
            "as-ok-retire",
            auth,
            key,
            base(
                agent_key=key_from_label("agent-key-retire").public, label="retirable", retired=True
            ),
            version=2,
            v1=r1,
            prev=r1,
            issued=ISSUED + 1,
            label="sponsor",
        )
        # sponsor proof (needs a verifier of class agent)
        vauth, vkey = self.authority("agent-verifier")
        pauth, pkey = self.authority("person-verifier")
        self.named["verifier-agent-class"] = w.append(
            self._verifier_env(vauth, "agent", "Agent sponsor verifier", AGENT_VALIDITY),
            [(b"agent-verifier", vkey)],
        )
        self.named["verifier-person-class"] = w.append(
            self._verifier_env(pauth, "person", "A person-class verifier"),
            [(b"person-verifier", pkey)],
        )
        self.vauth, self.pauth = vauth, pauth

        def proof_of(issuer, label, epoch=AGENT_EPOCH, **kw):
            kid = fixtures.fixed_bytes("kid-agent" if issuer == vauth else "kid-person", 8)
            return sp.sponsor_proof(
                issuer,
                kid,
                epoch,
                fixtures.fixed_bytes(f"sponsor-presentation-{label}", 96),
                fixtures.fixed_bytes(f"sponsor-pseudonym-{label}", 48),
                **kw,
            )

        self.proof_of = proof_of
        proof = proof_of(vauth, "ok")
        proof_key = key_from_label("agent-key-proof").public
        mf(
            "as-ok-with-proof",
            auth,
            key,
            base(agent_key=proof_key, label="vouched", sponsor_proof=proof),
            refs={"verifier": self.named["verifier-agent-class"].cid},
            label="sponsor",
        )
        mf(
            "as-bad-proof-no-verifier",
            auth,
            key,
            base(agent_key=proof_key, label="vouched", sponsor_proof=proof),
            label="sponsor",
        )
        mf(
            "as-bad-proof-class",
            auth,
            key,
            base(agent_key=proof_key, label="vouched", sponsor_proof=proof),
            refs={"verifier": self.named["verifier-person-class"].cid},
            label="sponsor",
        )
        # as-bad-proof-scope (a proof under another scope) is a P4 case: pending a BBS library
        disclosed = proof_of(vauth, "disclosed", disclosed={1: 1})
        mf(
            "as-bad-proof-disclosed",
            auth,
            key,
            base(agent_key=proof_key, label="vouched", sponsor_proof=disclosed),
            refs={"verifier": self.named["verifier-agent-class"].cid},
            label="sponsor",
        )
        with_context = proof_of(vauth, "context", context=fixtures.fixed_bytes("a-context", 33))
        mf(
            "as-bad-proof-context-present",
            auth,
            key,
            base(agent_key=proof_key, label="vouched", sponsor_proof=with_context),
            refs={"verifier": self.named["verifier-agent-class"].cid},
            label="sponsor",
        )
        mf(
            "as-bad-proof-epoch-mismatch",
            auth,
            key,
            base(
                agent_key=proof_key,
                label="vouched",
                sponsor_proof=proof_of(vauth, "next-epoch", epoch=AGENT_EPOCH + 1),
            ),
            refs={"verifier": self.named["verifier-agent-class"].cid},
            label="sponsor",
        )
        self.after_epoch = mf(
            "as-ok-proof-after-epoch",
            auth,
            key,
            base(
                agent_key=proof_key, label="vouched-later", sponsor_proof=proof_of(vauth, "later")
            ),
            refs={"verifier": self.named["verifier-agent-class"].cid},
            label="sponsor",
        )
        # ---- invalid manifests
        mf("as-bad-tier", auth, key, base(tier=2), label="sponsor")
        mf(
            "as-bad-public-enclave",
            auth,
            key,
            base(tier=1, runtime=2, capabilities=[4], attestation=att, code_hash=code_hash),
            refs={"report": report_cid},
            label="sponsor",
        )
        mf("as-bad-shared-anywhere", auth, key, base(runtime=3), label="sponsor")
        mf(
            "as-bad-enclave-no-report",
            auth,
            key,
            base(runtime=2, attestation=att, code_hash=code_hash),
            label="sponsor",
        )
        mf(
            "as-bad-codehash",
            auth,
            key,
            base(agent_key=enc, runtime=2, attestation=att, code_hash=bytes(32)),
            refs={"report": report_cid},
            label="sponsor",
        )
        bad_att = dict(att)
        bad_att[sp.AT_PLATFORM] = 9
        mf(
            "as-bad-platform",
            auth,
            key,
            base(agent_key=enc, runtime=2, attestation=bad_att, code_hash=code_hash),
            refs={"report": report_cid},
            label="sponsor",
        )
        mf(
            "as-bad-public-post",
            auth,
            key,
            base(tier=1, runtime=3, capabilities=[0, 4]),
            label="sponsor",
        )
        mf("as-bad-capability-unknown", auth, key, base(capabilities=[0, 9]), label="sponsor")
        mf("as-bad-capability-dup", auth, key, base(capabilities=[0, 0]), label="sponsor")
        mf(
            "as-bad-window",
            auth,
            key,
            base(rate_limits={0: 1, 1: 10, 2: 50, 3: 2}),
            label="sponsor",
        )
        mf(
            "as-bad-rate-limits-missing",
            auth,
            key,
            base(rate_limits={0: 86_400, 1: 10}),
            label="sponsor",
        )
        mf("as-bad-key-reuse", auth, key, base(agent_key=key.public), label="sponsor")
        mf("as-bad-no-expiry", auth, key, base(), expires=None, label="sponsor")
        mf("as-bad-long-expiry", auth, key, base(), expires=ISSUED + 365 * DAY, label="sponsor")
        mf("as-bad-label-long", auth, key, base(label="x" * 65), label="sponsor")
        mf("as-bad-description-long", auth, key, base(description="d" * 561), label="sponsor")
        swap1 = mf(
            "swappable-v1",
            auth,
            key,
            base(agent_key=key_from_label("agent-key-swap").public, label="swappable"),
            label="sponsor",
        )
        mf(
            "as-bad-key-swap",
            auth,
            key,
            base(agent_key=key_from_label("agent-key-swap-2").public, label="swappable"),
            version=2,
            v1=swap1,
            prev=swap1,
            issued=ISSUED + 1,
            label="sponsor",
        )
        mf(
            "as-bad-after-retire",
            auth,
            key,
            base(agent_key=key_from_label("agent-key-retire").public, label="retirable"),
            version=3,
            v1=r1,
            prev=retired,
            issued=ISSUED + 2,
            label="sponsor",
        )
        w.finalize()


EXPECTED = {
    "as-bad-tier": "AS-1",
    "as-bad-public-enclave": "AS-1",
    "as-bad-shared-anywhere": "AS-1",
    "as-bad-enclave-no-report": "AS-2a",
    "as-bad-codehash": "AS-2a",
    "as-bad-platform": "AS-2a",
    "as-bad-public-post": "AS-3",
    "as-bad-capability-unknown": "AS-3",
    "as-bad-capability-dup": "AS-3",
    "as-bad-window": "AS-4",
    "as-bad-rate-limits-missing": "AS-4",
    "as-bad-key-reuse": "AS-5",
    "as-bad-no-expiry": "AS-6",
    "as-bad-long-expiry": "AS-6",
    "as-bad-label-long": "AS-7",
    "as-bad-description-long": "AS-7",
    "as-bad-proof-no-verifier": "AS-8",
    "as-bad-proof-class": "AS-8",
    "as-bad-proof-disclosed": "AS-8",
    "as-bad-proof-context-present": "AS-8",
    "as-bad-proof-epoch-mismatch": "AS-8",
    "as-bad-key-swap": "AS-9",
    "as-bad-after-retire": "AS-9",
}


def manifests_file(wd: World) -> File:
    notes = (
        "Sponsor manifests under a 1-of-1 sponsor authority, verified with a fresh phone state "
        "(now = issued + 1 h, or the agent verifier's next epoch where `now` says so). "
        "sponsorProof is a credentials.md presentation of one possession leaf from the "
        "agent-class verifier, epoch only, verified as a logged presentation against the "
        "manifest's issued (ADR 0101); BBS proof bytes and pseudonyms are fixed (P4 pending, so "
        "as-bad-proof-scope has no vector). The log-submission cases are the log's clock check; "
        "the log of record of a sponsor manifest is the log whose proof its bundle carries (RS6)."
    )
    f = File(SPEC, "manifests", notes)
    for name, b in wd.named.items():
        env = cbor.decode(b.envelope)
        if env[m.TYPE] != "agent-sponsor":
            continue
        now = VERIFY_AT.get(name, NOW)
        ctx = wd.w.context(now=now)
        inputs = {"bundle": bundle_json(b), "view": jsonable(env), "now": now}
        try:
            m.verify_bundle(ctx, b)
        except m.Rejection as e:
            exp = EXPECTED.get(name)
            if exp is None or e.step != 10 or e.rule != exp:
                raise AssertionError(
                    f"{name}: got step {e.step} rule {e.rule} ({e.reason}), expected {exp}"
                ) from e
            f.add(
                name,
                f"{name}: rejected by {e.rule}",
                S_RULES,
                inputs,
                rejection={"step": 10, "rule": e.rule, "reason": e.reason},
            )
            continue
        if name in EXPECTED:
            raise AssertionError(f"{name} was accepted; expected {EXPECTED[name]}")
        f.add(
            name, f"{name}: verifies", S_RULES, inputs, {"accept": True, "version": env[m.VERSION]}
        )
    b = wd.named["as-ok-with-proof"]
    env = cbor.decode(b.envelope)
    proof = env[m.BODY][sp.SPONSOR_PROOF]
    for name, log_now in (
        ("as-ok-proof-at-log", ISSUED + 1800),
        ("as-bad-proof-issued-skew", LOG_SKEW_T),
    ):
        reason = sp.log_submission_check(proof, env[m.ISSUED], log_now, 1)
        inputs = {
            "manifest": "as-ok-with-proof",
            "cid": hexify(b.cid),
            "issued": env[m.ISSUED],
            "log_clock_T": log_now,
            "V": 1,
        }
        if reason is None:
            f.add(name, "At the log: issued within an hour of T", S_RULES, inputs, {"accept": True})
        else:
            f.add(
                name,
                "At the log: issued two hours from T",
                S_RULES,
                inputs,
                rejection={"step": None, "check": "log-submission", "rule": "P5", "reason": reason},
            )
    # RS6: the log of record is the log whose proof the bundle carries; a context accepts the
    # manifest when that log is any entry of its logs
    record = sp.log_of_record(b)
    assert record == wd.w.log_authority
    other = fixtures.fixed_bytes("another log keyset cid", 33)
    for name, desc, logs, accept in (
        (
            "as-ok-log-of-record-listed-second",
            "The manifest's log of record (the log its proof names) is the context's second "
            "listed log: accepted; the verifier in force was read at the manifest's position "
            "in that log",
            [other, record],
            True,
        ),
        (
            "as-bad-log-of-record-not-listed",
            "The context lists no log holding the manifest: a phone in that context does not "
            "accept it",
            [other],
            False,
        ),
    ):
        assert sp.context_accepts_log(logs, b) == accept, name
        inputs = {
            "manifest": "as-ok-with-proof",
            "cid": hexify(b.cid),
            "log_of_record": hexify(record),
            "context_logs": [hexify(x) for x in logs],
        }
        if accept:
            f.add(name, desc, S_RULES, inputs, {"accept": True, "verifier_read_in": hexify(record)})
        else:
            f.add(
                name,
                desc,
                S_RULES,
                inputs,
                rejection={
                    "step": None,
                    "check": "context-logs",
                    "rule": "AS-8",
                    "reason": "the manifest's log of record is not one of the context's logs",
                },
            )
    return f


def world_file(wd: World) -> File:
    f = File(
        SPEC,
        "world",
        "Keysets, two custom-profile verifiers (agent and person class) and the report blob the sponsor cases resolve against.",
    )
    f.add(
        "world",
        "Bundles appended after the base manifest world",
        S_RULES,
        {
            "base": "manifest/world.json",
            "keys": {n: hexify(k.seed) for n, k in wd.keys.items()},
            "agent_keys": {
                n: hexify(key_from_label(n).seed)
                for n in [
                    "agent-key",
                    "agent-key-enclave",
                    "agent-key-public",
                    "agent-key-reader",
                    "agent-key-renew",
                    "agent-key-retire",
                    "agent-key-proof",
                    "agent-key-swap",
                    "agent-key-swap-2",
                ]
            },
            "blobs": {hexify(k): hexify(v) for k, v in wd.w.blobs.items()},
        },
        {
            "checkpoint": wd.w.note().text(),
            "bundles": [
                {"name": n, **bundle_json(b), "view": jsonable(cbor.decode(b.envelope))}
                for n, b in wd.named.items()
            ],
        },
    )
    return f


def attestation_file(wd: World) -> File:
    f = File(
        SPEC,
        "attestation",
        "AS-2b against the reference's synthetic report: CBOR {0: platform, 1: measurement, 2: report_data}, "
        'report_data = SHA-256("hum/attest/1" || agentKey || sponsor authority CID). Decides the Add commit, never manifest validity.',
    )
    body = wd.enclave_body
    auth = wd.auth
    f.add(
        "as-commit-ok-enclave",
        "The report binds the enclave manifest's agentKey and measurement",
        S_ATTEST,
        {
            "report": hexify(wd.report),
            "agentKey": hexify(body[sp.AGENT_KEY]),
            "authority": hexify(auth),
            "measurement": hexify(body[sp.ATTESTATION][sp.AT_MEASUREMENT]),
        },
        {
            "report_data": hexify(sp.report_data(body[sp.AGENT_KEY], auth)),
            "problems": sp.check_report(wd.report, body, auth),
            "accept_commit": True,
        },
    )
    other_img = sp.synthetic_report(
        0, fixtures.fixed_bytes("other-measurement", 48), sp.report_data(body[sp.AGENT_KEY], auth)
    )
    f.add(
        "as-commit-bad-measurement",
        "Report for another image",
        S_ATTEST,
        {"report": hexify(other_img), "authority": hexify(auth)},
        rejection={
            "step": None,
            "check": "add-commit",
            "rule": "AS-2b",
            "problems": sp.check_report(other_img, body, auth),
        },
    )
    other_key = sp.synthetic_report(
        0,
        body[sp.ATTESTATION][sp.AT_MEASUREMENT],
        sp.report_data(key_from_label("agent-key").public, auth),
    )
    f.add(
        "as-commit-bad-report-key-binding",
        "Report data bound to another key",
        S_ATTEST,
        {"report": hexify(other_key), "authority": hexify(auth)},
        rejection={
            "step": None,
            "check": "add-commit",
            "rule": "AS-2b",
            "problems": sp.check_report(other_key, body, auth),
        },
    )
    return f


def generate() -> list[File]:
    wd = World()
    return [world_file(wd), manifests_file(wd), attestation_file(wd)]
