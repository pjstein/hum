"""Vectors for docs/specs/verifier.md: one valid manifest per profile, a three-version district
lineage, disclosure summaries, one invalid case per rule 1-29 and 31 and lettered sub-rule,
the log's rule-30 clock check, and the message layout of an epoch.

Rule 31 allows one ``verifier`` lineage per authority, so every lineage here has its own
authority (a one-key service keyset); ``World.authority`` is the district lineage's.

Blob refs (``code``, ``build``, ``profile``, ``dataset.<name>``) are public blobs. Until
``manifest.py`` step 9 treats a CID held in ``ctx.blobs`` as a blob, ``blob_context`` below
marks them pre-verified so the rest of the eleven steps run as the spec says.
"""

from __future__ import annotations

import copy
from typing import Any

from .. import cbor, cose, fixtures
from .. import manifest as m
from ..bodies import verifier as vf
from ..bodies import verifier_runtime as vr
from ..cid import cid as compute_cid
from ..keys import SigningKey, key_from_label
from . import File, hexify, jsonable
from .manifest_vectors import bundle_json

SPEC = "verifier"
S_RULES = "Validation rules"
S_SUMMARY = "Disclosure summary"
TOOLCHAIN = vf.TOOLCHAIN
S_LOG = "Validation rules (rule 30, at the log)"
S_LAYOUT = "Attribute"


def blob_context(fx: fixtures.Fixture) -> m.VerificationContext:
    """A fresh context in which every blob the world holds counts as a resolved reference."""
    ctx = fx.world.context(now=fixtures.NOW)
    for cid, data in ctx.blobs.items():
        # Shim until manifest.py step 9 knows blobs: resolvable and already verified.
        ctx.resolver[cid] = m.Bundle(data, None, cid, None)
        ctx.verified[cid] = {}
    return ctx


# ---------------------------------------------------------------- the world


class World:
    def __init__(self) -> None:
        self.fx = fixtures.build()
        self.w = self.fx.world
        self.keys: dict[str, SigningKey] = {
            n: key_from_label(f"verifier-{n}") for n in ("vs", "vr")
        }
        ks = fixtures.service_keyset("vs", "vr", self.keys)
        self.authority_bundle = self.w.append(ks, [(b"vr", self.keys["vr"])])
        self.authority = self.authority_bundle.cid
        # authority CID -> the key that signs under it (rule 31: one lineage per authority)
        self.signers: dict[bytes, SigningKey] = {self.authority: self.keys["vs"]}
        self.authorities: dict[str, bytes] = {"district": self.authority}
        self.named: dict[str, m.Bundle] = {}
        self.blobs: dict[str, bytes] = {}
        for profile in vf.NAMED_PROFILES + ("custom",):
            module = b"\x00asm\x0d\x00\x01\x00" + fixtures.fixed_bytes(f"module-{profile}", 64)
            self.blobs[f"code-{profile}"] = self.w.put_blob(module)
            recipe = vr.build_recipe(
                fixtures.fixed_bytes(f"source-{profile}"),
                "https://example.invalid/hum-verifiers",
                "ghcr.io/hum/build@sha256:" + fixtures.fixed_bytes(f"image-{profile}").hex(),
                [
                    "cargo",
                    "build",
                    "--release",
                    "--target",
                    "wasm32-wasip2",
                    "-p",
                    f"verifier-{profile}",
                ],
                f"target/wasm32-wasip2/release/verifier_{profile}.wasm",
                TOOLCHAIN,
                "en",
                [(100, "That code has already been used.")] if profile == "invite" else [],
            )
            self.blobs[f"build-{profile}"] = self.w.put_blob(recipe)
        self.wards_records = [
            (b"ward-1", [("name", "Ward 1"), ("boundary", "north of Mill St")]),
            (b"ward-2", [("name", "Ward 2"), ("boundary", "between Mill St and the river")]),
            (b"ward-3", [("name", "Ward 3"), ("boundary", "south of the river")]),
        ]
        self.wards_salt = fixtures.fixed_bytes("wards-salt")
        self.blobs["dataset-wards"] = self.w.put_blob(
            vr.dataset_blob(self.wards_salt, self.wards_records)
        )
        self.wards_root = vr.dataset_root(self.wards_salt, self.wards_records)

    def source(self, profile: str) -> bytes:
        return fixtures.fixed_bytes(f"source-{profile}")

    def refs(self, profile: str, datasets: list[str] = ()) -> dict[str, bytes]:
        code_name = profile if profile in vf.NAMED_PROFILES else "custom"
        out = {"code": self.blobs[f"code-{code_name}"], "build": self.blobs[f"build-{code_name}"]}
        if profile in vf.NAMED_PROFILES:
            out["profile"] = self.blobs[f"code-{code_name}"]
        for d in datasets:
            out[f"dataset.{d}"] = self.blobs[f"dataset-{d}"]
        return out

    def new_authority(self, label: str) -> bytes:
        """A fresh authority (one-key service keyset) for one more verifier lineage."""
        if label in self.authorities:
            return self.authorities[label]
        keys = {n: key_from_label(f"verifier-{label}-{n}") for n in ("vs", "vr")}
        ks = fixtures.service_keyset("vs", "vr", keys)
        cid = self.w.append(ks, [(b"vr", keys["vr"])]).cid
        self.signers[cid] = keys["vs"]
        self.authorities[label] = cid
        return cid

    def append(self, name: str, env: dict) -> m.Bundle:
        b = self.w.append(env, [(b"vs", self.signers[env[m.AUTHORITY]])])
        self.named[name] = b
        return b

    def envelope(
        self,
        body: dict,
        refs: dict,
        *,
        version=1,
        lineage=None,
        prev=None,
        issued_offset=0,
        authority: bytes | None = None,
    ) -> dict:
        return m.envelope(
            "verifier",
            body,
            authority=authority if authority is not None else self.authority,
            version=version,
            lineage=lineage,
            prev=prev,
            issued=fixtures.ISSUED + issued_offset,
            refs=refs,
        )


def issuer(label: str, since: int = 1, from_epoch: int = 0) -> dict:
    return vf.issuer_key(
        fixtures.fixed_bytes(f"kid-{label}", 8),
        fixtures.fixed_bytes(f"bbs-{label}", 96),
        from_epoch,
        since,
    )


def host(label: str) -> dict:
    return vf.host_key(
        fixtures.fixed_bytes(f"hkid-{label}", 8), fixtures.fixed_bytes(f"hpke-{label}", 32)
    )


# ---------------------------------------------------------------- profile bodies


def invite_link(w: World) -> dict:
    return vf.body(
        name="Millbrook tenants invite",
        operator="Millbrook Tenants Union organizers",
        profile="invite",
        issuer_keys=[issuer("invite")],
        host_keys=[host("invite")],
        attributes=[vf.attribute("invite", "bool", "gate", "Invited")],
        evidence_=[vf.evidence("link", "link", "none", "To check you opened the invite link")],
        dedup_=[],
        code_=vf.code(w.source("invite"), TOOLCHAIN),
        assurance=0,
        validity=7_776_000,
    )


def invite_codes(w: World) -> dict:
    b = invite_link(w)
    b[vf.NAME] = "Millbrook one-time codes"
    b[vf.EVIDENCE] = [
        vf.evidence("code", "code", "text", "A one-time code from an organizer"),
        vf.evidence(
            "device", "device", "device", "To stop one phone redeeming many codes", required=False
        ),
    ]
    b[vf.DEDUP] = [
        vf.dedup("evidence", "code", "One card per code"),
        vf.dedup("device", "device", "One card per device"),
    ]
    b[vf.DATASETS] = [
        vf.dataset(
            "codes",
            "private",
            fixtures.fixed_bytes("codes-root"),
            250,
            "Salted hashes of one-time codes",
        )
    ]
    b[vf.ATTRIBUTES].append(
        vf.attribute("cohort", "enum", "breakdown", "Cohort", vf.enum_values(["Spring", "Fall"]))
    )
    return b


def approved_list(w: World) -> dict:
    return vf.body(
        name="Millbrook approved list",
        operator="Millbrook Tenants Union organizers",
        profile="approved-list",
        issuer_keys=[issuer("approved")],
        host_keys=[host("approved")],
        attributes=[
            vf.attribute("approved", "bool", "gate", "Approved"),
            vf.attribute("role", "enum", "gate", "Role", vf.enum_values(["Tenant", "Steward"])),
        ],
        evidence_=[
            vf.evidence("roster", "roster", "text", "A roster entry an organizer added for you"),
            vf.evidence("email", "email", "text", "To match you to the roster entry"),
        ],
        dedup_=[vf.dedup("evidence", "roster", "One card per roster row")],
        code_=vf.code(w.source("approved-list"), TOOLCHAIN),
        assurance=1,
        validity=15_552_000,
        datasets=[
            vf.dataset(
                "roster",
                "private",
                fixtures.fixed_bytes("roster-root"),
                412,
                "Approved tenants, 2026-09",
            )
        ],
    )


def district(w: World, version: int = 1) -> dict:
    wards = ["Ward 1", "Ward 2", "Ward 3"] + (["Ward 4"] if version >= 2 else [])
    keys = [issuer("district-1")]
    retired: list[bytes] = []
    if version == 2:
        keys = [issuer("district-1"), issuer("district-2", since=2, from_epoch=4)]
    if version == 3:
        keys = [issuer("district-2", since=2, from_epoch=4)]
        retired = [fixtures.fixed_bytes("kid-district-1", 8)]
    return vf.body(
        name="Millbrook district verifier",
        operator="Hum reference operator",
        profile="district",
        issuer_keys=keys,
        host_keys=[host("district")],
        attributes=[
            vf.attribute("ward", "enum", "breakdown", "Ward", vf.enum_values(wards)),
            vf.attribute(
                "area",
                "enum",
                "breakdown",
                "Area",
                vf.enum_values(["Millbrook", "Outside Millbrook"]),
            ),
        ],
        evidence_=[
            vf.evidence("match", "voter-file", "text", "To find your ward in the county voter file")
        ],
        dedup_=[vf.dedup("evidence", "match", "One card per voter-file record")],
        code_=vf.code(w.source("district"), TOOLCHAIN),
        assurance=2,
        validity=15_552_000,
        datasets=[
            vf.dataset(
                "voters",
                "private",
                fixtures.fixed_bytes("voters-root"),
                48210,
                "County voter file, 2026-09 extract",
            ),
            vf.dataset("wards", "public", w.wards_root, 3, "Ward boundaries, 2024 redistricting"),
        ],
        retired_kids=retired if version == 3 else None,
    )


def age_band(w: World) -> dict:
    return vf.body(
        name="Age band verifier",
        operator="Hum reference operator",
        profile="age-band",
        issuer_keys=[issuer("age")],
        host_keys=[host("age")],
        attributes=[vf.attribute("age-band", "band", "breakdown", "Age band", vf.band_values())],
        evidence_=[
            vf.evidence("dob", "date-of-birth", "date", "To place you in an age band"),
            vf.evidence(
                "doc", "document", "image", "To check the date of birth against a document"
            ),
        ],
        dedup_=[vf.dedup("evidence", "doc", "One card per document number")],
        code_=vf.code(w.source("age-band"), TOOLCHAIN),
        assurance=3,
        validity=31_536_000,
    )


def uniqueness(w: World) -> dict:
    return vf.body(
        name="Uniqueness verifier",
        operator="Hum reference operator",
        profile="uniqueness",
        issuer_keys=[issuer("unique")],
        host_keys=[host("unique")],
        attributes=[vf.attribute("unique", "bool", "gate", "Unique")],
        evidence_=[
            vf.evidence("device", "device", "device", "A one-time attestation from this phone"),
            vf.evidence("doc", "document", "image", "A photo of an identity document"),
            vf.evidence(
                "selfie", "selfie", "image", "A photo of your face, matched to your document"
            ),
        ],
        dedup_=[
            vf.dedup("evidence", "doc", "One card per document"),
            vf.dedup("device", "device", "One card per device"),
        ],
        code_=vf.code(w.source("uniqueness"), TOOLCHAIN),
        assurance=3,
        validity=31_536_000,
    )


def custom(w: World) -> dict:
    return vf.body(
        name="Union membership verifier",
        operator="Local 1234",
        profile="custom",
        issuer_keys=[issuer("custom")],
        host_keys=[host("custom")],
        attributes=[
            vf.attribute("member", "bool", "gate", "Member"),
            vf.attribute("unit", "uint", "gate", "Unit", max_=5000),
        ],
        evidence_=[
            vf.evidence(
                "card",
                "other",
                "text",
                "Something else: your union card number",
                kept=86_400,
                stored_as="hash",
            ),
            vf.evidence(
                "ref",
                "credential",
                "credential",
                "A resident card from the district verifier",
                accepts=[
                    {
                        vf.ACC_AUTHORITY: compute_cid(b"district authority placeholder"),
                        vf.ACC_ATTRIBUTES: ["ward"],
                    }
                ],
            ),
        ],
        dedup_=[
            vf.dedup("evidence", "card", "One card per union card"),
            vf.dedup("credential", "ref", "One card per resident card"),
        ],
        code_=vf.code(w.source("custom"), TOOLCHAIN),
        assurance=1,
        validity=8_640_000,
        session_cap=3,
    )


def agent_class(w: World) -> dict:
    return vf.body(
        name="Agent sponsor verifier",
        operator="Hum reference operator",
        profile="custom",
        class_="agent",
        issuer_keys=[issuer("agent")],
        host_keys=[host("agent")],
        attributes=[vf.attribute("agent-sponsor", "bool", "gate", "Sponsored agent")],
        evidence_=[
            vf.evidence(
                "org", "other", "text", "Something else: the sponsoring organization's registration"
            )
        ],
        dedup_=[],
        code_=vf.code(w.source("custom"), TOOLCHAIN),
        assurance=1,
        validity=7_776_000,
    )


PROFILE_BUILDERS = {
    "invite-link": (invite_link, "invite", ()),
    "invite-codes": (invite_codes, "invite", ()),
    "approved-list": (approved_list, "approved-list", ()),
    "age-band": (age_band, "age-band", ()),
    "uniqueness": (uniqueness, "uniqueness", ()),
    "custom": (custom, "custom", ()),
    "agent": (agent_class, "custom", ()),
}


# ---------------------------------------------------------------- generation


def build() -> tuple[World, dict[str, Any]]:
    w = World()
    valid: dict[str, m.Bundle] = {}
    for name, (fn, profile, ds) in PROFILE_BUILDERS.items():
        valid[name] = w.append(
            f"valid-{name}",
            w.envelope(fn(w), w.refs(profile, ds), authority=w.new_authority(name)),
        )
    d1 = w.append("valid-district-v1", w.envelope(district(w, 1), w.refs("district", ["wards"])))
    d2 = w.append(
        "valid-district-v2",
        w.envelope(
            district(w, 2),
            w.refs("district", ["wards"]),
            version=2,
            lineage=d1.cid,
            prev=d1.cid,
            issued_offset=60,
        ),
    )
    d3 = w.append(
        "valid-district-v3",
        w.envelope(
            district(w, 3),
            w.refs("district", ["wards"]),
            version=3,
            lineage=d1.cid,
            prev=d2.cid,
            issued_offset=120,
        ),
    )
    valid["district-v1"], valid["district-v2"], valid["district-v3"] = d1, d2, d3

    # step-10 lineages: a fresh v1 (district, distinct name) plus a bad later version, logged
    bad10: list[tuple[str, str, m.Bundle]] = []

    def lineage(name: str, rule: str, mutate, from_version: int = 1, mid_version: int = 2):
        base = district(w, 1)
        base[vf.NAME] = f"District lineage for {name}"
        auth = w.new_authority(f"lineage-{name}")
        v1 = w.append(
            f"lineage-{name}-v1",
            w.envelope(base, w.refs("district", ["wards"]), authority=auth),
        )
        prev = v1
        if from_version == 2:
            v2body = district(w, mid_version)
            v2body[vf.NAME] = base[vf.NAME]
            prev = w.append(
                f"lineage-{name}-v2",
                w.envelope(
                    v2body,
                    w.refs("district", ["wards"]),
                    version=2,
                    lineage=v1.cid,
                    prev=v1.cid,
                    issued_offset=60,
                    authority=auth,
                ),
            )
        nxt = district(w, from_version + 1 if from_version == 2 else 2)
        nxt[vf.NAME] = base[vf.NAME]
        mutate(nxt)
        env = w.envelope(
            nxt,
            w.refs("district", ["wards"]),
            version=from_version + 1,
            lineage=v1.cid,
            prev=prev.cid,
            issued_offset=60 * (from_version + 1),
            authority=auth,
        )
        bad10.append((name, rule, w.append(f"lineage-{name}-bad", env)))

    def custom_lineage(name: str, rule: str, mutate):
        base = custom(w)
        base[vf.NAME] = f"Custom lineage for {name}"
        base[vf.ATTRIBUTES].append(
            vf.attribute(
                "tier", "enum", "gate", "Tier", vf.enum_values(["A", "B"]), status="deprecated"
            )
        )
        auth = w.new_authority(f"lineage-{name}")
        v1 = w.append(f"lineage-{name}-v1", w.envelope(base, w.refs("custom"), authority=auth))
        nxt = copy.deepcopy(base)
        mutate(nxt)
        env = w.envelope(
            nxt,
            w.refs("custom"),
            version=2,
            lineage=v1.cid,
            prev=v1.cid,
            issued_offset=60,
            authority=auth,
        )
        bad10.append((name, rule, w.append(f"lineage-{name}-bad", env)))

    def change_profile(b):
        b[vf.PROFILE] = "invite"
        b[vf.ASSURANCE] = 0
        b[vf.ATTRIBUTES] = [vf.attribute("invite", "bool", "gate", "Invited")]
        b[vf.EVIDENCE] = [
            vf.evidence("link", "link", "none", "To check you opened the invite link")
        ]
        b[vf.DEDUP] = []

    def change_profile_env(b):
        change_profile(b)

    # rule 21 needs the profile ref too; build it by hand on a custom base
    base21 = custom(w)
    base21[vf.NAME] = "Custom lineage for 21-profile"
    auth21 = w.new_authority("lineage-21-profile")
    v1_21 = w.append(
        "lineage-21-profile-v1", w.envelope(base21, w.refs("custom"), authority=auth21)
    )
    bad21 = copy.deepcopy(base21)
    change_profile(bad21)
    bad10.append(
        (
            "21-profile",
            "21",
            w.append(
                "lineage-21-profile-bad",
                w.envelope(
                    bad21,
                    w.refs("invite"),
                    version=2,
                    lineage=v1_21.cid,
                    prev=v1_21.cid,
                    issued_offset=60,
                    authority=auth21,
                ),
            ),
        )
    )

    custom_lineage("22-attribute-removed", "22", lambda b: b[vf.ATTRIBUTES].pop(1))
    lineage(
        "22-value-inserted",
        "22",
        lambda b: b[vf.ATTRIBUTES][0][vf.AT_VALUES].insert(
            1, {vf.ENUM_V: 9, vf.ENUM_LABEL: "Ward 9"}
        ),
    )

    def type_changed(b):
        b[vf.ATTRIBUTES][1] = vf.attribute("unit", "bool", "gate", "Unit")

    custom_lineage("22-type-changed", "22", type_changed)
    custom_lineage(
        "23-gate-to-breakdown",
        "23",
        lambda b: b[vf.ATTRIBUTES][0].__setitem__(vf.AT_EXPOSURE, "breakdown"),
    )
    custom_lineage(
        "23-reactivated", "23", lambda b: b[vf.ATTRIBUTES][2].__setitem__(vf.AT_STATUS, "active")
    )

    lineage(
        "24-dropped-not-retired",
        "24",
        lambda b: b.__setitem__(vf.ISSUER_KEYS, [issuer("district-2", since=2, from_epoch=4)]),
    )

    def reuse_kid(b):
        b[vf.ISSUER_KEYS] = [
            issuer("district-2", since=2, from_epoch=4),
            issuer("district-1", since=3, from_epoch=8),
        ]
        b.pop(vf.RETIRED_KIDS, None)

    lineage("24-reused-kid", "24", reuse_kid, from_version=2, mid_version=3)
    lineage(
        "25-key-bytes",
        "25",
        lambda b: b[vf.ISSUER_KEYS][0].__setitem__(
            vf.IK_KEY, fixtures.fixed_bytes("bbs-other", 96)
        ),
    )

    lineage(
        "26-from-epoch-changed",
        "26",
        lambda b: b[vf.ISSUER_KEYS][0].__setitem__(vf.IK_FROM_EPOCH, 1),
    )

    def new_key_earlier(b):
        b[vf.ISSUER_KEYS][0][vf.IK_FROM_EPOCH] = 2
        b[vf.ISSUER_KEYS][1][vf.IK_FROM_EPOCH] = 0

    lineage("26-new-key-earlier-epoch", "26", new_key_earlier)
    custom_lineage("21-validity", "21", lambda b: b.__setitem__(vf.VALIDITY, 17_280_000))

    lineage("27-since-changed", "27", lambda b: b[vf.ISSUER_KEYS][0].__setitem__(vf.IK_SINCE, 2))
    lineage("28-new-key-since-1", "28", lambda b: b[vf.ISSUER_KEYS][1].__setitem__(vf.IK_SINCE, 1))

    def from_epoch_changed(b):
        for a in b[vf.ATTRIBUTES]:
            a[vf.AT_FROM_EPOCH] = 1  # still non-decreasing, so step 4 passes

    lineage("29-from-epoch-changed", "29", from_epoch_changed)

    # rule 30 at the log: the district grid (V = 6) is outside handover at the fixture clock,
    # the custom grid (validity 100 days, V = 3) is inside it
    e_district, hand_d = vf.epoch_now(fixtures.NOW, district(w, 1)[vf.VALIDITY])
    e_custom, hand_c = vf.epoch_now(fixtures.NOW, custom(w)[vf.VALIDITY])
    assert not hand_d and hand_c
    log30: list[tuple[str, str, dict, dict | None, int]] = []  # (suffix, desc, env, prev, now)

    def appended(b, from_epoch):
        b[vf.ATTRIBUTES].append(
            vf.attribute(
                "tier", "enum", "gate", "Tier", vf.enum_values(["A", "B"]), from_epoch=from_epoch
            )
        )

    def district_v2(name: str, from_epoch: int, accept: bool):
        base = district(w, 1)
        base[vf.NAME] = f"District lineage for {name}"
        auth = w.new_authority(f"lineage-{name}")
        v1_env = w.envelope(base, w.refs("district", ["wards"]), authority=auth)
        v1 = w.append(f"lineage-{name}-v1", v1_env)
        nxt = district(w, 1)
        nxt[vf.NAME] = base[vf.NAME]
        appended(nxt, from_epoch)
        env = w.envelope(
            nxt,
            w.refs("district", ["wards"]),
            version=2,
            lineage=v1.cid,
            prev=v1.cid,
            issued_offset=60,
            authority=auth,
        )
        if accept:
            valid[name] = w.append(f"lineage-{name}-v2", env)
        return env, v1_env

    def custom_v2(name: str, from_epoch: int, accept: bool):
        base = custom(w)
        base[vf.NAME] = f"Custom lineage for {name}"
        auth = w.new_authority(f"lineage-{name}")
        v1_env = w.envelope(base, w.refs("custom"), authority=auth)
        v1 = w.append(f"lineage-{name}-v1", v1_env)
        nxt = copy.deepcopy(base)
        appended(nxt, from_epoch)
        env = w.envelope(
            nxt,
            w.refs("custom"),
            version=2,
            lineage=v1.cid,
            prev=v1.cid,
            issued_offset=60,
            authority=auth,
        )
        if accept:
            valid[name] = w.append(f"lineage-{name}-v2", env)
        return env, v1_env

    env, prev = district_v2("30-new-attr-e-now", e_district, False)
    log30.append(
        (
            "verifier-invalid-30-new-attr-e-now",
            f"version 2 appends an attribute with fromEpoch = E_now ({e_district}) outside handover",
            env,
            prev,
            fixtures.NOW,
        )
    )
    env, prev = district_v2("30-new-attr-next-epoch", e_district + 1, True)
    log30.append(
        (
            "verifier-valid-30-new-attr-next-epoch",
            f"version 2 appends an attribute with fromEpoch = E_now + 1 ({e_district + 1}) "
            "outside handover",
            env,
            prev,
            fixtures.NOW,
        )
    )
    env, prev = custom_v2("30-handover-e-now-plus-1", e_custom + 1, False)
    log30.append(
        (
            "verifier-invalid-30-handover-e-now-plus-1",
            f"during handover, version 2 appends an attribute with fromEpoch = E_now + 1 "
            f"({e_custom + 1})",
            env,
            prev,
            fixtures.NOW,
        )
    )
    env, prev = custom_v2("30-handover-e-now-plus-2", e_custom + 2, True)
    log30.append(
        (
            "verifier-valid-30-handover-e-now-plus-2",
            f"during handover, version 2 appends an attribute with fromEpoch = E_now + 2 "
            f"({e_custom + 2})",
            env,
            prev,
            fixtures.NOW,
        )
    )
    env, prev = district_v2("30-ceiling", e_district + 3, False)
    log30.append(
        (
            "verifier-invalid-30-ceiling",
            f"version 2 appends an attribute with fromEpoch = E_now + 3 ({e_district + 3})",
            env,
            prev,
            fixtures.NOW,
        )
    )
    far = district(w, 1)
    far[vf.NAME] = "District lineage for 30-v1-500"
    appended(far, 500)
    log30.append(
        (
            "verifier-invalid-30-v1-500",
            "version 1 with an attribute whose fromEpoch is 500",
            w.envelope(far, w.refs("district", ["wards"]), authority=w.new_authority("30-v1-500")),
            None,
            fixtures.NOW,
        )
    )

    # rule 31: a second version 1 under the district authority, logged after the first
    dup = district(w, 1)
    dup[vf.NAME] = "Millbrook district verifier, again"
    dup_bundle = w.append("31-second-lineage", w.envelope(dup, w.refs("district", ["wards"])))

    w.w.finalize()
    return w, {"valid": valid, "bad10": bad10, "log30": log30, "dup31": dup_bundle}


def _resign(w: World, env: dict, proof_from: m.Bundle) -> m.Bundle:
    data = cbor.encode(env)
    c = compute_cid(data)
    sig = cose.encode_cose_sign([cose.sign_cid(w.keys["vs"], b"vs", c)])
    return m.Bundle(data, sig, c, copy.deepcopy(proof_from.proof))


def _run(
    f: File,
    w: World,
    suffix: str,
    desc: str,
    bundle: m.Bundle,
    *,
    step: int | None = None,
    rule: str | None = None,
):
    ctx = blob_context(w.fx)
    inputs = {"bundle": bundle_json(bundle), "view": jsonable(cbor.decode(bundle.envelope))}
    try:
        env = m.verify_bundle(ctx, bundle)
    except m.Rejection as e:
        if step is None or e.step != step or (rule is not None and e.rule != rule):
            raise AssertionError(
                f"{suffix}: expected step {step} rule {rule}, got {e} (rule {e.rule})"
            ) from e
        f.add(
            suffix,
            desc,
            S_RULES,
            inputs,
            rejection={"step": e.step, "rule": e.rule, "reason": e.reason},
        )
        return
    if step is not None:
        raise AssertionError(f"{suffix}: expected rejection at step {step}, accepted")
    f.add(
        suffix,
        desc,
        S_RULES,
        inputs,
        {"accept": True, "profile": env[m.BODY][vf.PROFILE], "version": env[m.VERSION]},
    )


def _step4_cases(w: World) -> list[tuple[str, str, str, Any, str]]:
    """(suffix, rule, description, mutate(env), base name)."""
    B = vf
    c: list = []

    def add(rule, name, desc, fn, base="valid-district-v1"):
        c.append((f"verifier-invalid-{rule}-{name}", rule, desc, fn, base))

    body = lambda e: e[m.BODY]  # noqa: E731
    add("1", "profile", "profile 'other'", lambda e: body(e).__setitem__(B.PROFILE, "other"))
    add("1", "class", "class 'robot'", lambda e: body(e).__setitem__(B.CLASS, "robot"))
    add("1", "lang", "lang 'e' fails the pattern", lambda e: body(e).__setitem__(B.LANG, "e"))
    add("2", "name-long", "name of 65 bytes", lambda e: body(e).__setitem__(B.NAME, "n" * 65))
    add(
        "2",
        "control-char",
        "operator with a control character",
        lambda e: body(e).__setitem__(B.OPERATOR, "Hum\x01"),
    )
    add(
        "2",
        "too-many-hosts",
        "nine host keys",
        lambda e: body(e).__setitem__(B.HOST_KEYS, [host(f"h{i}") for i in range(9)]),
    )
    add(
        "3",
        "same-from-epoch",
        "two issuer keys with the same fromEpoch",
        lambda e: body(e).__setitem__(B.ISSUER_KEYS, [issuer("a"), issuer("b")]),
    )
    add(
        "3",
        "from-epoch-type",
        "fromEpoch that is not a uint",
        lambda e: body(e)[B.ISSUER_KEYS][0].__setitem__(B.IK_FROM_EPOCH, "0"),
    )
    add(
        "3",
        "unknown-suite",
        "unknown credential suite",
        lambda e: body(e)[B.ISSUER_KEYS][0].__setitem__(B.IK_ALG, "rsa"),
    )
    add(
        "3",
        "key-length",
        "issuer key of 95 bytes",
        lambda e: body(e)[B.ISSUER_KEYS][0].__setitem__(B.IK_KEY, bytes(95)),
    )
    add(
        "3", "since-zero", "since 0", lambda e: body(e)[B.ISSUER_KEYS][0].__setitem__(B.IK_SINCE, 0)
    )
    add(
        "3",
        "since-future",
        "since 2 in version 1",
        lambda e: body(e)[B.ISSUER_KEYS][0].__setitem__(B.IK_SINCE, 2),
    )
    add(
        "4",
        "duplicate-kid",
        "two keys with one kid",
        lambda e: body(e).__setitem__(B.ISSUER_KEYS, [issuer("a"), issuer("a", from_epoch=3)]),
    )
    add(
        "4",
        "kid-retired",
        "kid listed in retiredKids",
        lambda e: body(e).__setitem__(B.RETIRED_KIDS, [fixtures.fixed_bytes("kid-district-1", 8)]),
    )
    add("5", "no-host", "no host keys", lambda e: body(e).__setitem__(B.HOST_KEYS, []))
    add(
        "5",
        "host-length",
        "host key of 31 bytes",
        lambda e: body(e)[B.HOST_KEYS][0].__setitem__(B.HK_KEY, bytes(31)),
    )
    add(
        "6",
        "name-pattern",
        "attribute name 'Ward'",
        lambda e: body(e)[B.ATTRIBUTES][0].__setitem__(B.AT_NAME, "Ward"),
    )
    add(
        "6",
        "duplicate-name",
        "two attributes named ward",
        lambda e: body(e)[B.ATTRIBUTES][1].__setitem__(B.AT_NAME, "ward"),
    )
    add(
        "7a",
        "one-value",
        "enum with one value",
        lambda e: body(e)[B.ATTRIBUTES][1].__setitem__(B.AT_VALUES, vf.enum_values(["Only"])),
    )
    add(
        "7b",
        "duplicate-v",
        "duplicate enum v",
        lambda e: body(e)[B.ATTRIBUTES][1].__setitem__(
            B.AT_VALUES, [{0: 1, 1: "A"}, {0: 1, 1: "B"}]
        ),
    )
    add(
        "7c",
        "band-overlap",
        "overlapping bands",
        lambda e: body(e)[B.ATTRIBUTES][0].__setitem__(
            B.AT_VALUES, [{0: 18, 1: 30, 2: "a"}, {0: 25, 1: 40, 2: "b"}]
        ),
        base="valid-age-band",
    )
    add(
        "8",
        "uint-no-max",
        "uint attribute without max",
        lambda e: body(e)[B.ATTRIBUTES][1].pop(B.AT_MAX),
        base="valid-custom",
    )
    add(
        "8",
        "uint-breakdown",
        "uint attribute with breakdown exposure",
        lambda e: body(e)[B.ATTRIBUTES][1].__setitem__(B.AT_EXPOSURE, "breakdown"),
        base="valid-custom",
    )
    add(
        "8",
        "enum-max",
        "enum attribute with max",
        lambda e: body(e)[B.ATTRIBUTES][0].__setitem__(B.AT_MAX, 9),
    )
    add(
        "9",
        "65-values",
        "breakdown enum with 65 values",
        lambda e: body(e)[B.ATTRIBUTES][0].__setitem__(
            B.AT_VALUES, vf.enum_values([f"W{i}" for i in range(65)])
        ),
    )
    add(
        "29",
        "no-from-epoch",
        "attribute without fromEpoch",
        lambda e: body(e)[B.ATTRIBUTES][0].pop(B.AT_FROM_EPOCH),
    )
    add(
        "29",
        "decreasing",
        "fromEpoch 1 then 0 in array order",
        lambda e: body(e)[B.ATTRIBUTES][0].__setitem__(B.AT_FROM_EPOCH, 1),
    )
    add(
        "10",
        "duplicate-evidence",
        "two evidence items named match",
        lambda e: body(e)[B.EVIDENCE].append(vf.evidence("match", "address", "text", "x")),
    )
    add(
        "10",
        "unknown-kind",
        "evidence kind 'dna'",
        lambda e: body(e)[B.EVIDENCE][0].__setitem__(B.EV_KIND, "dna"),
    )
    add(
        "10",
        "other-no-purpose",
        "kind other with empty purpose",
        lambda e: body(e)[B.EVIDENCE][0].update({B.EV_KIND: "other", B.EV_PURPOSE: ""}),
        base="valid-custom",
    )
    add(
        "11",
        "kept-long",
        "kept beyond validity plus 30 days",
        lambda e: body(e)[B.EVIDENCE][0].update(
            {B.EV_KEPT: 15_552_000 + 2_592_001, B.EV_STORED_AS: "hash"}
        ),
    )
    add(
        "12",
        "none-kept",
        "storedAs none with kept 86400",
        lambda e: body(e)[B.EVIDENCE][0].__setitem__(B.EV_KEPT, 86_400),
    )
    add(
        "13",
        "credential-no-accepts",
        "credential item without accepts",
        lambda e: body(e)[B.EVIDENCE][1].pop(B.EV_ACCEPTS),
        base="valid-custom",
    )
    add(
        "13",
        "accepts-on-text",
        "accepts on a text item",
        lambda e: body(e)[B.EVIDENCE][0].__setitem__(
            B.EV_ACCEPTS, [{0: compute_cid(b"x"), 1: ["ward"]}]
        ),
    )
    add(
        "14",
        "unknown-field",
        "dedup field names no evidence item",
        lambda e: body(e)[B.DEDUP][0].__setitem__(B.DD_FIELD, "nope"),
    )
    add(
        "14",
        "device-on-text",
        "device dedup on a text item",
        lambda e: body(e)[B.DEDUP][0].__setitem__(B.DD_METHOD, "device"),
    )
    add(
        "14",
        "duplicate-field",
        "two dedup items on one field",
        lambda e: body(e)[B.DEDUP].append(vf.dedup("evidence", "match", "again")),
    )
    add(
        "14",
        "only-credential",
        "custom verifier whose only dedup item is credential",
        lambda e: body(e).__setitem__(
            B.DEDUP, [vf.dedup("credential", "ref", "One card per resident card")]
        ),
        base="valid-custom",
    )
    add(
        "15",
        "unknown-method",
        "revocation method 'expiry'",
        lambda e: body(e)[B.REVOCATION].__setitem__(B.RV_METHOD, "expiry"),
    )
    add(
        "15",
        "accumulator",
        "accumulator method (no scheme defined)",
        lambda e: body(e).__setitem__(
            B.REVOCATION, {B.RV_METHOD: "accumulator", B.RV_ACCUMULATOR: "x"}
        ),
    )
    add(
        "16",
        "not-days",
        "validity not a multiple of 86400",
        lambda e: body(e).__setitem__(B.VALIDITY, 15_552_001),
    )
    add(
        "16",
        "too-short",
        "validity of 27 days",
        lambda e: body(e).__setitem__(B.VALIDITY, 27 * 86_400),
    )
    add(
        "16",
        "too-long",
        "validity of 367 days",
        lambda e: body(e).__setitem__(B.VALIDITY, 367 * 86_400),
    )
    add("17", "assurance-4", "assurance 4", lambda e: body(e).__setitem__(B.ASSURANCE, 4))
    add(
        "18",
        "format",
        "code format 'wasm/0'",
        lambda e: body(e)[B.CODE].__setitem__(B.CD_FORMAT, "wasm/0"),
    )
    add(
        "18",
        "abi",
        "unknown module world",
        lambda e: body(e)[B.CODE].__setitem__(B.CD_ABI, "hum:verifier/module@9.9"),
    )
    add("19", "no-build", "build ref missing", lambda e: e[m.REFS].pop("build"))
    add(
        "19",
        "custom-no-code",
        "custom verifier without a code ref",
        lambda e: e[m.REFS].pop("code"),
        base="valid-custom",
    )
    add(
        "19",
        "public-dataset-no-ref",
        "public dataset without dataset.<name> ref",
        lambda e: e[m.REFS].pop("dataset.wards"),
    )
    add(
        "19",
        "commitment-31",
        "dataset commitment of 31 bytes",
        lambda e: body(e)[B.DATASETS][0].__setitem__(B.DS_COMMITMENT, bytes(31)),
    )
    add(
        "20a",
        "district-no-area",
        "district manifest missing area",
        lambda e: body(e)[B.ATTRIBUTES].pop(1),
    )
    add(
        "20a",
        "wrong-exposure",
        "district ward declared gate",
        lambda e: body(e)[B.ATTRIBUTES][0].__setitem__(B.AT_EXPOSURE, "gate"),
    )
    add(
        "20b",
        "invite-voter-file",
        "invite verifier asking for the voter file",
        lambda e: body(e)[B.EVIDENCE].append(vf.evidence("vf", "voter-file", "text", "x")),
        base="valid-invite-link",
    )
    add(
        "20c",
        "approved-no-roster-dedup",
        "approved-list without the roster dedup",
        lambda e: body(e).__setitem__(B.DEDUP, []),
        base="valid-approved-list",
    )
    add(
        "20c",
        "uniqueness-no-device-dedup",
        "uniqueness without the device dedup item",
        lambda e: body(e).__setitem__(
            B.DEDUP, [vf.dedup("evidence", "doc", "One card per document")]
        ),
        base="valid-uniqueness",
    )
    add(
        "20d",
        "invite-assurance-2",
        "invite with assurance 2",
        lambda e: body(e).__setitem__(B.ASSURANCE, 2),
        base="valid-invite-link",
    )
    add(
        "20e",
        "no-profile-ref",
        "named profile without the profile ref",
        lambda e: e[m.REFS].pop("profile"),
    )
    add(
        "20e",
        "profile-differs",
        "profile ref differs from code ref",
        lambda e: e[m.REFS].__setitem__("profile", w.blobs["code-custom"]),
    )
    return c


def manifests_file(w: World, built: dict[str, Any]) -> File:
    f = File(
        SPEC,
        "manifests",
        "Verifier manifests: one valid per profile, the district lineage, the two rule-30 "
        "versions the log admits, one invalid per rule 1-29 and 31 and lettered sub-rule. Blob "
        "refs resolve through the world's blobs. Rules 1-20 and the array-order half of rule "
        "29 reject at step 4, rules 21-29 and 31 at step 10. Rule 30 is in log.json.",
    )
    for name, b in built["valid"].items():
        _run(f, w, f"verifier-valid-{name}", f"{name} verifies", b)
    for suffix, rule, desc, fn, base in _step4_cases(w):
        base_bundle = w.named[base]
        env = copy.deepcopy(cbor.decode(base_bundle.envelope))
        fn(env)
        _run(f, w, suffix, desc, _resign(w, env, base_bundle), step=4, rule=rule)
    for name, rule, b in built["bad10"]:
        _run(
            f,
            w,
            f"verifier-invalid-{name}",
            f"version {cbor.decode(b.envelope)[m.VERSION]} breaks rule {rule}",
            b,
            step=10,
            rule=rule,
        )
    dup = built["dup31"]
    _run(
        f,
        w,
        "verifier-invalid-31-second-lineage",
        "a second verifier lineage under the district authority, logged after the first",
        dup,
        step=10,
        rule="31",
    )
    ctx = blob_context(w.fx)
    d1 = w.named["valid-district-v1"]
    view = m.Resolved(ctx, d1, cbor.decode(d1.envelope), d1.proof.position)
    chosen = vf.verifier_of_authority(view, w.authority)
    assert m.envelope_cid(chosen) == d1.cid
    f.add(
        "verifier-valid-31-lower-index-wins",
        "A reader that finds two lineages under one authority uses the lower log index",
        S_RULES,
        {
            "authority": hexify(w.authority),
            "candidates": [
                {"cid": hexify(d1.cid), "position": d1.proof.position},
                {"cid": hexify(dup.cid), "position": dup.proof.position},
            ],
        },
        {"chosen": hexify(d1.cid), "ignored": hexify(dup.cid)},
    )
    return f


def log_file(w: World, built: dict[str, Any]) -> File:
    f = File(
        SPEC,
        "log",
        "Rule 30, the log's clock check at submission: E_now from the lineage's validity and "
        "the log's clock; a new attribute's fromEpoch is E_now + 1 or E_now + 2 (exactly "
        "E_now + 2 in handover); version 1 at most E_now + 2. A later verifier does not "
        "re-check this rule.",
    )
    for suffix, desc, env, prev, now in built["log30"]:
        e_now, hand = vf.epoch_now(now, env[m.BODY][vf.VALIDITY])
        inputs = {
            "log_now": now,
            "envelope": hexify(cbor.encode(env)),
            "view": jsonable(env),
            "prev_view": jsonable(prev) if prev is not None else None,
            "E_now": e_now,
            "handover": hand,
        }
        result = vf.log_check(env, prev, now)
        if result is None:
            assert suffix.startswith("verifier-valid-"), suffix
            f.add(suffix, desc, S_LOG, inputs, {"admitted": True})
        else:
            assert suffix.startswith("verifier-invalid-"), suffix
            rule, reason = result
            f.add(
                suffix,
                desc,
                S_LOG,
                inputs,
                rejection={"step": None, "check": "log-admission", "rule": rule, "reason": reason},
            )
    return f


def layout_file(w: World) -> File:
    f = File(
        SPEC,
        "layout",
        "The message layout of an epoch from one manifest version alone: 2 + the attributes "
        'with fromEpoch <= E, in array order (verifier.md "Attribute"; credentials.md '
        '"Message layout").',
    )
    v3 = district(w, 1)
    v3[vf.NAME] = "District lineage for layout"
    v3[vf.ATTRIBUTES].append(
        vf.attribute("tier", "enum", "gate", "Tier", vf.enum_values(["A", "B"]), from_epoch=5)
    )
    v1 = district(w, 1)
    v1[vf.NAME] = v3[vf.NAME]
    v1_env = w.envelope(v1, w.refs("district", ["wards"]))
    lineage_cid = compute_cid(cbor.encode(v1_env))
    v2 = district(w, 2)
    v2[vf.NAME] = v3[vf.NAME]
    v2_env = w.envelope(
        v2, w.refs("district", ["wards"]), version=2, lineage=lineage_cid, prev=lineage_cid
    )
    v3[vf.ISSUER_KEYS] = v2[vf.ISSUER_KEYS]
    v3[vf.ATTRIBUTES][0][vf.AT_VALUES] = v2[vf.ATTRIBUTES][0][vf.AT_VALUES]
    env = w.envelope(
        v3,
        w.refs("district", ["wards"]),
        version=3,
        lineage=lineage_cid,
        prev=compute_cid(cbor.encode(v2_env)),
        issued_offset=120,
    )
    # a clock at which the log admits version 3: period 25, so E_now = 4 outside handover
    log_now = 25 * vf.PERIOD
    assert vf.epoch_now(log_now, v3[vf.VALIDITY]) == (4, False)
    assert vf.log_check(env, v2_env, log_now) is None
    f.add(
        "verifier-layout-v3-appends-from-epoch-5",
        "Version 3 appends an attribute with fromEpoch 5; message counts for epochs 4 and 5",
        S_LAYOUT,
        {
            "view": jsonable(env),
            "attributes": [[a[vf.AT_NAME], a[vf.AT_FROM_EPOCH]] for a in v3[vf.ATTRIBUTES]],
            "log_now": log_now,
        },
        {
            "message_count": {"4": vf.message_count(v3, 4), "5": vf.message_count(v3, 5)},
            "layout": {
                "4": [a[vf.AT_NAME] for a in v3[vf.ATTRIBUTES] if a[vf.AT_FROM_EPOCH] <= 4],
                "5": [a[vf.AT_NAME] for a in v3[vf.ATTRIBUTES] if a[vf.AT_FROM_EPOCH] <= 5],
            },
            "admitted_at_log_now": True,
        },
    )
    return f


def summary_file(w: World, built: dict[str, Any]) -> File:
    f = File(SPEC, "summary", "Disclosure summaries derived from each valid manifest alone.")
    for name, b in built["valid"].items():
        env = cbor.decode(b.envelope)
        f.add(
            f"verifier-summary-{name}",
            f"Disclosure summary of {name}",
            S_SUMMARY,
            {"cid": hexify(b.cid), "envelope": hexify(b.envelope)},
            {"summary": vf.disclosure_summary(env)},
        )
    return f


def world_file(w: World) -> File:
    f = File(
        SPEC,
        "world",
        "The district verifier authority and its keys, one authority per other lineage "
        "(rule 31), every logged verifier bundle and the blobs the refs name (module bytes, "
        "build recipes, the public wards dataset).",
    )
    f.add(
        "world",
        "Authority, bundles and blobs",
        S_RULES,
        {
            "authority": hexify(w.authority),
            "keys": {
                n: {"seed": hexify(k.seed), "public": hexify(k.public)} for n, k in w.keys.items()
            },
            "authorities": {
                label: {
                    "cid": hexify(cid),
                    "sign_seed": hexify(w.signers[cid].seed),
                    "sign_public": hexify(w.signers[cid].public),
                }
                for label, cid in w.authorities.items()
            },
            "base_world": "vectors/manifest/world.json",
        },
        {
            "bundles": [{"name": n, **bundle_json(b)} for n, b in w.named.items()],
            "blobs": {
                n: {"cid": hexify(c), "bytes": hexify(w.w.blobs[c])} for n, c in w.blobs.items()
            },
            "checkpoint": w.w.note().text(),
        },
    )
    return f


def keys_file(w: World, built: dict[str, Any]) -> File:
    f = File(
        SPEC,
        "keys",
        "Issuer key retirement timing (KEY_TAIL = 44,928,000 seconds, 520 days after the key's "
        "last epoch ends; ADR 0104). KEY_TAIL is not a validation rule: a key removed earlier is "
        "the emergency path, with the cost verifier.md's Lifetime section states, so both cases "
        "here are accepted and the earliest ordinary retirement time is the value under test.",
    )
    d2 = cbor.decode(built["valid"]["district-v2"].envelope)
    d3 = cbor.decode(built["valid"]["district-v3"].envelope)
    body2, body3 = d2[m.BODY], d3[m.BODY]
    old_kid = fixtures.fixed_bytes("kid-district-1", 8)
    last = vf.last_epoch_of_key(body2, old_kid)
    earliest = vf.earliest_retirement(last, body2[vf.VALIDITY])
    f.add(
        "verifier-key-tail-ordinary",
        "The district lineage's version 3 retires the version-1 key: its last epoch is the one "
        "before the version-2 key's fromEpoch, and version 3 is logged after KEY_TAIL past that "
        "epoch's end (ordinary retirement)",
        "Issuer key",
        {
            "kid": hexify(old_kid),
            "version_2_view": jsonable(d2),
            "version_3_issued": d3[m.ISSUED],
            "validity": body2[vf.VALIDITY],
            "KEY_TAIL": vf.KEY_TAIL,
        },
        {
            "last_epoch": last,
            "epoch_seconds": vf.epoch_seconds(body2[vf.VALIDITY]),
            "earliest_ordinary_retirement": earliest,
            "ordinary": d3[m.ISSUED] >= earliest,
            "retired_kids": [hexify(k) for k in body3[vf.RETIRED_KIDS]],
        },
    )
    recent_last = vf.epoch_now(d3[m.ISSUED], body2[vf.VALIDITY])[0] - 1
    early = vf.earliest_retirement(recent_last, body2[vf.VALIDITY])
    f.add(
        "verifier-key-tail-emergency",
        "A key whose last epoch ended one epoch ago, removed now: before KEY_TAIL, so this is an "
        "emergency removal, not ordinary retirement; valid under rules 24 to 28, with the effect "
        "on open decks the Lifetime section states",
        "Issuer key",
        {
            "last_epoch": recent_last,
            "removed_at": d3[m.ISSUED],
            "validity": body2[vf.VALIDITY],
            "KEY_TAIL": vf.KEY_TAIL,
        },
        {
            "earliest_ordinary_retirement": early,
            "ordinary": d3[m.ISSUED] >= early,
            "emergency": True,
        },
    )
    f.add(
        "verifier-key-tail-capacity",
        "issuerKeys holds at most 8 keys and a replaced key stays listed for KEY_TAIL, so about "
        "seven key changes fit in 520 days; an eighth forces an early removal",
        "Issuer key",
        {"max_issuer_keys": 8, "KEY_TAIL": vf.KEY_TAIL},
        {"changes_without_early_removal": 7},
    )
    return f


def evidence_file(w: World, built: dict[str, Any]) -> File:
    from .. import services

    f = File(
        SPEC,
        "evidence",
        "Evidence sealing strings (Host key, RT1): HPKE base mode to the host key, info = "
        "hum/evidence/1 ‖ verifier authority CID (33) ‖ item name, aad = the 16-byte session "
        "ID ‖ SHA-256(issuance request plaintext, canonical CBOR), 48 bytes. The phone builds "
        "the request before sealing; the host holds items sealed until the issue call, "
        "recomputes the hash from the request it receives and opens each item under it; any "
        "item that does not open ends the session with rejected, rule V-4. HPKE itself is "
        "pending a library (the Python `cryptography` HPKE has no aad argument): each case "
        "gives the exact info and aad bytes an implementation must seal and open under, and "
        "the rejections name which of the two would make the AEAD fail. Ciphertexts are "
        "placeholders.",
    )
    d1 = cbor.decode(built["valid"]["district-v1"].envelope)
    authority = d1[m.AUTHORITY]
    host_kid = d1[m.BODY][vf.HOST_KEYS][0][vf.HK_KID]
    session = fixtures.fixed_bytes("session-id", 16)
    other_session = fixtures.fixed_bytes("session-id-other", 16)
    kid = fixtures.fixed_bytes("issuer-kid", 8)
    manifest_cid = built["valid"]["district-v1"].cid

    def request(commits: list[bytes]) -> bytes:
        return cbor.encode({0: 1, 1: manifest_cid, 2: kid, 3: commits, 4: [1]})

    req = request([fixtures.fixed_bytes("commit-a", 200)])
    req_other = request([fixtures.fixed_bytes("commit-b", 200)])
    req_handover = request(
        [fixtures.fixed_bytes("commit-a", 200), fixtures.fixed_bytes("commit-a2", 200)]
    )
    info = services.evidence_info(authority, "match")
    aad = services.evidence_aad(session, req)
    sealed = {"info": info, "aad": aad, "ciphertext": fixtures.fixed_bytes("evidence-ct", 48)}

    def body(item):
        return hexify(
            services.encode_body(
                "verifier-evidence",
                {"name": "match", "kid": host_kid, "ciphertext": item["ciphertext"]},
            )
        )

    def inputs(sess, rq, item):
        return {
            "verifier_authority": hexify(authority),
            "host_kid": hexify(host_kid),
            "session_id": hexify(sess),
            "item_name": "match",
            "issuance_request_plaintext": hexify(rq),
            "request_hash": hexify(services.request_hash(rq)),
            "suite": "hpke-x25519-sha256-chacha20poly1305, base mode",
            "sealed_info": hexify(item["info"]),
            "sealed_aad": hexify(item["aad"]),
            "request_body": body(item),
        }

    f.add(
        "verifier-evidence-sealed",
        "An evidence item sealed for this verifier, this item name, this session and the "
        "issuance request the phone then submits: opens",
        "Host key",
        inputs(session, req, sealed),
        {"info": hexify(info), "aad": hexify(aad), "aad_length": len(aad), "opens": True},
    )
    aad_h = services.evidence_aad(session, req_handover)
    sealed_h = {**sealed, "aad": aad_h}
    assert (
        services.open_evidence_structural(sealed_h, authority, "match", session, req_handover)
        is None
    )
    f.add(
        "verifier-evidence-handover-two-commitments",
        "A first session during handover: one request with two commitments, one hash, every "
        "item sealed under it (valid)",
        "Host key",
        inputs(session, req_handover, sealed_h),
        {"info": hexify(info), "aad": hexify(aad_h), "opens": True, "commitments": 2},
    )
    aad_retry = services.evidence_aad(other_session, req)
    sealed_retry = {**sealed, "aad": aad_retry}
    assert (
        services.open_evidence_structural(sealed_retry, authority, "match", other_session, req)
        is None
    )
    f.add(
        "verifier-evidence-lost-response-retry",
        "A lost-response retry in a new session: the evidence is re-sealed under the new "
        "session ID and the same request hash; the identical request gets the identical "
        "response (services/host host-v2-identical-retry-new-session)",
        "Host key",
        inputs(other_session, req, sealed_retry),
        {"info": hexify(info), "aad": hexify(aad_retry), "opens": True,
         "same_request_hash_as_first_session": True},
    )  # fmt: skip
    for suffix, desc, sess, rq, sealed_bad, reason in (
        (
            "verifier-evidence-other-request",
            "The issuance request submitted in the session differs from the one the evidence "
            "was sealed for: the aad's hash half differs, the AEAD fails, the session ends with "
            "rejected, rule V-4",
            session, req_other, sealed, "other_request",
        ),
        (
            "verifier-evidence-session-id-replaced",
            "The session ID was replaced in transit (an edge handed the phone another "
            "session's ID): the aad's first 16 bytes differ, the AEAD fails (V-4)",
            other_session, req, sealed, "other_session",
        ),
        (
            "verifier-evidence-other-item",
            "Sealed under another item's name: the info differs, the AEAD fails (V-4)",
            session, req, {**sealed, "info": services.evidence_info(authority, "address")},
            "other_item_name",
        ),
        (
            "verifier-evidence-other-verifier",
            "Sealed for another verifier's authority: the info differs, the AEAD fails (V-4)",
            session, req,
            {**sealed, "info": services.evidence_info(w.new_authority("evidence-other"), "match")},
            "other_verifier",
        ),
    ):  # fmt: skip
        got = services.open_evidence_structural(sealed_bad, authority, "match", sess, rq)
        assert got == reason, (suffix, got)
        err = services.evidence_rejection()
        f.add(
            suffix,
            desc,
            "Host key",
            inputs(sess, rq, sealed_bad),
            rejection={
                "step": None,
                "check": "evidence-open",
                "rule": "V-4",
                "reason": reason,
                "status": err.status,
                "code": err.code,
                "body": hexify(services.encode_error(err)),
            },
        )
    return f


def generate() -> list[File]:
    w, built = build()
    return [
        world_file(w),
        manifests_file(w, built),
        log_file(w, built),
        layout_file(w),
        summary_file(w, built),
        keys_file(w, built),
        evidence_file(w, built),
    ]
