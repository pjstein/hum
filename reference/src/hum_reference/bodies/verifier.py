"""The ``verifier`` body: docs/specs/verifier.md.

Rules 1 to 20 (with 7a-7c and 20a-20e) and the array-order half of rule 29 run at
verification step 4; rules 21 to 29 run at step 10 against the previous version, and rule 31
against the log's history. Rule 30 is the log's own clock check at submission
(``log_check``); a later verifier does not re-check it. ``disclosure_summary`` derives the
structure the phone shows before any evidence is submitted, and ``message_count`` the card
layout of an epoch from any version that lists the attributes.

Sub-structure keys follow the field order of the spec's tables (small uints, as every
body does). The spec writes enum values as ``{v, label}`` and bands as ``{lo, hi, label}``
in its JSON view; here an enum value is ``{0: v, 1: label}``, a band ``{0: lo, 1: hi,
2: label}`` and an ``accepts`` entry ``{0: authority, 1: attributes}``.
"""

from __future__ import annotations

from typing import Any

from .. import manifest as m
from ..cid import cid_text
from . import (
    LANG_RE,
    NAME_RE,
    TypeRule,
    is_bytes,
    is_cid,
    is_text,
    is_uint,
    no_unknown_keys,
    require,
    require_keys,
)

__all__ = [
    "ATTRIBUTE_TYPES",
    "EVIDENCE_KINDS",
    "PROFILES",
    "attribute",
    "body",
    "dataset",
    "dedup",
    "disclosure_summary",
    "epoch_periods",
    "evidence",
    "host_key",
    "issuer_key",
    "key_of_epoch",
    "log_check",
    "message_count",
    "rules",
    "schema",
    "verifier_of_authority",
]

# ---------------------------------------------------------------- body keys

(
    NAME, OPERATOR, LANG, PROFILE, CLASS, ISSUER_KEYS, RETIRED_KIDS, HOST_KEYS, ATTRIBUTES,
    EVIDENCE, DATASETS, DEDUP, REVOCATION, VALIDITY, ASSURANCE, CODE, SESSION_CAP,
) = range(17)  # fmt: skip
REQUIRED = {
    NAME, OPERATOR, LANG, PROFILE, CLASS, ISSUER_KEYS, HOST_KEYS, ATTRIBUTES, EVIDENCE, DEDUP,
    REVOCATION, VALIDITY, ASSURANCE, CODE,
}  # fmt: skip
ALL_KEYS = set(range(17))

IK_KID, IK_ALG, IK_KEY, IK_FROM_EPOCH, IK_SINCE = range(5)
HK_KID, HK_ALG, HK_KEY = range(3)
AT_NAME, AT_LABEL, AT_TYPE, AT_VALUES, AT_MAX, AT_EXPOSURE, AT_STATUS, AT_FROM_EPOCH = range(8)
EV_NAME, EV_KIND, EV_SCHEMA, EV_PURPOSE, EV_KEPT, EV_STORED_AS, EV_REQUIRED, EV_ACCEPTS = range(8)
DS_NAME, DS_KIND, DS_COMMITMENT, DS_RECORDS, DS_DESCRIBE = range(5)
DD_METHOD, DD_FIELD, DD_SCOPE = range(3)
RV_METHOD, RV_ACCUMULATOR = range(2)
CD_FORMAT, CD_ABI, CD_SOURCE, CD_TOOLCHAIN = range(4)
ENUM_V, ENUM_LABEL = 0, 1
BAND_LO, BAND_HI, BAND_LABEL = 0, 1, 2
ACC_AUTHORITY, ACC_ATTRIBUTES = 0, 1

PROFILES = ("invite", "approved-list", "district", "age-band", "uniqueness", "custom")
NAMED_PROFILES = PROFILES[:5]
CLASSES = ("person", "agent")
ISSUER_SUITES = {"bbs-bls12381-sha256": 96}
HOST_SUITES = {"hpke-x25519-sha256-chacha20poly1305": 32}
PERIOD = 2_419_200  # 28 days, credentials.md
MIN_VALIDITY = PERIOD
ATTRIBUTE_TYPES = ("bool", "enum", "band", "uint")
EXPOSURES = ("gate", "breakdown")
ATTR_STATUSES = ("active", "deprecated")
EVIDENCE_KINDS = (
    "code", "link", "roster", "voter-file", "address", "date-of-birth", "document", "selfie",
    "phone", "email", "device", "credential", "other",
)  # fmt: skip
SCHEMAS = ("none", "text", "number", "date", "image", "credential", "device")
STORED_AS = ("none", "hash", "raw")
DEDUP_METHODS = ("evidence", "credential", "device")
REVOCATION_METHODS = ("reissue", "accumulator")
CODE_FORMAT = "wasm-component/1"
KNOWN_ABIS = ("hum:verifier/module@0.1",)
DAY = 86_400
MAX_VALIDITY = 31_622_400
TOOLCHAIN = "rustc 1.99.0, target wasm32-wasip2"  # verifier.md "Code"; no cargo-component
KEPT_GRACE = 2_592_000
AGE_BANDS = ((18, 24), (25, 34), (35, 49), (50, 64), (65, 150))

# profile table: required attributes (name -> (type, exposure)), optional attributes,
# allowed evidence kinds, allowed dedup methods, assurance range
PROFILE_RULES: dict[str, dict[str, Any]] = {
    "invite": {
        "required": {"invite": ("bool", "gate")},
        "optional": {"cohort": ("enum", "breakdown")},
        "evidence": {"link", "code", "device"},
        "dedup": {"evidence", "device"},
        "assurance": (0, 0),
    },
    "approved-list": {
        "required": {"approved": ("bool", "gate")},
        "optional": {"role": ("enum", "gate")},
        "evidence": {"roster", "email", "phone", "code", "device"},
        "dedup": {"evidence", "device"},
        "assurance": (1, 1),
    },
    "district": {
        "required": {"ward": ("enum", "breakdown"), "area": ("enum", "breakdown")},
        "optional": {},
        "evidence": {"voter-file", "address", "credential"},
        "dedup": {"evidence", "credential"},
        "assurance": (2, 2),
    },
    "age-band": {
        "required": {"age-band": ("band", "breakdown")},
        "optional": {},
        "evidence": {"date-of-birth", "document", "voter-file"},
        "dedup": {"evidence"},
        "assurance": (2, 3),
    },
    "uniqueness": {
        "required": {"unique": ("bool", "gate")},
        "optional": {},
        "evidence": {"device", "document", "selfie", "phone"},
        "dedup": {"evidence", "device"},
        "assurance": (2, 3),
    },
}


# ---------------------------------------------------------------- builders


def issuer_key(kid: bytes, key: bytes, from_epoch: int = 0, since: int = 1) -> dict:
    return {
        IK_KID: kid,
        IK_ALG: "bbs-bls12381-sha256",
        IK_KEY: key,
        IK_FROM_EPOCH: from_epoch,
        IK_SINCE: since,
    }


def host_key(kid: bytes, key: bytes) -> dict:
    return {HK_KID: kid, HK_ALG: "hpke-x25519-sha256-chacha20poly1305", HK_KEY: key}


def attribute(
    name: str,
    type_: str,
    exposure: str,
    label: str | None = None,
    values: list | None = None,
    max_: int | None = None,
    status: str = "active",
    from_epoch: int = 0,
) -> dict:
    out = {
        AT_NAME: name,
        AT_LABEL: label if label is not None else name.replace("-", " ").title(),
        AT_TYPE: type_,
        AT_EXPOSURE: exposure,
        AT_STATUS: status,
        AT_FROM_EPOCH: from_epoch,
    }
    if values is not None:
        out[AT_VALUES] = values
    if max_ is not None:
        out[AT_MAX] = max_
    return out


def enum_values(labels: list[str], start: int = 1) -> list[dict]:
    return [{ENUM_V: start + i, ENUM_LABEL: lab} for i, lab in enumerate(labels)]


def band_values(bands=AGE_BANDS) -> list[dict]:
    out = []
    for lo, hi in bands:
        label = f"{lo}-{hi}" if hi < 150 else f"{lo}+"
        out.append({BAND_LO: lo, BAND_HI: hi, BAND_LABEL: label})
    return out


def evidence(
    name: str,
    kind: str,
    schema_: str,
    purpose: str,
    kept: int = 0,
    stored_as: str = "none",
    required: bool = True,
    accepts: list[dict] | None = None,
) -> dict:
    out = {
        EV_NAME: name,
        EV_KIND: kind,
        EV_SCHEMA: schema_,
        EV_PURPOSE: purpose,
        EV_KEPT: kept,
        EV_STORED_AS: stored_as,
        EV_REQUIRED: required,
    }
    if accepts is not None:
        out[EV_ACCEPTS] = accepts
    return out


def dataset(name: str, kind: str, commitment: bytes, records: int, describe: str) -> dict:
    return {
        DS_NAME: name,
        DS_KIND: kind,
        DS_COMMITMENT: commitment,
        DS_RECORDS: records,
        DS_DESCRIBE: describe,
    }


def dedup(method: str, field: str, scope: str) -> dict:
    return {DD_METHOD: method, DD_FIELD: field, DD_SCOPE: scope}


def code(source: bytes, toolchain: str = TOOLCHAIN) -> dict:
    return {
        CD_FORMAT: CODE_FORMAT,
        CD_ABI: KNOWN_ABIS[0],
        CD_SOURCE: source,
        CD_TOOLCHAIN: toolchain,
    }


def body(
    *,
    name: str,
    operator: str,
    profile: str,
    issuer_keys: list[dict],
    host_keys: list[dict],
    attributes: list[dict],
    evidence_: list[dict],
    dedup_: list[dict],
    code_: dict,
    assurance: int,
    validity: int = 15_552_000,
    class_: str = "person",
    lang: str = "en",
    datasets: list[dict] | None = None,
    retired_kids: list[bytes] | None = None,
    revocation: dict | None = None,
    session_cap: int | None = None,
) -> dict[int, Any]:
    out: dict[int, Any] = {
        NAME: name,
        OPERATOR: operator,
        LANG: lang,
        PROFILE: profile,
        CLASS: class_,
        ISSUER_KEYS: issuer_keys,
        HOST_KEYS: host_keys,
        ATTRIBUTES: attributes,
        EVIDENCE: evidence_,
        DEDUP: dedup_,
        REVOCATION: revocation if revocation is not None else {RV_METHOD: "reissue"},
        VALIDITY: validity,
        ASSURANCE: assurance,
        CODE: code_,
    }
    if datasets is not None:
        out[DATASETS] = datasets
    if retired_kids is not None:
        out[RETIRED_KIDS] = retired_kids
    if session_cap is not None:
        out[SESSION_CAP] = session_cap
    return out


# ---------------------------------------------------------------- step 4: rules 1 to 20


def _text(v: Any, limit: int, rule: str, what: str, **kw) -> str:
    require(is_text(v, limit, **kw), rule, f"{what}: text within {limit} bytes, NFC, no controls")
    return v


def _list(v: Any, limit: int, rule: str, what: str, min_len: int = 0) -> list:
    require(
        isinstance(v, list) and min_len <= len(v) <= limit,
        rule,
        f"{what}: array of {min_len}..{limit}",
    )
    return v


def schema(env: dict[int, Any]) -> None:
    b = env[m.BODY]
    require_keys(b, REQUIRED, "2")
    no_unknown_keys(b, ALL_KEYS, "2")
    # rule 1
    require(b[PROFILE] in PROFILES, "1", "unknown profile")
    require(b[CLASS] in CLASSES, "1", "class must be person or agent")
    require(is_text(b[LANG], 16, pattern=LANG_RE), "1", "lang pattern")
    # rule 2: texts and array sizes
    _text(b[NAME], 64, "2", "name")
    _text(b[OPERATOR], 64, "2", "operator")
    keys = _list(b[ISSUER_KEYS], 8, "2", "issuerKeys", 1)
    retired = _list(b.get(RETIRED_KIDS, []), 64, "2", "retiredKids")
    hosts = _list(b[HOST_KEYS], 8, "2", "hostKeys")
    attrs = _list(b[ATTRIBUTES], 32, "2", "attributes")
    evs = _list(b[EVIDENCE], 16, "2", "evidence")
    dss = _list(b.get(DATASETS, []), 16, "2", "datasets")
    dds = _list(b[DEDUP], 4, "2", "dedup")
    # rule 3, 4: issuer keys
    kids: list[bytes] = []
    epochs: list[int] = []
    for k in keys:
        require_keys(k, {IK_KID, IK_ALG, IK_KEY, IK_FROM_EPOCH, IK_SINCE}, "3", "issuer key")
        no_unknown_keys(k, set(range(5)), "3", "issuer key")
        require(is_bytes(k[IK_KID], lo=4, hi=32), "3", "kid 4..32 bytes")
        require(k[IK_ALG] in ISSUER_SUITES, "3", "unknown credential suite")
        require(is_bytes(k[IK_KEY], ISSUER_SUITES[k[IK_ALG]]), "3", "issuer key length")
        require(is_uint(k[IK_FROM_EPOCH]), "3", "fromEpoch must be a uint")
        require(is_uint(k[IK_SINCE], 1, env[m.VERSION]), "3", "since must be 1..version")
        kids.append(k[IK_KID])
        epochs.append(k[IK_FROM_EPOCH])
    require(len(set(epochs)) == len(epochs), "3", "fromEpoch values must be unique")
    require(all(is_bytes(r, lo=4, hi=32) for r in retired), "4", "retiredKids entries")
    require(len(set(kids)) == len(kids), "4", "duplicate issuer kid")
    require(not set(kids) & set(retired), "4", "issuer kid also in retiredKids")
    # rule 5: host keys
    require(len(hosts) >= 1, "5", "at least one host key")
    for h in hosts:
        require_keys(h, {HK_KID, HK_ALG, HK_KEY}, "5", "host key")
        no_unknown_keys(h, {HK_KID, HK_ALG, HK_KEY}, "5", "host key")
        require(is_bytes(h[HK_KID], lo=4, hi=32), "5", "host kid")
        require(h[HK_ALG] in HOST_SUITES, "5", "unknown host suite")
        require(is_bytes(h[HK_KEY], HOST_SUITES[h[HK_ALG]]), "5", "host key length")
    # rules 6 to 9 and 29 (array order): attributes
    names: list[str] = []
    prev_from_epoch = 0
    for a in attrs:
        require_keys(a, {AT_NAME, AT_LABEL, AT_TYPE, AT_EXPOSURE, AT_STATUS}, "2", "attribute")
        no_unknown_keys(a, set(range(8)), "2", "attribute")
        require(AT_FROM_EPOCH in a, "29", "every attribute has a fromEpoch")
        require(is_uint(a[AT_FROM_EPOCH]), "29", "attribute fromEpoch must be a uint")
        require(
            a[AT_FROM_EPOCH] >= prev_from_epoch,
            "29",
            "attribute fromEpoch values must be non-decreasing in array order",
        )
        prev_from_epoch = a[AT_FROM_EPOCH]
        require(is_text(a[AT_NAME], 32, pattern=NAME_RE), "6", "attribute name pattern")
        names.append(a[AT_NAME])
        _text(a[AT_LABEL], 40, "2", "attribute label")
        require(a[AT_TYPE] in ATTRIBUTE_TYPES, "2", "attribute type")
        require(a[AT_EXPOSURE] in EXPOSURES, "2", "exposure")
        require(a[AT_STATUS] in ATTR_STATUSES, "2", "attribute status")
        t = a[AT_TYPE]
        if t in ("enum", "band"):
            vals = _list(a.get(AT_VALUES), 1024, "2", "values")
            require(len(vals) >= 2, "7a", f"{t} attribute needs at least two values")
            if t == "enum":
                vs, labels = [], []
                for v in vals:
                    require_keys(v, {ENUM_V, ENUM_LABEL}, "2", "enum value")
                    require(is_uint(v[ENUM_V]), "2", "enum v")
                    _text(v[ENUM_LABEL], 40, "2", "enum label")
                    vs.append(v[ENUM_V])
                    labels.append(v[ENUM_LABEL])
                require(
                    len(set(vs)) == len(vs) and len(set(labels)) == len(labels),
                    "7b",
                    "duplicate v or label",
                )
            else:
                prev_hi = -1
                labels = []
                for v in vals:
                    require_keys(v, {BAND_LO, BAND_HI, BAND_LABEL}, "2", "band")
                    require(is_uint(v[BAND_LO]) and is_uint(v[BAND_HI]), "2", "band bounds")
                    _text(v[BAND_LABEL], 40, "2", "band label")
                    require(
                        v[BAND_LO] <= v[BAND_HI] and v[BAND_LO] > prev_hi,
                        "7c",
                        "bands ascending, no overlap",
                    )
                    prev_hi = v[BAND_HI]
                    labels.append(v[BAND_LABEL])
                require(len(set(labels)) == len(labels), "7b", "duplicate band label")
            if len(vals) > 64:
                require(a[AT_EXPOSURE] == "gate", "9", "more than 64 values must be gate")
        else:
            require(AT_VALUES not in a, "2", f"{t} attribute has no values")
        if t == "uint":
            require(
                is_uint(a.get(AT_MAX), 0, (1 << 64) - 2),
                "8",
                "uint attribute needs max below 2^64-1",
            )
            require(a[AT_EXPOSURE] == "gate", "8", "uint attribute must be gate")
        else:
            require(AT_MAX not in a, "8", "only uint attributes carry max")
    require(len(set(names)) == len(names), "6", "duplicate attribute name")
    # rules 10 to 13: evidence
    ev_names: dict[str, str] = {}
    for e in evs:
        require_keys(e, set(range(7)), "10", "evidence item")
        no_unknown_keys(e, set(range(8)), "10", "evidence item")
        _text(e[EV_NAME], 32, "2", "evidence name")
        require(e[EV_NAME] not in ev_names, "10", "duplicate evidence name")
        require(e[EV_KIND] in EVIDENCE_KINDS, "10", "unknown evidence kind")
        require(e[EV_SCHEMA] in SCHEMAS, "10", "unknown schema")
        _text(e[EV_PURPOSE], 140, "2", "purpose")
        if e[EV_KIND] == "other":
            require(len(e[EV_PURPOSE]) > 0, "10", "other needs a purpose")
        require(is_uint(e[EV_KEPT]), "2", "kept")
        require(is_uint(b[VALIDITY]), "16", "validity must be a uint")
        require(e[EV_KEPT] <= b[VALIDITY] + KEPT_GRACE, "11", "kept over validity plus 30 days")
        require(e[EV_STORED_AS] in STORED_AS, "2", "storedAs")
        if e[EV_STORED_AS] == "none":
            require(e[EV_KEPT] == 0, "12", "storedAs none needs kept 0")
        require(isinstance(e[EV_REQUIRED], bool), "2", "required must be a bool")
        if e[EV_KIND] == "credential":
            acc = e.get(EV_ACCEPTS)
            require(
                isinstance(acc, list) and 1 <= len(acc) <= 8, "13", "credential item needs accepts"
            )
            for entry in acc:
                require_keys(entry, {ACC_AUTHORITY, ACC_ATTRIBUTES}, "13", "accepts entry")
                require(is_cid(entry[ACC_AUTHORITY]), "13", "accepts authority CID")
                at = entry[ACC_ATTRIBUTES]
                require(isinstance(at, list) and 1 <= len(at) <= 8, "13", "accepts attributes 1..8")
                require(
                    all(is_text(x, 32, min_bytes=1) for x in at), "13", "accepts attribute names"
                )
        else:
            require(EV_ACCEPTS not in e, "13", "accepts only on credential items")
        ev_names[e[EV_NAME]] = e[EV_KIND]
    # datasets (rule 19 commitment, rule 2 texts)
    ds_names = []
    for d in dss:
        require_keys(d, set(range(5)), "2", "dataset")
        no_unknown_keys(d, set(range(5)), "2", "dataset")
        _text(d[DS_NAME], 32, "2", "dataset name")
        require(d[DS_KIND] in ("public", "private"), "2", "dataset kind")
        require(is_bytes(d[DS_COMMITMENT], 32), "19", "dataset commitment must be 32 bytes")
        require(is_uint(d[DS_RECORDS]), "2", "records")
        _text(d[DS_DESCRIBE], 140, "2", "describe")
        ds_names.append(d[DS_NAME])
    require(len(set(ds_names)) == len(ds_names), "2", "duplicate dataset name")
    # rule 14: dedup
    fields = []
    for dd in dds:
        require_keys(dd, {DD_METHOD, DD_FIELD, DD_SCOPE}, "14", "dedup item")
        no_unknown_keys(dd, {DD_METHOD, DD_FIELD, DD_SCOPE}, "14", "dedup item")
        require(dd[DD_METHOD] in DEDUP_METHODS, "14", "unknown dedup method")
        _text(dd[DD_SCOPE], 64, "2", "dedup scope")
        kind = ev_names.get(dd[DD_FIELD])
        require(kind is not None, "14", "dedup field names no evidence item")
        if dd[DD_METHOD] == "credential":
            require(kind == "credential", "14", "credential dedup needs a credential item")
        if dd[DD_METHOD] == "device":
            require(kind == "device", "14", "device dedup needs a device item")
        fields.append(dd[DD_FIELD])
    require(len(set(fields)) == len(fields), "14", "duplicate dedup field")
    if dds:
        require(
            any(d[DD_METHOD] != "credential" for d in dds),
            "14",
            "a non-empty dedup needs an item whose method is not credential",
        )
    # rule 15: revocation
    rv = b[REVOCATION]
    require_keys(rv, {RV_METHOD}, "15", "revocation")
    no_unknown_keys(rv, {RV_METHOD, RV_ACCUMULATOR}, "15", "revocation")
    if rv[RV_METHOD] == "accumulator":
        raise TypeRule("15", "no accumulator scheme is defined in draft 0.1")
    require(rv[RV_METHOD] == "reissue", "15", "unknown revocation method")
    # rule 16, 17
    require(
        b[VALIDITY] % DAY == 0 and MIN_VALIDITY <= b[VALIDITY] <= MAX_VALIDITY,
        "16",
        "validity must be whole days between 28 and 366 days",
    )
    require(is_uint(b[ASSURANCE], 0, 3), "17", "assurance 0..3")
    if SESSION_CAP in b:
        require(is_uint(b[SESSION_CAP], 1), "2", "sessionCap")
    # rule 18: code
    cd = b[CODE]
    require_keys(cd, set(range(4)), "18", "code")
    no_unknown_keys(cd, set(range(4)), "18", "code")
    require(cd[CD_FORMAT] == CODE_FORMAT, "18", "code format")
    require(cd[CD_ABI] in KNOWN_ABIS, "18", "unknown module world")
    require(
        is_bytes(cd[CD_SOURCE]) and len(cd[CD_SOURCE]) in (20, 32),
        "2",
        "source hash 20 or 32 bytes",
    )
    _text(cd[CD_TOOLCHAIN], 120, "2", "toolchain")
    # rule 19: refs
    refs = env[m.REFS]
    require("code" in refs and "build" in refs, "19", "refs need code and build")
    for d in dss:
        if d[DS_KIND] == "public":
            require(
                f"dataset.{d[DS_NAME]}" in refs, "19", f"public dataset {d[DS_NAME]} needs a ref"
            )
    for name in refs:
        ok = name in ("code", "build", "profile") or (
            name.startswith("dataset.") and name[8:] in ds_names
        )
        require(ok, "19", f"unknown ref {name!r}")
    # rule 20: profile rules
    _profile_rules(b, refs, attrs, evs, dds)


def _profile_rules(b, refs, attrs, evs, dds) -> None:
    profile = b[PROFILE]
    if profile == "custom":
        return
    pr = PROFILE_RULES[profile]
    by_name = {a[AT_NAME]: a for a in attrs}
    for name, (t, ex) in pr["required"].items():
        a = by_name.get(name)
        require(a is not None, "20a", f"profile {profile} must declare {name}")
        require(a[AT_TYPE] == t and a[AT_EXPOSURE] == ex, "20a", f"{name} must be {t}/{ex}")
    for name, (t, ex) in pr["optional"].items():
        a = by_name.get(name)
        if a is not None:
            require(a[AT_TYPE] == t and a[AT_EXPOSURE] == ex, "20a", f"{name} must be {t}/{ex}")
    if profile == "age-band":
        vals = by_name["age-band"].get(AT_VALUES, [])
        los = [v[BAND_LO] for v in vals]
        require(
            los == [lo for lo, _ in AGE_BANDS],
            "20a",
            "age bands must be 18-24, 25-34, 35-49, 50-64, 65+",
        )
    kinds = {e[EV_KIND] for e in evs}
    for e in evs:
        require(
            e[EV_KIND] in pr["evidence"],
            "20b",
            f"evidence kind {e[EV_KIND]} not allowed for {profile}",
        )
    # 20c: every dedup item the profile's row requires is present. Methods are fixed by the
    # dedup schema, so the former method-in-set check was unreachable and is not a rule.
    methods = [d[DD_METHOD] for d in dds]
    ev_kind_by_field = {e[EV_NAME]: e[EV_KIND] for e in evs}
    required_ok = True
    if profile == "invite":
        if "code" in kinds:
            required_ok = any(
                d[DD_METHOD] == "evidence" and ev_kind_by_field[d[DD_FIELD]] == "code" for d in dds
            )
    elif profile == "approved-list":
        required_ok = any(
            d[DD_METHOD] == "evidence" and ev_kind_by_field[d[DD_FIELD]] == "roster" for d in dds
        )
    elif profile in ("district", "age-band"):
        required_ok = "evidence" in methods
    elif profile == "uniqueness":
        required_ok = "device" in methods and any(
            d[DD_METHOD] == "evidence" and ev_kind_by_field[d[DD_FIELD]] in ("document", "phone")
            for d in dds
        )
    require(required_ok, "20c", f"profile {profile} is missing a required dedup item")
    lo, hi = pr["assurance"]
    require(lo <= b[ASSURANCE] <= hi, "20d", f"assurance for {profile} must be in {lo}..{hi}")
    require(
        "profile" in refs and refs["profile"] == refs["code"],
        "20e",
        "profile ref must equal code ref",
    )


# ---------------------------------------------------------------- step 10: rules 21 to 29, 31


def verifier_of_authority(view: m.Resolved, authority: bytes) -> dict[int, Any] | None:
    """Rule 31 for a reader: the ``verifier`` lineage under ``authority`` with the lowest index
    in the log being read. Returns that lineage's version 1 envelope, or None."""
    for _, env, _ in view.all_of_type("verifier"):
        if env.get(m.AUTHORITY) == authority and m.LINEAGE not in env:
            return env
    return None


def rules(view: m.Resolved) -> None:
    prev = view.prev_env
    if prev is None:
        for k in view.body[ISSUER_KEYS]:
            require(k[IK_SINCE] == 1, "28", "version 1 keys must have since 1")
        # rule 31: one lineage per authority; the lower index in the log wins
        own = view.position
        for pos, env, b in view.all_of_type("verifier"):
            if b.cid == view.bundle.cid or env.get(m.AUTHORITY) != view.env[m.AUTHORITY]:
                continue
            if m.LINEAGE in env and env[m.LINEAGE] == view.bundle.cid:
                continue
            require(
                own is not None and pos > own,
                "31",
                "the log already holds a verifier lineage under this authority",
            )
        return
    b, pb = view.body, prev[m.BODY]
    version = view.env[m.VERSION]
    require(b[PROFILE] == pb[PROFILE] and b[CLASS] == pb[CLASS], "21", "profile or class changed")
    require(b[VALIDITY] == pb[VALIDITY], "21", "validity changed")
    # rule 22, 23: attributes
    by_name = {a[AT_NAME]: a for a in b[ATTRIBUTES]}
    for pa in pb[ATTRIBUTES]:
        a = by_name.get(pa[AT_NAME])
        require(a is not None, "22", f"attribute {pa[AT_NAME]} removed")
        require(
            a[AT_TYPE] == pa[AT_TYPE] and a.get(AT_MAX) == pa.get(AT_MAX),
            "22",
            "attribute type or max changed",
        )
        if pa[AT_TYPE] in ("enum", "band"):
            old, new = pa[AT_VALUES], a[AT_VALUES]
            require(len(new) >= len(old), "22", "values removed")
            for i, ov in enumerate(old):
                nv = new[i]
                if pa[AT_TYPE] == "enum":
                    require(nv[ENUM_V] == ov[ENUM_V], "22", "enum v numbers changed or reordered")
                else:
                    require(
                        nv[BAND_LO] == ov[BAND_LO] and nv[BAND_HI] == ov[BAND_HI],
                        "22",
                        "band ranges changed or reordered",
                    )
        require(
            not (pa[AT_EXPOSURE] == "gate" and a[AT_EXPOSURE] == "breakdown"),
            "23",
            f"{pa[AT_NAME]} moved from gate to breakdown",
        )
        require(
            not (pa[AT_STATUS] == "deprecated" and a[AT_STATUS] == "active"),
            "23",
            f"{pa[AT_NAME]} reactivated",
        )
        require(
            a[AT_FROM_EPOCH] == pa[AT_FROM_EPOCH],
            "29",
            f"{pa[AT_NAME]} changed its fromEpoch",
        )
    # rules 24 to 28: keys
    old_keys = {k[IK_KID]: k for k in pb[ISSUER_KEYS]}
    new_keys = {k[IK_KID]: k for k in b[ISSUER_KEYS]}
    old_retired = set(pb.get(RETIRED_KIDS, []))
    new_retired = set(b.get(RETIRED_KIDS, []))
    for kid in set(old_keys) | old_retired:
        if kid not in new_keys:
            require(kid in new_retired, "24", "a dropped kid is missing from retiredKids")
    for kid in new_keys:
        require(kid not in old_retired, "24", "a retired kid was reused")
    for kid, k in new_keys.items():
        if kid in old_keys:
            ok = old_keys[kid]
            require(k[IK_KEY] == ok[IK_KEY], "25", "issuer key bytes changed")
            require(k[IK_FROM_EPOCH] == ok[IK_FROM_EPOCH], "26", "fromEpoch changed")
            require(k[IK_SINCE] == ok[IK_SINCE], "27", "since changed")
    for kid, k in new_keys.items():
        if kid not in old_keys:
            others = [x[IK_FROM_EPOCH] for other, x in new_keys.items() if other != kid]
            require(
                all(k[IK_FROM_EPOCH] > e for e in others),
                "26",
                "a new key's fromEpoch must exceed every other listed key's",
            )
            require(k[IK_SINCE] == version, "28", "a new key must have since equal to this version")


# ---------------------------------------------------------------- rule 30: the log's clock check


def epoch_now(now: int, validity: int) -> tuple[int, bool]:
    """``(E_now, in_handover)`` by a clock ``now`` for a lineage's ``validity``: periods of
    2,419,200 s aligned to the Unix epoch, ``V = floor(validity / period)`` (at least 1),
    ``E = floor(p / V)``; handover is the last two periods of an epoch."""
    v = max(epoch_periods(validity), 1)
    p = now // PERIOD
    return p // v, p % v >= max(v - 2, 0)


def log_check(
    env: dict[int, Any], prev_env: dict[int, Any] | None, log_now: int
) -> tuple[str, str] | None:
    """Rule 30, run by the log at submission with its own clock. Returns ``(rule, reason)``
    for a refusal, or None. ``prev_env`` is the lineage's previous version (None for version
    1); ``validity`` is frozen (rule 21), so either version gives the same epoch grid."""
    b = env[m.BODY]
    e_now, in_handover = epoch_now(log_now, b[VALIDITY])
    if prev_env is None:
        for a in b[ATTRIBUTES]:
            if a[AT_FROM_EPOCH] > e_now + 2:
                return ("30", f"{a[AT_NAME]}: version 1 fromEpoch above E_now + 2 ({e_now + 2})")
        return None
    old = {a[AT_NAME] for a in prev_env[m.BODY][ATTRIBUTES]}
    lo = e_now + 2 if in_handover else e_now + 1
    for a in b[ATTRIBUTES]:
        if a[AT_NAME] in old:
            continue
        fe = a[AT_FROM_EPOCH]
        if fe < lo:
            when = "during handover" if in_handover else "outside handover"
            return ("30", f"{a[AT_NAME]}: new attribute fromEpoch {fe} below {lo} {when}")
        if fe > e_now + 2:
            return (
                "30",
                f"{a[AT_NAME]}: new attribute fromEpoch {fe} above E_now + 2 ({e_now + 2})",
            )
    return None


# ---------------------------------------------------------------- epochs and layout


def message_count(body: dict[int, Any], epoch: int) -> int:
    """The card layout of ``epoch``: ``2 + (attributes with fromEpoch <= epoch)`` (index 0 the
    epoch, one message per attribute in array order, the nym secret last). Computable from
    any version that lists the attributes, with no clock and no log position."""
    return 2 + sum(1 for a in body[ATTRIBUTES] if a[AT_FROM_EPOCH] <= epoch)


def key_of_epoch(body: dict[int, Any], epoch: int) -> dict | None:
    """ "Which key signs an epoch": the listed key with the largest ``fromEpoch <= epoch``."""
    best = None
    for k in body[ISSUER_KEYS]:
        if k[IK_FROM_EPOCH] <= epoch and (best is None or k[IK_FROM_EPOCH] > best[IK_FROM_EPOCH]):
            best = k
    return best


def epoch_periods(validity: int) -> int:
    """``V = floor(validity / 2,419,200)`` (verifier.md "Lifetime")."""
    return validity // PERIOD


# ---------------------------------------------------------------- disclosure summary


def disclosure_summary(env: dict[int, Any]) -> dict[str, Any]:
    b = env[m.BODY]
    refs = env[m.REFS]
    authority = env.get(m.AUTHORITY, m.envelope_cid(env))
    proves = []
    for a in b[ATTRIBUTES]:
        if a[AT_STATUS] != "active":
            continue
        entry: dict[str, Any] = {
            "name": a[AT_NAME],
            "label": a[AT_LABEL],
            "type": a[AT_TYPE],
            "values": [
                v[ENUM_LABEL] if a[AT_TYPE] == "enum" else v[BAND_LABEL]
                for v in a.get(AT_VALUES, [])
            ],
            "canBreakdown": a[AT_EXPOSURE] == "breakdown",
        }
        if a[AT_TYPE] == "uint":
            entry["max"] = a[AT_MAX]
        proves.append(entry)
    asks = []
    for e in b[EVIDENCE]:
        ask: dict[str, Any] = {
            "name": e[EV_NAME],
            "kind": e[EV_KIND],
            "schema": e[EV_SCHEMA],
            "purpose": e[EV_PURPOSE],
            "required": e[EV_REQUIRED],
            "keptSeconds": e[EV_KEPT],
            "storedAs": e[EV_STORED_AS],
        }
        if EV_ACCEPTS in e:
            ask["accepts"] = [
                {"authority": cid_text(x[ACC_AUTHORITY]), "attributes": list(x[ACC_ATTRIBUTES])}
                for x in e[EV_ACCEPTS]
            ]
        asks.append(ask)
    rv = b[REVOCATION]
    return {
        "who": {
            "name": b[NAME],
            "operator": b[OPERATOR],
            "lang": b[LANG],
            "assurance": b[ASSURANCE],
            "class": b[CLASS],
            "authority": cid_text(authority),
        },
        "proves": proves,
        "asks": asks,
        "links": [{"method": d[DD_METHOD], "scope": d[DD_SCOPE]} for d in b[DEDUP]],
        "expires": {
            "validitySeconds": b[VALIDITY],
            "epochPeriods": epoch_periods(b[VALIDITY]),
            "renewal": rv[RV_METHOD],
        },
        "code": {
            "cid": cid_text(refs["code"]),
            "source": b[CODE][CD_SOURCE].hex(),
            "toolchain": b[CODE][CD_TOOLCHAIN],
            "profile": cid_text(refs["profile"]) if "profile" in refs else None,
        },
        "datasets": [
            {
                "name": d[DS_NAME],
                "kind": d[DS_KIND],
                "records": d[DS_RECORDS],
                "describe": d[DS_DESCRIBE],
            }
            for d in b.get(DATASETS, [])
        ],
    }


m.register("verifier", schema=schema, rules=rules)
