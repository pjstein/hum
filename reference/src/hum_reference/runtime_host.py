"""Opt-in adapter for the proposed hum:verifier/host@0.1.0 WIT interface.

Only explicit session inputs cross the process boundary. There is no catch-all
session object, signing callback, request, credential proof, device identifier,
dedup table, transport metadata, clock or storage handle in this interface.
The caller verifies credential/device evidence before supplying disclosed claims.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from wasmtime import component

from . import cbor
from .bodies import verifier as vf
from .bodies import verifier_runtime as vr

PROPOSED_INTERFACE = "hum:verifier/host@0.1.0"
PROPOSED_ABI = "hum:verifier/module@0.1.0"
FUNCTIONS = (
    "manifest-body",
    "manifest-version",
    "evidence-get",
    "evidence-credential",
    "evidence-device",
    "dataset-lookup",
    "dataset-root",
    "time-day",
)


class HostAccessError(ValueError):
    """A guest requested undeclared inputs or used the wrong evidence kind."""


@dataclass(frozen=True)
class EvidenceValue:
    schema: str
    text: str | None = None
    number: int | None = None
    day: int | None = None
    image: bytes | None = None


@dataclass(frozen=True)
class AttributeClaim:
    authority: bytes
    name: str
    value: int


@dataclass(frozen=True)
class DeviceClaim:
    platform: str
    level: int


@dataclass(frozen=True)
class Dataset:
    salt: bytes
    records: tuple[tuple[bytes, tuple[tuple[str, str], ...]], ...]


def _record(**fields):
    result = component.Record()
    for name, value in fields.items():
        setattr(result, name, value)
    return result


@dataclass(frozen=True)
class HostInputs:
    manifest_body: bytes
    version: int
    opening_day: int
    evidence: dict[str, EvidenceValue] = field(default_factory=dict)
    credentials: dict[str, tuple[AttributeClaim, ...]] = field(default_factory=dict)
    devices: dict[str, DeviceClaim] = field(default_factory=dict)
    datasets: dict[str, Dataset] = field(default_factory=dict)

    def validate(self):
        body = cbor.decode(self.manifest_body)
        if cbor.encode(body) != self.manifest_body:
            raise ValueError("manifest body must be canonical CBOR")
        if type(self.version) is not int or not 0 <= self.version < 2**64:
            raise ValueError("invalid version")
        if type(self.opening_day) is not int or not 0 <= self.opening_day < 2**32:
            raise ValueError("invalid opening day")
        evidence = {item[vf.EV_NAME]: item for item in body[vf.EVIDENCE]}
        datasets = {item[vf.DS_NAME]: item for item in body[vf.DATASETS]}
        if (
            not (self.evidence.keys() | self.credentials.keys() | self.devices.keys())
            <= evidence.keys()
        ):
            raise ValueError("undeclared session evidence")
        if not self.datasets.keys() <= datasets.keys():
            raise ValueError("undeclared session dataset")
        for name, value in self.evidence.items():
            item = evidence[name]
            if type(value) is not EvidenceValue or value.schema != item[vf.EV_SCHEMA]:
                raise ValueError("evidence schema mismatch")
            if value.schema in ("credential", "device") or item[vf.EV_KIND] in (
                "credential",
                "device",
            ):
                raise ValueError("credential/device inputs use disclosed claims only")
            populated = {
                k for k in ("text", "number", "day", "image") if getattr(value, k) is not None
            }
            expected = {
                "text": {"text"},
                "number": {"number"},
                "date": {"day"},
                "image": {"image"},
                "none": set(),
            }[value.schema]
            if populated != expected:
                raise ValueError("evidence fields do not match schema")
            if value.text is not None and type(value.text) is not str:
                raise ValueError("text evidence must be text")
            if value.number is not None and (
                type(value.number) is not int or not -(2**63) <= value.number < 2**63
            ):
                raise ValueError("number evidence must fit s64")
            if value.day is not None and (type(value.day) is not int or not 0 <= value.day < 2**32):
                raise ValueError("date evidence must fit u32")
            if value.image is not None:
                if type(value.image) is not bytes:
                    raise ValueError("image must be bytes")
                _check_image(value.image)
        for name, claims in self.credentials.items():
            if evidence[name][vf.EV_KIND] != "credential" or any(
                type(c) is not AttributeClaim for c in claims
            ):
                raise ValueError("credential input must contain disclosed claims only")
            for claim in claims:
                if (
                    type(claim.authority) is not bytes
                    or len(claim.authority) != 33
                    or claim.authority[0] != 1
                    or type(claim.name) is not str
                    or type(claim.value) is not int
                    or not 0 <= claim.value < 2**64
                ):
                    raise ValueError("invalid disclosed attribute claim")
        for name, claim in self.devices.items():
            if evidence[name][vf.EV_KIND] != "device" or type(claim) is not DeviceClaim:
                raise ValueError("device input must contain platform and level only")
            if (
                type(claim.platform) is not str
                or type(claim.level) is not int
                or not 0 <= claim.level < 256
            ):
                raise ValueError("invalid disclosed device claim")
        for name, dataset in self.datasets.items():
            declared = datasets[name]
            if len(dataset.salt) != 32 or len(dataset.records) != declared[vf.DS_RECORDS]:
                raise ValueError("dataset size or salt mismatch")
            if vr.dataset_root(dataset.salt, dataset.records) != declared[vf.DS_COMMITMENT]:
                raise ValueError("dataset commitment mismatch")
        return body


class Host:
    def __init__(self, inputs: HostInputs):
        self.inputs = inputs
        self.body = inputs.validate()
        self.evidence = {item[vf.EV_NAME]: item for item in self.body[vf.EVIDENCE]}
        self.datasets = {item[vf.DS_NAME]: item for item in self.body[vf.DATASETS]}

    def _evidence(self, name, kind=None):
        if name not in self.evidence:
            raise HostAccessError("undeclared evidence")
        if kind is not None and self.evidence[name][vf.EV_KIND] != kind:
            raise HostAccessError("wrong evidence accessor")

    def _dataset(self, name):
        if name not in self.datasets:
            raise HostAccessError("undeclared dataset")

    def manifest_body(self):
        return self.inputs.manifest_body

    def manifest_version(self):
        return self.inputs.version

    def time_day(self):
        return self.inputs.opening_day

    def evidence_get(self, name):
        self._evidence(name)
        value = self.inputs.evidence.get(name)
        return (
            None
            if value is None
            else _record(
                schema=value.schema,
                text=value.text,
                number=value.number,
                day=value.day,
                image=value.image,
            )
        )

    def evidence_credential(self, name):
        self._evidence(name, "credential")
        values = self.inputs.credentials.get(name)
        return (
            None
            if values is None
            else [
                _record(authority=value.authority, name=value.name, value=value.value)
                for value in values
            ]
        )

    def evidence_device(self, name):
        self._evidence(name, "device")
        value = self.inputs.devices.get(name)
        return None if value is None else _record(platform=value.platform, level=value.level)

    def dataset_root(self, name):
        self._dataset(name)
        return self.datasets[name][vf.DS_COMMITMENT]

    def dataset_lookup(self, name, key):
        self._dataset(name)
        dataset = self.inputs.datasets.get(name)
        if dataset is None:
            raise HostAccessError("declared dataset unavailable")
        for index, (record_key, fields) in enumerate(sorted(dataset.records)):
            if record_key == key:
                return _record(
                    fields=list(fields),
                    salt=dataset.salt,
                    proof=vr.inclusion_proof(dataset.salt, dataset.records, index),
                    index=index,
                )
        return None

    def link(self, linker):
        with linker.root() as root, root.add_instance(PROPOSED_INTERFACE) as host:
            for name in FUNCTIONS:
                callback = getattr(self, name.replace("-", "_"))
                host.add_func(name, lambda _store, *args, callback=callback: callback(*args))


def _check_image(data):
    """Conservative container validation, not a pixel decoder or normalizer.

    PNG requires standard IHDR/IDAT/IEND framing and CRCs. JPEG requires SOF,
    SOS and EOI and scans all inter-scan segments, including progressive images.
    Trailing data, EXIF, and unsupported standalone markers fail closed.
    """
    import binascii

    if len(data) > 4 * 1024 * 1024:
        raise ValueError("image exceeds four MiB")
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        offset, seen_header, seen_data, data_ended = 8, False, False, False
        color, palette = None, False
        while offset + 12 <= len(data):
            length = int.from_bytes(data[offset : offset + 4], "big")
            kind = data[offset + 4 : offset + 8]
            end = offset + 12 + length
            if end > len(data):
                raise ValueError("truncated PNG")
            if not all(65 <= v <= 90 or 97 <= v <= 122 for v in kind):
                raise ValueError("invalid PNG chunk type")
            if kind[0] < 97 and kind not in (b"IHDR", b"PLTE", b"IDAT", b"IEND"):
                raise ValueError("unsupported PNG critical chunk")
            payload = data[offset + 8 : end - 4]
            crc = int.from_bytes(data[end - 4 : end], "big")
            if kind == b"eXIf":
                raise ValueError("image carries EXIF")
            if binascii.crc32(kind + payload) != crc:
                raise ValueError("invalid PNG CRC")
            if not seen_header:
                if kind != b"IHDR" or length != 13:
                    raise ValueError("PNG requires initial IHDR")
                width, height = (
                    int.from_bytes(payload[:4], "big"),
                    int.from_bytes(payload[4:8], "big"),
                )
                if (
                    not width
                    or not height
                    or payload[10:12] != b"\x00\x00"
                    or payload[12] not in (0, 1)
                ):
                    raise ValueError("invalid PNG header")
                depths = {0: {1, 2, 4, 8, 16}, 2: {8, 16}, 3: {1, 2, 4, 8}, 4: {8, 16}, 6: {8, 16}}
                if payload[8] not in depths.get(payload[9], set()):
                    raise ValueError("invalid PNG color/depth")
                color = payload[9]
                seen_header = True
            elif kind == b"IHDR":
                raise ValueError("duplicate PNG header")
            if kind == b"PLTE":
                if (
                    palette
                    or seen_data
                    or color in (0, 4)
                    or not length
                    or length > 768
                    or length % 3
                ):
                    raise ValueError("invalid PNG palette")
                palette = True
            if kind == b"IDAT":
                if color == 3 and not palette:
                    raise ValueError("indexed PNG requires palette")
                if data_ended:
                    raise ValueError("noncontiguous PNG data")
                seen_data = True
            elif seen_data:
                data_ended = True
            if kind == b"IEND":
                if length or not seen_data or end != len(data):
                    raise ValueError("invalid PNG end or trailing bytes")
                return
            offset = end
        raise ValueError("invalid PNG")
    if data.startswith(b"\xff\xd8"):
        offset, in_scan, seen_frame, seen_scan = 2, False, False, False
        while offset < len(data):
            if in_scan:
                # Entropy bytes are opaque. FF00 is stuffed data; restart markers
                # remain inside the scan. Every other marker exits entropy mode.
                if data[offset] != 255:
                    offset += 1
                    continue
                while offset < len(data) and data[offset] == 255:
                    offset += 1
                if offset == len(data):
                    break
                marker = data[offset]
                if marker == 0 or 0xD0 <= marker <= 0xD7:
                    offset += 1
                    continue
                offset -= 1
                in_scan = False
            if offset + 2 > len(data) or data[offset] != 255:
                raise ValueError("invalid JPEG segment")
            while offset < len(data) and data[offset] == 255:
                offset += 1
            if offset == len(data):
                break
            marker = data[offset]
            offset += 1
            if marker == 0xD9:
                if not seen_frame or not seen_scan or offset != len(data):
                    raise ValueError("invalid JPEG end or trailing bytes")
                return
            if marker in (0, 1, 0xD8) or 0xD0 <= marker <= 0xD7:
                raise ValueError("unsupported JPEG marker")
            if offset + 2 > len(data):
                break
            length = int.from_bytes(data[offset : offset + 2], "big")
            end = offset + length
            if length < 2 or end > len(data):
                raise ValueError("invalid JPEG segment length")
            payload = data[offset + 2 : end]
            if marker == 0xE1 and payload.startswith(b"Exif\0\0"):
                raise ValueError("image carries EXIF")
            if marker in (0xC0, 0xC1, 0xC2):
                if len(payload) < 6 or len(payload) != 6 + 3 * payload[5]:
                    raise ValueError("invalid JPEG frame")
                seen_frame = True
            elif 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
                raise ValueError("unsupported JPEG frame")
            if marker == 0xDA:
                if not seen_frame or not payload or len(payload) != 4 + 2 * payload[0]:
                    raise ValueError("invalid JPEG scan")
                seen_scan, in_scan = True, True
            offset = end
    raise ValueError("expected complete PNG or JPEG")


EVIDENCE_SHAPE = [
    ("schema", "String"),
    ("text", ("option", "String")),
    ("number", ("option", "S64")),
    ("day", ("option", "U32")),
    ("image", ("option", ("list", "U8"))),
]
CLAIM_SHAPE = [("authority", ("list", "U8")), ("name", "String"), ("value", "U64")]
DEVICE_SHAPE = [("platform", "String"), ("level", "U8")]
DATASET_SHAPE = [
    ("fields", ("list", ("tuple", "String", "String"))),
    ("salt", ("list", "U8")),
    ("proof", ("list", ("list", "U8"))),
    ("index", "U64"),
]
SIGNATURES = {
    "manifest-body": ([], ("list", "U8")),
    "manifest-version": ([], "U64"),
    "time-day": ([], "U32"),
    "evidence-get": ([("name", "String")], ("option", EVIDENCE_SHAPE)),
    "evidence-credential": ([("name", "String")], ("option", ("list", CLAIM_SHAPE))),
    "evidence-device": ([("name", "String")], ("option", DEVICE_SHAPE)),
    "dataset-lookup": ([("name", "String"), ("key", ("list", "U8"))], ("option", DATASET_SHAPE)),
    "dataset-root": ([("name", "String")], ("list", "U8")),
}


def imports_allowed(compiled, engine, shape):
    imports = compiled.type.imports(engine)
    if set(imports) - {PROPOSED_INTERFACE}:
        return False
    for imported in imports.values():
        if not isinstance(imported.ty, component.ComponentInstanceType):
            return False
        for name, item in imported.ty.exports(engine).items():
            if name in SIGNATURES:
                if not isinstance(item.ty, component.FuncType):
                    return False
                params, result = SIGNATURES[name]
                if [(n, shape(t)) for n, t in item.ty.params] != params or shape(
                    item.ty.result
                ) != result:
                    return False
            elif name not in {
                "evidence-value",
                "attribute-claim",
                "device-claim",
                "dataset-record",
            } or isinstance(item.ty, component.FuncType):
                return False
    return True
