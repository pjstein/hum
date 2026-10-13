import multiprocessing
import time

import pytest

from hum_reference import component_runtime as runtime
from hum_reference import runtime_host as rh
from hum_reference.bodies import verifier_runtime as vr
from hum_reference.cid import cid
from hum_reference.vectors.runtime_host_vectors import imported_probe, inputs


def test_session_day_replay_and_explicit_opt_in():
    module = imported_probe()
    assert runtime.run(module, cid(module)).status == "module-import"
    for day in (2, 3, 2):
        result = runtime.run(module, cid(module), proposed_host=inputs(day))
        assert result.value == {"code": day, "retry": False}


@pytest.mark.parametrize(
    "function,name,status",
    [
        ("evidence-get", "address", "rejected"),
        ("manifest-version", "", "rejected"),
        ("manifest-body", "", "rejected"),
        ("evidence-credential", "card", "rejected"),
        ("evidence-device", "device", "rejected"),
        ("dataset-root", "roster", "rejected"),
        ("evidence-get", "undeclared", "module-host-input"),
        ("dataset-lookup", "roster", "rejected"),
        ("dataset-lookup", "undeclared", "module-host-input"),
    ],
)
def test_real_import_access(function, name, status):
    module = imported_probe(function, name)
    result = runtime.run(module, cid(module), proposed_host=inputs())
    assert result.status == status
    if result.value:
        assert result.value["code"] == 1
    assert result.issued == result.dedup_writes == 0


def test_host_discloses_only_declared_claims_and_proofs():
    host = rh.Host(inputs())
    assert host.manifest_version() == 1
    assert host.evidence_get("address").text == "Synthetic"
    assert vars(host.evidence_device("device")) == {"platform": "synthetic", "level": 1}
    assert set(vars(host.evidence_credential("card")[0])) == {"authority", "name", "value"}
    record = host.dataset_lookup("roster", b"a")
    assert vr.verify_inclusion(
        record.salt, b"a", record.fields, record.index, 1, record.proof, host.dataset_root("roster")
    )
    assert host.dataset_lookup("roster", b"missing") is None
    with pytest.raises(rh.HostAccessError):
        host.evidence_device("address")
    with pytest.raises(TypeError):
        rh.DeviceClaim("synthetic", 1, device_key_hash=b"secret")


def _slow_import(connection, module, session, entered):
    def blocked(self):
        entered.set()
        time.sleep(30)
        return self.inputs.opening_day

    rh.Host.time_day = blocked
    runtime._worker(connection, module, None, session)


def test_deadline_interrupts_actual_host_import():
    context = multiprocessing.get_context("spawn")
    receive, send = context.Pipe(duplex=False)
    entered = context.Event()
    process = context.Process(
        target=_slow_import, args=(send, imported_probe(), inputs(), entered), daemon=True
    )
    process.start()
    send.close()
    try:
        assert entered.wait(3), "component must enter actual host callback"
    except BaseException:
        process.kill()
        process.join(timeout=0.1)
        raise
    start = time.monotonic()
    outcome = runtime._collect(process, receive, 0.5)
    assert outcome.status == "module-limit"
    assert time.monotonic() - start < 2
    assert not process.is_alive()


def test_wrong_function_signature_and_extra_capability_are_refused():
    import wasmtime

    for interface in (
        '(export "time-day" (func (result string)))',
        '(export "sign" (func (param "message" (list u8)) (result (list u8))))',
    ):
        module = wasmtime.wat2wasm(
            f'(component (import "{rh.PROPOSED_INTERFACE}" (instance {interface})))'
        )
        assert runtime.run(module, cid(module), proposed_host=inputs()).status == "module-import"


def test_secret_fields_cannot_leak_through_claim_projection():
    session = inputs()
    object.__setattr__(session.devices["device"], "device_key_hash", b"must not escape")
    object.__setattr__(session.credentials["card"][0], "nullifier", b"must not escape")
    object.__setattr__(session.evidence["address"], "transport_address", "must not escape")
    host = rh.Host(session)
    assert set(vars(host.evidence_device("device"))) == {"platform", "level"}
    assert set(vars(host.evidence_credential("card")[0])) == {"authority", "name", "value"}
    assert set(vars(host.evidence_get("address"))) == {"schema", "text", "number", "day", "image"}


def test_bad_dataset_and_undeclared_session_inputs_are_refused():
    import dataclasses

    session = inputs()
    with pytest.raises(ValueError, match="commitment"):
        rh.Host(
            dataclasses.replace(
                session,
                datasets={"roster": rh.Dataset(bytes(32), session.datasets["roster"].records)},
            )
        )
    with pytest.raises(ValueError, match="undeclared"):
        rh.Host(
            dataclasses.replace(
                session, evidence={"unknown": rh.EvidenceValue("text", text="private")}
            )
        )


def test_image_size_and_exif_are_checked_before_module_execution():
    with pytest.raises(ValueError, match="four MiB"):
        rh._check_image(bytes(4 * 1024 * 1024 + 1))
    jpeg = b"\xff\xd8\xff\xe1\x00\x08Exif\x00\x00\xff\xd9"
    with pytest.raises(ValueError, match="EXIF"):
        rh._check_image(jpeg)
    png = b"\x89PNG\r\n\x1a\n" + b"\0\0\0\0eXIf" + bytes(4)
    with pytest.raises(ValueError, match="EXIF"):
        rh._check_image(png)


def test_credential_kind_cannot_use_raw_text_schema():
    from dataclasses import replace

    from hum_reference import cbor
    from hum_reference.bodies import verifier as vf

    session = inputs()
    body = cbor.decode(session.manifest_body)
    for item in body[vf.EVIDENCE]:
        if item[vf.EV_NAME] == "card":
            item[vf.EV_SCHEMA] = "text"
    with pytest.raises(ValueError, match="disclosed claims"):
        rh.Host(
            replace(
                session,
                manifest_body=cbor.encode(body),
                evidence={"card": rh.EvidenceValue("text", text="raw proof")},
            )
        )


def test_image_container_end_and_inter_scan_metadata():
    import binascii

    def chunk(kind, payload=b""):
        return (
            len(payload).to_bytes(4, "big")
            + kind
            + payload
            + binascii.crc32(kind + payload).to_bytes(4, "big")
        )

    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", b"\x00\x00\x00\x01" * 2 + b"\x08\x02\x00\x00\x00")
        + chunk(b"IDAT", b"opaque compressed pixels")
        + chunk(b"IEND")
    )
    rh._check_image(png)  # Container check only; deliberately does not decode pixels.
    for bad in (
        png + b"Exif\0\0secret",
        png[:-1] + bytes([png[-1] ^ 1]),
        b"\x89PNG\r\n\x1a\n" + chunk(b"IEND"),
        png[:-12] + chunk(b"eXIf", b"secret") + chunk(b"IEND"),
    ):
        with pytest.raises(ValueError):
            rh._check_image(bad)

    def segment(marker, payload):
        return b"\xff" + bytes([marker]) + (len(payload) + 2).to_bytes(2, "big") + payload

    frame = segment(0xC2, b"\x08\x00\x01\x00\x01\x01\x01\x11\x00")
    scan = segment(0xDA, b"\x01\x01\x00\x00\x3f\x00")
    jpeg = b"\xff\xd8" + frame + scan + b"opaque\xff\x00\xff\xd0" + scan + b"pixels\xff\xd9"
    rh._check_image(jpeg)
    for bad in (
        jpeg + b"trailing",
        jpeg[:-2],
        jpeg[:-2] + segment(0xE1, b"Exif\0\0secret") + b"\xff\xd9",
    ):
        with pytest.raises(ValueError):
            rh._check_image(bad)
