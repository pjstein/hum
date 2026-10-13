"""Executable probes for the proposed (not yet normative) WIT host ABI."""

import dataclasses

import wasmtime

from .. import cbor
from .. import component_runtime as runtime
from .. import runtime_host as rh
from ..bodies import verifier as vf
from ..bodies import verifier_runtime as vr
from ..cid import cid
from . import File, jsonable


def inputs(day=2):
    records = ((b"a", (("name", "Synthetic"),)),)
    salt = bytes(range(32))
    body = {
        vf.PROFILE: "custom",
        vf.ATTRIBUTES: [],
        vf.DEDUP: [],
        vf.EVIDENCE: [
            vf.evidence("address", "address", "text", "synthetic test"),
            vf.evidence("card", "credential", "credential", "synthetic test"),
            vf.evidence("device", "device", "device", "synthetic test"),
        ],
        vf.DATASETS: [
            {
                vf.DS_NAME: "roster",
                vf.DS_COMMITMENT: vr.dataset_root(salt, records),
                vf.DS_RECORDS: 1,
            }
        ],
    }
    return rh.HostInputs(
        cbor.encode(body),
        1,
        day,
        evidence={"address": rh.EvidenceValue("text", text="Synthetic")},
        credentials={"card": (rh.AttributeClaim(b"\x01" + bytes(32), "member", 1),)},
        devices={"device": rh.DeviceClaim("synthetic", 1)},
        datasets={"roster": rh.Dataset(salt, records)},
    )


# The actual imported component executes its host operation before returning the
# normative rejection record. Codes here are probe signals, not profile decisions.
def imported_probe(function="time-day", name="address"):
    declarations = {
        "time-day": '(export "time-day" (func (result u32)))',
        "manifest-version": '(export "manifest-version" (func (result u64)))',
        "manifest-body": '(export "manifest-body" (func (result (list u8))))',
        "dataset-root": '(export "dataset-root" (func (param "name" string) (result (list u8))))',
        "evidence-credential": """(type $a (record (field "authority" (list u8)) (field "name" string) (field "value" u64)))
          (export "attribute-claim" (type $at (eq $a)))
          (export "evidence-credential" (func (param "name" string) (result (option (list $at)))))""",
        "evidence-device": """(type $d (record (field "platform" string) (field "level" u8)))
          (export "device-claim" (type $dt (eq $d)))
          (export "evidence-device" (func (param "name" string) (result (option $dt))))""",
        "evidence-get": """(type $e (record (field "schema" string) (field "text" (option string))
          (field "number" (option s64)) (field "day" (option u32)) (field "image" (option (list u8)))))
          (export "evidence-value" (type $et (eq $e)))
          (export "evidence-get" (func (param "name" string) (result (option $et))))""",
        "dataset-lookup": """(type $d (record (field "fields" (list (tuple string string)))
          (field "salt" (list u8)) (field "proof" (list (list u8))) (field "index" u64)))
          (export "dataset-record" (type $dt (eq $d)))
          (export "dataset-lookup" (func (param "name" string) (param "key" (list u8)) (result (option $dt))))""",
    }
    if function == "time-day":
        signature, call = "(result i32)", "call $call"
    elif function == "manifest-version":
        signature, call = "(result i64)", "call $call i32.wrap_i64"
    elif function == "manifest-body":
        signature = "(param i32)"
        call = "i32.const 512 call $call i32.const 516 i32.load i32.const 0 i32.ne"
    else:
        signature = (
            "(param i32 i32 i32 i32 i32)" if function == "dataset-lookup" else "(param i32 i32 i32)"
        )
        call = (
            f"i32.const 128 i32.const {len(name)} "
            + ("i32.const 256 i32.const 1 " if function == "dataset-lookup" else "")
            + "i32.const 512 call $call "
        )
        call += (
            "i32.const 516 i32.load i32.const 0 i32.ne"
            if function == "dataset-root"
            else "i32.const 512 i32.load8_u"
        )
    wat = f'''(component
      (import "{rh.PROPOSED_INTERFACE}" (instance $host {declarations[function]}))
      (alias export $host "{function}" (func $call))
      (core module $memory
        (memory (export "memory") 1)
        (global $next (mut i32) (i32.const 4096))
        (func (export "realloc") (param i32 i32 i32 i32) (result i32)
          (local $out i32)
          global.get $next local.get 2 i32.const 1 i32.sub i32.add
          i32.const 0 local.get 2 i32.sub i32.and local.tee $out
          local.get 3 i32.add global.set $next local.get $out))
      (core instance $memory (instantiate $memory))
      (core func $lower (canon lower (func $call) (memory $memory "memory") (realloc (func $memory "realloc"))))
      (core module $main
        (import "mem" "memory" (memory 1))
        (import "host" "call" (func $call {signature}))
        (data (i32.const 128) "{name}") (data (i32.const 256) "a")
        (func (export "decide") (result i32)
          i32.const 0 i32.const 1 i32.store
          i32.const 4 {call} i32.store16 i32.const 0))
      (core instance $main (instantiate $main
        (with "mem" (instance $memory)) (with "host" (instance (export "call" (func $lower))))))
      (type $d (record (field "attributes" (list (tuple string u64))) (field "dedup-keys" (list (list u8)))))
      (type $r (record (field "code" u16) (field "retry" bool)))
      (export $de "decision" (type $d)) (export $re "rejection" (type $r))
      (func (export "decide") (result (result $de (error $re)))
        (canon lift (core func $main "decide") (memory $memory "memory"))))'''
    return wasmtime.wat2wasm(wat)


def generate():
    f = File(
        "experimental",
        "proposed-host",
        "Experimental opt-in ABI hum:verifier/host@0.1.0; exact WIT artifact under reference/src/hum_reference/data/runtime/wit. Probes call each declared host operation and return actual result<decision,rejection>. Rejection codes in these probes signal a host return value; they do not implement any profile decision algorithm or phone response. No normative code.abi allowlist is changed.",
    )
    cases = [
        (name, parameter, 2 if name == "time-day" else 1, 2)
        for name, parameter in (
            ("time-day", ""),
            ("manifest-body", ""),
            ("manifest-version", ""),
            ("evidence-get", "address"),
            ("evidence-credential", "card"),
            ("evidence-device", "device"),
            ("dataset-root", "roster"),
            ("dataset-lookup", "roster"),
        )
    ]
    cases += [("time-day", "", 3, 3), ("time-day", "", 2, 2)]
    for function, name, code, day in cases:
        module = imported_probe(function, name)
        session = inputs(day)
        outcome = runtime.run(module, cid(module), proposed_host=session)
        assert outcome.value == {"code": code, "retry": False}, (function, outcome)
        f.add(
            function,
            "Call " + function + " under proposed ABI",
            "The host interface",
            {
                "proposed_abi": rh.PROPOSED_ABI,
                "component": module.hex(),
                "code_cid": cid(module).hex(),
                "session_inputs": jsonable(dataclasses.asdict(session)),
            },
            expected={"status": outcome.status, "result": outcome.value},
        )
    for function in ("evidence-get", "dataset-lookup"):
        module = imported_probe(function, "undeclared")
        session = inputs()
        outcome = runtime.run(module, cid(module), proposed_host=session)
        assert outcome.status == "module-host-input"
        f.add(
            function + "-undeclared",
            "Undeclared name traps without issuance",
            "Validation rules 4–5",
            {
                "proposed_abi": rh.PROPOSED_ABI,
                "component": module.hex(),
                "code_cid": cid(module).hex(),
                "session_inputs": jsonable(dataclasses.asdict(session)),
            },
            rejection={
                "step": None,
                "check": "host-import",
                "reason": outcome.status,
                "issued": 0,
                "dedup_writes": 0,
            },
        )
    return [f]
