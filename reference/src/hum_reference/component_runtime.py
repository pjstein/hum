"""Isolated no-import verifier component execution and hostile sandbox probes.

This implements the normative decide result shape, but is deliberately not the
five profile binaries or a complete host-world adapter. Until a pinned WIT ABI
is available, imports fail closed. No issuer secrets or dedup state enter here.
A process boundary makes the deadline enforceable even while native/host code
is running; each call has fresh memory and is reaped before returning.
"""

from __future__ import annotations

import multiprocessing
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import wasmtime
from wasmtime import component

from .cid import cid

MODULE_BYTES = 16 * 1024 * 1024
MEMORY_BYTES = 64 * 1024 * 1024
STACK_BYTES = 1024 * 1024
WALL_SECONDS = 10.0
PROBES = Path(__file__).parent / "data" / "runtime"


@dataclass(frozen=True)
class Outcome:
    status: str
    value: dict | None = None
    retryable: bool = False
    issued: int = 0
    dedup_writes: int = 0


def engine():
    config = wasmtime.Config()
    config.wasm_component_model = True
    config.wasm_threads = False
    config.wasm_relaxed_simd = False
    config.cranelift_nan_canonicalization = True
    config.max_wasm_stack = STACK_BYTES
    config.consume_fuel = True
    return wasmtime.Engine(config)


def _shape(ty):
    if isinstance(ty, component.RecordType):
        return [(name, _shape(value)) for name, value in ty.fields]
    if isinstance(ty, component.ListType):
        return ("list", _shape(ty.element))
    if isinstance(ty, component.TupleType):
        return ("tuple", *[_shape(value) for value in ty.elements])
    if isinstance(ty, component.ResultType):
        return ("result", _shape(ty.ok), _shape(ty.err))
    return type(ty).__name__


DECISION_SHAPE = (
    "result",
    [
        ("attributes", ("list", ("tuple", "String", "U64"))),
        ("dedup-keys", ("list", ("list", "U8"))),
    ],
    [("code", "U16"), ("retry", "Bool")],
)


def _worker(connection, module_bytes, fuel):
    try:
        runtime = engine()
        compiled = component.Component(runtime, module_bytes)
        if compiled.type.imports(runtime):
            connection.send(Outcome("module-import"))
            return
        store = wasmtime.Store(runtime)
        # At most one memory prevents multiplying the per-memory cap.
        store.set_limits(memory_size=MEMORY_BYTES, memories=1)
        store.set_fuel(fuel if fuel is not None else 2**64 - 1)
        instance = component.Linker(runtime).instantiate(store, compiled)
        decide = instance.get_func(store, "decide")
        if decide is None:
            connection.send(Outcome("module-abi"))
            return
        signature = decide.type(store)
        if signature.params or _shape(signature.result) != DECISION_SHAPE:
            connection.send(Outcome("module-abi"))
            return
        answer = decide(store)
        decide.post_return(store)
        if answer.tag == "ok":
            value = {
                "attributes": answer.payload.attributes,
                "dedup_keys": getattr(answer.payload, "dedup-keys"),
            }
            connection.send(Outcome("decision", value))
        else:
            code, retry = answer.payload.code, answer.payload.retry
            if code > 999 or 6 <= code < 100:
                connection.send(Outcome("module-invalid-rejection"))
            else:
                connection.send(Outcome("rejected", {"code": code, "retry": retry}, retry))
    except wasmtime.WasmtimeError as error:
        text = str(error).lower()
        limited = any(
            marker in text
            for marker in (
                "fuel",
                "stack overflow",
                "call stack exhausted",
                "memory minimum size",
                "resource limit",
                "memory size",
            )
        )
        connection.send(Outcome("module-limit" if limited else "module-invalid", retryable=limited))
    except wasmtime.Trap:
        connection.send(Outcome("module-limit", retryable=True))
    finally:
        connection.close()


def run(module_bytes: bytes, expected_cid: bytes, *, timeout=WALL_SECONDS, fuel=1_000_000):
    """Execute one isolated call. Shorter host deadlines/fuel may stop early.

    Compilation/startup count against this host's budget too (stricter than the
    maximum decide budget). The harness returns no credential or dedup mutation.
    """
    if not 0 < timeout <= WALL_SECONDS:
        raise ValueError("deadline must be positive and at most ten seconds")
    if len(module_bytes) > MODULE_BYTES:
        return Outcome("module-limit", retryable=True)
    if cid(module_bytes) != expected_cid:
        return Outcome("module-cid")
    context = multiprocessing.get_context("spawn")
    receive, send = context.Pipe(duplex=False)
    process = context.Process(target=_worker, args=(send, module_bytes, fuel), daemon=True)
    started = time.monotonic()
    process.start()
    send.close()
    return _collect(process, receive, max(0, timeout - (time.monotonic() - started)))


def _collect(process, receive, timeout):
    # poll() only promises a partial pipe message. recv() must itself remain
    # inside the deadline, including deserialization of a large module result.
    complete = threading.Event()
    result = []

    def receive_result():
        try:
            result.append(receive.recv())
        except (EOFError, OSError):
            result.append(Outcome("module-invalid"))
        finally:
            complete.set()

    reader = threading.Thread(target=receive_result, daemon=True)
    reader.start()
    try:
        if complete.wait(timeout):
            return result[0]
        return Outcome("module-limit", retryable=True)
    finally:
        if process.is_alive():
            process.kill()
        # Do not turn cleanup into an unbounded wait after a deadline expired.
        process.join(timeout=0.1)
        reader.join(timeout=0.1)
        receive.close()


def probe(name):
    return wasmtime.wat2wasm((PROBES / f"{name}.wat").read_text())


def validate_decision(value: dict, verifier_body: dict) -> str | None:
    """Host rules 7–10 before any credential signing or dedup reads/writes.

    The caller must supply a validated manifest body and a decision decoded from
    the checked component ABI. Epoch selection remains credentials.decide_issuance.
    """
    from .bodies import verifier as vf

    declared = {a[vf.AT_NAME]: a for a in verifier_body[vf.ATTRIBUTES]}
    attributes = value["attributes"]
    for name, _number in attributes:
        if name not in declared or declared[name][vf.AT_STATUS] != "active":
            return "host-invalid-attribute"
    for name, number in attributes:
        attribute = declared[name]
        kind = attribute[vf.AT_TYPE]
        if type(number) is not int or not 0 <= number < 2**64:
            return "host-invalid-value"
        if kind == "bool":
            valid = number == 1
        elif kind == "enum":
            valid = number in {v[vf.ENUM_V] for v in attribute[vf.AT_VALUES]}
        elif kind == "band":
            valid = number < len(attribute[vf.AT_VALUES])
        else:
            valid = number <= attribute[vf.AT_MAX]
        if not valid:
            return "host-invalid-value"
    required = vf.PROFILE_RULES.get(verifier_body[vf.PROFILE], {}).get("required", {})
    if not set(required) <= {name for name, _ in attributes}:
        return "host-missing-attribute"
    count = sum(item[vf.DD_METHOD] == "evidence" for item in verifier_body[vf.DEDUP])
    if len(value["dedup_keys"]) != count:
        return "host-invalid-dedup"
    return None
