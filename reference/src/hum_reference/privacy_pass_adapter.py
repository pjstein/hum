"""Actual privacypass 0.2.0-pre.3 bridge, isolated from the root Cargo workspace.

Explicit deterministic nonce/blind parameters are for public reference fixtures only.
This is not a network issuer or a membership-proof verifier.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from functools import lru_cache
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

ROOT = Path(__file__).resolve().parents[3]
TOOL = ROOT / "tools/privacy-pass-kat"


@lru_cache(maxsize=1)
def prepare_bridge() -> Path:
    """Build once if source/lock/fixture fingerprint changed; otherwise reuse binary."""
    import fcntl

    target = TOOL / "target"
    target.mkdir(exist_ok=True)
    binary = target / "debug/hum-privacy-pass-kat"
    sources = [
        TOOL / "Cargo.toml",
        TOOL / "Cargo.lock",
        *sorted((TOOL / "src").glob("*.rs")),
        ROOT / "reference/src/hum_reference/data/rfc9578.json",
    ]
    fingerprint = hashlib.sha256(b"".join(p.read_bytes() for p in sources)).hexdigest()
    stamp = target / "bridge.fingerprint"
    with (target / "bridge.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not binary.exists() or not stamp.exists() or stamp.read_text() != fingerprint:
            subprocess.run(
                [
                    "cargo",
                    "build",
                    "--locked",
                    "--manifest-path",
                    str(TOOL / "Cargo.toml"),
                    "--target-dir",
                    str(target),
                ],
                check=True,
                capture_output=True,
            )
            stamp.write_text(fingerprint)
    return binary


def bridge(op: str, **fields: object) -> dict:
    payload = {"op": op, **{k: v.hex() if isinstance(v, bytes) else v for k, v in fields.items()}}
    result = subprocess.run(
        [str(prepare_bridge())],
        input=json.dumps(payload) + "\n",
        text=True,
        capture_output=True,
        check=True,
    )
    reply = json.loads(result.stdout)
    if "error" in reply:
        raise ValueError(reply["error"])
    return reply["ok"]


def channel_seed(master_secret: bytes, group_id: bytes) -> bytes:
    if len(master_secret) != 32 or len(group_id) != 32:
        raise ValueError("delivery master secret and group_id must be 32 bytes")
    return HKDFExpand(
        algorithm=hashes.SHA256(), length=32, info=b"hum/pp-issuer/1" + group_id
    ).derive(master_secret)


def channel_issuer(master_secret: bytes, group_id: bytes) -> dict:
    seed = channel_seed(master_secret, group_id)
    return {
        "seed": seed,
        "info": group_id,
        "public_key": bytes.fromhex(bridge("derive", seed=seed, info=group_id)["public_key"]),
    }
