"""Service-side token policy around verified library outputs.

Issuer configuration and current context/key authorization come from an externally
verified context. Issuance requires the separate P4 membership proof boundary; this
module deliberately exposes no boolean that pretends to verify that proof. Rotation
expiry is caller-owned until the spec resolves exact context-key retention semantics.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from . import cbor
from .privacy_pass import Token, verify_public_token
from .privacy_pass_adapter import bridge


@dataclass(frozen=True)
class IssuerBinding:
    context: bytes
    authority: bytes
    issuer_name: str
    public_key: bytes
    seed: bytes
    info: bytes
    token_type: int = 1


class NonceLedger:
    """Durable T1 uniqueness. No automatic expiry/pruning invents key lifetime."""

    def __init__(self, path: str | Path):
        self.path = str(path)
        with self._connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS spent "
                "(issuer BLOB, nonce BLOB, PRIMARY KEY(issuer,nonce))"
            )

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        try:
            with db:
                yield db
        finally:
            db.close()

    def spend(self, issuer: bytes, nonce: bytes) -> None:
        try:
            with self._connect() as db:
                db.execute("INSERT INTO spent VALUES (?,?)", (issuer, nonce))
        except sqlite3.IntegrityError as error:
            raise ValueError("token_spent") from error


def redeem(
    token: bytes,
    *,
    binding: IssuerBinding,
    context: bytes,
    accepted_issuers: set[bytes],
    issuance_connection: bytes,
    spend_connection: bytes,
    ledger: NonceLedger,
) -> None:
    if binding.context != context or binding.authority not in accepted_issuers:
        raise ValueError("issuer_context_binding")
    if not issuance_connection or not spend_connection or issuance_connection == spend_connection:
        raise ValueError("connection_separation")
    fixed = bridge("challenge", token_type=binding.token_type, issuer_name=binding.issuer_name)
    if binding.token_type == 2:
        if not verify_public_token(token, bytes.fromhex(fixed["challenge"]), binding.public_key):
            raise ValueError("issuer_key_challenge_binding")
        parsed = Token.decode(token)
        ledger.spend(parsed.key_id, parsed.nonce)
        return
    result = bridge("verify", seed=binding.seed, info=binding.info, token=token)
    if (
        bytes.fromhex(result["public_key"]) != binding.public_key
        or bytes.fromhex(result["key_id"]) != hashlib.sha256(binding.public_key).digest()
        or result["challenge_digest"] != fixed["digest"]
    ):
        raise ValueError("issuer_key_challenge_binding")
    ledger.spend(bytes.fromhex(result["key_id"]), bytes.fromhex(result["nonce"]))


def finalize_channel_token(
    *, binding: IssuerBinding, group_id: bytes, directory_key: bytes, nonce: bytes, blind: bytes
) -> dict:
    """Directory/context issuerKeys are externally verified; pin before request/finalize."""
    if (
        binding.context != group_id
        or binding.public_key != directory_key
        or binding.token_type != 1
    ):
        raise ValueError("directory_issuer_binding")
    return bridge(
        "private_issue",
        seed=binding.seed,
        info=binding.info,
        pinned_public=directory_key,
        nonce=nonce,
        blind=blind,
        challenge=bridge("challenge", token_type=1, issuer_name=binding.issuer_name)["challenge"],
    )


def authenticate_channel_request(
    request: dict, held_secrets: tuple[bytes, ...], tokens_per_issuance: int
) -> int:
    """Return matched held-secret index; caller must record its use per chat policy."""
    if (
        set(request) != {0, 1, 2, 3, 4}
        or type(request[0]) is not int
        or request[0] != 1
        or not isinstance(request[1], bytes)
        or len(request[1]) != 32
        or type(request[2]) is not int
        or not 0 <= request[2] < 2**64
        or not isinstance(request[3], list)
        or not 1 <= len(request[3]) <= tokens_per_issuance
        or not all(
            isinstance(x, bytes) and len(x) == 52 and x[:2] == b"\x00\x01" for x in request[3]
        )
        or not isinstance(request[4], bytes)
        or len(request[4]) != 32
    ):
        raise ValueError("channel_request_shape")
    for blinded in request[3]:
        bridge("validate_request", request=blinded)
    message = b"hum/token-request/1" + cbor.dumps({i: request[i] for i in range(4)})
    for index, secret in enumerate(held_secrets):
        if hmac.compare_digest(hmac.digest(secret, message, "sha256"), request[4]):
            return index
    raise ValueError("channel_request_mac")


class FetchSessions:
    """15-minute fetch-only cookies, minted only after token redemption.

    The service supplies its trusted session clock and periodically calls expire
    even while idle; request-time cleanup alone cannot implement idle forgetting.
    """

    def __init__(self):
        self._sessions: dict[bytes, tuple[bytes, float]] = {}

    def expire(self, *, now: float) -> int:
        """Forget elapsed cookies; return the number removed, using a trusted clock."""
        try:
            valid = type(now) in (int, float) and math.isfinite(now)
        except OverflowError:
            valid = False
        if not valid:
            raise ValueError("invalid session clock")
        expired = [
            cookie for cookie, (_, started) in self._sessions.items() if now - started >= 900
        ]
        for cookie in expired:
            del self._sessions[cookie]
        return len(expired)

    def redeem_and_open(self, token: bytes, *, now: float, **policy) -> bytes:
        self.expire(now=now)
        redeem(token, **policy)
        cookie = secrets.token_bytes(16)
        self._sessions[cookie] = (policy["context"], now)
        return cookie

    def authorize_fetch(self, cookie: bytes, *, context: bytes, now: float) -> None:
        self.expire(now=now)
        item = self._sessions.get(cookie)
        if item is None or item[0] != context or not 0 <= now - item[1] < 900:
            raise ValueError("fetch_session_expired")
