"""Actual library channel derivation/issuance and durable redemption vectors."""

import tempfile
from dataclasses import replace
from pathlib import Path

from ..privacy_pass import rfc_fixtures
from ..privacy_pass_adapter import bridge, channel_issuer
from ..token_policy import IssuerBinding, NonceLedger, redeem
from . import File


def generate() -> list[File]:
    f = File(
        "services",
        "token-policy",
        "Actual pinned privacypass library outputs; public synthetic keys/nonces/blinds only. DLEQ proof randomness is not serialized. P4 membership and key-lifetime decisions remain external boundaries.",
    )
    group, master, nonce = b"g" * 32, b"s" * 32, b"n" * 32
    issuer = channel_issuer(master, group)
    challenge = bridge("challenge", token_type=1, issuer_name="delivery.example")
    inputs = {
        "master_secret": master.hex(),
        "group_id": group.hex(),
        "nonce": nonce.hex(),
        "blind": rfc_fixtures()["cases"][0]["blind"],
        "issuer_name": "delivery.example",
    }
    actual = bridge(
        "private_issue",
        seed=issuer["seed"],
        info=group,
        challenge=challenge["challenge"],
        nonce=nonce,
        blind=inputs["blind"],
        pinned_public=issuer["public_key"],
    )
    f.add(
        "channel-derive-issue",
        "Derive RFC9497 issuer and finalize actual channel token",
        "chat §12; T-2",
        inputs,
        {"seed": issuer["seed"].hex(), "challenge": challenge["challenge"], **actual},
    )
    binding = IssuerBinding(
        group, b"authority", "delivery.example", issuer["public_key"], issuer["seed"], group
    )
    with tempfile.TemporaryDirectory() as directory:
        policy = dict(
            binding=binding,
            context=group,
            accepted_issuers={b"authority"},
            issuance_connection=b"issue",
            spend_connection=b"spend",
            ledger=NonceLedger(Path(directory) / "spent.sqlite"),
        )
        token = bytes.fromhex(actual["token"])
        for suffix, changes in (
            ("wrong-context", {"context": b"other"}),
            ("unaccepted-authority", {"accepted_issuers": set()}),
            ("same-connection", {"spend_connection": b"issue"}),
            ("wrong-challenge", {"binding": replace(binding, issuer_name="other.example")}),
            ("wrong-key", {"binding": replace(binding, public_key=b"wrong")}),
        ):
            try:
                redeem(token, **{**policy, **changes})
            except ValueError as error:
                f.add(
                    suffix,
                    "Reject policy mismatch without consuming the valid nonce",
                    "T-1–T-4",
                    {"token": actual["token"], "mutation": suffix, "setup": inputs},
                    rejection={"step": None, "check": str(error)},
                )
            else:
                raise AssertionError(suffix)
        redeem(token, **policy)
        f.add(
            "first-spend",
            "Accept after all policy rejections leave nonce unspent",
            "T-1",
            {"token": actual["token"], "setup": inputs},
            {"accepted": True},
        )
        policy["ledger"] = NonceLedger(Path(directory) / "spent.sqlite")
        try:
            redeem(token, **policy)
        except ValueError as error:
            assert str(error) == "token_spent"
            f.add(
                "persistent-repeat",
                "Reject repeat after reopening nonce database",
                "T-1",
                {"token": actual["token"], "setup": inputs},
                rejection={"step": None, "check": "token_spent"},
            )
        else:
            raise AssertionError("repeat accepted")
    return [f]
