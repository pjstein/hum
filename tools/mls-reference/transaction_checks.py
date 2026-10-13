"""Synthetic group snapshots enable exact replay; --capture explicitly replaces the fixture.

The fixture contains PUBLIC SYNTHETIC PRIVATE KEYS and must never be used for live groups.
No attempt is made to pretend the provider's random group setup is deterministic.
"""

import copy
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hum_policy import cbor, frank_aad, stamp_input, verify_frank
from mls_rs_uniffi import (
    CipherSuite,
    Client,
    ClientConfig,
    Error,
    GroupStateStorage,
    Message,
    SignatureKeypair,
    SignaturePublicKey,
    SignatureSecretKey,
    generate_signature_keypair,
)

HERE = Path(__file__).resolve().parent
GID = bytes(range(32))
LABEL = b"hum/delivery/1"


class Store(GroupStateStorage):
    def __init__(self, snapshot=None):
        self.rows = copy.deepcopy(snapshot or {})
        self.writes = 0

    def state(self, group_id):
        row = self.rows.get(group_id.hex())
        return bytes.fromhex(row["state"]) if row else None

    def epoch(self, group_id, epoch_id):
        row = self.rows.get(group_id.hex())
        value = row["epochs"].get(str(epoch_id)) if row else None
        return bytes.fromhex(value) if value else None

    def write(self, group_id, group_state, epoch_inserts, epoch_updates):
        self.writes += 1
        row = self.rows.setdefault(group_id.hex(), {"epochs": {}})
        row["state"] = group_state.hex()
        for epoch in [*epoch_inserts, *epoch_updates]:
            row["epochs"][str(epoch.id)] = epoch.data.hex()

    def max_epoch_id(self, group_id):
        row = self.rows.get(group_id.hex())
        return max(map(int, row["epochs"]), default=None) if row else None


def key_json(key):
    return {"public": key.public_key.bytes.hex(), "secret": key.secret_key.bytes.hex()}


def key_from(value):
    return SignatureKeypair(
        cipher_suite=CipherSuite.CURVE25519_AES128,
        public_key=SignaturePublicKey(bytes=bytes.fromhex(value["public"])),
        secret_key=SignatureSecretKey(bytes=bytes.fromhex(value["secret"])),
    )


def client(name, key, store, private=True):
    cfg = ClientConfig(group_state_storage=store, use_ratchet_tree_extension=True)
    return Client.new_with_private_messages(name, key, cfg, private)


def rejects(call):
    try:
        call()
    except Error as error:
        assert type(error).__module__ == "mls_rs_uniffi", type(error)
    else:
        raise AssertionError("expected MLS/policy rejection")


def capture():
    ak, bk = [
        generate_signature_keypair(CipherSuite.CURVE25519_AES128) for _ in range(2)
    ]
    ast, bst = Store(), Store()
    ac, bc = client(b"synthetic-alice", ak, ast), client(b"synthetic-bob", bk, bst)
    ag = ac.create_group(GID)
    add = ag.add_members_with_aad([bc.generate_key_package_message()], b"\x00")
    ag.process_incoming_message_transactional(add.commit_message, True)
    bg = bc.join_group(None, add.welcome_message).group
    ag.write_to_storage()
    bg.write_to_storage()
    stores = {"alice": copy.deepcopy(ast.rows), "bob": copy.deepcopy(bst.rows)}
    # MIMI InlinePart: fixture plaintext includes its test franking key.
    mimi = cbor.encode(
        [
            bytes(16),
            None,
            b"",
            None,
            None,
            {"hum.frank": bytes([83]) * 32},
            [1, "", 1, "text/plain", b"synthetic message"],
        ]
    )
    aad = frank_aad(GID, 1, mimi)
    frame = ag.encrypt_application_message_with_aad(mimi, aad).to_bytes()
    assert frame.count(aad) == 1
    offset = frame.index(aad)
    tampered = (
        frame[: offset + 1] + bytes([frame[offset + 1] ^ 1]) + frame[offset + 2 :]
    )

    # Create alternate next-epoch commits from the same saved sender state.
    def sender(private=True):
        return client(
            b"synthetic-alice", ak, Store(stores["alice"]), private
        ).load_group(GID)

    wrong = sender().commit_with_aad(b"").commit_message.to_bytes()
    public = sender(False).commit_with_aad(b"\x00").commit_message.to_bytes()
    valid_sender = sender()
    commit = valid_sender.commit_with_aad(b"\x00").commit_message
    valid_sender.process_incoming_message_transactional(commit, True)
    # Separate application-policy failure generated before control advances epoch.
    malformed_app = (
        sender().encrypt_application_message_with_aad(mimi, b"\x00").to_bytes()
    )
    proposal_sender = sender()
    ck = generate_signature_keypair(CipherSuite.CURVE25519_AES128)
    cc = client(b"synthetic-charlie", ck, Store())
    proposal = proposal_sender.propose_add_members_with_aad(
        [cc.generate_key_package_message()], b"\x00"
    )[0]
    stamp_key = Ed25519PrivateKey.from_private_bytes(bytes([91]) * 32)
    stamp = stamp_key.sign(stamp_input(GID, 7, 1791900000000, aad))
    return {
        "warning": "PUBLIC SYNTHETIC PRIVATE KEYS AND MLS STATE; NEVER USE IN LIVE GROUPS",
        "source_commit": "8f1b43f447a792ff9307f1c2c7f54da63914870e",
        "group_id": GID.hex(),
        "key": key_json(bk),
        "store": stores["bob"],
        "frames": {
            "original": frame.hex(),
            "tampered": tampered.hex(),
            "wrong_control_aad": wrong.hex(),
            "public_control": public.hex(),
            "valid_commit": commit.to_bytes().hex(),
            "wrong_app_aad": malformed_app.hex(),
            "valid_proposal": proposal.to_bytes().hex(),
        },
        "expected": {
            "plaintext": mimi.hex(),
            "aad": aad.hex(),
            "epoch1_export": bg.export_secret(LABEL, b"", 32).hex(),
            "epoch2_export": valid_sender.export_secret(LABEL, b"", 32).hex(),
            "stamp": stamp.hex(),
        },
    }


def replay(fixture):
    assert fixture["group_id"] == GID.hex()
    store = Store(fixture["store"])
    bc = client(b"synthetic-bob", key_from(fixture["key"]), store)
    bg = bc.load_group(GID)
    frames = {
        k: Message.from_bytes(bytes.fromhex(v)) for k, v in fixture["frames"].items()
    }
    before = copy.deepcopy(store.rows)
    baseline = bg.export_secret(LABEL, b"", 32)
    assert baseline.hex() == fixture["expected"]["epoch1_export"]
    checks = []
    for name in ["tampered", "wrong_control_aad", "public_control", "wrong_app_aad"]:
        writes = store.writes
        rejects(
            lambda name=name: bg.process_incoming_message_transactional(
                frames[name], True
            )
        )
        assert store.writes == writes and store.rows == before
        assert bg.export_secret(LABEL, b"", 32) == baseline
        # Prove failed receives did not even change the serialized ratchet/state.
        bg.write_to_storage()
        assert store.rows == before, name
        checks.append(name + "_rejected_without_memory_or_storage_change")
    out = bg.process_incoming_message_transactional(frames["original"], True)
    assert out.data.hex() == fixture["expected"]["plaintext"]
    assert out.authenticated_data.hex() == fixture["expected"]["aad"]
    verify_frank(GID, 1, out.data, out.authenticated_data)
    checks.append("original_after_auth_failure_decrypts_and_frank_verifies")
    rejects(lambda: bg.process_incoming_message_transactional(frames["original"], True))
    checks.append("accepted_message_replay_rejected")
    # Persist successful consumption; reloading must not resurrect the accepted generation.
    bg.write_to_storage()
    restored = bc.load_group(GID)
    rejects(
        lambda: restored.process_incoming_message_transactional(
            frames["original"], True
        )
    )
    checks.append("persistent_replay_rejected_after_reload")
    restored.process_incoming_message_transactional(frames["valid_commit"], True)
    assert (
        restored.export_secret(LABEL, b"", 32).hex()
        == fixture["expected"]["epoch2_export"]
    )
    rejects(
        lambda: restored.process_incoming_message_transactional(
            frames["valid_commit"], True
        )
    )
    checks.append("valid_control_applies_exactly_once")
    separate = client(
        b"synthetic-bob", key_from(fixture["key"]), Store(fixture["store"])
    ).load_group(GID)
    received = separate.process_incoming_message_transactional(
        frames["valid_proposal"], True
    )
    assert received.authenticated_data == b"\x00"
    checks.append("private_proposal_with_required_control_aad")
    # Exercise the provider's past-epoch storage cache as well as current epoch state.
    pst = Store(fixture["store"])
    pc = client(b"synthetic-bob", key_from(fixture["key"]), pst)
    pg = pc.load_group(GID)
    pg.process_incoming_message_transactional(frames["valid_commit"], True)
    pg.write_to_storage()
    past_before = copy.deepcopy(pst.rows)
    writes = pst.writes
    rejects(lambda: pg.process_incoming_message_transactional(frames["tampered"], True))
    assert pst.writes == writes and pst.rows == past_before
    pg.write_to_storage()
    assert pst.rows == past_before
    delayed = pg.process_incoming_message_transactional(frames["original"], True)
    assert delayed.data == out.data
    checks.append("past_epoch_auth_failure_preserves_stored_generation")
    aad, payload = out.authenticated_data, out.data
    for group, epoch, data in [
        (bytes([1]) * 32, 1, payload),
        (GID, 2, payload),
        (GID, 1, payload[:-1] + b"x"),
    ]:
        try:
            verify_frank(group, epoch, data, aad)
        except ValueError:
            pass
        else:
            raise AssertionError("franking mismatch accepted")
    checks.append("frank_rejects_group_epoch_content_changes")
    key = Ed25519PrivateKey.from_private_bytes(bytes([91]) * 32).public_key()
    signature = bytes.fromhex(fixture["expected"]["stamp"])
    key.verify(signature, stamp_input(GID, 7, 1791900000000, aad))
    for seq, stamp_aad in [(8, aad), (7, b"\x01" + bytes(32))]:
        try:
            key.verify(signature, stamp_input(GID, seq, 1791900000000, stamp_aad))
        except InvalidSignature:
            pass
        else:
            raise AssertionError("altered stamp accepted")
    checks.append("stamp_verifies_and_rejects_changed_sequence_or_aad")
    return checks


if __name__ == "__main__":
    path = HERE / "fixtures" / "synthetic-replay.json"
    if "--capture" in sys.argv:
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps(capture(), indent=2, sort_keys=True) + "\n")
    fixture = json.loads(path.read_text())
    first = replay(fixture)
    assert replay(fixture) == first
    print(
        json.dumps(
            {
                "passed": len(first),
                "replays": 2,
                "checks": first,
                "fixture_kind": "captured synthetic state, exact deterministic replay; not deterministic setup",
            },
            indent=2,
        )
    )
