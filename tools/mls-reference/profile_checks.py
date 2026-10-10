"""Live library checks through generated bindings, not deterministic protocol vectors."""
import json
from mls_rs_uniffi import Client, CipherSuite, Message, generate_signature_keypair, client_config_default

checks = []
limitations = []

def check(name, predicate):
    assert predicate, name
    checks.append(name)


def reject(name, operation):
    try:
        operation()
    except Exception as error:
        # UniFFI exposes provider/version-specific error classes; require an MLS error.
        assert error.__class__.__module__ == "mls_rs_uniffi", (name, type(error))
        checks.append(name)
    else:
        raise AssertionError(f"{name}: accepted")


def client(identity):
    cfg = client_config_default()
    cfg.use_ratchet_tree_extension = False
    key = generate_signature_keypair(CipherSuite.CURVE25519_AES128)
    return Client.new_with_private_messages(identity, key, cfg, True)


def wire(message):
    # RFC 9420 MLSMessage's uint16 version then uint16 wire_format.
    data = message.to_bytes()
    assert data[:2] == b"\x00\x01"
    return int.from_bytes(data[2:4], "big")

alice, bob, charlie = (client(name) for name in (b"alice-synthetic", b"bob-synthetic", b"charlie-synthetic"))
ag = alice.create_group(bytes(range(32)))
# Opaque transport fixture only: NOT a validated/sealed Hum tree reference.
extension = b"synthetic-tree-reference-transport-fixture"
added = ag.add_members_with_group_info_extension([bob.generate_key_package_message()], 0xF001, extension)
check("private_add_commit", wire(added.commit_message) == 2)
check("welcome_wire_format", wire(added.welcome_message) == 3)
check("out_of_band_ratchet_tree", added.ratchet_tree is not None)
ag.process_incoming_message(added.commit_message)
joined = bob.join_group(added.ratchet_tree, added.welcome_message)
bg = joined.group
check("private_group_info_extension_roundtrip", joined.group_info_extensions.get_data(0xF001) == extension)
check("absent_extension", joined.group_info_extensions.get_data(0xF002) is None)

for label, length in ((b"hum/keyring/1", 16), (b"hum/delivery/1", 32)):
    value = ag.export_secret(label, b"", length)
    check("exporter_agreement_" + label.decode(), len(value) == length and value == bg.export_secret(label, b"", length))
old_delivery = ag.export_secret(b"hum/delivery/1", b"", 32)
check("exporter_label_separation", old_delivery != ag.export_secret(b"hum/keyring/1", b"", 32))
check("exporter_context_separation", old_delivery != ag.export_secret(b"hum/delivery/1", b"different", 32))

for name, aad in (("library_one_byte", b"\x00"), ("profile_33_byte_shape", b"\x01" + bytes(range(32)))):
    sent = ag.encrypt_application_message_with_aad(b"synthetic content " + name.encode(), aad)
    check("private_application_" + name, wire(sent) == 2)
    encoded = sent.to_bytes()
    # Send deserialized bytes rather than an in-memory shared message object.
    received = bg.process_incoming_message(Message.from_bytes(encoded))
    check("aad_and_plaintext_roundtrip_" + name,
          received.authenticated_data == aad and received.data == b"synthetic content " + name.encode())
    reject("replayed_message_" + name, lambda: bg.process_incoming_message(Message.from_bytes(encoded)))

# authenticated_data is visible but signed/authenticated by MLS. Flip it in transit.
aad = b"\x01" + bytes([167]) * 32
sent = ag.encrypt_application_message_with_aad(b"tamper test", aad)
encoded = sent.to_bytes()
check("aad_present_in_frame", encoded.count(aad) == 1)
offset = encoded.index(aad)
tampered = encoded[:offset + 1] + bytes([encoded[offset + 1] ^ 1]) + encoded[offset + 2:]
reject("tampered_authenticated_data", lambda: bg.process_incoming_message(Message.from_bytes(tampered)))
reject("truncated_frame", lambda: Message.from_bytes(encoded[:3]))
try:
    bg.process_incoming_message(Message.from_bytes(encoded))
except Exception as error:
    assert error.__class__.__module__ == "mls_rs_uniffi"
    assert "key not available" in str(error), str(error)
    limitations.append("upstream consumes receive generation on failed authentication; later original frame cannot decrypt")
else:
    raise AssertionError("known upstream generation-consumption behavior changed: review and remove limitation")

proposals = ag.propose_add_members([charlie.generate_key_package_message()])
check("private_proposal", len(proposals) == 1 and wire(proposals[0]) == 2)
bg.process_incoming_message(proposals[0])
commit = ag.commit()
check("private_epoch_commit", wire(commit.commit_message) == 2)
ag.process_incoming_message(commit.commit_message)
bg.process_incoming_message(commit.commit_message)
new_delivery = ag.export_secret(b"hum/delivery/1", b"", 32)
check("exporter_epoch_rotation", new_delivery != old_delivery)
check("exporter_agreement_after_commit", new_delivery == bg.export_secret(b"hum/delivery/1", b"", 32))
cg = charlie.join_group(commit.ratchet_tree, commit.welcome_message).group
old_keyring = ag.export_secret(b"hum/keyring/1", b"", 16)
removal = ag.remove_members([bob.signing_identity()])
check("private_remove_commit", wire(removal.commit_message) == 2)
ag.process_incoming_message(removal.commit_message)
bg.process_incoming_message(removal.commit_message)
cg.process_incoming_message(removal.commit_message)
new_keyring = ag.export_secret(b"hum/keyring/1", b"", 16)
check("keyring_export_after_removal", new_keyring != old_keyring and
      new_keyring == cg.export_secret(b"hum/keyring/1", b"", 16))
sent = ag.encrypt_application_message_with_aad(b"post-removal", b"\x00")
reject("removed_member_cannot_decrypt", lambda: bg.process_incoming_message(sent))
check("remaining_member_can_decrypt", cg.process_incoming_message(sent).data == b"post-removal")
# Keyring scheduling is a Hum policy, deliberately not inferred from these primitive calls.
print(json.dumps({"passed": len(checks), "checks": checks,
                  "scope": "live MLS primitive integration; not full Hum-profile conformance",
                  "known_limitations": limitations, "secrets_or_random_bytes_recorded": False}, indent=2))
