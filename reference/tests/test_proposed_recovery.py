"""Cross-proposal recovery check; neither E1 nor B1 is normative Hum yet."""

from hum_reference import bbs
from hum_reference import proposed_backup as backup
from hum_reference import proposed_bbs as e1


def test_restored_hidden_blind_and_nym_can_generate_valid_proof():
    sk = 12345
    pk = bbs.public_key(sk)
    messages = [bbs.i2osp(42, 8), bbs.i2osp(1, 8)]
    commitment, blind = e1.commit(123, [7, 11, 13])
    signature = e1.blind_sign(sk, commitment, 456, messages)
    nym = e1.finalize(pk, signature, 123, 456, blind, messages)
    card = {
        0: b"\x01" + bytes(32),
        1: b"synthetic",
        2: 4,
        3: messages,
        4: signature,
        5: bbs.i2osp(nym),
        6: bbs.i2osp(blind),
    }
    plaintext = {0: 1, 1: bytes(32), 2: bytes([1]) * 32, 3: [card], 4: [], 5: 0}
    phrase = backup.phrase_from_entropy(bytes(16))
    packed = backup.pack_backup(
        plaintext,
        phrase,
        salt=bytes(range(16)),
        content_key=bytes(range(16)),
        ephemeral_private=bytes(range(32)),
    )
    restored = backup.unpack_backup(packed, phrase, max_envelope_bytes=1000000)[3][0]
    proof, pseudonym = e1.proof_gen(
        pk,
        restored[4],
        restored[3],
        int.from_bytes(restored[6], "big"),
        int.from_bytes(restored[5], "big"),
        [0, 1],
        list(range(2, 9)),
        scope=b"synthetic-scope",
    )
    assert e1.proof_verify(
        pk, proof, pseudonym, len(messages), messages, [0, 1], scope=b"synthetic-scope"
    )
    assert not e1.proof_verify(
        pk, proof, pseudonym, len(messages), messages, [0, 1], scope=b"different-scope"
    )
