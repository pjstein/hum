import hashlib
import json

import pytest

from hum_reference import credentials as cr
from hum_reference.vectors import credentials_vectors as cv


def test_periods_epochs_and_handover():
    assert cr.period(cr.PERIOD * 5 + 1) == 5
    assert cr.validity_periods(86_400) == 1
    assert cr.epoch_of_period(13, 6) == 2
    assert cr.handover(4, 6) and cr.handover(5, 6) and not cr.handover(3, 6)
    assert cr.handover(0, 1)


def test_ballot_window_and_grace():
    v = 6
    e = cr.ballot_window_epoch(cv.CLOSES_V1, v)
    assert cr.card_accepted(e, v, cv.NOW, use="ballot", closes_v1=cv.CLOSES_V1)
    assert not cr.card_accepted(e + 1, v, cv.NOW, use="ballot", closes_v1=cv.CLOSES_V1)
    boundary = (e * v + v) * cr.PERIOD
    assert cr.card_accepted(e, v, boundary + 3599)
    assert not cr.card_accepted(e, v, boundary + 3600)


def test_scopes_are_distinct_and_nullifier_shape():
    assert cr.scopes.prefixes_distinct()
    n = cr.nullifier(bytes(48))
    assert n == hashlib.sha256(b"hum/nullifier/1" + bytes(48)).digest()
    with pytest.raises(ValueError):
        cr.nullifier(bytes(47))


def test_presentation_round_trip_and_valid_ballot():
    pres = cr.Presentation(cv.ballot_cards(), [], cv.CONTEXT_VERSION)
    back = cr.Presentation.decode(pres.encode())
    assert back.to_item() == pres.to_item()
    _, _, out, _ = cv.run_ballot(pres)
    assert out["primary"] == cr.nullifier(cv.pseudonym("unique"))
    assert out["used"] == [0, 1, 2]


def test_layout_and_logged_validity():
    assert cr.layout_length(2) == 4
    assert cr.message_bytes(0, None, 123) == (123).to_bytes(8, "big")
    assert cr.message_bytes(2, None) == cr.ABSENT.to_bytes(8, "big")
    with pytest.raises(ValueError):
        cr.message_bytes(3, 1, length=4)  # L - 1 is the nym secret
    v = 6
    e = cr.epoch_now(cv.NOW, v)
    boundary = (e + 1) * v * cr.PERIOD
    assert cr.logged_epochs(boundary + 7199, v) == {e, e + 1}
    assert cr.logged_epochs(boundary + 7200, v) == {e + 1}
    assert cr.logged_epochs(boundary - 3600, v) == {e, e + 1}
    assert cr.logged_epochs(boundary - 3601, v) == {e}
    assert cr.card_accepted(e, v, None, use="logged", issued=cv.NOW)  # no clock: any later time
    assert not cr.card_accepted(e + 1, v, None, use="logged", issued=cv.NOW)
    assert cr.log_submission_check(e, v, boundary + 1800, boundary + 1800) is None
    assert cr.log_submission_check(e, v, boundary + 3660, boundary + 3660) is not None
    assert cr.log_submission_check(e + 1, v, boundary + 9000, boundary + 16200) is not None
    assert cr.log_submission_check(e + 1, v, boundary + 9000, boundary + 12600) is None


def test_c16_rejects_any_nodes_and_branches():
    with pytest.raises(cr.PresentationError) as e:
        cv.run_ballot(cr.Presentation(cv.ballot_cards(), [0], cv.CONTEXT_VERSION))
    assert e.value.rule == "P6"
    with pytest.raises(cr.PresentationError) as e:
        cv.run_ballot(
            cr.Presentation(cv.ballot_cards(), [], cv.CONTEXT_VERSION), policy=cv.ENTRY_ANY
        )
    assert e.value.rule == "P6"


def test_rules_fire():
    with pytest.raises(cr.PresentationError) as e:
        cv.run_ballot(cr.Presentation(cv.ballot_cards()[:2], [], cv.CONTEXT_VERSION))
    assert e.value.rule == "P6"
    bad = cv.ballot_cards()
    bad[2].proof_valid = False
    with pytest.raises(cr.PresentationError) as e:
        cv.run_ballot(cr.Presentation(bad, [], cv.CONTEXT_VERSION))
    assert e.value.rule == "P4"


def test_issuance_decisions():
    v = 6
    e_now = cr.epoch_now(cv.NOW, v)
    h = bytes(32)
    assert cr.decide_issuance([], cv.NOW, v, h, set())["issue"] == [e_now]
    row = cr.DedupRow(e_now, b"k", h)
    assert cr.decide_issuance([row], cv.NOW, v, h, {b"k"})["retry"]
    assert cr.decide_issuance([row], cv.NOW, v, bytes([1]) * 32, {b"k"})["refuse"]
    assert cr.decide_issuance([row], cv.NOW, v, h, set())["issue"] == [e_now]


def test_backup_refuses_vote_keys():
    with pytest.raises(ValueError):
        cr.write_backup(bytes(32), bytes(32), [], [], 0, extra={"hand": b""})


def test_generate_is_deterministic():
    a = [json.dumps(f.cases, sort_keys=True) for f in cv.generate()]
    b = [json.dumps(f.cases, sort_keys=True) for f in cv.generate()]
    assert a == b
    assert sum(len(f.cases) for f in cv.generate()) > 60


def test_accepts_alternatives_and_log_of_record():
    e_now = cr.epoch_now(cv.NOW, 6)
    accepts = [(cv.APPROVED, ["approved"]), (cv.UNIQUE, ["unique"])]
    assert cr.choose_accepts_entry(accepts, {cv.UNIQUE}) == 1
    assert cr.choose_accepts_entry(accepts, {cv.APPROVED, cv.UNIQUE}) == 0
    assert cr.choose_accepts_entry(accepts, set()) is None
    one = cr.Presentation([cv.card(cv.UNIQUE, cv.KID_U0, 3, {0: e_now, 1: 1}, "u")], [], None)
    k, policy, allowed = cr.accepts_entry(one, accepts, cv.issuers())
    assert k == 1 and policy == [cr.NODE_POSSESSION, cv.UNIQUE] and allowed == {1}
    assert cr.possession_leaf(cv.UNIQUE) == [4, cv.UNIQUE]
    two = cr.Presentation(one.creds + one.creds, [], None)
    with pytest.raises(cr.PresentationError) as e:
        cr.accepts_entry(two, accepts, cv.issuers())
    assert e.value.rule == "P6"
    record, second = b"\x01" + bytes(32), b"\x01" + bytes([1]) * 32
    assert cr.log_of_record([record, second]) == record
    assert not cr.object_in_log_of_record([record, second], [second])
    kw = dict(logs=[record, second], card_epoch=e_now, v=6, issued=cv.NOW, log_now=cv.NOW + 10800)
    assert (
        cr.log_accepts_logged_object(
            this_log=second, proof_logs=[record], issuer_lineage_in_history=True, **kw
        )
        is None
    )
    assert cr.log_accepts_logged_object(
        this_log=second, proof_logs=[], issuer_lineage_in_history=True, **kw
    )
    assert cr.log_accepts_logged_object(
        this_log=record, proof_logs=[], issuer_lineage_in_history=False, **kw
    )
    infos = list(cv.issuers().values())
    assert set(cr.issuers_by_authority(infos)) == set(cv.issuers())
