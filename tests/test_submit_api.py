"""
End-to-end tests for the flag submission API (POST /api/submit).

These exercise the route the way a logged-in student really hits it, and pin
down the rules that stop points being awarded wrongly:

  * you must be logged in
  * a correct flag only counts once you've attached a write-up
  * a correct flag with a write-up is recorded and awarded
  * a wrong flag is recorded as an attempt but awards nothing
  * you can't bank the same challenge twice
  * missing fields and unknown challenge ids are rejected cleanly
"""

from breachbox.extensions import db
from breachbox.models import Submission

SQLI_FLAG = "flag{sql1_st4ff_p0rt4l_byp4ss_2026}"


def test_submit_requires_login(client, cid):
    resp = client.post("/api/submit", data={
        "challenge_id": cid(), "flag": SQLI_FLAG, "writeup_text": "x",
    })
    assert resp.status_code == 302  # redirected to the login page


def test_correct_flag_with_writeup_is_recorded(client, solver, app, cid):
    challenge_id = cid()
    resp = client.post("/api/submit", data={
        "challenge_id": challenge_id,
        "flag": SQLI_FLAG,
        "writeup_text": "logged in with  admin' OR '1'='1",
    })
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["is_correct"] is True
    assert body["recorded"] is True

    with app.app_context():
        solved = Submission.query.filter_by(
            student_id=solver, challenge_id=challenge_id, is_correct=True
        ).all()
        assert len(solved) == 1
        assert solved[0].writeup_text


def test_correct_flag_without_writeup_is_not_banked(client, solver, app, cid):
    challenge_id = cid()
    resp = client.post("/api/submit", data={
        "challenge_id": challenge_id, "flag": SQLI_FLAG,
    })
    assert resp.status_code == 400
    body = resp.get_json()
    assert body["is_correct"] is True
    assert body["recorded"] is False

    with app.app_context():
        assert Submission.query.filter_by(
            student_id=solver, challenge_id=challenge_id, is_correct=True
        ).count() == 0


def test_wrong_flag_is_recorded_but_awards_nothing(client, solver, app, cid):
    challenge_id = cid()
    resp = client.post("/api/submit", data={
        "challenge_id": challenge_id, "flag": "flag{wrong}", "writeup_text": "x",
    })
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["is_correct"] is False
    assert body["recorded"] is True

    with app.app_context():
        assert Submission.query.filter_by(
            student_id=solver, challenge_id=challenge_id, is_correct=False
        ).count() == 1


def test_a_challenge_cannot_be_solved_twice(client, solver, cid):
    payload = {"challenge_id": cid(), "flag": SQLI_FLAG, "writeup_text": "x"}
    assert client.post("/api/submit", data=payload).status_code == 200
    resp = client.post("/api/submit", data=payload)
    assert resp.status_code == 400
    assert "already" in resp.get_json()["error"].lower()


def test_missing_fields_are_rejected(client, solver, cid):
    # no challenge_id
    assert client.post("/api/submit", data={"flag": SQLI_FLAG}).status_code == 400
    # no flag
    assert client.post(
        "/api/submit", data={"challenge_id": cid()}
    ).status_code == 400


def test_unknown_challenge_id_is_404(client, solver):
    resp = client.post("/api/submit", data={
        "challenge_id": 999999, "flag": "x", "writeup_text": "y",
    })
    assert resp.status_code == 404
