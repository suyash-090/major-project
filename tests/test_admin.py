"""
Teacher / admin area.

Covers the access control (only admins get in), the teacher powers (see a
student's token, dock points, edit a challenge description), and the fact that
the admin account itself never shows up on the student scoreboard.

The app seeds one admin, "teacher", with the default password below, so these
tests log in as that account.
"""

from breachbox.extensions import db
from breachbox.models import Student, Challenge, Submission
from breachbox.scoreboard.routes import calculate_scoreboard

ADMIN_NAME = "teacher"
ADMIN_PW = "breachbox-teacher"


def _login(client, name, pw):
    return client.post("/auth/login", data={"display_name": name, "password": pw})


def test_admin_requires_login(client):
    resp = client.get("/admin/")
    assert resp.status_code == 302
    assert "/auth/login" in resp.headers["Location"]


def test_students_cannot_reach_admin(client, solver):
    # `solver` logs the client in as a normal (non-admin) student.
    assert client.get("/admin/").status_code == 403


def test_student_cannot_dock_points(client, solver, make_student):
    victim = make_student("victim", "pw")
    resp = client.post("/admin/adjust", data={
        "student_id": victim, "delta": -1000, "reason": "nope",
    })
    assert resp.status_code == 403


def test_admin_sees_students_and_their_tokens(client, app, make_student):
    sid = make_student("pupil", "pw")
    with app.app_context():
        token = db.session.get(Student, sid).flag_token

    _login(client, ADMIN_NAME, ADMIN_PW)
    resp = client.get("/admin/")
    assert resp.status_code == 200
    assert token.encode() in resp.data  # the student's token is shown to the teacher


def test_admin_can_dock_points(client, app, make_student, cid):
    sid = make_student("pupil2", "pw")
    challenge_id = cid()  # Staff Portal Login Bypass, 100 pts
    with app.app_context():
        db.session.add(Submission(
            student_id=sid, challenge_id=challenge_id, is_correct=True, writeup_text="x"
        ))
        db.session.commit()
        before = {r["student_id"]: r["total_score"] for r in calculate_scoreboard()}[sid]
    assert before == 100

    _login(client, ADMIN_NAME, ADMIN_PW)
    resp = client.post("/admin/adjust", data={
        "student_id": sid, "delta": -40, "reason": "shared a flag",
    })
    assert resp.status_code in (302, 200)

    with app.app_context():
        after = {r["student_id"]: r["total_score"] for r in calculate_scoreboard()}[sid]
    assert after == 60


def test_admin_can_edit_a_challenge_description(client, app, cid):
    challenge_id = cid()
    _login(client, ADMIN_NAME, ADMIN_PW)
    resp = client.post(f"/admin/challenge/{challenge_id}", data={
        "description": "Teacher reworded this.",
    })
    assert resp.status_code in (302, 200)
    with app.app_context():
        assert db.session.get(Challenge, challenge_id).description == "Teacher reworded this."


def test_admin_account_is_not_on_the_student_scoreboard(app):
    with app.app_context():
        names = [r["display_name"] for r in calculate_scoreboard()]
    assert ADMIN_NAME not in names
