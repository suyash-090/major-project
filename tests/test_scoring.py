"""
Scoreboard maths. calculate_scoreboard() is the heart of the scoring system,
so these tests pin down the rules it has to follow:

  * a solved challenge adds its points, once
  * an earlier wrong attempt on the same challenge changes nothing
  * unlocked hints subtract their point cost
  * a student who solved nothing still appears, on zero
  * rows come back sorted highest score first
  * the database refuses to record the same solve twice (the safety net the
    submit route relies on)
"""

import pytest
from sqlalchemy.exc import IntegrityError

from breachbox.extensions import db
from breachbox.models import Student, Challenge, Submission, Hint, HintUnlock
from breachbox.scoreboard.routes import calculate_scoreboard


def _add_student(name):
    student = Student(display_name=name, class_group="Y12-A")
    student.set_password("pw")
    db.session.add(student)
    db.session.commit()
    return student.student_id


def _challenge(name):
    return Challenge.query.filter_by(name=name).first()


def _solve(student_id, challenge, writeup="done"):
    db.session.add(Submission(
        student_id=student_id,
        challenge_id=challenge.challenge_id,
        is_correct=True,
        writeup_text=writeup,
    ))


def _wrong_attempt(student_id, challenge):
    db.session.add(Submission(
        student_id=student_id,
        challenge_id=challenge.challenge_id,
        is_correct=False,
    ))


def test_totals_sum_points_and_subtract_hint_costs(app):
    with app.app_context():
        alice = _add_student("alice")
        bob = _add_student("bob")
        _add_student("carol")  # solves nothing

        sqli = _challenge("Staff Portal Login Bypass")        # 100
        idor = _challenge("Support Ticket IDOR")               # 150
        cmdi = _challenge("Diagnostics Command Injection")     # 200

        # alice: one wrong try on sqli, then solves sqli and idor
        _wrong_attempt(alice, sqli)
        _solve(alice, sqli)
        _solve(alice, idor)
        # ...and unlocks the first hint on sqli
        sqli_hint = (
            Hint.query.filter_by(challenge_id=sqli.challenge_id)
            .order_by(Hint.hint_order)
            .first()
        )
        db.session.add(HintUnlock(student_id=alice, hint_id=sqli_hint.hint_id))

        # bob: solves cmdi only, no hints
        _solve(bob, cmdi)
        db.session.commit()

        board = {row["display_name"]: row for row in calculate_scoreboard()}

        assert board["alice"]["points_from_challenges"] == 250
        assert board["alice"]["points_lost_to_hints"] == sqli_hint.point_cost
        assert board["alice"]["total_score"] == 250 - sqli_hint.point_cost

        assert board["bob"]["points_from_challenges"] == 200
        assert board["bob"]["points_lost_to_hints"] == 0
        assert board["bob"]["total_score"] == 200

        # carol appears via the outer join even with no solves
        assert board["carol"]["total_score"] == 0


def test_wrong_attempts_alone_score_zero(app):
    with app.app_context():
        dan = _add_student("dan")
        sqli = _challenge("Staff Portal Login Bypass")
        _wrong_attempt(dan, sqli)
        _wrong_attempt(dan, sqli)
        db.session.commit()

        board = {row["display_name"]: row for row in calculate_scoreboard()}
        assert board["dan"]["total_score"] == 0


def test_board_is_sorted_highest_first(app):
    with app.app_context():
        low = _add_student("low")
        high = _add_student("high")
        _solve(high, _challenge("Chained: Ticket Leak to Staff Console"))  # 250
        _solve(low, _challenge("Staff Portal Login Bypass"))               # 100
        db.session.commit()

        board = calculate_scoreboard()
        scores = [row["total_score"] for row in board]
        assert scores == sorted(scores, reverse=True)
        assert board[0]["display_name"] == "high"


def test_database_refuses_a_duplicate_correct_solve(app):
    # The submit route checks "already solved" in Python, but a DB-level
    # partial unique index is the real backstop against double-awarding.
    with app.app_context():
        erin = _add_student("erin")
        sqli = _challenge("Staff Portal Login Bypass")
        _solve(erin, sqli, writeup="first")
        db.session.commit()

        _solve(erin, sqli, writeup="second")
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()
