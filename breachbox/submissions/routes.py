"""
This is the Flag Submission API, Week 7 (Harry's track). It is
deliberately generic: it does not know anything about SQL injection,
XSS, or any specific vulnerability. It looks up whichever Challenge
subclass matches the submitted challenge_id, asks that class's own
check_solution() whether the flag is right, and records the result.

This is the piece that lets Sameer's SQLi challenge, Suyash's IDOR
challenge, and anything added later all plug into the exact same
submission flow without this file ever changing.
"""

from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user

from breachbox.submissions import submissions_bp
from breachbox.extensions import db
from breachbox.models import Challenge, Submission
from breachbox.challenges.base import discover_challenges


def _find_challenge_class_by_name(name):
    """
    Matches a database Challenge row (by name) back to the actual Python
    class that implements it, so we can call its check_solution(). This
    is the bridge between the DB row (used for points/category/display)
    and the code (used for the actual validation logic).
    """
    for cls in discover_challenges():
        if cls.name == name:
            return cls
    return None


@submissions_bp.route("/challenges", methods=["GET"])
@login_required
def list_challenges():
    """
    Returns every known challenge as JSON. This exists now so Harry's
    Week 11 dashboard has a real endpoint to call for the challenge
    list, rather than needing to query the database directly from a
    template.
    """
    challenges = Challenge.query.all()
    return jsonify([
        {
            "challenge_id": c.challenge_id,
            "name": c.name,
            "category": c.category,
            "difficulty": c.difficulty,
            "points": c.points,
            "is_chained": c.is_chained,
        }
        for c in challenges
    ])


@submissions_bp.route("/submit", methods=["POST"])
@login_required
def submit():
    challenge_id = request.form.get("challenge_id", type=int)
    submitted_flag = request.form.get("flag", "").strip()
    writeup_text = request.form.get("writeup_text", "").strip()

    if not challenge_id or not submitted_flag:
        return jsonify({"error": "challenge_id and flag are both required"}), 400

    challenge_row = db.session.get(Challenge, challenge_id)
    if challenge_row is None:
        return jsonify({"error": "no such challenge"}), 404

    challenge_class = _find_challenge_class_by_name(challenge_row.name)
    if challenge_class is None:
        # This means a Challenge row exists in the database with no
        # matching Python class anymore, most likely because a subclass
        # was renamed or deleted without re-running the sync. This is a
        # setup problem, not something the student did wrong.
        return jsonify({"error": "challenge is misconfigured, no matching class found"}), 500

    is_correct = challenge_class().check_solution(submitted_flag)

    if is_correct:
        # Review-note fix: don't award points twice for the same
        # challenge. This is the app-level half of the "already solved"
        # check, backed by a DB-level partial unique index on Submission
        # in models.py so a bug here can't double-award even so.
        already_solved = Submission.query.filter_by(
            student_id=current_user.student_id,
            challenge_id=challenge_row.challenge_id,
            is_correct=True,
        ).first()
        if already_solved:
            return jsonify({
                "error": "already solved, this challenge won't award points again",
                "is_correct": True,
                "recorded": False,
            }), 400

    # The write-up requirement from the proposal: a correct submission
    # without a write-up is rejected before anything gets recorded as
    # correct, rather than silently accepting it and hoping someone
    # fills the write-up in later.
    if is_correct and not writeup_text:
        return jsonify({
            "error": "correct flag, but a short write-up is required before this counts",
            "is_correct": True,
            "recorded": False,
        }), 400

    submission = Submission(
        student_id=current_user.student_id,
        challenge_id=challenge_row.challenge_id,
        is_correct=is_correct,
        writeup_text=writeup_text if is_correct else None,
    )
    db.session.add(submission)
    db.session.commit()

    return jsonify({
        "is_correct": is_correct,
        "recorded": True,
        "challenge": challenge_row.name,
    })
