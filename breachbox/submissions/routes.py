"""
Flag Submission API. Generic across any Challenge subclass, doesn't know
anything about SQLi/XSS/IDOR/command injection specifically.
"""

from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user

from breachbox.submissions import submissions_bp
from breachbox.extensions import db
from breachbox.models import Challenge, Submission
from breachbox.challenges.base import discover_challenges
from breachbox.ratelimit import flag_limiter


def _find_challenge_class_by_name(name):
    # Bridges a DB Challenge row (points/category/display) to the actual
    # Python class (validation logic).
    for cls in discover_challenges():
        if cls.name == name:
            return cls
    return None


@submissions_bp.route("/challenges", methods=["GET"])
@login_required
def list_challenges():
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
        # DB row with no matching Python class, e.g. after a rename with
        # no re-sync, a setup problem, not the student's fault.
        return jsonify({"error": "challenge is misconfigured, no matching class found"}), 500

    # Rate limit wrong guesses per student+challenge so a flag can't be
    # brute-forced. A correct solve clears the counter.
    rl_key = f"{current_user.student_id}:{challenge_row.challenge_id}"
    allowed, retry_after = flag_limiter.check(rl_key)
    if not allowed:
        return jsonify({
            "error": f"too many attempts on this challenge, wait about {retry_after}s",
            "is_correct": False,
            "recorded": False,
        }), 429

    is_correct = challenge_class().check_solution(submitted_flag)
    if is_correct:
        flag_limiter.reset(rl_key)
    else:
        flag_limiter.record(rl_key)

    if is_correct:
        # Already-solved check, backed by a DB-level unique index on
        # Submission, so this can't double-award points either way.
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
