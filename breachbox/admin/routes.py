"""Teacher / admin area.

Admin-only: see every student's personal token and their per-student flags,
read write-ups, dock or award points, and edit the challenge descriptions
students see. Every route is guarded by admin_required, so a normal student
who guesses the URL gets a 403, not the page.
"""

from functools import wraps

from flask import render_template, request, redirect, url_for, flash, abort
from flask_login import login_required, current_user

from breachbox.admin import admin_bp
from breachbox.extensions import db
from breachbox.models import Student, Challenge, Submission, ScoreAdjustment
from breachbox.flags import make_flag, CHALLENGE_KEYS
from breachbox.scoreboard.routes import calculate_scoreboard


def admin_required(view):
    """login_required, plus a check that the account is actually an admin."""
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


@admin_bp.route("/")
@admin_required
def home():
    board = {row["student_id"]: row for row in calculate_scoreboard()}
    students = (
        Student.query.filter_by(is_admin=False)
        .order_by(Student.display_name)
        .all()
    )
    rows = []
    for s in students:
        solved = Submission.query.filter_by(
            student_id=s.student_id, is_correct=True
        ).count()
        rows.append({
            "student": s,
            "score": board.get(s.student_id, {}).get("total_score", 0),
            "solved": solved,
        })
    challenges = Challenge.query.order_by(Challenge.points.asc()).all()
    return render_template("admin.html", rows=rows, challenges=challenges)


@admin_bp.route("/student/<int:student_id>")
@admin_required
def student_detail(student_id):
    student = db.session.get(Student, student_id)
    if student is None or student.is_admin:
        abort(404)

    challenges = Challenge.query.order_by(Challenge.points.asc()).all()
    flags = []
    for c in challenges:
        key = CHALLENGE_KEYS.get(c.name)
        solved = Submission.query.filter_by(
            student_id=student.student_id,
            challenge_id=c.challenge_id,
            is_correct=True,
        ).first() is not None
        flags.append({
            "challenge": c,
            "flag": make_flag(student.flag_token, key) if key else "(no key)",
            "solved": solved,
        })

    writeups = (
        Submission.query.filter_by(student_id=student.student_id, is_correct=True)
        .order_by(Submission.submitted_at.desc())
        .all()
    )
    adjustments = (
        ScoreAdjustment.query.filter_by(student_id=student.student_id)
        .order_by(ScoreAdjustment.created_at.desc())
        .all()
    )
    board = {row["student_id"]: row for row in calculate_scoreboard()}
    score = board.get(student.student_id, {}).get("total_score", 0)
    return render_template(
        "admin_student.html",
        student=student,
        flags=flags,
        writeups=writeups,
        adjustments=adjustments,
        score=score,
    )


@admin_bp.route("/adjust", methods=["POST"])
@admin_required
def adjust_points():
    student_id = request.form.get("student_id", type=int)
    delta = request.form.get("delta", type=int)
    reason = request.form.get("reason", "").strip()

    student = db.session.get(Student, student_id) if student_id else None
    if student is None or student.is_admin or delta is None:
        flash("Could not apply that adjustment.")
        return redirect(url_for("admin.home"))

    db.session.add(ScoreAdjustment(
        student_id=student.student_id,
        delta=delta,
        reason=reason or None,
        created_by=current_user.display_name,
    ))
    db.session.commit()
    flash(f"Adjusted {student.display_name} by {delta:+d} points.")
    return redirect(url_for("admin.student_detail", student_id=student.student_id))


@admin_bp.route("/challenge/<int:challenge_id>", methods=["POST"])
@admin_required
def edit_challenge(challenge_id):
    challenge = db.session.get(Challenge, challenge_id)
    if challenge is None:
        abort(404)
    challenge.description = request.form.get("description", "").strip()
    db.session.commit()
    flash(f"Updated the description for {challenge.name}.")
    return redirect(url_for("admin.home"))
