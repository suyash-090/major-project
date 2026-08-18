"""
The scoring QUERY itself is built for real here, since it's the same
logic as the scoreboard SQL view in the database schema (points earned
from solved challenges, minus points spent on unlocked hints), and there
is no good reason to leave that as a placeholder, it's schema-level work,
not the Week 11 UX/UI work.

What's still a placeholder: the template only renders a plain table right
now. Wiring up Chart.js, the category filter, and live auto-refresh is
Harry's Week 11 task, not part of this skeleton.
"""

from flask import render_template
from flask_login import login_required
from sqlalchemy import func

from breachbox.scoreboard import scoreboard_bp
from breachbox.extensions import db
from breachbox.models import Student, Challenge, Submission, Hint, HintUnlock


def calculate_scoreboard():
    """
    Returns a list of dicts, one per student, each with total_score,
    sorted highest first. Mirrors the `scoreboard` SQL view: a challenge
    only counts once per student even if they had incorrect attempts
    first, and unlocked hints deduct points.
    """
    # Distinct (student_id, challenge_id) pairs the student solved at
    # least once, then sum those challenges' points.
    solved_points = (
        db.session.query(
            Submission.student_id,
            func.sum(Challenge.points).label("points_from_challenges"),
        )
        .join(Challenge, Challenge.challenge_id == Submission.challenge_id)
        .filter(Submission.is_correct.is_(True))
        .group_by(Submission.student_id, Submission.challenge_id)
        .subquery()
    )

    points_per_student = (
        db.session.query(
            solved_points.c.student_id,
            func.sum(solved_points.c.points_from_challenges).label("points_from_challenges"),
        )
        .group_by(solved_points.c.student_id)
        .subquery()
    )

    hint_costs = (
        db.session.query(
            HintUnlock.student_id,
            func.sum(Hint.point_cost).label("points_lost_to_hints"),
        )
        .join(Hint, Hint.hint_id == HintUnlock.hint_id)
        .group_by(HintUnlock.student_id)
        .subquery()
    )

    rows = (
        db.session.query(
            Student.student_id,
            Student.display_name,
            Student.class_group,
            func.coalesce(points_per_student.c.points_from_challenges, 0).label("points_from_challenges"),
            func.coalesce(hint_costs.c.points_lost_to_hints, 0).label("points_lost_to_hints"),
        )
        .outerjoin(points_per_student, points_per_student.c.student_id == Student.student_id)
        .outerjoin(hint_costs, hint_costs.c.student_id == Student.student_id)
        .all()
    )

    scoreboard = [
        {
            "student_id": r.student_id,
            "display_name": r.display_name,
            "class_group": r.class_group,
            "points_from_challenges": r.points_from_challenges,
            "points_lost_to_hints": r.points_lost_to_hints,
            "total_score": r.points_from_challenges - r.points_lost_to_hints,
        }
        for r in rows
    ]
    scoreboard.sort(key=lambda s: s["total_score"], reverse=True)
    return scoreboard


@scoreboard_bp.route("/")
@login_required
def view():
    return render_template("scoreboard.html", scoreboard=calculate_scoreboard())
