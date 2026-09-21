"""
Dashboard: every Challenge with its Hints (locked/unlocked per student)
and a recent-activity feed. Optional ?category= filter.
"""

from flask import render_template, request
from flask_login import login_required, current_user

from breachbox.dashboard import dashboard_bp
from breachbox.models import Challenge, Hint, HintUnlock, Submission


@dashboard_bp.route("/")
@login_required
def home():
    category = request.args.get("category")

    query = Challenge.query
    if category:
        query = query.filter_by(category=category)
    challenges = query.order_by(Challenge.points.asc()).all()

    unlocked_hint_ids = {
        h.hint_id
        for h in HintUnlock.query.filter_by(student_id=current_user.student_id).all()
    }

    challenge_data = []
    for challenge in challenges:
        hints = (
            Hint.query.filter_by(challenge_id=challenge.challenge_id)
            .order_by(Hint.hint_order)
            .all()
        )
        challenge_data.append({
            "challenge": challenge,
            "hints": [
                {"hint": h, "unlocked": h.hint_id in unlocked_hint_ids}
                for h in hints
            ],
        })

    recent_submissions = (
        Submission.query.order_by(Submission.submitted_at.desc()).limit(15).all()
    )

    return render_template(
        "dashboard.html",
        student=current_user,
        challenge_data=challenge_data,
        recent_submissions=recent_submissions,
        categories=Challenge.VALID_CATEGORIES,
        active_category=category,
    )
