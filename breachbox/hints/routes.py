"""
Hint unlocking, Week 11 (reassigned to Sameer). The HintUnlock model
and its unique-per-student-per-hint constraint already existed in
models.py, so the data layer was ready, this is just the route.

A student can unlock any hint for any challenge at any time. Unlocking
permanently costs points: calculate_scoreboard() in
breachbox/scoreboard/routes.py already subtracts every unlocked hint's
point_cost from a student's total, that scoring logic predates this
route. Re-requesting an already-unlocked hint never charges twice,
HintUnlock's unique constraint on (student_id, hint_id) is the DB-level
backstop, this route checks first so a repeat request just returns the
same hint text again for free instead of erroring.
"""

from flask import jsonify
from flask_login import login_required, current_user

from breachbox.hints import hints_bp
from breachbox.extensions import db
from breachbox.models import Hint, HintUnlock


@hints_bp.route("/unlock/<int:hint_id>", methods=["POST"])
@login_required
def unlock(hint_id):
    hint = db.session.get(Hint, hint_id)
    if hint is None:
        return jsonify({"error": "no such hint"}), 404

    existing = HintUnlock.query.filter_by(
        student_id=current_user.student_id, hint_id=hint_id
    ).first()

    if existing is None:
        db.session.add(HintUnlock(student_id=current_user.student_id, hint_id=hint_id))
        db.session.commit()

    return jsonify({
        "hint_id": hint.hint_id,
        "text": hint.text,
        "point_cost": hint.point_cost,
        "already_unlocked": existing is not None,
    })
