"""
Hint unlocking. Costs points, permanently; calculate_scoreboard() in
scoreboard/routes.py deducts unlocked hints from the total.
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
