"""
PLACEHOLDER, Week 11 (Harry's Track D). The HintUnlock model and its
unique-per-student-per-hint constraint already exist in models.py, so the
data layer is ready. What's not built yet is the actual unlock route:
checking the hint exists, checking it isn't already unlocked, inserting
the HintUnlock row, and returning the hint text to the student. Build
that here once there are real Hint rows in the database to unlock.
"""

from flask import jsonify
from flask_login import login_required

from breachbox.hints import hints_bp


@hints_bp.route("/unlock/<int:hint_id>", methods=["POST"])
@login_required
def unlock(hint_id):
    return jsonify({
        "status": "not_implemented",
        "message": "Hint unlocking is a Week 11 task, not built yet."
    }), 501
