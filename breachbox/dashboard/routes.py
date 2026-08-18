"""
PLACEHOLDER, Week 11 (Harry's Track D). This route currently just proves
a logged-in student can reach a protected page. The real dashboard needs
to query challenges by category, pull the live scoreboard, and show the
recent submissions feed, none of that exists yet because Challenge and
Submission rows don't exist yet either. Build that out once Sameer and
Suyash's vulnerabilities are in the database.
"""

from flask import render_template
from flask_login import login_required, current_user

from breachbox.dashboard import dashboard_bp


@dashboard_bp.route("/")
@login_required
def home():
    return render_template("dashboard.html", student=current_user)
