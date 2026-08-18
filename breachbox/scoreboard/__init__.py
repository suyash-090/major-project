from flask import Blueprint

scoreboard_bp = Blueprint("scoreboard", __name__, template_folder="../../templates")

from breachbox.scoreboard import routes  # noqa: E402,F401
