from flask import Blueprint

dashboard_bp = Blueprint("dashboard", __name__, template_folder="../../templates")

from breachbox.dashboard import routes  # noqa: E402,F401
