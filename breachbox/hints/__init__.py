from flask import Blueprint

hints_bp = Blueprint("hints", __name__, template_folder="../../templates")

from breachbox.hints import routes  # noqa: E402,F401
