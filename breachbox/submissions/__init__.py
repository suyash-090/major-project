from flask import Blueprint

submissions_bp = Blueprint("submissions", __name__, template_folder="../../templates")

from breachbox.submissions import routes  # noqa: E402,F401
