"""
Answers Sameer's isolation issue: the two-zone setup left breachbox_app
and target_app sharing nothing, blocking the flag-submission path
entirely. The fix is his own suggested direction, rather than putting
the whole breachbox_app on a shared network, the flag-submission route
gets pulled into this small, separate service. flag_api is the ONLY
thing that sits on submission_zone alongside target_app. It shares the
same database as breachbox_app via a Docker volume, not a network path,
and reuses the same models and the same submissions blueprint, but
registers nothing else, no auth routes, no dashboard, no hints.

Security property this buys: if target_app is fully compromised,
whatever an attacker can reach on submission_zone is exactly this file,
two routes, submit and list-challenges. They cannot reach breachbox_app
at all, it was never on this network to begin with.
"""

from flask import Flask

from config import Config
from breachbox.extensions import db, init_api_login_manager
from breachbox.submissions import submissions_bp


def create_flag_api_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    init_api_login_manager(app)

    app.register_blueprint(submissions_bp, url_prefix="/api")

    # Deliberately NOT calling db.create_all() here. breachbox_app owns
    # schema creation, this service just uses whatever schema already
    # exists in the shared database. Two independent services racing to
    # create the same tables in the same SQLite file at startup is a
    # real failure we hit directly while building this, not a
    # hypothetical one. Start breachbox_app first, see docker-compose's
    # depends_on and the README.

    return app


app = create_flag_api_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=True)
