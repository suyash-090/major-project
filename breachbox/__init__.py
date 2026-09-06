from flask import Flask

from config import Config
from breachbox.extensions import db, init_login_manager


def create_app(config_class=Config):
    """
    Builds breachbox_app: accounts, dashboard, scoreboard, hints. This is
    the protected_zone service. It deliberately does NOT register the
    submissions blueprint, that lives only in flag_api now (see
    flag_api/app.py), since exposing flag submission from this app would
    put the whole app back on a network reachable from the vulnerable
    zone, which is exactly the isolation gap this refactor fixes.
    """
    app = Flask(__name__, template_folder="../templates")
    app.config.from_object(config_class)

    db.init_app(app)
    init_login_manager(app)

    from breachbox.auth import auth_bp
    from breachbox.dashboard import dashboard_bp
    from breachbox.scoreboard import scoreboard_bp
    from breachbox.hints import hints_bp

    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(dashboard_bp, url_prefix="/dashboard")
    app.register_blueprint(scoreboard_bp, url_prefix="/scoreboard")
    app.register_blueprint(hints_bp, url_prefix="/hints")

    @app.route("/")
    def index():
        return "BreachBox is alive"

    with app.app_context():
        db.create_all()
        _sync_and_print_challenges()

    return app


def _sync_and_print_challenges():
    from breachbox.challenges.base import sync_challenges_to_db

    found = sync_challenges_to_db()
    print(f"[BreachBox] Discovered and synced {len(found)} challenge subclass(es):")
    for cls in found:
        print(f"  - {cls.name} ({cls.category}, {cls.difficulty}, {cls.points} pts)")
