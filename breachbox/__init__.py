import os
from flask import Flask

from config import Config
from breachbox.extensions import db, login_manager
from breachbox.models import Student


def create_app(config_class=Config):
    app = Flask(__name__, instance_relative_config=True, template_folder="../templates")
    app.config.from_object(config_class)

    # Flask's instance folder holds things that shouldn't be in version
    # control, our SQLite file lives here. Create it if it doesn't exist,
    # since a fresh clone of the repo won't have it yet.
    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(student_id):
        return db.session.get(Student, int(student_id))

    # Blueprints are registered here, not imported at the top of the file,
    # because each blueprint module imports `db` from extensions.py, and
    # importing them before db.init_app(app) has run causes issues.
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
        _print_discovered_challenges()

    return app


def _print_discovered_challenges():
    """
    Runs once at startup so the team can see, in the terminal, that the
    challenge loader actually found something. This is your confirmation
    that discover_challenges() works before anyone builds a real
    vulnerability on top of it.
    """
    from breachbox.challenges.base import discover_challenges

    found = discover_challenges()
    print(f"[BreachBox] Discovered {len(found)} challenge subclass(es):")
    for cls in found:
        print(f"  - {cls.name} ({cls.category}, {cls.difficulty}, {cls.points} pts)")
