import os
from flask import Flask, render_template, redirect, url_for

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
    from breachbox.submissions import submissions_bp

    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(dashboard_bp, url_prefix="/dashboard")
    app.register_blueprint(scoreboard_bp, url_prefix="/scoreboard")
    app.register_blueprint(hints_bp, url_prefix="/hints")
    app.register_blueprint(submissions_bp, url_prefix="/api")

    @app.route("/")
    def index():
        return render_template("index.html")

    # Friendly top-level routes that map to the auth blueprint's handlers
    @app.route("/login")
    def login_route():
        return redirect(url_for("auth.login"))

    @app.route("/register")
    def register_route():
        return redirect(url_for("auth.register"))

    @app.route("/logout")
    def logout_route():
        return redirect(url_for("auth.logout"))

    with app.app_context():
        db.create_all()
        _sync_and_print_challenges()

    return app


def _sync_and_print_challenges():
    """
    Runs once at startup. Syncs discovered Challenge subclasses into the
    database, then prints what it found so the team can see, in the
    terminal, that discovery and syncing actually worked, before anyone
    builds a real vulnerability on top of it.
    """
    from breachbox.challenges.base import sync_challenges_to_db

    found = sync_challenges_to_db()
    print(f"[BreachBox] Discovered and synced {len(found)} challenge subclass(es):")
    for cls in found:
        print(f"  - {cls.name} ({cls.category}, {cls.difficulty}, {cls.points} pts)")
