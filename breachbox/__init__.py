import os
from flask import Flask

from config import Config
from breachbox.extensions import db, login_manager
from breachbox.models import Student


def create_app(config_class=Config):
    app = Flask(__name__, instance_relative_config=True, template_folder="../templates", static_folder="../static")
    app.config.from_object(config_class)

    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(student_id):
        return db.session.get(Student, int(student_id))

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
        return "BreachBox is alive"

    with app.app_context():
        db.create_all()
        _sync_and_print_challenges()
        _seed_hints_if_needed()

    return app


def _sync_and_print_challenges():
    from breachbox.challenges.base import sync_challenges_to_db

    found = sync_challenges_to_db()
    print(f"[BreachBox] Discovered and synced {len(found)} challenge subclass(es):")
    for cls in found:
        print(f"  - {cls.name} ({cls.category}, {cls.difficulty}, {cls.points} pts)")


def _seed_hints_if_needed():
    from breachbox.extensions import db
    from breachbox.models import Challenge, Hint

    if Hint.query.count() > 0:
        return

    hint_ladder = {
        "Staff Portal Login Bypass": [
            (1, "The login route builds its SQL query with an f-string. "
                "What happens if your username includes a quote character?", 20),
        ],
        "Staff Feedback Reflected XSS": [
            (1, "Check how the message query parameter gets rendered on "
                "the page. Does anything strip or escape HTML tags in it?", 20),
        ],
        "Support Ticket IDOR": [
            (1, "After you submit your own ticket, look closely at the ID "
                "in the URL. What happens if you try a smaller number?", 25),
            (2, "Ticket IDs are assigned in creation order starting from 1. "
                "The very first ticket ever created wasn't yours.", 50),
        ],
        "Diagnostics Command Injection": [
            (1, "The diagnostics tool runs a real shell command behind the "
                "scenes. Some punctuation characters mean something "
                "special to a shell.", 40),
            (2, "In a Unix shell, a semicolon lets you run a second, "
                "separate command right after the first one finishes.", 80),
        ],
    }

    for challenge_name, hints in hint_ladder.items():
        challenge = Challenge.query.filter_by(name=challenge_name).first()
        if challenge is None:
            continue
        for order, text, cost in hints:
            db.session.add(Hint(
                challenge_id=challenge.challenge_id,
                hint_order=order,
                text=text,
                point_cost=cost,
            ))

    db.session.commit()
