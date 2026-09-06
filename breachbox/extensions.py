from flask import jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

# `db` is shared between breachbox_app and flag_api, since both
# genuinely operate on the same database.
db = SQLAlchemy()

# breachbox_app's login manager: a real browser-facing app, so an
# unauthenticated request gets redirected to an actual login page.
login_manager = LoginManager()
login_manager.login_view = "auth.login"

# flag_api gets its OWN separate LoginManager instance, deliberately not
# a shared one with breachbox_app. Flask-Login's login_view is stored on
# the LoginManager instance itself and applies to every app that
# instance is bound to, so reusing one instance across two services with
# different registered routes breaks: flag_api has no "auth.login"
# endpoint to redirect to. flag_api is an API, not something a browser
# navigates directly, so it returns a JSON 401 instead of a redirect.
api_login_manager = LoginManager()


@api_login_manager.unauthorized_handler
def _api_unauthorized():
    return jsonify({"error": "authentication required"}), 401


def _load_user(student_id):
    """The actual lookup, shared by both LoginManager instances below."""
    from breachbox.models import Student
    return db.session.get(Student, int(student_id))


def init_login_manager(app):
    """Used by breachbox_app."""
    login_manager.init_app(app)
    login_manager.user_loader(_load_user)


def init_api_login_manager(app):
    """
    Used by flag_api. Both services trust the same session cookie
    because both read SECRET_KEY from the same Config, so a student who
    logs in via breachbox_app is recognised here too without logging in
    twice.
    """
    api_login_manager.init_app(app)
    api_login_manager.user_loader(_load_user)
