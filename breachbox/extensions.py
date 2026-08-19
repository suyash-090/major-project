from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

# These are created here, unattached to any app, and "attached" to the
# real app later inside create_app() in __init__.py. This pattern avoids
# a circular import problem: models.py needs `db`, and blueprints need
# both `db` and `login_manager`, but none of them can import directly
# from an app.py that also imports them.
db = SQLAlchemy()
login_manager = LoginManager()

# Where Flask-Login sends a user if they try to access a @login_required
# route without being logged in.
login_manager.login_view = "auth.login"
