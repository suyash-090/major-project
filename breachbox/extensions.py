from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

# Created here unattached and bound to the app in create_app(). Keeps us
# from a circular import between models and the blueprints.
db = SQLAlchemy()
login_manager = LoginManager()

login_manager.login_view = "auth.login"
