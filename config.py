import os


class Config:
    # SECRET_KEY signs the session cookie. Flask-Login depends on this
    # for session-based auth, which is why it's not optional.
    # In real use, set this via an environment variable, never commit a
    # real secret to GitHub. The fallback here is only for local dev.
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-me")

    # SQLALCHEMY_DATABASE_URI points at a SQLite file. Flask-SQLAlchemy
    # automatically resolves a relative sqlite:/// path against the app's
    # instance folder, so this becomes <instance_path>/breachbox.db.
    # Do NOT write "sqlite:///instance/breachbox.db" here, that double-nests
    # it into instance/instance/breachbox.db, which doesn't exist and
    # fails with "unable to open database file".
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///breachbox.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
