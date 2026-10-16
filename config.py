import os


class Config:
    # Signs the session cookie. Set via env var in real use, not committed.
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-me")

    # A relative sqlite path resolves against the instance folder, so this
    # ends up as instance/breachbox.db.
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///breachbox.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
