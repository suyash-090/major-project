import os

# Computed from this file's own location, not the current working
# directory, so config.py resolves to the exact same path regardless of
# which script imports it. This matters because two separate services
# (breachbox_app and flag_api) both need to agree on the same database
# file without any implicit "magic" folder resolution deciding it for
# them, since that exact kind of implicit resolution has already caused
# real bugs earlier in this project.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_DB_PATH = os.path.join(BASE_DIR, "instance", "breachbox.db")


class Config:
    # SECRET_KEY signs the session cookie. Both breachbox_app and
    # flag_api must use the SAME value, since a student's login session,
    # created by breachbox_app, needs to be understood by flag_api too
    # when they submit a flag there.
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-me")

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{_DEFAULT_DB_PATH}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False


def ensure_instance_folder_exists():
    os.makedirs(os.path.dirname(_DEFAULT_DB_PATH), exist_ok=True)


ensure_instance_folder_exists()
