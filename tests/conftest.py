"""
Shared pytest fixtures for the BreachBox test suite.

Every test gets its own throwaway SQLite database (a temp file), built fresh
by the real application factory, so tests never touch the dev database and
never depend on each other's data. The challenge and hint tables are seeded
automatically by create_app(), exactly as they are when the app really runs.
"""

import pytest

from breachbox import create_app
from breachbox.extensions import db
from breachbox.models import Student, Challenge
from breachbox.ratelimit import login_limiter, flag_limiter


class _BaseTestConfig:
    TESTING = True
    SECRET_KEY = "test-secret-key"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


@pytest.fixture
def app(tmp_path):
    """A fresh application bound to a per-test temp SQLite database."""
    db_path = tmp_path / "breachbox_test.db"

    class _TestConfig(_BaseTestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{db_path}"

    application = create_app(_TestConfig)
    yield application

    with application.app_context():
        db.session.remove()


@pytest.fixture
def client(app):
    """A test client for the app. Keeps cookies across requests in one test."""
    return app.test_client()


@pytest.fixture(autouse=True)
def _reset_rate_limiters():
    """
    The login and flag limiters are process-wide singletons, so their counters
    would otherwise leak between tests. Clear them before and after each test.
    """
    login_limiter._hits.clear()
    flag_limiter._hits.clear()
    yield
    login_limiter._hits.clear()
    flag_limiter._hits.clear()


@pytest.fixture
def make_student(app):
    """Factory: create a Student row and return its student_id."""
    def _make(name="player1", password="pw", class_group="Y12-A"):
        with app.app_context():
            student = Student(display_name=name, class_group=class_group)
            student.set_password(password)
            db.session.add(student)
            db.session.commit()
            return student.student_id
    return _make


@pytest.fixture
def solver(app, client, make_student):
    """Create a student named 'solver' and log the test client in as them.

    Returns the student_id. Because `client` is the same instance the test
    uses, requests made with `client` after requesting this fixture are
    authenticated.
    """
    student_id = make_student("solver", "pw")
    resp = client.post(
        "/auth/login", data={"display_name": "solver", "password": "pw"}
    )
    assert resp.status_code == 302  # redirect to dashboard on success
    return student_id


@pytest.fixture
def cid(app):
    """Factory: look up a seeded challenge_id by its display name."""
    def _cid(name="Staff Portal Login Bypass"):
        with app.app_context():
            return Challenge.query.filter_by(name=name).first().challenge_id
    return _cid


@pytest.fixture
def flag_for(app):
    """The correct flag a given student should capture for a given challenge key.

    Flags are per-student, so a test has to build the right one from the
    student's own token, exactly the way target_app does.
    """
    from breachbox.flags import make_flag
    from breachbox.models import Student

    def _flag(student_id, key):
        with app.app_context():
            token = db.session.get(Student, student_id).flag_token
        return make_flag(token, key)
    return _flag
