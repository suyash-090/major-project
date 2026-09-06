from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from breachbox.extensions import db


class Student(UserMixin, db.Model):
    """
    One row per participant. UserMixin bolts on the properties Flask-Login
    needs (is_authenticated, is_active, get_id, etc.) so this class can be
    used directly with @login_required and current_user.
    """
    __tablename__ = "student"

    student_id = db.Column(db.Integer, primary_key=True)
    display_name = db.Column(db.String(80), unique=True, nullable=False)
    class_group = db.Column(db.String(40), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    submissions = db.relationship("Submission", backref="student", lazy=True)
    hint_unlocks = db.relationship("HintUnlock", backref="student", lazy=True)

    def set_password(self, raw_password):
        # Never store a plaintext password. This hashes it with a salt
        # baked in, using Werkzeug's default algorithm.
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password):
        return check_password_hash(self.password_hash, raw_password)

    # Flask-Login needs get_id() to return a string. UserMixin provides a
    # default that uses self.id, but our primary key is student_id, so we
    # override it explicitly rather than relying on a naming coincidence.
    def get_id(self):
        return str(self.student_id)

    def __repr__(self):
        return f"<Student {self.display_name}>"


class Challenge(db.Model):
    """
    One row per deliberate vulnerability. The `category` column backs the
    Challenge base class's category attribute (see challenges/base.py),
    and is what the dashboard's category filter will query against once
    that's built in Week 11.

    flag_hash stores a hash of the correct flag, never the flag itself,
    so the database isn't a second place the answer could leak from.
    """
    __tablename__ = "challenge"

    VALID_CATEGORIES = ("Web", "Injection", "Access Control", "Other")
    VALID_DIFFICULTIES = ("Easy", "Medium", "Hard")

    challenge_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    category = db.Column(db.String(30), nullable=False)
    difficulty = db.Column(db.String(10), nullable=False)
    points = db.Column(db.Integer, nullable=False)
    description = db.Column(db.Text)
    flag_hash = db.Column(db.String(255), nullable=False)
    is_chained = db.Column(db.Boolean, default=False, nullable=False)

    hints = db.relationship("Hint", backref="challenge", lazy=True,
                             cascade="all, delete-orphan")
    submissions = db.relationship("Submission", backref="challenge", lazy=True,
                                   cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Challenge {self.name} ({self.category}/{self.difficulty})>"


class Hint(db.Model):
    """One or more hints per challenge, each with its own point cost."""
    __tablename__ = "hint"

    hint_id = db.Column(db.Integer, primary_key=True)
    challenge_id = db.Column(db.Integer, db.ForeignKey("challenge.challenge_id"),
                              nullable=False)
    hint_order = db.Column(db.Integer, default=1, nullable=False)
    text = db.Column(db.Text, nullable=False)
    point_cost = db.Column(db.Integer, nullable=False)

    unlocks = db.relationship("HintUnlock", backref="hint", lazy=True,
                               cascade="all, delete-orphan")


class Submission(db.Model):
    """
    One row per flag attempt, correct or not. This is a full attempt log,
    not just a "solved" table, so incorrect attempts stay recorded for the
    dashboard's recent submissions feed. writeup_text is only required by
    the application layer when is_correct is True, that check belongs in
    the flag-submission route, not here in the model.

    __table_args__ adds a DB-level backstop for the "already solved" check
    the flag-submission route makes at the app layer (see
    breachbox/submissions/routes.py): at most one is_correct=True
    Submission can ever exist per (student_id, challenge_id), so a bug in
    the route logic can't award the same student points twice for the
    same challenge. This is a partial unique index (SQLite-specific,
    matching this project's DATABASE_URL), not a table-wide constraint,
    since multiple incorrect attempts for the same pair are expected and
    fine.
    """
    __tablename__ = "submission"
    __table_args__ = (
        db.Index(
            "uq_submission_student_challenge_correct",
            "student_id", "challenge_id",
            unique=True,
            sqlite_where=db.text("is_correct = 1"),
        ),
    )

    submission_id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey("student.student_id"),
                            nullable=False)
    challenge_id = db.Column(db.Integer, db.ForeignKey("challenge.challenge_id"),
                              nullable=False)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_correct = db.Column(db.Boolean, nullable=False)
    writeup_text = db.Column(db.Text)


class HintUnlock(db.Model):
    """
    One row per hint a student has unlocked. The unique constraint means
    unlocking the same hint twice never charges a student twice, matching
    the point-penalty design in the proposal.
    """
    __tablename__ = "hint_unlock"
    __table_args__ = (
        db.UniqueConstraint("student_id", "hint_id", name="uq_student_hint"),
    )

    unlock_id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey("student.student_id"),
                            nullable=False)
    hint_id = db.Column(db.Integer, db.ForeignKey("hint.hint_id"),
                         nullable=False)
    unlocked_at = db.Column(db.DateTime, default=datetime.utcnow)
