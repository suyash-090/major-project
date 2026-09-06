"""
This is the VULNERABLE ZONE target app, a separate Flask service from
breachbox_app, with its own tiny database, and no connection whatsoever
to the real student/challenge/submission database in the protected zone.
That separation is deliberate, and is the entire point of the isolation
model in Section 2.2 of the proposal: this app should have nothing worth
protecting inside it, so a full compromise of it costs nothing.

WHAT'S BUILT HERE (skeleton, Week 6-7 infra):
  - A minimal Flask app that boots on its own, in its own container
  - A tiny "staff_users" table with a couple of dummy accounts, so
    there's something real to query against once the vulnerable route
    exists
  - A login form template

WHAT'S NOW BUILT (Sameer's Week 6-7 milestone, done):
  - The actual POST /login handler
  - The deliberately unsafe SQL query
  - Wiring the flag string into a successful bypass response

Built following the worked example in
breachbox/challenges/_reference_sqli_login.py, adapted to query the
real staff_users table below instead of a hypothetical `users` table.
The matching Challenge subclass that checks this same flag lives at
breachbox/challenges/sqli_login.py.
"""

import os
from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

app = Flask(__name__)

# Using an explicit absolute path here rather than a relative
# "sqlite:///target_app.db" string. Flask-SQLAlchemy silently resolves
# relative SQLite paths against Flask's instance folder, not the
# current working directory, which is an easy trap, we hit this exact
# thing once already while building breachbox_app's config. Being
# explicit here avoids the same confusion in a second codebase.
_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "target_app.db")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", f"sqlite:///{_DB_PATH}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# The flag a student gets on a successful SQLi bypass. Plaintext here on
# purpose, this app has nothing worth protecting by design, see the
# module docstring above. The matching SHA-256 hash lives on the
# Challenge subclass in breachbox/challenges/sqli_login.py, which is
# what breachbox_app's /api/submit actually checks a submission
# against, not anything in this file.
FLAG = "flag{sql1_st4ff_p0rt4l_byp4ss_2026}"


class StaffUser(db.Model):
    """
    Fake staff accounts, local to this app only. This is the data the
    SQL injection is meant to expose, it has no relationship to the real
    Student table in breachbox_app, and never should.
    """
    __tablename__ = "staff_users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)


def seed_dummy_staff_accounts():
    if StaffUser.query.count() == 0:
        db.session.add_all([
            StaffUser(username="admin", password="staffportal2026"),
            StaffUser(username="itsupport", password="hunter2"),
        ])
        db.session.commit()


@app.route("/")
def index():
    return "Target app is alive (vulnerable zone)"


@app.route("/login", methods=["GET"])
def login_form():
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login_submit():
    """
    DELIBERATE VULNERABILITY: raw, string-formatted SQL against
    StaffUser, on purpose, rather than SQLAlchemy's normal filter_by().
    Exploitable via something like  admin' OR '1'='1  in the username
    field, which collapses the WHERE clause to always-true regardless
    of the password supplied.
    """
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    query = (
        f"SELECT * FROM staff_users WHERE username = '{username}' "
        f"AND password = '{password}'"
    )
    result = db.session.execute(text(query)).fetchone()

    if result:
        return (
            f"Welcome, {result.username}! "
            f"Flag: {FLAG} "
            "(submit this flag at breachbox_app's /api/submit)"
        )

    return render_template("login.html", error="Invalid username or password"), 401


with app.app_context():
    db.create_all()
    seed_dummy_staff_accounts()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
