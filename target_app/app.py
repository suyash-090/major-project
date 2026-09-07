"""
This is the VULNERABLE ZONE target app, a separate Flask service from
breachbox_app, with its own tiny database, and no connection whatsoever
to the real student/challenge/submission database in the protected zone.
That separation is deliberate, and is the entire point of the isolation
model in Section 2.2 of the proposal: this app should have nothing worth
protecting inside it, so a full compromise of it costs nothing.

WHAT'S BUILT HERE:
  - A tiny "staff_users" table with a couple of dummy accounts
  - A login form, POST-handled, deliberately vulnerable to SQL injection
    (Vulnerability Set 1, "Staff Portal Login Bypass")
  - A staff feedback board, deliberately vulnerable to reflected XSS
    (Vulnerability Set 1, "Staff Feedback Reflected XSS")

Both vulnerabilities live in this one small app on purpose, matching the
"target app" role described in the proposal: a single vulnerable-zone
service with more than one deliberate flaw, rather than a service per
vulnerability.
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

# Flags this app can hand out on a successful bypass. Plaintext here on
# purpose, this app has nothing worth protecting by design, see the
# module docstring above. The matching SHA-256 hashes live on the two
# Challenge subclasses in breachbox/challenges/, which is what
# breachbox_app's /api/submit actually checks a submission against, not
# anything in this file.
SQLI_FLAG = "flag{sql1_st4ff_p0rt4l_byp4ss_2026}"
XSS_FLAG = "flag{r3fl3ct3d_xss_st4ff_f33db4ck_2026}"


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
            f"Flag: {SQLI_FLAG} "
            "(submit this flag at breachbox_app's /api/submit)"
        )

    return render_template("login.html", error="Invalid username or password"), 401


@app.route("/feedback", methods=["GET"])
def feedback():
    """
    DELIBERATE VULNERABILITY: reflected XSS. The `message` query
    parameter is passed straight into the template and rendered with
    Jinja2's `|safe` filter, which turns off Jinja's normal
    auto-escaping. Anything the visitor puts in `message` becomes raw
    HTML in the response, including <script> tags, which the browser
    genuinely executes as part of the page, since this is a full
    server-rendered response, not something injected into an
    already-loaded page via JS. Try it directly in a browser, e.g.
      /feedback?message=<script>alert(document.domain)</script>
    and the alert really fires.

    Design note on the flag: unlike the SQLi challenge, "did the
    exploit work" for XSS isn't something this server can observe by
    itself, script execution happens in the visitor's browser, not
    here. Rather than stand up a headless-browser bot to prove it, the
    flag is revealed when `message` contains an unescaped script
    trigger (a <script> tag or an inline event handler like onerror=),
    which is exactly the signature of a payload that would execute.
    That's a deliberate simplification, not a claim that this route
    itself renders the page and inspects it, worth being explicit
    about in the write-up.
    """
    message = request.args.get("message", "")
    flag = XSS_FLAG if _looks_like_working_xss_payload(message) else None
    return render_template("feedback.html", message=message, flag=flag)


def _looks_like_working_xss_payload(message: str) -> bool:
    lowered = message.lower()
    return "<script" in lowered or "onerror=" in lowered or "onload=" in lowered


with app.app_context():
    db.create_all()
    seed_dummy_staff_accounts()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
