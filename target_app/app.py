"""
This is the VULNERABLE ZONE target app, a separate Flask service from
breachbox_app, with its own tiny database, and no connection whatsoever
to the real student/challenge/submission database in the protected zone.
That separation is deliberate, and is the entire point of the isolation
model in Section 2.2 of the proposal: this app should have nothing worth
protecting inside it, so a full compromise of it costs nothing.

Four deliberate vulnerabilities live here, Vulnerability Sets 1 and 2:
  - SQL injection ("Staff Portal Login Bypass"), POST /login
  - Reflected XSS ("Staff Feedback Reflected XSS"), GET /feedback
  - IDOR / broken access control ("Support Ticket IDOR"), GET /tickets/<id>
  - OS command injection ("Diagnostics Command Injection"), POST /diagnostics
"""

import os
import subprocess
from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

app = Flask(__name__)

# Using an explicit absolute path here rather than a relative
# "sqlite:///target_app.db" string. Flask-SQLAlchemy silently resolves
# relative SQLite paths against Flask's instance folder, not the
# current working directory, which is an easy trap, we hit this exact
# thing once already while building breachbox_app's config. Being
# explicit here avoids the same confusion in a second codebase.
_APP_DIR = os.path.dirname(os.path.abspath(__file__))
_DB_PATH = os.path.join(_APP_DIR, "target_app.db")
_OPS_NOTES_PATH = os.path.join(_APP_DIR, "ops_notes.txt")

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", f"sqlite:///{_DB_PATH}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# Flags this app can hand out on a successful bypass. Plaintext here on
# purpose, this app has nothing worth protecting by design, see the
# module docstring above. The matching SHA-256 hashes live on the four
# Challenge subclasses in breachbox/challenges/, which is what
# breachbox_app's /api/submit actually checks a submission against, not
# anything in this file.
SQLI_FLAG = "flag{sql1_st4ff_p0rt4l_byp4ss_2026}"
XSS_FLAG = "flag{r3fl3ct3d_xss_st4ff_f33db4ck_2026}"
IDOR_FLAG = "flag{1d0r_t1ck3t_3num3r4t10n_2026}"
CMDI_FLAG = "flag{cmd1_p1ng_ut1l1ty_1nj3ct10n_2026}"


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


class Ticket(db.Model):
    """
    Internal "IT support ticket" style records, local to this app. This
    is the resource the IDOR vulnerability exposes, no relationship to
    breachbox_app's real tables.
    """
    __tablename__ = "tickets"

    id = db.Column(db.Integer, primary_key=True)
    requester_name = db.Column(db.String(80), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)


def seed_dummy_staff_accounts():
    if StaffUser.query.count() == 0:
        db.session.add_all([
            StaffUser(username="admin", password="staffportal2026"),
            StaffUser(username="itsupport", password="hunter2"),
        ])
        db.session.commit()


def seed_admin_ticket():
    # Ticket #1, created before anyone else's, is what a student finds
    # by simply trying low IDs after filing their own ticket, that's
    # the entire IDOR here.
    if Ticket.query.count() == 0:
        db.session.add(Ticket(
            requester_name="admin",
            subject="Password rotation reminder",
            body=(
                "Internal note, staff eyes only: rotate the staff portal "
                "credentials after last week's incident review. "
                f"Flag: {IDOR_FLAG}"
            ),
        ))
        db.session.commit()


def seed_ops_notes_file():
    # Not served by any route, not linked from anywhere in the UI. The
    # only way to ever see this file's contents is the command
    # injection below.
    if not os.path.exists(_OPS_NOTES_PATH):
        with open(_OPS_NOTES_PATH, "w") as f:
            f.write(
                "Internal ops notes, not linked from the site anywhere.\n"
                f"Flag: {CMDI_FLAG}\n"
            )


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
    auto-escaping. Try it directly in a browser, e.g.
      /feedback?message=<script>alert(document.domain)</script>
    and the alert really fires.

    Design note on the flag: since script execution happens in the
    visitor's browser, not on the server, this route can't directly
    observe whether a payload executed. It reveals the flag when
    `message` contains an unescaped script trigger (<script>, onerror=,
    onload=), a deliberate simplification, not server-verified proof of
    execution.
    """
    message = request.args.get("message", "")
    flag = XSS_FLAG if _looks_like_working_xss_payload(message) else None
    return render_template("feedback.html", message=message, flag=flag)


def _looks_like_working_xss_payload(message: str) -> bool:
    lowered = message.lower()
    return "<script" in lowered or "onerror=" in lowered or "onload=" in lowered


@app.route("/tickets/new", methods=["GET"])
def new_ticket_form():
    return render_template("new_ticket.html")


@app.route("/tickets", methods=["POST"])
def create_ticket():
    requester_name = request.form.get("requester_name", "").strip() or "anonymous"
    subject = request.form.get("subject", "").strip()
    body = request.form.get("body", "").strip()
    ticket = Ticket(requester_name=requester_name, subject=subject, body=body)
    db.session.add(ticket)
    db.session.commit()
    return redirect(url_for("view_ticket", ticket_id=ticket.id))


@app.route("/tickets/<int:ticket_id>", methods=["GET"])
def view_ticket(ticket_id):
    """
    DELIBERATE VULNERABILITY: IDOR / broken access control. This route
    returns whichever ticket matches ticket_id with no check that the
    requester is the one who created it, or is staff at all. A student
    files their own ticket (gets some ID, say 7), then simply tries
    /tickets/1, /tickets/2, ... and finds ticket 1, the seeded admin
    ticket, which was never meant to be readable by anyone else.
    """
    ticket = db.session.get(Ticket, ticket_id)
    if ticket is None:
        return "No such ticket", 404
    return render_template("view_ticket.html", ticket=ticket)


@app.route("/diagnostics", methods=["GET"])
def diagnostics_form():
    return render_template("diagnostics.html", output=None)


@app.route("/diagnostics", methods=["POST"])
def diagnostics_run():
    """
    DELIBERATE VULNERABILITY: OS command injection. `host` goes straight
    into a shell string via subprocess.run(..., shell=True) rather than
    being passed as a separate argument list, so shell metacharacters in
    `host` (; && |) let a visitor chain in an arbitrary second command.
    Try, for example:
      127.0.0.1; cat ops_notes.txt
    ops_notes.txt is written at startup below, in this app's own working
    directory, not served by any route, only reachable this way.
    """
    host = request.form.get("host", "")
    try:
        result = subprocess.run(
            f"ping -c 1 {host}",
            shell=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        output = "(command timed out)"
    return render_template("diagnostics.html", output=output)


with app.app_context():
    db.create_all()
    seed_dummy_staff_accounts()
    seed_admin_ticket()
    seed_ops_notes_file()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
