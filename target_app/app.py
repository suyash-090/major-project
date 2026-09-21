"""
target_app: the deliberately vulnerable app (vulnerable zone).
Separate Flask service and database from breachbox_app, no connection
between them. Four vulnerabilities: SQLi (/login), XSS (/feedback),
IDOR (/tickets/<id>), command injection (/diagnostics).
"""

import os
import subprocess
from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

app = Flask(__name__)

_APP_DIR = os.path.dirname(os.path.abspath(__file__))
_DB_PATH = os.path.join(_APP_DIR, "target_app.db")
_OPS_NOTES_PATH = os.path.join(_APP_DIR, "ops_notes.txt")

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", f"sqlite:///{_DB_PATH}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# Plaintext flags. breachbox/challenges/ only ever stores the hash of each.
SQLI_FLAG = "flag{sql1_st4ff_p0rt4l_byp4ss_2026}"
XSS_FLAG = "flag{r3fl3ct3d_xss_st4ff_f33db4ck_2026}"
IDOR_FLAG = "flag{1d0r_t1ck3t_3num3r4t10n_2026}"
CMDI_FLAG = "flag{cmd1_p1ng_ut1l1ty_1nj3ct10n_2026}"


class StaffUser(db.Model):
    __tablename__ = "staff_users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)


class Ticket(db.Model):
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
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # VULNERABLE: raw f-string SQL instead of a parameterized query, so a
    # quote in `username` can break out of the string and change the
    # query's logic, e.g. admin' OR '1'='1
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
    message = request.args.get("message", "")
    flag = XSS_FLAG if _looks_like_working_xss_payload(message) else None
    return render_template("feedback.html", message=message, flag=flag)


def _looks_like_working_xss_payload(message: str) -> bool:
    # Signature check standing in for real browser execution, see
    # feedback.html's |safe filter, that's the actual vulnerability.
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
    # VULNERABLE: no check that the requester owns this ticket, or is
    # staff at all, any valid ID returns that ticket's content.
    ticket = db.session.get(Ticket, ticket_id)
    if ticket is None:
        return "No such ticket", 404
    return render_template("view_ticket.html", ticket=ticket)


@app.route("/diagnostics", methods=["GET"])
def diagnostics_form():
    return render_template("diagnostics.html", output=None)


@app.route("/diagnostics", methods=["POST"])
def diagnostics_run():
    host = request.form.get("host", "")
    try:
        # VULNERABLE: shell=True with unsanitized input lets shell
        # metacharacters (; && |) chain in a second, arbitrary command.
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
