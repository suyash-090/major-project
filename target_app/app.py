"""target_app: the deliberately vulnerable site (the vulnerable zone). It's a
separate Flask app and database from breachbox_app. Vulnerabilities: SQLi
(/login), XSS (/feedback), IDOR (/tickets/<id>), command injection
(/diagnostics), path traversal (/reports) and a chained IDOR to staff
console (/staff/console)."""

import hashlib
import hmac
import os
import subprocess
from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

app = Flask(__name__)

_APP_DIR = os.path.dirname(os.path.abspath(__file__))
_DB_PATH = os.path.join(_APP_DIR, "target_app.db")
_OPS_NOTES_PATH = os.path.join(_APP_DIR, "ops_notes.txt")
_REPORTS_DIR = os.path.join(_APP_DIR, "reports")
_STAFF_REPORT_FLAG_PATH = os.path.join(_APP_DIR, "staff_only_report.txt")

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", f"sqlite:///{_DB_PATH}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# Per-student flags. The strings below are PLACEHOLDERS; personalise_flags()
# swaps each one for a flag unique to the attacking student just before the
# response leaves this app. So a flag one student captures can never be shared
# with another: breachbox_app only accepts the flag built from that student's
# own token.
SQLI_FLAG = "__FLAG_SQLI__"
XSS_FLAG = "__FLAG_XSS__"
IDOR_FLAG = "__FLAG_IDOR__"
CMDI_FLAG = "__FLAG_CMDI__"
PTRAVERSAL_FLAG = "__FLAG_PTRAVERSAL__"
CHAINED_FLAG = "__FLAG_CHAINED__"

# Shared with breachbox_app through config only (no network link, no shared
# database), so both sides derive the same per-student flags. Same default as
# breachbox/flags.py; set FLAG_SECRET in the environment for a real deploy.
FLAG_SECRET = os.environ.get("FLAG_SECRET", "breachbox-dev-flag-secret-change-me")

_FLAG_PLACEHOLDERS = {
    "__FLAG_SQLI__": "sqli",
    "__FLAG_XSS__": "xss",
    "__FLAG_IDOR__": "idor",
    "__FLAG_CMDI__": "cmdi",
    "__FLAG_PTRAVERSAL__": "ptraversal",
    "__FLAG_CHAINED__": "chained",
}


def make_flag(token, key):
    digest = hmac.new(
        FLAG_SECRET.encode(), f"{token}:{key}".encode(), hashlib.sha256
    ).hexdigest()[:16]
    return f"flag{{{key}_{digest}}}"


def _current_token():
    # The student pastes their BreachBox token into the box in the nav, which
    # sets this cookie. With no token set we fall back to a fixed "anon" flag,
    # so the app still works on its own for testing.
    return request.cookies.get("bb_token") or "anon"

# Leaked on purpose inside a staff ticket, which is the chained challenge:
# read the ticket through the IDOR, then reuse the token at /staff/console.
STAFF_CONSOLE_TOKEN = "s3ss-9f2a7c41-staff-console"


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
    body = (
        "Internal note, staff eyes only: rotate the staff portal "
        "credentials after last week's incident review. "
        f"Flag: {IDOR_FLAG}"
    )
    existing = Ticket.query.filter_by(subject="Password rotation reminder").first()
    if existing is None:
        db.session.add(Ticket(
            requester_name="admin",
            subject="Password rotation reminder",
            body=body,
        ))
    else:
        existing.body = body  # keep the placeholder current on an old database
    db.session.commit()


def seed_ops_notes_file():
    # Always rewrite so the placeholder flag stays current, even on an old checkout.
    with open(_OPS_NOTES_PATH, "w") as f:
        f.write(
            "Internal ops notes, not linked from the site anywhere.\n"
            f"Flag: {CMDI_FLAG}\n"
        )


def seed_reports():
    # The real flag file is written one level above _REPORTS_DIR, so it's only
    # reachable from the viewer by escaping the folder with ../.
    os.makedirs(_REPORTS_DIR, exist_ok=True)
    seed_files = {
        "weekly_summary.txt": "Weekly staff summary: nothing unusual to report.\n",
        "incident_log.txt": "Incident log: 0 open incidents this week.\n",
    }
    for filename, contents in seed_files.items():
        path = os.path.join(_REPORTS_DIR, filename)
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write(contents)
    # Always rewrite the flag file so the placeholder stays current.
    with open(_STAFF_REPORT_FLAG_PATH, "w") as f:
        f.write(
            "Staff-only report, not meant to be served by the viewer.\n"
            f"Flag: {PTRAVERSAL_FLAG}\n"
        )


def seed_staff_console_ticket():
    # Puts the staff-console token in a ticket that isn't the viewer's own,
    # so it's reachable through the ticket IDOR (step one of the chain).
    existing = Ticket.query.filter_by(subject="Staff console access").first()
    if existing is None:
        db.session.add(Ticket(
            requester_name="itsupport",
            subject="Staff console access",
            body=(
                "Reminder for staff: the internal console session token is "
                f"{STAFF_CONSOLE_TOKEN}. Do not share it outside the team."
            ),
        ))
        db.session.commit()


@app.route("/")
def index():
    return render_template("home.html")


@app.route("/login", methods=["GET"])
def login_form():
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login_submit():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # vulnerable: raw f-string SQL, so a quote like admin' OR '1'='1 breaks out.
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
    # Stands in for real browser execution; the actual bug is the |safe filter
    # in feedback.html.
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
    # vulnerable: no ownership check, so any valid id returns that ticket.
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
        # vulnerable: shell=True with raw input, so ; or && chains a second command.
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


@app.route("/reports", methods=["GET"])
def reports():
    available = sorted(os.listdir(_REPORTS_DIR)) if os.path.isdir(_REPORTS_DIR) else []
    name = request.args.get("name", "")
    if not name:
        return render_template(
            "reports.html", files=available, name=None, content=None, error=None
        )

    # vulnerable: name is joined onto the folder with no check, so ../ escapes it.
    path = os.path.join(_REPORTS_DIR, name)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except (FileNotFoundError, IsADirectoryError, PermissionError, OSError):
        return (
            render_template(
                "reports.html",
                files=available,
                name=name,
                content=None,
                error="Could not read that file.",
            ),
            404,
        )
    return render_template(
        "reports.html", files=available, name=name, content=content, error=None
    )


@app.route("/staff/console", methods=["GET"])
def staff_console():
    # vulnerable: only a shared token guards this, and that token is leaked in
    # a ticket reachable via the IDOR, so the two bugs chain together.
    token = request.args.get("token", "")
    if token != STAFF_CONSOLE_TOKEN:
        return render_template("staff_console.html", authorised=False, flag=None), 403
    return render_template("staff_console.html", authorised=True, flag=CHAINED_FLAG)


@app.route("/set-token", methods=["POST"])
def set_token():
    # Store the student's BreachBox token in a cookie so their captured flags
    # are built from it. This is only a personalisation seed, not a login.
    token = request.form.get("token", "").strip()[:64]
    response = redirect(request.referrer or url_for("index"))
    if token:
        response.set_cookie("bb_token", token, max_age=60 * 60 * 24 * 30, samesite="Lax")
    else:
        response.delete_cookie("bb_token")
    return response


@app.after_request
def personalise_flags(response):
    # Swap each flag placeholder for one unique to the attacking student,
    # wherever it turns up in a text response: a page, a file read through the
    # report viewer, or the output of an injected shell command.
    if response.direct_passthrough:
        return response
    ctype = response.content_type or ""
    if "text/" not in ctype and "application/json" not in ctype:
        return response
    body = response.get_data(as_text=True)
    if "__FLAG_" not in body:
        return response
    token = _current_token()
    for placeholder, key in _FLAG_PLACEHOLDERS.items():
        if placeholder in body:
            body = body.replace(placeholder, make_flag(token, key))
    response.set_data(body)
    return response


with app.app_context():
    db.create_all()
    seed_dummy_staff_accounts()
    seed_admin_ticket()
    seed_staff_console_ticket()
    seed_ops_notes_file()
    seed_reports()


if __name__ == "__main__":
    # debug is off by default. This app is deliberately vulnerable, so the
    # last thing we want is Flask's interactive debugger hanging off an
    # unhandled error as a bonus way to run code on the host. Set
    # TARGET_DEBUG=1 locally only if you really need it.
    debug = os.environ.get("TARGET_DEBUG") == "1"
    app.run(host="0.0.0.0", port=5001, debug=debug)
