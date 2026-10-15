"""
Minimal working session-based authentication, using Flask-Login. This is
genuinely functional, not a stub, since Accounts is listed as required
tech in the proposal and everything else (submissions, hint unlocks) needs
a real current_user to attribute actions to. What's NOT built here yet:
any styling, password reset, or admin-only registration restrictions,
those are judgement calls for whoever picks this up in a later week.

class_group was dropped from the registration form. The Student model
still has the column (nullable=False), so every new account gets a
placeholder value rather than requiring a change to the schema or to
scoreboard.html, which still displays class_group for existing rows.

Login is rate limited (see breachbox/ratelimit.py) so the portal can't be
brute-forced during the Week 13 dry-run.
"""

from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user

from breachbox.auth import auth_bp
from breachbox.extensions import db
from breachbox.models import Student
from breachbox.ratelimit import login_limiter


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        display_name = request.form.get("display_name", "").strip()
        password = request.form.get("password", "")

        if not display_name or not password:
            flash("All fields are required.")
            return redirect(url_for("auth.register"))

        if Student.query.filter_by(display_name=display_name).first():
            flash("That display name is already taken.")
            return redirect(url_for("auth.register"))

        student = Student(display_name=display_name, class_group="N/A")
        student.set_password(password)
        db.session.add(student)
        db.session.commit()

        flash("Account created, you can log in now.")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        display_name = request.form.get("display_name", "").strip()
        password = request.form.get("password", "")

        # Rate limit by IP + display name so repeated wrong guesses get
        # locked out for a short window, instead of allowing unlimited tries.
        limiter_key = f"{request.remote_addr}:{display_name.lower()}"
        allowed, retry_after = login_limiter.check(limiter_key)
        if not allowed:
            flash(f"Too many login attempts. Try again in about {retry_after} seconds.")
            return redirect(url_for("auth.login"))

        student = Student.query.filter_by(display_name=display_name).first()

        if student is None or not student.check_password(password):
            login_limiter.record(limiter_key)
            flash("Incorrect display name or password.")
            return redirect(url_for("auth.login"))

        login_limiter.reset(limiter_key)
        login_user(student)
        return redirect(url_for("dashboard.home"))

    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))
