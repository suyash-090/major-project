"""
Minimal working session-based authentication, using Flask-Login. This is
genuinely functional, not a stub, since Accounts is listed as required
tech in the proposal and everything else (submissions, hint unlocks) needs
a real current_user to attribute actions to. What's NOT built here yet:
any styling, password reset, or admin-only registration restrictions,
those are judgement calls for whoever picks this up in a later week.
"""

from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user

from breachbox.auth import auth_bp
from breachbox.extensions import db
from breachbox.models import Student


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        display_name = request.form.get("display_name", "").strip()
        class_group = request.form.get("class_group", "").strip()
        password = request.form.get("password", "")

        if not display_name or not class_group or not password:
            flash("All fields are required.")
            return redirect(url_for("auth.register"))

        if Student.query.filter_by(display_name=display_name).first():
            flash("That display name is already taken.")
            return redirect(url_for("auth.register"))

        student = Student(display_name=display_name, class_group=class_group)
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

        student = Student.query.filter_by(display_name=display_name).first()

        if student is None or not student.check_password(password):
            flash("Incorrect display name or password.")
            return redirect(url_for("auth.login"))

        login_user(student)
        return redirect(url_for("dashboard.home"))

    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))
