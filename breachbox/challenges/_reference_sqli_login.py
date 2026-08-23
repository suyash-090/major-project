"""
REFERENCE EXAMPLE — not intended to be merged as-is.

This is a worked example of the Week 6-7 "Vulnerability Set 1" SQLi
login-bypass PoC described in the proposal (Section 2.2), adapted to
match the real Challenge base class in breachbox/challenges/base.py
(VALID_CATEGORIES / VALID_DIFFICULTIES, hashed flag comparison to
match how Challenge.flag_hash is stored in models.py).

Like _example_challenge.py, this exists to demonstrate the shape a
real vulnerability class takes and to give Sameer a starting point to
adapt, extend, or rewrite for the actual milestone — it is not meant
to be merged into main as a finished submission. Delete or replace
once the real version is built.

Two things this reference deliberately shows:
  1. The Challenge subclass itself (check_solution against a hash,
     matching the model's flag_hash column rather than storing/
     comparing a plaintext flag anywhere).
  2. A worked example of the *vulnerable route* it's meant to pair
     with — a login form using raw string-formatted SQL instead of a
     parameterised query, exploitable via a classic
     ' OR '1'='1 payload — included as a comment block below rather
     than a live blueprint, since no route-registration pattern
     exists yet in this codebase for how a Challenge exposes a live
     endpoint. That's a design decision for whoever builds the real
     version to make deliberately, not something to inherit from a
     PR opened by someone outside the team.
"""

import hashlib

from breachbox.challenges.base import Challenge

# In the real version this would NOT be a module-level constant --
# the flag lives in the database as Challenge.flag_hash (see models.py),
# checked against a hash of what the student submits. This constant is
# here only so the reference is runnable/testable in isolation.
_REFERENCE_FLAG = "flag{sql1_1nj3ct10n_byp4ss3d_th3_l0g1n}"
_REFERENCE_FLAG_HASH = hashlib.sha256(_REFERENCE_FLAG.encode()).hexdigest()


class SqlInjectionLoginReference(Challenge):
    name = "Staff Portal Login Bypass (reference)"
    category = "Injection"       # must be one of Challenge.VALID_CATEGORIES
    difficulty = "Easy"          # must be one of Challenge.VALID_DIFFICULTIES
    points = 100

    def check_solution(self, submitted_flag: str) -> bool:
        submitted_hash = hashlib.sha256(submitted_flag.strip().encode()).hexdigest()
        return submitted_hash == _REFERENCE_FLAG_HASH


# --- Worked example of the paired vulnerable route (not wired in) ---
#
# @some_blueprint.route("/challenges/sqli-login", methods=["GET", "POST"])
# def sqli_login_route():
#     if request.method == "POST":
#         username = request.form.get("username", "")
#         password = request.form.get("password", "")
#
#         # DELIBERATE VULNERABILITY: raw string-formatted SQL instead
#         # of a parameterised query (Section 2.1 of the proposal).
#         # Payload  admin' OR '1'='1  in `username` collapses the
#         # WHERE clause to always-true regardless of `password`.
#         query = (
#             f"SELECT * FROM users WHERE username = '{username}' "
#             f"AND password_hash = '{hash_pw(password)}'"
#         )
#         result = db.session.execute(text(query)).fetchone()
#         if result:
#             return f"Welcome, {result.username}! Flag: {FLAG}"
#
#     return render_template("sqli_login.html")
