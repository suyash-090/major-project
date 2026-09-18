"""
Week 6-7 "Vulnerability Set 1": SQL injection login bypass in
target_app's staff portal (see target_app/app.py's POST /login route).
"""

import hashlib

from breachbox.challenges.base import Challenge

_FLAG_HASH = "789ffe632c18dfb48dfb2dd79bbc718363a2ae52a2899e84b9707397b6ee6660"


class SqlInjectionLogin(Challenge):
    name = "Staff Portal Login Bypass"
    category = "Injection"
    difficulty = "Easy"
    points = 100
    description = (
        "A staff-only login portal for target_app. Find a way past the "
        "password check without a valid staff password."
    )

    def check_solution(self, submitted_flag: str) -> bool:
        submitted_hash = hashlib.sha256(submitted_flag.strip().encode()).hexdigest()
        return submitted_hash == _FLAG_HASH
