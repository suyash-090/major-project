"""
Week 6-7 "Vulnerability Set 1": SQL injection login bypass in
target_app's staff portal (see target_app/app.py's POST /login route).

This is the real, live Challenge subclass, replacing
breachbox/challenges/_reference_sqli_login.py as the version that's
actually discovered and checked against. Same shape as the reference:
check_solution() compares a SHA-256 hash of the submitted flag against
a hash of the real flag that target_app returns on a successful
' OR '1'='1 style bypass.
"""

import hashlib

from breachbox.challenges.base import Challenge

# Must match target_app.app.FLAG exactly. The plaintext flag lives in
# target_app on purpose (see that module's docstring), this file only
# ever stores the hash, never the flag itself.
_FLAG_HASH = "789ffe632c18dfb48dfb2dd79bbc718363a2ae52a2899e84b9707397b6ee6660"


class SqlInjectionLogin(Challenge):
    name = "Staff Portal Login Bypass"
    category = "Injection"       # must be one of Challenge.VALID_CATEGORIES
    difficulty = "Easy"          # must be one of Challenge.VALID_DIFFICULTIES
    points = 100

    def check_solution(self, submitted_flag: str) -> bool:
        submitted_hash = hashlib.sha256(submitted_flag.strip().encode()).hexdigest()
        return submitted_hash == _FLAG_HASH
