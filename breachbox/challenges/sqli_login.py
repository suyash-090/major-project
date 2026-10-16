"""SQL injection login bypass on target_app's /login route (Vulnerability Set 1)."""

import hashlib

from breachbox.challenges.base import Challenge

# Must match target_app.app.SQLI_FLAG. We only ever store the hash here.
_FLAG_HASH = "789ffe632c18dfb48dfb2dd79bbc718363a2ae52a2899e84b9707397b6ee6660"


class SqlInjectionLogin(Challenge):
    name = "Staff Portal Login Bypass"
    category = "Injection"
    difficulty = "Easy"
    points = 100

    def check_solution(self, submitted_flag: str) -> bool:
        submitted_hash = hashlib.sha256(submitted_flag.strip().encode()).hexdigest()
        return submitted_hash == _FLAG_HASH
