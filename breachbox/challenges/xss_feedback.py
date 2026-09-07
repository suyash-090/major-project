"""
Vulnerability Set 1, second half: reflected XSS on target_app's staff
feedback board (see target_app/app.py's GET /feedback route).

Same shape as sqli_login.py: check_solution() hashes the submitted flag
and compares it against a hash of the real flag target_app hands out,
target_app owns the plaintext flag, this file only ever stores the hash.
"""

import hashlib

from breachbox.challenges.base import Challenge

# Must match target_app.app.XSS_FLAG exactly.
_FLAG_HASH = "29a4fffb507385bfa7f3488dcf450311ab1a91acb7d6bf32d36d2d877deb3e4f"


class ReflectedXssFeedback(Challenge):
    name = "Staff Feedback Reflected XSS"
    category = "Web"              # must be one of Challenge.VALID_CATEGORIES
    difficulty = "Easy"           # must be one of Challenge.VALID_DIFFICULTIES
    points = 100

    def check_solution(self, submitted_flag: str) -> bool:
        submitted_hash = hashlib.sha256(submitted_flag.strip().encode()).hexdigest()
        return submitted_hash == _FLAG_HASH
