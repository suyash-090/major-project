"""Reflected XSS on target_app's /feedback route (Vulnerability Set 1)."""

import hashlib

from breachbox.challenges.base import Challenge

# Must match target_app.app.XSS_FLAG.
_FLAG_HASH = "29a4fffb507385bfa7f3488dcf450311ab1a91acb7d6bf32d36d2d877deb3e4f"


class ReflectedXssFeedback(Challenge):
    name = "Staff Feedback Reflected XSS"
    category = "Web"
    difficulty = "Easy"
    points = 100

    def check_solution(self, submitted_flag: str) -> bool:
        submitted_hash = hashlib.sha256(submitted_flag.strip().encode()).hexdigest()
        return submitted_hash == _FLAG_HASH
