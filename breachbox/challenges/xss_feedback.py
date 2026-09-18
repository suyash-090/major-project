"""
Week 6-7 "Vulnerability Set 1": reflected XSS on target_app's staff
feedback board (see target_app/app.py's GET /feedback route).
"""

import hashlib

from breachbox.challenges.base import Challenge

_FLAG_HASH = "29a4fffb507385bfa7f3488dcf450311ab1a91acb7d6bf32d36d2d877deb3e4f"


class ReflectedXssFeedback(Challenge):
    name = "Staff Feedback Reflected XSS"
    category = "Web"
    difficulty = "Easy"
    points = 100
    description = (
        "A feedback board where visitors can leave a message. Something "
        "about how that message gets shown back to you might be worth "
        "checking."
    )

    def check_solution(self, submitted_flag: str) -> bool:
        submitted_hash = hashlib.sha256(submitted_flag.strip().encode()).hexdigest()
        return submitted_hash == _FLAG_HASH
