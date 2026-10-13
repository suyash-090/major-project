"""
Chained challenge on target_app: the ticket IDOR feeds a staff-console
privilege step (see target_app/app.py's GET /staff/console route). Same shape
as the other challenge files: check_solution() compares a SHA-256 of the
submitted flag against the hash of the real flag, which only ever lives in
target_app, never here.
"""

import hashlib

from breachbox.challenges.base import Challenge

# Must match target_app.app.CHAINED_FLAG exactly.
_FLAG_HASH = "086dc75e1b5c1afa7a753bf3f8bef3748a64990893ed3bbc0c94293bd09a73d4"


class ChainedStaffConsole(Challenge):
    name = "Chained: Ticket Leak to Staff Console"
    category = "Access Control"   # must be one of Challenge.VALID_CATEGORIES
    difficulty = "Hard"           # must be one of Challenge.VALID_DIFFICULTIES
    points = 250
    description = (
        "Two steps. First use the ticket IDOR to read a staff ticket that is "
        "not yours and recover a leaked session token. Then reuse that token "
        "at /staff/console to reach a staff-only page and its flag."
    )

    def check_solution(self, submitted_flag: str) -> bool:
        submitted_hash = hashlib.sha256(submitted_flag.strip().encode()).hexdigest()
        return submitted_hash == _FLAG_HASH
