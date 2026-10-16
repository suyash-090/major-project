"""Chained challenge: the ticket IDOR leaks a token reused at /staff/console."""

import hashlib

from breachbox.challenges.base import Challenge

# Must match target_app.app.CHAINED_FLAG.
_FLAG_HASH = "086dc75e1b5c1afa7a753bf3f8bef3748a64990893ed3bbc0c94293bd09a73d4"


class ChainedStaffConsole(Challenge):
    name = "Chained: Ticket Leak to Staff Console"
    category = "Access Control"
    difficulty = "Hard"
    points = 250
    description = (
        "Two steps. First use the ticket IDOR to read a staff ticket that is "
        "not yours and recover a leaked session token. Then reuse that token "
        "at /staff/console to reach a staff-only page and its flag."
    )

    def check_solution(self, submitted_flag: str) -> bool:
        submitted_hash = hashlib.sha256(submitted_flag.strip().encode()).hexdigest()
        return submitted_hash == _FLAG_HASH
