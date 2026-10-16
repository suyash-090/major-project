"""IDOR / broken access control on target_app's /tickets/<id> route (Vulnerability Set 2)."""

import hashlib

from breachbox.challenges.base import Challenge

# Must match target_app.app.IDOR_FLAG.
_FLAG_HASH = "c1fcceeaa03d3883635dd13ec72ff5466f9d1ee134db1d330d9f6abad632e8ff"


class IdorTickets(Challenge):
    name = "Support Ticket IDOR"
    category = "Access Control"
    difficulty = "Medium"
    points = 150

    def check_solution(self, submitted_flag: str) -> bool:
        submitted_hash = hashlib.sha256(submitted_flag.strip().encode()).hexdigest()
        return submitted_hash == _FLAG_HASH
