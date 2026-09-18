"""
Vulnerability Set 2: IDOR / broken access control on target_app's
support ticket system (see target_app/app.py's GET /tickets/<id>
route).
"""

import hashlib

from breachbox.challenges.base import Challenge

_FLAG_HASH = "c1fcceeaa03d3883635dd13ec72ff5466f9d1ee134db1d330d9f6abad632e8ff"


class IdorTickets(Challenge):
    name = "Support Ticket IDOR"
    category = "Access Control"
    difficulty = "Medium"
    points = 150
    description = (
        "A lightweight support-ticket system. File a ticket of your own, "
        "then see what else you can find."
    )

    def check_solution(self, submitted_flag: str) -> bool:
        submitted_hash = hashlib.sha256(submitted_flag.strip().encode()).hexdigest()
        return submitted_hash == _FLAG_HASH
