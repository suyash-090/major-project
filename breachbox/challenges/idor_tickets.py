"""IDOR / broken access control on target_app's /tickets/<id> route (Vulnerability Set 2).

The flag is per-student and verified by the base class; see breachbox/flags.py.
"""

from breachbox.challenges.base import Challenge


class IdorTickets(Challenge):
    name = "Support Ticket IDOR"
    key = "idor"
    category = "Access Control"
    difficulty = "Medium"
    points = 150
