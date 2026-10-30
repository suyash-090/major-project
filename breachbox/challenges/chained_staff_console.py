"""Chained challenge: the ticket IDOR leaks a token reused at /staff/console.

The flag is per-student and verified by the base class; see breachbox/flags.py.
"""

from breachbox.challenges.base import Challenge


class ChainedStaffConsole(Challenge):
    name = "Chained: Ticket Leak to Staff Console"
    key = "chained"
    category = "Access Control"
    difficulty = "Hard"
    points = 250
    description = (
        "Two steps. First use the ticket IDOR to read a staff ticket that is "
        "not yours and recover a leaked session token. Then reuse that token "
        "at /staff/console to reach a staff-only page and its flag."
    )
