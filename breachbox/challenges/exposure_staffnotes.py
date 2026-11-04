"""Sensitive data exposure on target_app: a secret file left in the open.

The flag is per-student and verified by the base class; see breachbox/flags.py.
"""

from breachbox.challenges.base import Challenge


class ExposedStaffNotes(Challenge):
    name = "Exposed Staff Notes"
    key = "exposure"
    category = "Web"
    difficulty = "Easy"
    points = 100
    description = (
        "The site's /robots.txt asks crawlers to skip a path, which just "
        "advertises where a secret file is. Read robots.txt, then open the "
        "staff notes file it names to find the flag. robots.txt is not "
        "security."
    )
