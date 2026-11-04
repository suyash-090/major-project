"""Privilege escalation on target_app's /manager route.

The flag is per-student and verified by the base class; see breachbox/flags.py.
"""

from breachbox.challenges.base import Challenge


class ManagerPrivEsc(Challenge):
    name = "Manager Console Privilege Escalation"
    key = "privesc"
    category = "Access Control"
    difficulty = "Medium"
    points = 150
    description = (
        "The manager console decides whether you're an admin from a 'role' "
        "cookie your own browser sends, not from your account. Change the "
        "cookie to role=admin and the site treats you as a manager and hands "
        "over the flag."
    )
