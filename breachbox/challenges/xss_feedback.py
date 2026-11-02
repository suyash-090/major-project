"""Reflected XSS on target_app's /feedback route (Vulnerability Set 1).

The flag is per-student and verified by the base class; see breachbox/flags.py.
"""

from breachbox.challenges.base import Challenge


class ReflectedXssFeedback(Challenge):
    name = "Staff Feedback Reflected XSS"
    key = "xss"
    category = "Web"
    difficulty = "Easy"
    points = 100
