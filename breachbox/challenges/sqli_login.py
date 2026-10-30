"""SQL injection login bypass on target_app's /login route (Vulnerability Set 1).

The flag is per-student and verified by the base class; see breachbox/flags.py.
"""

from breachbox.challenges.base import Challenge


class SqlInjectionLogin(Challenge):
    name = "Staff Portal Login Bypass"
    key = "sqli"
    category = "Injection"
    difficulty = "Easy"
    points = 100
