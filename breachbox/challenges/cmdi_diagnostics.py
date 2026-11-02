"""OS command injection on target_app's /diagnostics route (Vulnerability Set 2).

The flag is per-student and verified by the base class; see breachbox/flags.py.
"""

from breachbox.challenges.base import Challenge


class CommandInjectionDiagnostics(Challenge):
    name = "Diagnostics Command Injection"
    key = "cmdi"
    category = "Injection"
    difficulty = "Hard"
    points = 200
