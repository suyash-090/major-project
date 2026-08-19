"""
DELETE THIS FILE once Sameer starts building the real Vulnerability Set 1
in Week 6 to 7. It exists only to prove discover_challenges() actually
finds subclasses, and to show the shape a real one takes.

Run `python app.py` and check the terminal output on startup, it should
list this class as discovered. That's your confirmation the loader works
before anyone builds a real vulnerability on top of it.
"""

import hashlib
from breachbox.challenges.base import Challenge


class ExampleChallenge(Challenge):
    name = "Example Challenge (delete me)"
    category = "Other"
    difficulty = "Easy"
    points = 0

    _correct_flag = "FLAG{this_is_just_a_placeholder}"

    def check_solution(self, submitted_flag: str) -> bool:
        submitted_hash = hashlib.sha256(submitted_flag.encode()).hexdigest()
        correct_hash = hashlib.sha256(self._correct_flag.encode()).hexdigest()
        return submitted_hash == correct_hash
