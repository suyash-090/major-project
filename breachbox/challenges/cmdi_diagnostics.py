"""OS command injection on target_app's /diagnostics route (Vulnerability Set 2)."""

import hashlib

from breachbox.challenges.base import Challenge

# Must match target_app.app.CMDI_FLAG.
_FLAG_HASH = "1bbc48be1baa38590f1fcdecf2e6a6d902bb547efc0e050079c33f2d0ece7ebb"


class CommandInjectionDiagnostics(Challenge):
    name = "Diagnostics Command Injection"
    category = "Injection"
    difficulty = "Hard"
    points = 200

    def check_solution(self, submitted_flag: str) -> bool:
        submitted_hash = hashlib.sha256(submitted_flag.strip().encode()).hexdigest()
        return submitted_hash == _FLAG_HASH
