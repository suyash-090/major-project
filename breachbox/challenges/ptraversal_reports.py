"""Path traversal on target_app's /reports route."""

import hashlib

from breachbox.challenges.base import Challenge

# Must match target_app.app.PTRAVERSAL_FLAG.
_FLAG_HASH = "b04b57c2303ce87584553a5776ddbb9ba44566deba5db03b15e8f8567ae86cff"


class ReportViewerPathTraversal(Challenge):
    name = "Report Viewer Path Traversal"
    category = "Web"
    difficulty = "Medium"
    points = 150
    description = (
        "The staff report viewer builds a file path straight from the ?name= "
        "query parameter with no checks. Step out of the reports folder with "
        "../ to read a staff-only file the viewer was never meant to serve."
    )

    def check_solution(self, submitted_flag: str) -> bool:
        submitted_hash = hashlib.sha256(submitted_flag.strip().encode()).hexdigest()
        return submitted_hash == _FLAG_HASH
