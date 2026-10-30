"""Path traversal on target_app's /reports route.

The flag is per-student and verified by the base class; see breachbox/flags.py.
"""

from breachbox.challenges.base import Challenge


class ReportViewerPathTraversal(Challenge):
    name = "Report Viewer Path Traversal"
    key = "ptraversal"
    category = "Web"
    difficulty = "Medium"
    points = 150
    description = (
        "The staff report viewer builds a file path straight from the ?name= "
        "query parameter with no checks. Step out of the reports folder with "
        "../ to read a staff-only file the viewer was never meant to serve."
    )
