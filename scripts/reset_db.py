"""
Reset BreachBox to a clean state for a fresh dry-run.

Both apps use SQLite plus a couple of generated flag files, and
docker-compose bind-mounts the project into the containers, so those files
persist on the host between runs. This script deletes them, so the next
`docker compose up` re-seeds everything from scratch: the staff accounts and
seeded tickets, the ops-notes and report flag files, and the breachbox
challenge and hint tables.

Run it from the project root on the host, with the stack stopped:

    docker compose down
    python scripts/reset_db.py
    docker compose up --build

It only deletes known generated files; it never touches source code.
"""

import os
import shutil

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_FILES = [
    os.path.join(_ROOT, "instance", "breachbox.db"),
    os.path.join(_ROOT, "target_app", "target_app.db"),
    os.path.join(_ROOT, "target_app", "ops_notes.txt"),
    os.path.join(_ROOT, "target_app", "staff_only_report.txt"),
]
_DIRS = [
    os.path.join(_ROOT, "target_app", "reports"),
]


def main():
    removed = []
    for path in _FILES:
        if os.path.exists(path):
            os.remove(path)
            removed.append(path)
    for path in _DIRS:
        if os.path.isdir(path):
            shutil.rmtree(path)
            removed.append(path + os.sep)

    if removed:
        print("Reset: removed")
        for path in removed:
            print("  -", os.path.relpath(path, _ROOT))
    else:
        print("Reset: nothing to remove, already clean.")
    print("Now run: docker compose up --build")


if __name__ == "__main__":
    main()
