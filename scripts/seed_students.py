"""
Seed a handful of test student accounts for the Week 13 class dry-run, so
facilitators don't have to register each one by hand.

Run it against the running breachbox_app container (it imports the app):

    docker compose up --build        # in one terminal
    docker compose exec breachbox_app python scripts/seed_students.py

Safe to run more than once: accounts that already exist are skipped.
"""

from breachbox import create_app
from breachbox.extensions import db
from breachbox.models import Student

# (display name, password). Simple on purpose: these are throwaway dry-run
# logins, not real credentials.
TEST_STUDENTS = [
    ("player1", "dryrun123"),
    ("player2", "dryrun123"),
    ("player3", "dryrun123"),
    ("player4", "dryrun123"),
    ("player5", "dryrun123"),
]


def main():
    app = create_app()
    with app.app_context():
        created = []
        for display_name, password in TEST_STUDENTS:
            if Student.query.filter_by(display_name=display_name).first():
                continue
            student = Student(display_name=display_name, class_group="Dry-run")
            student.set_password(password)
            db.session.add(student)
            created.append(display_name)
        db.session.commit()

    if created:
        print("Seeded test students:", ", ".join(created))
    else:
        print("All test students already exist, nothing to do.")


if __name__ == "__main__":
    main()
