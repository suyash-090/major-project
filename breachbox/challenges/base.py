"""Modular challenge loader. Each vulnerability is a Challenge subclass in this
folder, and discover_challenges() picks them all up automatically."""

import hmac
import importlib
import inspect
import pkgutil
from abc import ABC


class Challenge(ABC):
    """Base class every vulnerability subclasses. category/difficulty/key must be valid."""

    VALID_CATEGORIES = ("Web", "Injection", "Access Control", "Other")
    VALID_DIFFICULTIES = ("Easy", "Medium", "Hard")

    name: str = "Unnamed Challenge"
    key: str = ""  # stable id used to derive this challenge's per-student flag
    category: str = "Other"
    difficulty: str = "Easy"
    points: int = 0
    description: str = ""

    def check_solution(self, submitted_flag: str, token: str) -> bool:
        """True if the flag is the one THIS student should have captured.

        Flags are per-student: we recompute the expected flag from the
        student's own token and this challenge's key, so a flag captured by
        another student (built from a different token) never validates here.
        """
        from breachbox.flags import make_flag

        expected = make_flag(token, self.key)
        return hmac.compare_digest(submitted_flag.strip(), expected)

    @classmethod
    def validate_metadata(cls):
        if cls.category not in cls.VALID_CATEGORIES:
            raise ValueError(
                f"{cls.__name__} has invalid category '{cls.category}', "
                f"must be one of {cls.VALID_CATEGORIES}"
            )
        if cls.difficulty not in cls.VALID_DIFFICULTIES:
            raise ValueError(
                f"{cls.__name__} has invalid difficulty '{cls.difficulty}', "
                f"must be one of {cls.VALID_DIFFICULTIES}"
            )
        if not cls.key:
            raise ValueError(f"{cls.__name__} is missing a 'key' for its flag")


def discover_challenges(package_name: str = "breachbox.challenges"):
    """Find every Challenge subclass defined in this package."""
    discovered = []
    package = importlib.import_module(package_name)

    for _, module_name, _ in pkgutil.iter_modules(package.__path__):
        if module_name in ("base",):
            continue
        if module_name.startswith("_"):
            continue  # skip reference/placeholder files

        try:
            module = importlib.import_module(f"{package_name}.{module_name}")
        except Exception as exc:
            print(f"[discover_challenges] failed to import {module_name}: {exc}")
            continue

        for _, obj in inspect.getmembers(module, inspect.isclass):
            if not (issubclass(obj, Challenge) and obj is not Challenge):
                continue
            if obj.__module__ != module.__name__:
                continue  # imported in, not defined here

            try:
                obj.validate_metadata()
            except Exception as exc:
                print(f"[discover_challenges] {obj.__name__} failed validation: {exc}")
                continue

            discovered.append(obj)

    return discovered


def sync_challenges_to_db():
    """Create or update a Challenge row for every discovered subclass."""
    from breachbox.extensions import db
    from breachbox.models import Challenge

    discovered = discover_challenges()

    for cls in discovered:
        row = Challenge.query.filter_by(name=cls.name).first()
        if row is None:
            row = Challenge(
                name=cls.name,
                category=cls.category,
                difficulty=cls.difficulty,
                points=cls.points,
                description=cls.description,
                flag_hash="per_student_hmac",
            )
            db.session.add(row)
        else:
            row.category = cls.category
            row.difficulty = cls.difficulty
            row.points = cls.points
            row.description = cls.description

    db.session.commit()
    return discovered
