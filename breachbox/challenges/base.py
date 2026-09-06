"""
This is the modular challenge-loader architecture described in Section 2.1
of the proposal. Every vulnerability, current and future, is a subclass of
Challenge, dropped into this /challenges folder. discover_challenges() finds
them automatically, so adding Vulnerability Set 2 in Week 10 means writing
one new class here, not touching Flask routes anywhere else.
"""

import importlib
import inspect
import pkgutil
from abc import ABC, abstractmethod


class Challenge(ABC):
    """
    Abstract base class. Every real vulnerability (SQLi, XSS, IDOR, command
    injection, the eventual chained exploit) subclasses this and fills in
    the four attributes plus check_solution().

    category must be one of Challenge.VALID_CATEGORIES, matching the
    Challenge model's category column in models.py, so a subclass here and
    a database row for it always agree on what values are valid.
    """

    VALID_CATEGORIES = ("Web", "Injection", "Access Control", "Other")
    VALID_DIFFICULTIES = ("Easy", "Medium", "Hard")

    # Subclasses override these four class attributes.
    name: str = "Unnamed Challenge"
    category: str = "Other"
    difficulty: str = "Easy"
    points: int = 0

    @abstractmethod
    def check_solution(self, submitted_flag: str) -> bool:
        """
        Return True if submitted_flag is correct for this challenge, False
        otherwise. The actual comparison logic (hashing, lookup, whatever
        each challenge needs) is written per-subclass here, not in the
        Flask route that calls it.
        """
        raise NotImplementedError

    @classmethod
    def validate_metadata(cls):
        """
        Sanity-checks a subclass's category and difficulty against the
        allowed values, so a typo in a new Challenge subclass fails loudly
        at startup instead of silently breaking the dashboard's category
        filter later.
        """
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


def discover_challenges(package_name: str = "breachbox.challenges"):
    """
    Scans the given package for every class that subclasses Challenge
    (excluding Challenge itself) and returns them as a list. This is what
    lets new vulnerabilities be "discovered" automatically rather than
    manually registered somewhere.

    Review-note fixes (see issue tracking discovery + DB schema review):
      - Underscore-prefixed modules (_example_challenge.py,
        _reference_sqli_login.py, etc.) are skipped. Those are explicitly
        marked as placeholders/references, not real challenges, and
        without this skip they'd get auto-synced into the DB as live
        challenges the moment they're merged.
      - A broken challenge file (import error or bad metadata) is caught
        per-module and logged, rather than killing app startup for
        everyone. With three of us adding challenge files concurrently,
        one bad file shouldn't take the whole app down.
      - Only classes actually *defined* in a given module are counted
        (obj.__module__ == module.__name__), not ones merely imported
        into its namespace (e.g. `from breachbox.challenges.other import
        SomeChallenge` for reuse), which would otherwise get discovered,
        and synced to the DB, twice.
    """
    discovered = []
    package = importlib.import_module(package_name)

    for _, module_name, _ in pkgutil.iter_modules(package.__path__):
        if module_name in ("base",):
            continue  # skip this file itself
        if module_name.startswith("_"):
            continue  # skip placeholder/reference-only modules

        try:
            module = importlib.import_module(f"{package_name}.{module_name}")
        except Exception as exc:
            print(f"[discover_challenges] failed to import {module_name}: {exc}")
            continue

        for _, obj in inspect.getmembers(module, inspect.isclass):
            if not (issubclass(obj, Challenge) and obj is not Challenge):
                continue
            if obj.__module__ != module.__name__:
                continue  # imported into this namespace, not defined here

            try:
                obj.validate_metadata()
            except Exception as exc:
                print(f"[discover_challenges] {obj.__name__} failed validation: {exc}")
                continue

            discovered.append(obj)

    return discovered


def sync_challenges_to_db():
    """
    Ensures every discovered Challenge subclass has a matching row in the
    challenge table, creating one if it doesn't exist yet, or updating
    its category/difficulty/points if a subclass changed since last run.

    This is what lets Sameer or Suyash add a new Challenge subclass and
    have it just show up in the database and the dashboard, without
    anyone manually inserting a row for it.

    Deliberate design note for the team: flag validation itself happens
    by calling check_solution() on the actual Python class instance, NOT
    by comparing against the flag_hash column here. The column still
    exists and gets set, mainly so the schema matches the ERD and so a
    hash is on record, but the source of truth for "is this flag correct"
    is each Challenge subclass's own check_solution(), since that's where
    the real logic already lives for something like the SQLi reference.
    If the team later prefers DB-driven validation instead, that's a
    genuine design decision to make on purpose, not something to
    assume from this helper.
    """
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
                flag_hash="managed_by_challenge_class",
            )
            db.session.add(row)
        else:
            row.category = cls.category
            row.difficulty = cls.difficulty
            row.points = cls.points

    db.session.commit()
    return discovered
