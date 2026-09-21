"""
Modular challenge-loader. Every vulnerability is a Challenge subclass
dropped into this folder; discover_challenges() finds them automatically.
"""

import importlib
import inspect
import pkgutil
from abc import ABC, abstractmethod


class Challenge(ABC):
    """Base class every vulnerability subclasses. category must be one
    of VALID_CATEGORIES, matching the Challenge model's column."""

    VALID_CATEGORIES = ("Web", "Injection", "Access Control", "Other")
    VALID_DIFFICULTIES = ("Easy", "Medium", "Hard")

    name: str = "Unnamed Challenge"
    category: str = "Other"
    difficulty: str = "Easy"
    points: int = 0
    description: str = ""

    @abstractmethod
    def check_solution(self, submitted_flag: str) -> bool:
        raise NotImplementedError

    @classmethod
    def validate_metadata(cls):
        # Fails loudly at startup on a bad category/difficulty, instead
        # of silently breaking the dashboard's filter later.
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
    """Finds every Challenge subclass defined in this package."""
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
    """Creates or updates a Challenge row for every discovered subclass."""
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
                flag_hash="managed_by_challenge_class",
            )
            db.session.add(row)
        else:
            row.category = cls.category
            row.difficulty = cls.difficulty
            row.points = cls.points
            row.description = cls.description

    db.session.commit()
    return discovered
