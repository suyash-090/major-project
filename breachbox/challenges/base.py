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
    """
    discovered = []
    package = importlib.import_module(package_name)

    for _, module_name, _ in pkgutil.iter_modules(package.__path__):
        if module_name in ("base",):
            continue  # skip this file itself
        module = importlib.import_module(f"{package_name}.{module_name}")
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, Challenge) and obj is not Challenge:
                obj.validate_metadata()
                discovered.append(obj)

    return discovered
