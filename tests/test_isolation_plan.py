"""Unit tests for the planning logic in scripts/isolation_test.py (no Docker needed)."""

import importlib.util
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "isolation_test", Path(__file__).resolve().parent.parent / "scripts" / "isolation_test.py"
)
iso = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(iso)


def svc(name, nets, port=None):
    ports = (iso.Port(port, port),) if port else ()
    return iso.Service(name, frozenset(nets), ports)


def test_two_zones_are_tested_in_both_directions():
    a, b = svc("a", {"zone_a"}, 5000), svc("b", {"zone_b"}, 5001)
    assert [(x.name, y.name) for x, y in iso.isolated_pairs([a, b])] == [("a", "b"), ("b", "a")]


def test_shared_network_is_not_expected_to_be_isolated():
    a, b = svc("a", {"x", "y"}, 5000), svc("b", {"y"}, 5001)
    assert iso.isolated_pairs([a, b]) == []


def test_third_zone_is_covered_without_code_changes():
    services = [svc(n, {n}, 5000 + i) for i, n in enumerate("abc")]
    assert len(iso.isolated_pairs(services)) == 6


def test_service_without_ports_is_never_a_target():
    a, b = svc("a", {"x"}, 5000), svc("b", {"y"})
    assert [(x.name, y.name) for x, y in iso.isolated_pairs([a, b])] == [("b", "a")]


@pytest.mark.parametrize("path,connected,strict,expected", [
    ("dns", False, False, "PASS"),
    ("ip", True, False, "FAIL"),
    ("dns", True, True, "FAIL"),
    ("host-pivot", False, False, "PASS"),
    ("host-pivot", True, False, "WARN"),
    ("host-pivot", True, True, "FAIL"),
])
def test_classify(path, connected, strict, expected):
    assert iso.classify(path, connected, strict) == expected


def test_targets_cover_dns_ip_and_host_pivot():
    dst = svc("b", {"zb"}, 5001)
    src_live = iso.Live("s", {"za": ("10.0.1.2", "10.0.1.1")})
    dst_live = iso.Live("d", {"zb": ("10.0.2.2", "10.0.2.1")})
    assert list(iso.targets(src_live, dst, dst_live)) == [
        ("dns", "b", 5001), ("ip", "10.0.2.2", 5001), ("host-pivot", "10.0.1.1", 5001)
    ]
