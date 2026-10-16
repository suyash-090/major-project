#!/usr/bin/env python3
"""
Automated zone isolation test for BreachBox.

Proves that services which share no Docker network cannot reach each other.
Zones are discovered from docker-compose.yml, so adding a service or a zone
needs no change here: every ordered pair of services with no common network
is expected to be isolated and is tested in both directions.

For each isolated pair (src -> dst) the test connects from inside src to:
  dns         dst's service name        (name resolution across zones)
  ip          dst's address on each of its networks   (routing)
  host-pivot  src's bridge gateway on dst's published host port
              (a path through the host instead of a shared network)

Before testing, each service must accept a connection on its own address.
That control stops a dead or misconfigured stack from passing as "isolated".

Run with the stack up, from any directory:

    docker compose up -d --build
    python scripts/isolation_test.py [--strict]

Exit codes: 0 isolated, 1 isolation broken, 2 inconclusive (test could not run).

By default a host-pivot connection is a WARN, because published ports are how
students reach the apps. --strict turns that WARN into a FAIL.

Requires the docker CLI with Compose v2, and python inside each service image.
Standard library only.
"""

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from itertools import permutations
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONNECT_TIMEOUT = 3
EXEC_TIMEOUT = 20

# Runs inside a container. Exit 0 = connected, exit 1 = refused/blocked with a
# reason on stdout. Anything else (traceback, missing python) is inconclusive.
PROBE = (
    "import socket, sys\n"
    "try:\n"
    "    socket.create_connection((sys.argv[1], int(sys.argv[2])), "
    "timeout=float(sys.argv[3])).close()\n"
    "except OSError as e:\n"
    "    print(e.strerror or e)\n"
    "    sys.exit(1)\n"
    "print('connected')\n"
)


class Inconclusive(Exception):
    """The test could not establish a trustworthy result."""


@dataclass(frozen=True)
class Port:
    target: int
    published: int | None


@dataclass(frozen=True)
class Service:
    name: str
    networks: frozenset[str]  # real Docker network names
    ports: tuple[Port, ...]


@dataclass(frozen=True)
class Live:
    cid: str
    nets: dict[str, tuple[str, str]]  # network name -> (ip, gateway)


@dataclass(frozen=True)
class Result:
    src: str
    dst: str
    path: str
    addr: str
    status: str
    detail: str


# Docker plumbing

def docker(*args, timeout=EXEC_TIMEOUT):
    try:
        return subprocess.run(
            ["docker", *args], cwd=ROOT, capture_output=True, text=True, timeout=timeout
        )
    except FileNotFoundError:
        raise Inconclusive("docker CLI not found")
    except subprocess.TimeoutExpired:
        raise Inconclusive(f"'docker {' '.join(args[:2])}' timed out")


def docker_ok(*args):
    r = docker(*args)
    if r.returncode != 0:
        raise Inconclusive(f"'docker {' '.join(args[:2])}' failed: {r.stderr.strip()}")
    return r.stdout


def probe(cid, host, port):
    """Return (connected, detail). Raise Inconclusive if the probe itself broke."""
    r = docker("exec", cid, "python", "-c", PROBE, host, str(port), str(CONNECT_TIMEOUT))
    if r.returncode == 0:
        return True, "connected"
    if r.returncode == 1 and r.stdout.strip():
        return False, r.stdout.strip()
    raise Inconclusive(f"probe failed in {cid[:12]}: {r.stderr.strip() or r.returncode}")


# Discovery

def parse_port(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None  # unpublished or a port range


def load_services():
    cfg = json.loads(docker_ok("compose", "config", "--format", "json"))
    net_names = {k: (v or {}).get("name", k) for k, v in cfg.get("networks", {}).items()}
    services = []
    for name, svc in cfg["services"].items():
        keys = svc.get("networks") or {"default": None}
        ports = tuple(
            Port(int(p["target"]), parse_port(p.get("published")))
            for p in svc.get("ports", [])
        )
        services.append(Service(name, frozenset(net_names.get(k, k) for k in keys), ports))
    return services


def inspect_service(svc):
    ids = docker_ok("compose", "ps", "-q", svc.name).split()
    if len(ids) != 1:
        raise Inconclusive(f"expected 1 running container for '{svc.name}', found {len(ids)}")
    info = json.loads(docker_ok("inspect", ids[0]))[0]
    if not info["State"]["Running"]:
        raise Inconclusive(f"'{svc.name}' is not running")
    nets = {
        name: (n["IPAddress"], n["Gateway"])
        for name, n in info["NetworkSettings"]["Networks"].items()
    }
    return Live(ids[0], nets)


# Test plan (pure logic, unit-tested)

def isolated_pairs(services):
    """Ordered (src, dst) pairs with no shared network and a port to aim at."""
    return [
        (a, b)
        for a, b in permutations(services, 2)
        if not (a.networks & b.networks) and b.ports
    ]


def targets(src_live, dst, dst_live):
    for port in dst.ports:
        yield "dns", dst.name, port.target
        for ip, _ in dst_live.nets.values():
            yield "ip", ip, port.target
        if port.published:
            for _, gateway in src_live.nets.values():
                if gateway:
                    yield "host-pivot", gateway, port.published


def classify(path, connected, strict):
    if not connected:
        return "PASS"
    return "WARN" if path == "host-pivot" and not strict else "FAIL"


# Execution

def check_controls(services, live):
    """Every service must accept connections on its own address, else results are void."""
    for svc in services:
        for port in svc.ports:
            for ip, _ in live[svc.name].nets.values():
                ok, detail = probe(live[svc.name].cid, ip, port.target)
                if not ok:
                    raise Inconclusive(
                        f"control failed: {svc.name} not reachable on its own {ip}:{port.target} ({detail})"
                    )


def run(services, strict):
    pairs = isolated_pairs(services)
    if not pairs:
        raise Inconclusive("no isolated service pairs found in docker-compose.yml")
    live = {s.name: inspect_service(s) for s in services}
    check_controls(services, live)
    results = []
    for src, dst in pairs:
        for path, host, port in targets(live[src.name], dst, live[dst.name]):
            connected, detail = probe(live[src.name].cid, host, port)
            results.append(
                Result(src.name, dst.name, path, f"{host}:{port}", classify(path, connected, strict), detail)
            )
    return results


# Reporting

def commit():
    r = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True
    )
    return r.stdout.strip() if r.returncode == 0 else "unknown"


def report(results, strict):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"BreachBox isolation test | {now} | commit {commit()} | strict={strict}\n")
    print("| From | To | Path | Address | Result | Detail |")
    print("|---|---|---|---|---|---|")
    for r in results:
        print(f"| {r.src} | {r.dst} | {r.path} | {r.addr} | {r.status} | {r.detail} |")
    counts = {s: sum(r.status == s for r in results) for s in ("PASS", "WARN", "FAIL")}
    print(f"\n{counts['PASS']} blocked, {counts['WARN']} warn, {counts['FAIL']} fail "
          f"out of {len(results)} attempts.")
    if counts["FAIL"]:
        print("RESULT: ISOLATION BROKEN")
    elif counts["WARN"]:
        print("RESULT: NO DIRECT PATH between zones. WARN = reachable through a "
              "host-published port; review before final submission.")
    else:
        print("RESULT: ISOLATION VERIFIED. No path between zones.")
    return 1 if counts["FAIL"] else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--strict", action="store_true",
                        help="treat host-published-port reachability as a failure")
    args = parser.parse_args()
    try:
        return report(run(load_services(), args.strict), args.strict)
    except Inconclusive as e:
        print(f"INCONCLUSIVE: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
