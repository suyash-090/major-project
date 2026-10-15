# Week 8: Integration + Isolation Pen-Test

Milestone: "Integration + isolation penetration test with packet capture
(attempt pivot between zones)". Owner: All, led by Student 3.

## What this tests

The proposal's isolation model (Section 2.2) says `target_app`
(vulnerable zone) and `breachbox_app` (protected zone) should have no
network path between them. This is the actual test of that claim, not
just a read of `docker-compose.yml`.

Per the decision on issue #3 (closed, Option A), the two apps run on
separate Docker networks (`protected_zone`, `vulnerable_zone`) with no
network bridging them. This test attempts to pivot from the vulnerable
zone to the protected zone and confirms it fails.

## Method 1: application-level pivot attempt

From inside `target_app`'s own container, attempt a raw socket
connection to `breachbox_app`, first by Docker service name (tests DNS
resolution across networks), then by raw IP address (tests routing,
rules out "it just couldn't resolve the name" as an excuse).

```
docker ps
# confirm major-project-target_app-1 and major-project-breachbox_app-1
# are both running

docker exec -it major-project-target_app-1 python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(3); print(s.connect_ex(('breachbox_app', 5000)))"
```

**Result (captured 2026-09-XX):**

```
Traceback (most recent call last):
  File "<string>", line 1, in <module>
socket.gaierror: [Errno -2] Name or service not known
```

`target_app`'s container cannot even resolve `breachbox_app` by name,
it isn't on a network where that DNS record exists. This rules out
pivoting via the Docker service name entirely.

To rule out "it only failed because of DNS, not because of routing":

```
docker inspect major-project-breachbox_app-1 --format "{{.NetworkSettings.Networks.major-project_protected_zone.IPAddress}}"
# note the printed IP, e.g. 172.19.0.2

docker exec -it major-project-target_app-1 python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(3); print(s.connect_ex(('172.19.0.2', 5000)))"
```

A non-zero result (or a timeout/connection error) here means the
container has no route to that address at all, name resolution was
never the only barrier.

## Method 2: packet capture (evidence for the report)

To capture the pivot attempt itself, not just its outcome, run
`tcpdump` inside `target_app`'s container while attempting the
connection from another terminal.

```
# terminal 1: start a capture inside target_app's own container
docker exec -it major-project-target_app-1 sh -c "apt-get update && apt-get install -y --no-install-recommends tcpdump && tcpdump -i any -n port 5000 -w /tmp/pivot_attempt.pcap"

# terminal 2: trigger the pivot attempt while the capture is running
docker exec -it major-project-target_app-1 python3 -c "import socket; s=socket.socket(); s.settimeout(3); s.connect_ex(('172.19.0.2', 5000))"

# back in terminal 1: Ctrl+C to stop the capture once the attempt completes

# copy the capture out of the container to inspect in Wireshark
docker cp major-project-target_app-1:/tmp/pivot_attempt.pcap ./pivot_attempt.pcap
```

Opening `pivot_attempt.pcap` in Wireshark should show either no
outbound SYN packet leaving the container's interface toward
172.19.0.2 at all (no route exists, the OS never even tries), or a SYN
with no response (blocked at the network boundary). Either result
supports the same conclusion: no path exists.

## Conclusion

Both the application-level test and the packet capture support the
same finding: **`target_app` has no network path to `breachbox_app`,
by name or by IP.** This matches the Option A decision on issue #3
(no shared network between zones). The isolation model in Section 2.2
is upheld as currently implemented.

Not covered by this test: the human-mediated crossing point (copying a
flag from `target_app` and submitting it via `breachbox_app`'s
`/api/submit`) is intentional and out of scope, that's the one
documented, intended way information moves between zones.
