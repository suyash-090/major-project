# Network topology

The two-zone isolation model as a picture. This is the same setup the
[Week 8 isolation test](week8_isolation_test.md) and the automated
`scripts/isolation_test.py` check.

There are two Docker bridge networks, `protected_zone` and
`vulnerable_zone`, with **no network joining them**. Each app is published
to the host on its own port, so a learner reaches both from their browser,
but the two containers have no route to each other.

```mermaid
flowchart TB
    learner["Learner's browser"]

    subgraph host["Host machine (localhost)"]
        p5000(["port 5000"])
        p5001(["port 5001"])
    end

    subgraph protected["protected_zone - Docker bridge"]
        bb["breachbox_app<br/>accounts, scoring, dashboard, hints<br/>container port 5000"]
    end

    subgraph vulnerable["vulnerable_zone - Docker bridge"]
        ta["target_app<br/>deliberately vulnerable staff portal<br/>container port 5001"]
    end

    learner --> p5000
    learner --> p5001
    p5000 -->|"5000:5000"| bb
    p5001 -->|"5001:5001"| ta

    bb -. "no shared network, no route between zones" .- ta

    classDef prot fill:#e6f0ff,stroke:#2b6cb0,color:#1a365d;
    classDef vuln fill:#ffe6e6,stroke:#c53030,color:#742a2a;
    class bb prot;
    class ta vuln;
```

The dashed line is **not** a connection, it marks the gap: there is
deliberately no Docker network between the two zones. `docker-compose.yml`
puts `breachbox_app` only on `protected_zone` and `target_app` only on
`vulnerable_zone`, and lists no network they share. Any attempt to connect
from one zone to the other, by service name or by raw container IP, fails,
which is what `scripts/isolation_test.py` confirms.

## The one intended crossing

A student exploits `target_app`, recovers a flag string, and then manually
submits that string to `breachbox_app` at `/api/submit`. That human step is
the only designed path between the zones, and it carries a short piece of
text, not a network connection. Everything else is blocked by design.
