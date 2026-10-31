# BreachBox

Our Major IT Project, built by Sameer, Harry and Suyash.

BreachBox is a capture the flag app for learning web security. You break into a deliberately vulnerable website, find a flag, and submit that flag on a separate scoring site to earn points. It's built as two apps that can't talk to each other, and that split is the whole idea behind it.

## Running the protected app (breachbox_app)

This is the scoring side: accounts, challenges, hints and the scoreboard.

```
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000/

## Running the vulnerable app (target_app)

This is the site you actually attack. It's a separate app with its own requirements and its own small database of fake staff accounts, and it has no connection to the real student database.

```
cd target_app
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5001/

Both apps start with Flask's debug mode off. The debugger lets anyone run code from the browser when a page errors, and that's the last thing you want on a deliberately vulnerable site. If you need it while coding, set `BREACHBOX_DEBUG=1` (breachbox_app) or `TARGET_DEBUG=1` (target_app) before starting the app. With debug off the app won't auto-reload either, so restart it after changing code.

## Running both with Docker

```
docker compose up --build
```

breachbox_app runs on the protected_zone network and target_app runs on vulnerable_zone. They don't share a network or a database, which is on purpose. The only intended way across is a person: solve a challenge in target_app, copy the flag, and paste it into breachbox_app at /api/submit. There's a picture of the setup in [docs/network_topology.md](docs/network_topology.md).

## Per-student flags

Flags are unique to each student, so one student can't just hand their flag to a friend. Every account gets a personal token (shown on the dashboard). target_app builds each flag from that token, so the flag you capture is different from everyone else's, and breachbox_app only accepts the flag built from your own token. You have to do each hack yourself.

The two apps never share a database or talk over the network to do this. They only share one secret value, `FLAG_SECRET` (set the same in both, through the environment in docker-compose.yml), and each app derives the same flags from it on its own, using HMAC. So the two zones stay fully separate, exactly as before.

To play through BreachBox: copy your token from your dashboard, paste it into the "BreachBox token" box at the top of target_app, then do the challenges. The flags you capture will be yours.

## Teacher / admin area

There's a separate admin area at `/admin`, reachable only by a teacher account (a student who guesses the URL gets a 403, not the page). From there a teacher can see every student's token and their per-student flags, read their write-ups, dock or award points (each change is kept as a record, so the scoreboard stays auditable), and edit the challenge descriptions students see.

The app seeds one admin account, `teacher`, on first run. Set its password with the `ADMIN_PASSWORD` environment variable; the built-in default is only meant for local use.

## Running the tests

We wrote automated tests for the main logic: the flag checking, the challenge loader, the scoreboard maths, the submit API, the rate limiting and the planning part of the isolation test.

```
pip install -r requirements.txt -r requirements-dev.txt
pytest
```

There are 68 of them and they all sit in the tests/ folder. Each test builds its own throwaway database, so they never touch your real one and don't rely on each other.

## Checking the zones are isolated

With the Docker stack running, this script checks that the two zones really can't reach each other:

```
docker compose up -d --build
python scripts/isolation_test.py
```

It reads docker-compose.yml, then from inside each container it tries to reach the other zone by service name, by IP and through the server's published ports, and prints a table of results. PASS means the attempt was blocked, which is what we want. The script exits with 0 if the zones are isolated, 1 if they aren't, and 2 if it couldn't run the test properly (for example if the stack isn't up).

You'll probably see a WARN row too. Both apps are published on the server's ports so students can reach them from their laptops. That isn't a shared network between the zones, but it is a way round through the server, so the script flags it to keep it in view. Add `--strict` if you want WARN to count as FAIL.

Heads up: on Docker Desktop for Windows you'll also see FAIL rows for the direct-IP checks. Docker Desktop doesn't enforce the isolation between separate networks that a native Linux host does, so the containers can still reach each other by IP there. On a Linux host those rows pass. For the live event, run the zones on a Linux host or on separate machines so the separation actually holds.

This is the automated version of the manual test in [docs/week8_isolation_test.md](docs/week8_isolation_test.md).

## What we've built so far

Week 5, the skeleton:
- breachbox/models.py, the five database tables
- breachbox/challenges/base.py, the Challenge base class plus the loader that finds every challenge on its own and syncs them to the database
- breachbox/auth/, working login, register and logout (session based)

Week 6-7:
- breachbox/challenges/_reference_sqli_login.py, Sameer's worked example for the first vulnerability. We left it in as a reference and don't load it as a real challenge
- breachbox/submissions/, the flag submission API. It works for any challenge, makes you write a short explanation, and checks you haven't already solved something so nobody gets points twice for the same bug
- target_app/, the vulnerable site. The SQL injection login works: it builds the query with a raw string, so logging in with ' OR '1'='1 gets you in and hands back the flag
- breachbox/challenges/sqli_login.py, the real challenge class for that bug, checked against the flag target_app gives out
- the loader in base.py now skips the underscore reference files, only picks up classes that are actually written in a file instead of imported into it, and keeps one broken challenge file from taking down the whole app at startup
- breachbox/models.py, Submission now has a database level unique index so there can only ever be one correct submission per student per challenge, backing up the check in the submissions code

We deleted the old _example_challenge.py once a real vulnerability was underway, it was only ever there to show the loader worked.

Week 7, the network split: we decided protected_zone and vulnerable_zone stay fully separate with no shared network (see #3). Getting a flag from one side to the other is the manual copy paste above, not an automatic endpoint. That's a deliberate change from section 2.2 of our proposal, which had an automatic path. docker-compose.yml already sets this up so nothing needed changing. We left two jobs for the week 12 hardening pass: locking down vulnerable_zone's internet access with internal: true, and double checking target_app's published port only exposes target_app.

Week 12, the hardening pass:
- Flask debug mode is now off by default on both apps (#23)
- scripts/isolation_test.py, Suyash's automated isolation test, plus unit tests for its planning logic (#22, from #19). It also covers the second job above, since it checks every path between the zones, including the published ports
- docs/network_topology.md, the topology diagram showing the two zones and their ports (#22)
- we left internal: true out in the end. BreachBox runs on one server that students reach from their laptops, and putting target_app on an internal network would stop them getting to it at all

Since the prototype feedback:
- Per-student flags (see the section above): each student now gets a unique flag for every challenge, so flags can't be shared between students. It uses a shared `FLAG_SECRET` and HMAC, so the two zones still never share a database or a network path. This answers the marker's note that the standard flag strings could be passed around.
