# major-project

Sameer, Harry & Suyash's Major IT Project, BreachBox.

## Running locally, protected zone (breachbox_app)

```
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000/

## Running locally, vulnerable zone (target_app)

This is a separate app, its own dependencies, its own tiny database of
fake staff accounts, no connection to the real student database:

```
cd target_app
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5001/

## Running everything with Docker

```
docker compose up --build
```

`breachbox_app` runs on the `protected_zone` network, `target_app` runs
on `vulnerable_zone`. They do not share a network or a database. The
only intended crossing point is a human: solve the challenge in
`target_app`, get a flag string, submit it manually via
`breachbox_app`'s `/api/submit`.

## What's here

**Week 5 (skeleton):**
- `breachbox/models.py`, the five-table schema
- `breachbox/challenges/base.py`, the modular Challenge base class,
  auto-discovery loader, and DB sync helper
- `breachbox/auth/`, working session-based login/register/logout

**Week 6-7 (this round):**
- `breachbox/challenges/_reference_sqli_login.py`, Sameer's worked
  reference for the Vulnerability Set 1 pattern, kept as a reference,
  not merged as a live challenge
- `breachbox/submissions/`, the real Flag Submission API, generic
  across any Challenge subclass, includes the write-up requirement and
  an already-solved check so a challenge can't award points twice
- `target_app/`, the vulnerable-zone target app. The real vulnerable
  `POST /login` route is done: a raw string-formatted SQL query against
  `staff_users`, exploitable via `' OR '1'='1`, returns the flag on a
  successful bypass
- `breachbox/challenges/sqli_login.py`, the live Challenge subclass for
  that same vulnerability (`SqlInjectionLogin`), checked against the
  flag `target_app` actually returns
- `breachbox/challenges/base.py`, `discover_challenges()` now skips
  underscore-prefixed (reference/placeholder) modules, only counts
  classes actually defined in a module rather than merely imported into
  it, and isolates a broken challenge file so it can't take down app
  startup for everyone else
- `breachbox/models.py`, `Submission` now has a DB-level partial unique
  index so at most one correct submission per (student, challenge) can
  ever exist, backing the app-level check in `submissions/routes.py`

`breachbox/challenges/_example_challenge.py` has been deleted now that
a real vulnerability (`sqli_login.py`) is underway; it was only ever
there to prove the loader worked before anything real existed.

**Still open (deliberately, for the Week 7 network-isolation review):**
the two-zone Docker network topology (`protected_zone` /
`vulnerable_zone`) is unchanged in this round, see the open network
isolation issue, that's the next thing to work through before the
Week 8 isolation pen-test.
