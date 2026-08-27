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
  reference for the Vulnerability Set 1 pattern, not meant to be merged
  as a finished submission, a starting point to adapt
- `breachbox/submissions/`, the real Flag Submission API, generic
  across any Challenge subclass, includes the write-up requirement
- `target_app/`, the vulnerable-zone target app skeleton, boots on its
  own, seeded with dummy staff accounts, the actual vulnerable
  `POST /login` route is still open, that's Sameer's milestone to
  finish, following his own reference

Delete `breachbox/challenges/_example_challenge.py` once real
vulnerabilities are underway, it was only ever there to prove the
loader worked before anything real existed.
