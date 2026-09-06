# major-project

Sameer, Harry & Suyash's Major IT Project, BreachBox.

## Running locally

Start in this order, breachbox_app owns database schema creation:

**1. breachbox_app**
```
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000/

**2. flag_api** (same venv, same dependencies, run as a module so its
imports of the shared `breachbox` package and root `config.py` resolve
correctly)
```
python -m flag_api.app
```

**3. target_app** (fully separate app, own dependencies, own tiny
database of fake staff accounts)
```
cd target_app
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5001/

## Running everything with Docker

```
docker compose up --build
```

## Trying the real Vulnerability Set 1 (SQL injection)

1. Register and log in at http://127.0.0.1:5000/auth/register
2. Go to http://127.0.0.1:5001/login
3. Username: `admin' OR '1'='1`, password: anything
4. Copy the flag from the response
5. Submit it: `POST http://127.0.0.1:5002/api/submit` with `challenge_id`,
   `flag`, and `writeup_text`
6. Check http://127.0.0.1:5000/scoreboard/

## The three-zone network model

- `protected_zone`: breachbox_app only (accounts, dashboard, hints)
- `vulnerable_zone`: target_app only
- `submission_zone`: target_app AND flag_api, nothing else

flag_api is a small, separate service exposing only flag submission and
challenge listing. It is the only thing target_app can reach on
submission_zone. breachbox_app never joins submission_zone, so even a
fully compromised target_app has no network path to accounts, the
dashboard, or hints. breachbox_app and flag_api share the same database
via a Docker volume, not a network path.

## What's here

**Week 4-5 (skeleton):** app factory, five-table schema, modular
Challenge base class with auto-discovery, session-based auth.

**Week 6-7 (Vulnerability Set 1):**
- `target_app/app.py`, the real SQL injection login bypass, live and
  exploitable
- `breachbox/challenges/sqli_login.py`, its matching Challenge subclass
- `breachbox/challenges/_reference_sqli_login.py`, kept intentionally,
  the discovery loader explicitly skips underscore-prefixed files, so
  this stays as reference material without being treated as a live
  challenge
- `flag_api/`, the narrow standalone submission service, isolated onto
  its own network from target_app
- `breachbox/challenges/base.py`'s discovery loader now also isolates
  import errors per-file and ignores classes merely imported rather
  than defined in a module, both added during review

**Still open:** dashboard's category filtering and live challenge list
(Week 11), hint unlocking (Week 11), Vulnerability Set 2 (Week 10-11).
