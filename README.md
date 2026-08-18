# major-project

Sameer, Harry & Suyash's Major IT Project, BreachBox.

## Running locally

```
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000/

## Running with Docker

```
docker compose up --build
```

## What's here (Week 5 skeleton)

- `breachbox/models.py`, the five-table schema: student, challenge, hint,
  submission, hint_unlock
- `breachbox/challenges/base.py`, the modular Challenge base class and
  auto-discovery loader
- `breachbox/auth/`, working session-based login/register/logout
- `breachbox/dashboard/`, `breachbox/scoreboard/`, `breachbox/hints/`,
  placeholder blueprints, real routes and real queries where it made
  sense (scoreboard scoring), TODO markers where the actual feature work
  belongs to Weeks 7 and 11

Delete `breachbox/challenges/_example_challenge.py` once real
vulnerabilities start getting built in Week 6.
