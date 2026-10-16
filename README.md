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

## Running both with Docker

```
docker compose up --build
```

breachbox_app runs on the protected_zone network and target_app runs on vulnerable_zone. They don't share a network or a database, which is on purpose. The only way across is a person: solve a challenge in target_app, copy the flag, and paste it into breachbox_app at /api/submit.

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

Week 7, the network split: we decided protected_zone and vulnerable_zone stay fully separate with no shared network (see #3). Getting a flag from one side to the other is the manual copy paste above, not an automatic endpoint. That's a deliberate change from section 2.2 of our proposal, which had an automatic path. docker-compose.yml already sets this up so nothing needed changing. Two jobs left for the week 12 hardening pass: locking down vulnerable_zone's internet access with internal: true, and double checking target_app's published port only exposes target_app.
