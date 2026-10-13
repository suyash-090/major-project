# BreachBox Dry-Run Playbook (Week 13)

A short guide for running the class CTF dry-run: how to set up a clean
instance, seed test logins, and what each challenge is. Actual flag strings
are deliberately left out so players have to exploit the bugs themselves.

## 1. Start a clean instance

From the project root, with the stack stopped:

```
docker compose down
python scripts/reset_db.py
docker compose up --build
```

`reset_db.py` deletes the generated databases and flag files so everything
re-seeds fresh. No Python on the host? Delete these by hand instead:
`instance/breachbox.db`, `target_app/target_app.db`,
`target_app/ops_notes.txt`, `target_app/staff_only_report.txt`, and the
`target_app/reports/` folder.

## 2. Seed test logins

In a second terminal, with the stack running:

```
docker compose exec breachbox_app python scripts/seed_students.py
```

This creates player1 through player5, all with password `dryrun123`.
Players can also register their own account at `/auth/register`.

## 3. The two zones

- Scoring app (safe): http://127.0.0.1:5000 - log in, read challenges,
  unlock hints, submit flags, see the scoreboard.
- Target app (vulnerable): http://127.0.0.1:5001 - the deliberately broken
  staff portal where the flags live.

The two run on separate Docker networks and never talk to each other. The
only crossing is a human: exploit the target, get a flag string, paste it
into the scoring app.

## 4. Challenges

| Challenge | Where | Idea |
|-----------|-------|------|
| Staff Portal Login Bypass | 5001 `/login` | SQL injection in the login form |
| Staff Feedback Reflected XSS | 5001 `/feedback` | a script runs from the `message` parameter |
| Support Ticket IDOR | 5001 `/tickets/<id>` | read a ticket that isn't yours |
| Diagnostics Command Injection | 5001 `/diagnostics` | chain a second shell command |
| Report Viewer Path Traversal | 5001 `/reports` | escape the folder with `../` |
| Chained: Ticket Leak to Staff Console | 5001 `/tickets/<id>` then `/staff/console` | IDOR a leaked token, then reuse it |

The last two land once the "two new challenges" PR is merged.

## 5. Scoring and rules

- Each flag is worth points by difficulty. Unlocking a hint costs points.
- A short write-up is required with each correct flag before it counts.
- A challenge only scores once per student, and wrong guesses are rate
  limited, so there is no brute forcing.

## 6. Reset between groups

Run step 1 again. Every group starts from a clean board.
