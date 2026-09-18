# BreachBox: Vulnerability Documentation

Internal write-up of every deliberate vulnerability in `target_app`.
This is instructor/team-facing documentation, not the CTF experience
itself, so it deliberately does **not** print the literal flag strings
anywhere below. Volunteers in the Week 13 dry-run should still have to
actually exploit each bug, not just read the answer here.

---

## 1. SQL Injection: Staff Portal Login Bypass

- **Where:** `target_app/app.py`, `POST /login`
- **Class:** CWE-89, SQL Injection
- **Category / difficulty / points:** Injection, Easy, 100

**The bug:** the username and password from the login form are
inserted directly into a SQL string via an f-string, then executed as
raw SQL, instead of using SQLAlchemy's normal parameterized
`filter_by()`.

**Reproduction:** submit `admin' OR '1'='1` as the username, with any
password. The injected `OR '1'='1'` makes the `WHERE` clause always
true, so the query returns the first row in `staff_users` regardless
of whether the password matched.

**Why it's exploitable:** string formatting into a SQL query lets
attacker input change the query's logical structure, not just its
data. Quote characters in the input close the intended string literal
early.

**Fix:** use parameterized queries throughout, e.g.
`StaffUser.query.filter_by(username=username, password=password)`, or
`text(query)` with bound parameters (`:username`) rather than an
f-string.

---

## 2. Reflected XSS: Staff Feedback Board

- **Where:** `target_app/app.py`, `GET /feedback`
- **Class:** CWE-79, Cross-Site Scripting (reflected)
- **Category / difficulty / points:** Web, Easy, 100

**The bug:** the `message` query parameter is rendered into the page
via Jinja2's `|safe` filter, which disables Jinja's automatic HTML
escaping.

**Reproduction:** visit `/feedback?message=<script>alert(document.domain)</script>`.
The script tag becomes part of the actual HTML document the server
returns, so the browser parses and executes it as part of the page
load, not as injected-after-the-fact content.

**Why it's exploitable:** `|safe` tells Jinja "trust this content
completely", appropriate for content the app itself generated, never
appropriate for unmodified user input.

**Fix:** remove `|safe` entirely, Jinja's default auto-escaping is
already correct here. If limited HTML formatting is genuinely wanted
in feedback text, sanitize with an allow-list library (e.g.
`bleach`) rather than trusting raw input outright.

**Design note:** because script execution happens client-side, this
route can't directly verify a payload executed; it detects a
script-trigger signature (`<script`, `onerror=`, `onload=`) in the
input as a proxy for "this would have executed." A more rigorous
version would drive a real (headless) browser to confirm execution.

---

## 3. IDOR: Support Ticket System

- **Where:** `target_app/app.py`, `GET /tickets/<id>`
- **Class:** CWE-639, Insecure Direct Object Reference / broken access control
- **Category / difficulty / points:** Access Control, Medium, 150

**The bug:** the ticket-view route looks up a ticket purely by its
numeric ID in the URL, with no check that the requester is the ticket's
creator, or has any staff privilege at all.

**Reproduction:** file your own ticket via `/tickets/new` (you'll be
redirected to some ID, e.g. `/tickets/7`). Then simply visit
`/tickets/1`, the first ticket ever created (seeded at startup,
belonging to "admin"), which is readable by anyone who guesses or
enumerates the ID.

**Why it's exploitable:** sequential, guessable IDs plus no
authorization check means "I know the URL" is treated as equivalent
to "I'm allowed to see this."

**Fix:** check `ticket.requester_name` (or, in a real system, a proper
`owner_id` foreign key) against the current authenticated user before
returning ticket content, and return 403/404 rather than the ticket's
data if it doesn't match. Non-sequential (UUID) IDs help against casual
enumeration but are not a substitute for an actual authorization check.

---

## 4. OS Command Injection: Network Diagnostics Tool

- **Where:** `target_app/app.py`, `POST /diagnostics`
- **Class:** CWE-78, OS Command Injection
- **Category / difficulty / points:** Injection, Hard, 200

**The bug:** the `host` field from the diagnostics form is interpolated
directly into a shell command string, executed via
`subprocess.run(..., shell=True)`.

**Reproduction:** enter `127.0.0.1; cat ops_notes.txt` as the host to
ping. The shell run by `shell=True` treats `;` as a command separator,
so it runs the intended `ping` command, then a second, entirely
attacker-chosen command, against a file that isn't linked anywhere in
the app's UI.

**Why it's exploitable:** `shell=True` hands the whole string to a
real shell interpreter, so any shell metacharacter (`; && | \` $( ) `)
in user input can inject additional commands. This is a strictly
worse version of the SQLi bug, arbitrary OS commands instead of
arbitrary SQL.

**Fix:** never build a shell command string from user input. Use
`subprocess.run(["ping", "-c", "1", host], shell=False)` (a real
argument list, not a string) and separately validate `host` looks like
a plausible hostname/IP before use at all.

---

## Summary table

| # | Name                     | Class                | Difficulty | Points |
|---|--------------------------|-----------------------|------------|--------|
| 1 | Staff Portal Login Bypass| SQL Injection          | Easy       | 100    |
| 2 | Staff Feedback XSS       | Reflected XSS          | Easy       | 100    |
| 3 | Support Ticket IDOR      | Broken Access Control  | Medium     | 150    |
| 4 | Diagnostics Cmd Injection| OS Command Injection   | Hard       | 200    |

Total available: 550 points across Vulnerability Sets 1 and 2.
