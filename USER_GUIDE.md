# BreachBox — User Guide

BreachBox is a capture-the-flag (CTF) app for learning web security. You attack a deliberately broken website, find a hidden **flag**, and submit it on a separate scoring site to earn points. This guide shows how to start it and how to use it, for both users and assessors.

## 1. What you need

- A computer running **Docker Desktop** (the easy way), or Python 3.
- A web browser.

Install Docker Desktop from docker.com, open it, and wait until it says **"Engine running"** before you start. (If you would rather run it without Docker, the manual Python steps are in the [README](README.md).)

## 2. Start BreachBox

Open a terminal **inside the `major-project` folder** and run:

```
docker compose up --build
```

When it finishes building, open two browser tabs:

- **http://localhost:5000** — BreachBox: the scoring site (accounts, challenges, hints, scoreboard).
- **http://localhost:5001** — the target site: the deliberately vulnerable site you attack.

The two run in separate network zones and never share data. The only way across is a person: you capture a flag on the target site and submit it on the scoring site.

## 3. Play as a student

1. On **:5000**, click **Create an account**, then log in.
2. On your **dashboard**, copy your **personal token**. Your flags are built from this token, so a flag only ever works for you.
3. Go to the target site (**:5001**) and paste your token into the **BreachBox token** box at the top, then click **Set**.
4. Pick a challenge, exploit it, and copy the **flag** it reveals.
5. Back on your dashboard (**:5000**), paste the flag into that challenge, write one line about how you did it, and click **Submit flag**.
6. Stuck? Unlock a **hint** — it costs a few points.
7. Check the **Scoreboard** to see how the class is doing.

## 4. The 10 challenges (on the target site, :5001)

| # | Challenge | Where | What to try |
|---|-----------|-------|-------------|
| 1 | SQL injection | Staff Login | log in with `' OR '1'='1` as the username |
| 2 | Reflected XSS | Feedback | submit a `<script>` or `onerror=` payload |
| 3 | Stored XSS | Noticeboard | post a script note — it runs for everyone who opens the board |
| 4 | IDOR | Submit Ticket | open `/tickets/1`, a ticket that isn't yours |
| 5 | Command injection | Diagnostics | host: `127.0.0.1; cat ops_notes.txt` |
| 6 | Path traversal | Reports | file name: `../staff_only_report.txt` |
| 7 | Privilege escalation | Manager | add a cookie `role=admin`, then reload |
| 8 | SSRF | Link Check | fetch `http://127.0.0.1:5001/internal/ops` |
| 9 | Exposed files | (not in the menu) | open `/robots.txt`, then open the file it names |
| 10 | Chained | Staff Console | read the token in ticket 2, then use it at `/staff/console?token=...` |

Every challenge also has an entry on the **Learn** page: what the bug is, why it matters, and how to prevent it.

## 5. Teacher / assessor view

Log in on **:5000** with:

- **Username:** `teacher`
- **Password:** `breachbox-teacher`

An orange **Admin** link then appears in the top bar. From the admin area you can:

- see every student and their personal token,
- see each student's flags and write-ups,
- edit a challenge's description (your wording is kept, even after a restart),
- add or remove points, which is kept as a record so the scoreboard stays fair.

## 6. If something goes wrong

- **"Cannot connect to the Docker daemon"** — open Docker Desktop first and wait for "Engine running".
- **"not a git repository" / command not found** — make sure your terminal is inside the `major-project` folder.
- **A database error when it starts** — delete the old database files `breachbox.db` and `target_app.db` from the project, then run `docker compose up --build` again. (On Windows: `del /s /q breachbox.db` and `del /s /q target_app.db`.)
- **"port is already in use"** — an old copy is still running. Stop it first (press `Ctrl + C` in its terminal).

## 7. Safety

The target site is **deliberately vulnerable** and is filled with **fake** staff data. Keep it on your own machine or local network — do **not** put it on the public internet. Only use these techniques here, or on systems you own or have permission to test.
