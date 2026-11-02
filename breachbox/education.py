"""Teaching content for each challenge: what it teaches, why it matters in the
real world, and how to prevent it, plus the OWASP Top 10 category it comes from.
Keyed by challenge name so the dashboard and the Learn page can show it beside
each challenge. This is the layer that turns BreachBox from a flag hunt into a
lesson: every bug you exploit here, you also learn how to stop."""

EDUCATION = {
    "Staff Portal Login Bypass": {
        "owasp": "A03:2021 - Injection",
        "owasp_url": "https://owasp.org/Top10/2021/A03_2021-Injection/",
        "learn": "How SQL injection works: when your input is dropped straight into a database query, you can change what that query does.",
        "matters": "SQL injection can log an attacker in with no password, or read, change and delete a whole database. It is one of the oldest and most damaging web bugs.",
        "prevent": "Use parameterised queries (prepared statements) so input is always treated as data, never as SQL. Never build a query by joining strings together.",
    },
    "Staff Feedback Reflected XSS": {
        "owasp": "A03:2021 - Injection (Cross-Site Scripting)",
        "owasp_url": "https://owasp.org/Top10/2021/A03_2021-Injection/",
        "learn": "How reflected XSS works: when a page echoes your input back without escaping it, you can make someone's browser run your script.",
        "matters": "XSS lets an attacker run code in another user's browser, steal their login session, change what they see, or trick them into actions they never meant to take.",
        "prevent": "Escape and encode all user input when it goes into a page, and let the template auto-escape it (never mark it 'safe'). Add a Content-Security-Policy header.",
    },
    "Staff Noticeboard Stored XSS": {
        "owasp": "A03:2021 - Injection (Cross-Site Scripting)",
        "owasp_url": "https://owasp.org/Top10/2021/A03_2021-Injection/",
        "learn": "How stored XSS works: when a page saves your input and later shows it to other people without escaping it, your script runs in their browsers, not just your own.",
        "matters": "Stored XSS is the more dangerous kind of XSS: the payload is saved once and then fires for every visitor who loads the page, so a single post can hit a whole site's users, staff and admins included.",
        "prevent": "Escape user input when it is shown on a page and let the template auto-escape it (never mark it 'safe'). Validate input on the way in as well, and add a Content-Security-Policy header so injected scripts can't run.",
    },
    "Support Ticket IDOR": {
        "owasp": "A01:2021 - Broken Access Control",
        "owasp_url": "https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control/",
        "learn": "How an Insecure Direct Object Reference works: when a page hands you data based on an ID in the URL without checking it is yours, you just change the number to see someone else's.",
        "matters": "IDOR quietly leaks private records, other people's tickets, invoices or messages, by changing one number. It is extremely common and easy to miss.",
        "prevent": "Check ownership on every request: confirm the logged-in user is allowed to see that exact object before returning it. Never rely on an ID being hard to guess.",
    },
    "Diagnostics Command Injection": {
        "owasp": "A03:2021 - Injection",
        "owasp_url": "https://owasp.org/Top10/2021/A03_2021-Injection/",
        "learn": "How OS command injection works: when your input is passed into a shell command, characters like ; let you run your own commands on the server.",
        "matters": "Command injection can hand an attacker full control of the server, running any program, reading any file, and pivoting deeper into the network. It is one of the most severe bugs there is.",
        "prevent": "Do not build shell commands from user input. Call the tool directly instead of going through a shell, pass arguments as a list rather than one string, avoid shell=True, and allow-list what input you accept.",
    },
    "Report Viewer Path Traversal": {
        "owasp": "A01:2021 - Broken Access Control",
        "owasp_url": "https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control/",
        "learn": "How path traversal works: when a filename comes from user input with no checks, ../ lets you climb out of the intended folder and read other files.",
        "matters": "It lets an attacker read files they should never reach, config files, passwords, source code, or other users' documents.",
        "prevent": "Never build a file path straight from user input. Allow-list the exact filenames, strip ../, and resolve the final path to confirm it stays inside the folder you meant.",
    },
    "Chained: Ticket Leak to Staff Console": {
        "owasp": "A01:2021 - Broken Access Control",
        "owasp_url": "https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control/",
        "learn": "How two smaller bugs chain into a bigger one: the ticket IDOR leaks a secret token, and that token unlocks a staff-only page. Real attacks are usually chains, not a single bug.",
        "matters": "It shows that a 'low' issue (reading a ticket) plus a weak secret (a shared token) can add up to a full staff takeover. You have to think about how problems combine, not just one at a time.",
        "prevent": "Fix every link: proper access checks on tickets, and never guard a sensitive page with a shared, leakable token, use real per-user authentication and sessions.",
    },
}


def for_challenge(name):
    """Return the teaching content for a challenge, or None if we have none."""
    return EDUCATION.get(name)
