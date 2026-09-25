# Kickoff Prompt

Paste this at the start of a new engagement session. Replace the `<...>` parts. Delete lines that do not apply.

---

Target: `<host / program name>`
Program: `<HackerOne / Bugcrowd / private / URL to policy>`
My handle for attribution: `<handle>`
Auth I have: `<unauth only | creds in targets/<target>/scope.md | two accounts, roles X and Y>`
Rate limit from policy: `<n req/s, or "not stated, use kit default">`
Forbidden by policy: `<e.g. no automated scanners, no request smuggling, no social engineering>`

Read `CLAUDE.md` first, then `playbook/00-surface-and-ledger.md`. Follow the five phases. Do not skip to probing.

Scope for this session: **INJECTION** and **INFORMATION DISCLOSURE** only. Anything else goes in
`out-of-scope.md` as one line. Do not chase it.

What I have already done: `<e.g. clicked around the main dashboard, my rough notes are in targets/<target>/notes.md — they are incomplete, I did not open every menu>`

My Burp proxy history has the traffic from that. Read it through Burp MCP before you crawl anything yourself.

Screenshots of the app are at `<path>` so you know what the UI looks like.

How I want you to work:
- Plain language. Short. No fancy words, no hype. I need to read your notes fast and stay in sync with you.
- Keep `targets/<target>/notes.md` updated as you go, not at the end.
- The ledger in `targets/<target>/coverage.md` is mandatory. I will check it. Zero `untested` rows means done,
  nothing else does.
- Every negative result needs the payload you used written next to it. "Looked fine" is not a result.
- When you need me — a tool to install, creds, a login wall, a WAF ban, a browser action, an unclear scope call —
  **stop and ask me**. Do not work around it and do not break your own workflow improvising. Discuss it with me.
- Do not inflate severity. Call a stack trace a stack trace.
- Stay inside the rules of engagement in `CLAUDE.md` section 2. If you think there is a reason to step outside,
  ask me first.

Start with phase 1 and tell me when the ledger is built, before you start probing.

---

## Notes on why this prompt is shaped this way

| Line | What it prevents |
|---|---|
| "Read CLAUDE.md first" | Agent inventing its own methodology instead of using the kit. |
| "Do not skip to probing" | The most common failure: firing payloads at the three parameters it noticed, calling it app-wide. |
| "Read Burp history before you crawl" | Agent re-discovering surface you already found, and missing the surface only your browsing revealed. |
| "My notes are incomplete" | Agent treating your notes as the full scope of the app. |
| "Zero untested rows means done" | Agent declaring victory after finding one bug. |
| "Negatives need payloads" | Agent silently skipping vectors and reporting them clean. |
| "Stop and ask" | Agent burning an hour on a workaround for a missing tool, or getting you IP-banned. |
| "Do not inflate severity" | Reports that get closed as informational and cost you program reputation. |
