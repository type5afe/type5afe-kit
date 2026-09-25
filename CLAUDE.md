# Pentest Kit — Injection + Information Disclosure

Read this file fully at session start. It is the contract. The playbook files hold the technique detail.

## 1. Scope — hard boundary

Only two vulnerability classes are in scope:

- **INJECTION** — see `playbook/01-injection.md`
- **INFORMATION DISCLOSURE** — see `playbook/02-info-disclosure.md`

Anything else you notice (broken access control, IDOR, business logic, CSRF, auth bypass, rate limiting, subdomain takeover):
write one line in `targets/<target>/out-of-scope.md` and move on. Do not chase it. Do not write a report for it.

Exception: if an out-of-scope bug is the delivery mechanism for an in-scope bug (e.g. an IDOR that exposes the
parameter you can inject into), use it, but the finding is still written up as the injection/disclosure bug.

## 2. Rules of engagement — bug bounty, private and public

These are not suggestions. Breaking them can get the user banned from a program.

| Rule | Detail |
|---|---|
| Read program scope first | If `targets/<target>/scope.md` does not exist, ask the user for scope + policy before touching the target. Never guess scope from a domain name. |
| No DoS | No `sleep()`/`WAITFOR` over 5s. No more than 3 time-based probes on one parameter. No heavy `BENCHMARK`/`pg_sleep` loops. No ReDoS payloads. No zip bombs / billion laughs on XXE — use OOB DTD instead. |
| No data destruction | Never `UPDATE`, `DELETE`, `DROP`, `INSERT` into real tables. Stacked-query proof stops at a read (`SELECT`). Command injection proof stops at `id`/`whoami`/`hostname`. No writing webshells. |
| No lateral movement | Proving RCE stops at the proof. Do not read other users' data beyond one record needed as evidence, do not pivot to internal hosts, do not dump full tables. Extract schema, not contents. |
| Rate limit yourself | Default max 5 req/s, 1 concurrent wordlist job. Back off to 1 req/s on any 429/503. If the user has not told you a limit, use these. |
| No third parties | Do not attack anything not in scope, including CDN origins, analytics vendors, OAuth providers, or subdomains you found but cannot confirm are in scope. |
| Attribution header | Send `X-Bug-Bounty: <researcher-handle>` on scanner traffic when the program asks for it. Ask the user for the handle once, store in `targets/<target>/scope.md`. |
| Keep it yours | Stay logged in as the user's own test accounts. Never use credentials you found in a disclosure finding to log in — that is the finding, report it. |

## 3. Communication style

- Plain English. Short sentences. No hype, no "critical!!", no marketing words.
- No severity inflation. If it is a reflected stack trace, say that, not "critical information disclosure".
- When you do not know, say "unknown" or "not tested yet".
- Progress updates are one or two lines: what you just did, what you found, what is next.
- Never claim something is "confirmed" unless you have the request and response saved.

## 4. Stop and ask — do not work around

Stop, explain in one or two lines, and wait for the user. Do not improvise a workaround.

- A tool you need is not installed → ask to install it. Do not hand-roll a worse substitute.
- Auth expired, session dead, login wall, MFA, CAPTCHA → ask.
- You need credentials, an API key, a second account, or a specific role.
- WAF starts blocking you or you get IP-banned.
- Target returns 5xx repeatedly or looks like it is falling over → stop immediately, report.
- You are about to do anything in the "no" column of section 2 and think there is a reason to → ask first.
- Scope is unclear for a host or endpoint you found.
- You found something that looks like real user data (PII, tokens, keys) → stop reading it, report what you have.
- You hit something that needs a browser action you cannot do headlessly.

## 5. Workflow

Six phases. Do not skip ahead. Each phase writes to disk before the next starts.

1. **Setup** — `playbook/99-tools.md`. Confirm tools. Create `targets/<target>/` from `templates/`.
2. **Surface map + ledger** — `playbook/00-surface-and-ledger.md`. Enumerate every input vector into
   `targets/<target>/coverage.md`. This is the anti-miss step. No probing before the ledger exists.
3. **Injection sweep** — `playbook/01-injection.md`, driven by the ledger, row by row.
4. **Disclosure sweep** — `playbook/02-info-disclosure.md`.
5. **Write up** — one file per finding in `targets/<target>/findings/`, from `templates/finding.md`.
6. **Feed the kit** — for every confirmed finding, ask: *why was this nearly missed?* If the answer is a
   reasoning trap (a result that looked clean, a mitigation that looked complete, a channel not tried), add an
   entry to `playbook/04-false-negatives.md` F.1-F.8. If it is implementation behaviour, add a row to
   `playbook/05-quirks.md`. One or two lines is enough. Skip it if the answer is "nothing, it was obvious" —
   do not pad the reference files with things a capable model already knows.

   This step is what makes the kit better than the model on its own. The operator finds bugs manually that
   agents miss; phase 6 is where that knowledge stops being in their head.

Phases 3 and 4 can interleave if a disclosure finding hands you new injection surface. The ledger tracks both.

## 6. Anti-miss rules

The user finds bugs manually that agents miss. These rules exist because of that. Follow them literally.
The playbook cites them as `6.<n>` — `6.8` means rule 8 below.

1. **The ledger is the source of truth.** Every input vector is a row. Every row has a state per sink type:
   `untested` / `tested-negative` / `suspicious` / `confirmed`. You are not done while any row says `untested`.
2. **Record negatives with evidence, and clear the catalog first.** `tested-negative` requires the payload used
   and what the response was. "Looked fine" is not a result. If you cannot show the payload, the state is
   `untested`. Before writing `tested-negative` on any row, run the pre-negative checklist in
   `playbook/04-false-negatives.md` F.9. Most missed bugs are a row that was marked negative for a reason
   that does not hold.
3. **Test names, not just values.** JSON keys, parameter names, cookie names, header names, path segments,
   multipart filenames, `Content-Type` values, XML element and attribute names. Agents test values and stop.
4. **Sink shortlist by shape, never by name.** Each vector gets the mandatory shortlist for its *shape* —
   see the table in `playbook/00-surface-and-ledger.md` 2.5. You may narrow the list using what the input
   *is* (a short string in a filter, a URL, a filename, a map key). You may never narrow it using what the
   input is *called* or what you assume it is for. "It's an email field" is not a reason to skip SQLi.
   Then escalate to the full matrix on any anomaly: an error, a 500, a non-baseline length or status, a
   timing delta, a WAF block, or any reflection you did not expect. Anomaly means that vector gets
   everything, not just the shortlist.
5. **Baseline before fuzzing.** For each endpoint record status, response length, timing, and a content hash of a
   normal request. Subtle injection shows up as a small diff, and you will not see it without the baseline.
6. **403 / WAF block is not a negative result.** It is a `suspicious` state and a jump to
   `playbook/03-bypass-and-blind.md`. Never downgrade a row to negative because a WAF answered.
7. **Re-crawl after every write.** Anything you submit may render somewhere else later. Second-order injection is
   the single most missed class. After any POST/PUT that stores data, re-visit the pages that display it, plus
   exports (CSV, PDF, XLSX), emails, logs, and admin views.
8. **Blind means out-of-band, not "no result".** If a sink has no reflected output, you need a callback channel
   before you may call it negative. See `playbook/03-bypass-and-blind.md`.
9. **One finding per file.** Do not batch findings into a single report. Do not file a finding without a
   reproducible curl or Burp request.
10. **When a payload works, do not stop.** Map the full impact within the ROE limits, then move on. One confirmed
    SQLi does not end the sweep — the ledger does.

## 7. Files

```
CLAUDE.md                     this file
playbook/99-tools.md          tool inventory, install commands, Burp MCP usage
playbook/00-surface-and-ledger.md   attack surface enumeration, fingerprinting, ledger build (§2.x)
playbook/01-injection.md      injection technique cards by sink (§3.0-3.23)
playbook/02-info-disclosure.md      disclosure cards, payability triage first (§4.1-4.22)
playbook/03-bypass-and-blind.md     WAF bypass, parser differentials, OOB channels (§B.1-B.10)
playbook/04-false-negatives.md      results that look clean and are not; pre-negative checklist (§F.1-F.10)
playbook/05-quirks.md         driver/version/engine behaviour that decides a payload (§Q.1-Q.9)
templates/                    coverage.md, finding.md, scope.md, notes.md, kickoff-prompt.md
targets/<target>/             per-engagement working dir
```

Per target:
```
targets/<target>/
  scope.md          program scope, policy, rate limits, researcher handle
  notes.md          running log, plain language, what you did and saw
  coverage.md       the ledger
  out-of-scope.md   one-liners for things you are not chasing
  evidence/         saved requests/responses, named <finding-slug>-<n>.txt
  findings/         one md file per finding
```

Section numbering: the playbook files use the phase number they belong to (`00-` is §2.x, `01-` is §3.x,
`02-` is §4.x). The three reference files are not phases and use letters: §B.x bypass and blind,
§F.x false negatives and §Q.x quirks. So a bare `3.7` always means the injection file, and `B.7` / `F.7` / `Q.7`
are never ambiguous.

The reference files: §B.x bypass and blind, §F.x false negatives, §Q.x quirks. `01-` and `02-` carry technique
and payloads. `04-` and `05-` carry the things a capable model gets wrong or forgets — `04-` the false-negative
traps, `05-` the implementation behaviour behind them. If you already know a payload, you do not need the card.
You still need `04-` before you call a row negative.

## 8. Tooling notes

- Prefer Burp MCP for anything the user has already browsed — their proxy history is the best surface map you
  will get. Read it before you crawl.
- Prefer `curl` for single precise probes; you can see and paste the exact request into a report.
- Use scanners (`ffuf`, `nuclei`, `sqlmap`) for breadth, never as the only evidence. A scanner hit is
  `suspicious` until you reproduce it by hand.
- Save every interesting request/response to `evidence/` as you go, not at the end.
