# <Impact-first title>

Copy to `targets/<target>/findings/<slug>.md`. **One finding per file** (`CLAUDE.md` 6.9). Delete these
instruction lines before submitting.

Title rule: lead with what an attacker gets, then the sink, then the location. No adjectives, no severity word
in the title.

```
good   Database read via boolean SQL injection in POST /api/search "q"
good   Full application source disclosed via exposed .git directory
good   Server-side template evaluation via uploaded filename, rendered in CSV export
bad    Critical SQLi!!
bad    Security issue in search
bad    Possible information leakage
```

## Target

| Field | Value |
|---|---|
| Program | |
| Host | |
| Endpoint | `POST /api/search` |
| Parameter / vector | json value `q` |
| Ledger row | `R0001` in `coverage.md` |
| Auth context | A1, operator's own test account `test-user-1@example.com` |
| First observed | YYYY-MM-DD HH:MM UTC |
| Reproduced | YYYY-MM-DD HH:MM UTC (second run) |

## Class

One of, and only one of (`CLAUDE.md` 1):

- **Injection** — sub-type: SQL / NoSQL / command / SSTI / XXE / XPath / LDAP / CRLF / XSS / spreadsheet formula / deserialization / SSI / log
- **Information disclosure** — sub-type: source code / secrets / stack trace / internal host or path / API spec / backup file / PII in response / debug endpoint / version

If it is neither, it does not get a report. One line in `out-of-scope.md`.

## Severity

| Field | Value |
|---|---|
| Severity | Low / Medium / High / Critical |
| CVSS 3.1 vector | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| Base score | 6.5 |
| Justification | One line. Which metrics drove it and why. |

Example justification: "Authenticated user (PR:L) reads arbitrary rows from the application database (C:H);
no write path observed (I:N), no availability effect (A:N)."

**No inflation.** The severity is what the evidence supports, not what you hope it is. Specifically:

- A reflected stack trace is a stack trace, not "critical information disclosure" (`CLAUDE.md` 3).
- `PR:N` only if you proved it unauthenticated. Re-run the request with no session and paste the result.
- `C:H` only if you demonstrated access to data beyond your own account's, within ROE.
- `I:*` above None requires a demonstrated write. Do not claim one you did not do — writes are forbidden
  (`CLAUDE.md` 2), so if it is theoretical, say "write path not tested, forbidden by ROE".
- `S:C` only if you crossed a real security boundary and can show it.
- If you are between two scores, take the lower one and say why in the justification. Triage respects that;
  it does not respect a padded vector.

## Summary

Two to three lines, plain language. What the bug is, where, and what it lets someone do. No build-up.

```
The q parameter of POST /api/search is concatenated into a PostgreSQL query. A boolean-differential payload
changes the response body reliably, allowing an authenticated user to read arbitrary data from the database.
Confirmed against the schema and one value; no data beyond the reporter's own record was extracted.
```

## Affected component

| Field | Value |
|---|---|
| Component | search API handler |
| Technology | PostgreSQL 14 (from `version()` first character), framework <x> |
| Evidence for the stack | which signal told you (`playbook/00-surface-and-ledger.md` 2.2) |
| Other endpoints likely affected | only if you tested them; list them with their ledger IDs, or write "not tested" |

## Prerequisites

| Requirement | Detail |
|---|---|
| Auth level needed | none / any registered user / specific role / admin |
| Account type | free tier / paid / invited to an org |
| Preconditions | e.g. "must have uploaded at least one file", "org must have CSV export enabled" |
| User interaction | none, or: a specific user must open a page (say which page and which user) |
| Network position | none (public internet) |

State this precisely. Triage downgrades findings whose prerequisites turn out heavier than claimed.

## Reproduction steps

Numbered, exact, no gaps. A triager pastes these and sees the same thing. Include every header that matters
(auth, content type, attribution). Redact the session value but keep its shape.

```
1. Log in as a standard user. Capture the session cookie.
2. Send the baseline request. Note status 200, body length 1843.
3. Send the true-condition request. Note status 200, body length 1843 (unchanged).
4. Send the false-condition request. Note status 200, body length 1791 (52 bytes shorter, results list empty).
5. The length difference tracks the injected condition, which confirms the injection.
```

Baseline:

```bash
curl -s -i 'https://TARGET/api/search' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=<REDACTED-SESSION-OF-test-user-1>' \
  -H 'X-Bug-Bounty: <HANDLE>' \
  --data-raw '{"q":"widget"}'
```

True condition:

```bash
curl -s -i 'https://TARGET/api/search' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=<REDACTED-SESSION-OF-test-user-1>' \
  -H 'X-Bug-Bounty: <HANDLE>' \
  --data-raw '{"q":"widget'"'"' AND (SELECT SUBSTR(version(),1,1))='"'"'P'"'"'-- -"}'
```

False condition:

```bash
curl -s -i 'https://TARGET/api/search' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=<REDACTED-SESSION-OF-test-user-1>' \
  -H 'X-Bug-Bounty: <HANDLE>' \
  --data-raw '{"q":"widget'"'"' AND (SELECT SUBSTR(version(),1,1))='"'"'X'"'"'-- -"}'
```

If a bypass was needed to land the payload, the reproduction must include it, with a one-line note saying
which layer it beat (`playbook/03-bypass-and-blind.md` B.10). A report that does not reproduce because the
WAF step was omitted gets closed as unreproducible.

## Evidence

Files in `targets/<target>/evidence/`, named `<slug>-<n>.txt`:

| File | Contents |
|---|---|
| `<slug>-1.txt` | baseline request + response |
| `<slug>-2.txt` | true-condition request + response |
| `<slug>-3.txt` | false-condition request + response |
| `<slug>-4.txt` | OOB callback log excerpt, if any (canary label + timestamp) |

Excerpt inline, trimmed to the lines that matter:

```http
POST /api/search HTTP/1.1
Host: TARGET
Content-Type: application/json
Cookie: session=<REDACTED>

{"q":"widget' AND (SELECT SUBSTR(version(),1,1))='P'-- -"}
```

```http
HTTP/1.1 200 OK
Content-Length: 1843

{"results":[{"id":1,"name":"widget-a"}, ...]}
```

Redaction rules, applied before the file is written:

- Session cookies, bearer tokens, API keys → `<REDACTED>`, keep the length/shape if it is relevant.
- Any real user's name, email, phone, address, ID → `<REDACTED-PII>`. Never paste another user's record in
  full, even as proof. One redacted field is proof enough.
- Internal hostnames and IPs: keep them if they are the finding, redact them if they belong to a third party.
- Screenshots: crop to the relevant pane, check the browser tabs and bookmarks bar for leaked URLs.
- If you found credentials, report their existence and location. Do not paste them and do not use them
  (`CLAUDE.md` 2).

## Impact

What an attacker actually gets, from what you demonstrated. Concrete. No speculation, no "could lead to full
compromise" unless you showed it.

```
An authenticated user with a free account can read arbitrary rows from the application database, including
tables belonging to other tenants. Demonstrated by reading the schema (public.users, public.orders,
public.api_tokens) and one value from the reporter's own row. The public.api_tokens table exists and contains
2,418 rows; its contents were not read, per the program's rules.
```

Say plainly what you did not test and why:

```
Not tested: write access. ROE forbids UPDATE/INSERT/DELETE against a live database, so the integrity impact
is unknown and scored as None.
```

## Scope of exposure

How much is exposed, stated honestly, with the method that produced the number.

| Question | Answer | How determined |
|---|---|---|
| How many records are reachable? | 2,418 rows in `public.api_tokens` | `COUNT(*)` via the boolean oracle. Contents not read |
| How many users affected? | unknown | not determined; row count in `users` is 40,112 by the same method |
| Cross-tenant? | yes | `public.orders` rows exist with `tenant_id` values other than the reporter's |
| Other endpoints affected? | not tested | only `/api/search` was in the ledger row |

Never round up, never extrapolate. "Unknown" is an acceptable answer and a credible one. If the number came
from a `COUNT(*)` rather than from reading rows, say so — it shows you respected the program's limits.

## Remediation

Specific to this sink and this code path. Boilerplate gets ignored by triage and by the developer.

```
The q value reaches the query as string concatenation in the search handler. Bind it as a parameter:

  cur.execute("SELECT id, name FROM products WHERE name ILIKE %s", (f"%{q}%",))

Not this:

  cur.execute(f"SELECT id, name FROM products WHERE name ILIKE '%{q}%'")

Parameter binding does not cover the ORDER BY / column-name position, which cannot be bound. If the sort
column is also user-controlled (see coverage.md R0011), map it through a server-side allowlist of column
names instead.

Secondary: the search query runs as a role with SELECT on every table in the schema. Restrict the application
role to the tables the handler needs, so the same bug class has a smaller blast radius next time.
```

Per-class prompts for writing a useful remediation:

| Class | Say this, specifically |
|---|---|
| SQLi / NoSQLi | which call site, the bound-parameter form, and the allowlist for positions that cannot be bound (identifiers, ORDER BY, LIMIT) |
| Command injection | replace the shell call with an argument-array exec; name the function. Allowlist the value if a shell is unavoidable |
| SSTI | render with a fixed template and pass the value as a variable; do not compile user input as a template. Name the engine's sandbox setting if one exists |
| XXE | disable external entities and DTDs on this parser; give the exact setting for the library in use |
| XSS | context-correct output encoding at the sink named (HTML body / attribute / JS / URL), plus the CSP directive that would have contained it |
| CRLF | reject `\r` and `\n` in the header value at the named call |
| Spreadsheet formula | prefix `=`, `+`, `-`, `@`, tab and CR with `'` on export, or quote the cell |
| Deserialization | do not deserialize untrusted input with this library; the safe format and the allowlist option |
| Source / secret disclosure | remove the artefact, **and rotate the exposed credential** — the removal alone is not a fix |
| Stack trace / debug | turn off debug mode in this environment; name the setting |
| Exposed spec / admin endpoint | authenticate it or remove it; say which |

## References

| Type | Value |
|---|---|
| CWE | CWE-89 SQL Injection |
| OWASP | A03:2021 Injection |
| OWASP testing guide | WSTG-INPV-05 |
| Vendor doc | link to the parameter-binding doc for the library in use |
| CVE | only if this is a known vulnerability in a named component, with the version you observed |

Common ones:

| Class | CWE | OWASP 2021 |
|---|---|---|
| SQL injection | CWE-89 | A03 |
| Command injection | CWE-78 | A03 |
| SSTI | CWE-1336 | A03 |
| XXE | CWE-611 | A05 |
| XSS | CWE-79 | A03 |
| CRLF / header injection | CWE-93 | A03 |
| LDAP injection | CWE-90 | A03 |
| XPath injection | CWE-643 | A03 |
| Formula injection | CWE-1236 | A03 |
| Deserialization | CWE-502 | A08 |
| Source code disclosure | CWE-540 | A01 / A05 |
| Hardcoded / exposed credential | CWE-798 | A07 |
| Stack trace / verbose error | CWE-209 | A05 |
| Sensitive data in response | CWE-200 | A01 |
| Debug feature enabled | CWE-489 | A05 |

## Pre-submit checklist

Every box ticked, or it is not submitted.

- [ ] Reproduced twice, from a clean session, at least a few minutes apart.
- [ ] Reproduction steps followed literally from this file, by re-reading them, not from memory.
- [ ] ROE respected throughout (`CLAUDE.md` 2): no DoS, no writes, no lateral movement, rate limit held.
- [ ] No destructive action taken. Extraction stopped at schema + one proof value.
- [ ] PII and credentials redacted in every excerpt and screenshot.
- [ ] No credential found during testing was used to log in.
- [ ] Host and endpoint confirmed against `scope.md`. Not a third party, not an unlisted origin IP.
- [ ] Class is injection or disclosure. Anything else went to `out-of-scope.md`.
- [ ] Severity not inflated; CVSS vector matches what was actually demonstrated.
- [ ] Impact section says only what was shown; untested claims marked "not tested".
- [ ] Scope-of-exposure numbers have a stated method.
- [ ] Remediation is specific to this sink, not boilerplate.
- [ ] Evidence files exist in `evidence/` and are referenced by name.
- [ ] Ledger row updated to `confirmed` with the evidence ref.
- [ ] Dupe-checked: searched the program's disclosed reports and your own previous submissions for this
      endpoint and parameter.
- [ ] Attribution header present in the traffic if the program asks for it.
- [ ] One finding in this file. Related-but-different sinks are separate files.
