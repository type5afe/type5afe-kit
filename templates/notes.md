# Notes — <TARGET>

Running log. One line per action, newest at the bottom of each day. Plain language: what you did, what you
saw. Not a place for analysis — findings go to `findings/`, states go to `coverage.md`.

## Blocked / need operator

Pinned. Anything here stops a line of work. Clear a line only when it is resolved.

| Date | Blocked on | What is needed | Ledger rows affected |
|---|---|---|---|
| | | | |

Put a line here rather than improvising a workaround (`CLAUDE.md` 4): missing tool, expired session, MFA,
CAPTCHA, WAF block you cannot pass inside ROE, unclear scope, need for a second account or role, repeated 5xx,
anything that looks like real user data.

## Working facts

Short, stable things worth not re-deriving.

```
stack guess:    <lang> / <framework> / <db> / <WAF>       confidence: low|medium|high
signals:        <list, per playbook/00-surface-and-ledger.md 2.2>
OOB domain:     cXXXXXXXX.oast.pro
working bypass: <the one that gets past this target's filter, per 03-bypass-and-blind.md B.10>
rate in use:    <req/s>
```

## Log

### YYYY-MM-DD

```
09:40  read scope.md, policy confirms 5 req/s and requires X-Bug-Bounty header
09:45  interactsh up, domain cXXXXXXXX.oast.pro, logging to evidence/oob.log
09:50  pulled Burp proxy history: 4 hosts, 61 paths, 38 distinct params
10:20  fetched 9 JS bundles, jsluice gives 22 API paths not in proxy history
10:35  wafw00f: Cloudflare. block page fingerprint saved to evidence/waf-block-1.txt
11:05  ledger built: 142 rows across 31 endpoints, all untested
11:30  baselines recorded for 12 endpoints
13:10  R0001 /api/search q: boolean differential, len 1843 vs 1791. reproduced by hand. confirmed
14:00  R0003 same param, cmd injection: 403 every variant, edge block. suspicious, bypass log in the row
15:20  asked operator about origin IP 203.0.113.x -> blocked line added above
```
