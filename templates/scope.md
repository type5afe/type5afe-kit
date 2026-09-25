# Scope — <TARGET>

Fill before any traffic. If this file is incomplete, **stop and ask the operator** (`CLAUDE.md` 2, 4).
Never infer scope from a domain name.

| Field | Value |
|---|---|
| Program name | |
| Platform | HackerOne / Bugcrowd / Intigriti / YesWeHack / private / direct |
| Policy URL | |
| Policy read on | YYYY-MM-DD |
| Researcher handle | |
| Attribution header | `X-Bug-Bounty: <handle>` — required? yes / no / not stated |
| Rate limit from policy | e.g. 5 req/s (if not stated, use the `CLAUDE.md` defaults) |
| Safe-harbour stated | yes / no |
| Disclosure policy | coordinated / none / requires permission |
| Bounty in scope classes | injection: yes/no, disclosure: yes/no |

## In scope

| Host / asset | Notes |
|---|---|
| `example.com` | apex, web app |
| `*.api.example.com` | wildcard as written in the policy |

Copy the policy's wording. Do not widen a wildcard, do not add a host you merely found.

## Out of scope

| Host / asset / technique | Source |
|---|---|
| `blog.example.com` (WordPress, third-party hosted) | policy |
| `*.cdn.example.com` | policy |
| any host resolving outside the listed assets | policy |
| origin IPs not listed as assets | `playbook/03-bypass-and-blind.md` B.5 — ask before touching |

## Forbidden techniques, from the policy

Quote them. These are in addition to the standing rules in `CLAUDE.md` 2.

- [ ] DoS / stress testing / volumetric
- [ ] Automated scanning (or: allowed at <rate>)
- [ ] Brute force / credential stuffing
- [ ] Social engineering / phishing
- [ ] Physical
- [ ] Testing against other users' accounts
- [ ] Data exfiltration / destruction / modification
- [ ] Spam or mass account creation
- [ ] Other: <quote the policy>

## Test accounts

Operator-provided only. Never register extra accounts unless the policy allows it.

| Ctx | Email / username | Password location | Role / tenant | Notes |
|---|---|---|---|---|
| A1 | | operator-supplied, not stored here | user | |
| A2 | | | admin | |

Do not write credentials into this file. Record where they are held.

## Open questions for the operator

- [ ] 
