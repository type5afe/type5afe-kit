# Phase 1 — Setup and Tools

Read at session start, before `00-surface-and-ledger.md`. Nothing here is a technique; it is what you run and
what keeps the run inside ROE.

Assumption: Kali Linux with the standard offensive toolchain already installed. Install lines are given only
for what Kali does not ship. If a tool is missing, see 1.6 — you ask, you do not substitute.

Every rate and thread number below comes from `CLAUDE.md` 2: 5 req/s ceiling, one concurrent wordlist job,
1 req/s after any 429/503. If `targets/<target>/scope.md` sets a lower limit, that wins.

## 1.1 Session start checklist

Work top to bottom. Do not send a probe until every line is done.

| # | Check | How | If it fails |
|---|---|---|---|
| 1 | Burp is running and the proxy is up | ask Burp MCP for proxy history for any host | start Burp, or ask the operator to |
| 2 | Burp MCP is reachable from this session | one read-only MCP call that returns data | stop and ask (`CLAUDE.md` 4) |
| 3 | `targets/<target>/scope.md` exists and is filled | read it | **stop and ask the operator for scope + policy.** Never guess (`CLAUDE.md` 2) |
| 4 | Researcher handle and attribution header known | from `scope.md` | ask once, write it to `scope.md` |
| 5 | Rate limit decided and written down | from `scope.md`, else the `CLAUDE.md` defaults | use the defaults |
| 6 | Target dir created from templates | `mkdir -p` + copy, see below | — |
| 7 | OOB listener up, domain recorded | `interactsh-client`, see below | no blind testing is valid without it (`CLAUDE.md` 8) |
| 8 | Out-of-scope note file exists | `targets/<target>/out-of-scope.md` | create empty |
| 9 | Stack guess recorded (after phase 2) | `notes.md` per `00-surface-and-ledger.md` 2.2 | — |

```bash
# 6 — target dir from templates
T=TARGET
mkdir -p "/root/pentest/targets/$T/evidence" "/root/pentest/targets/$T/findings"
cp /root/pentest/templates/scope.md    "/root/pentest/targets/$T/scope.md"
cp /root/pentest/templates/notes.md    "/root/pentest/targets/$T/notes.md"
cp /root/pentest/templates/coverage.md "/root/pentest/targets/$T/coverage.md"
: > "/root/pentest/targets/$T/out-of-scope.md"

# 7 — OOB listener, logged so a late callback is still evidence
interactsh-client -json -o "/root/pentest/targets/$T/evidence/oob.log"
# record the assigned domain in notes.md immediately; canary scheme in playbook/03-bypass-and-blind.md B.7
```

## 1.2 Burp MCP usage patterns

`CLAUDE.md` 8 and `00-surface-and-ledger.md` 2.1: **the operator's proxy history is read before you crawl.**
It is a better surface map than any crawler, it costs the target zero requests, and it is already authenticated.

Ask Burp for, in this order:

| Ask | Why | Feeds |
|---|---|---|
| Proxy history, all in-scope hosts | the real host list, including ones not in DNS | `scope.md`, ledger |
| Proxy history filtered by host | per-host path list | ledger rows |
| Distinct paths + methods | endpoint inventory | ledger rows |
| All parameters seen — query, body, JSON, cookie, header | the vector list; this is the anti-miss payload | one ledger row per (vector, sink) |
| All request `Content-Type`s used | tells you which body parsers exist → parser differentials | `03-bypass-and-blind.md` B.4 |
| Every response 3xx | redirect targets, open-redirect-shaped params, new hosts | ledger |
| Every response 4xx/5xx | error shapes, stack traces, framework fingerprints | `02-info-disclosure.md`, baseline error shape |
| Sitemap for a host | structure the crawler would miss | ledger |
| A specific request by URL/id | exact bytes to reproduce or to paste into a finding | `templates/finding.md` |
| Repeat a request with one field changed | single precise probe without leaving the tool | ledger evidence |
| Scanner findings, if the operator ran a scan | leads only | `suspicious` rows, never `confirmed` |

Discipline:

- A Burp scanner hit is `suspicious` until reproduced by hand (`CLAUDE.md` 8). Reproduce with `curl` so the
  finding has copy-pasteable proof.
- Never re-request something already in history. Read it from Burp (3.6 request budget in
  `03-bypass-and-blind.md`).
- Save the raw request and response of anything interesting to `targets/<target>/evidence/` as you go, named
  `<finding-slug>-<n>.txt`.
- Proxy your own tool traffic through Burp where the tool supports it (`-x`, `--proxy`, `HTTP_PROXY`). Then
  the history is complete and every probe is reproducible.
- Do not use Burp's active scanner to "just check" an endpoint. It ignores your rate limit and it sends
  payloads you have not read.

## 1.3 Tool to job

One canonical invocation each, already carrying safe flags. `TARGET`, `HANDLE`, `URL` are placeholders.

### Discovery and surface

**ffuf** — content and parameter discovery.

- Good for: directories, files, extensions, vhosts, parameter names, value fuzzing with a baseline filter.
- Bad for: anything needing a stateful session or a JSON body shape it cannot template. Not evidence on its own.

```bash
ffuf -u 'https://TARGET/FUZZ' \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -H 'X-Bug-Bounty: HANDLE' -H 'User-Agent: HANDLE-bugbounty' \
  -rate 5 -t 5 -p 0.1 -timeout 10 \
  -mc all -fc 404 -ac \
  -o /root/pentest/targets/TARGET/evidence/ffuf-dirs.json -of json
```

`-rate 5` is the ROE ceiling, `-t 5` caps threads, `-p 0.1` adds delay, `-ac` auto-calibrates against the
soft-404 baseline. RISK: `-rate 0` (unlimited) and large `-t` are a DoS. Never.

**httpx** — probe a host list, get status/title/tech.

```bash
httpx -l hosts.txt -rl 5 -threads 5 -timeout 10 -retries 1 \
  -H 'X-Bug-Bounty: HANDLE' -sc -cl -title -tech-detect -server -location \
  -json -o /root/pentest/targets/TARGET/evidence/httpx.json
```

- Good for: turning a host list into a live, fingerprinted list. Feeds `00-surface-and-ledger.md` 2.2.
- Bad for: finding content. It probes roots.

**katana** — crawler, including JS-aware.

```bash
katana -u 'https://TARGET' -rl 5 -c 5 -d 3 -jc -kf all -aff \
  -H 'X-Bug-Bounty: HANDLE' -timeout 10 \
  -o /root/pentest/targets/TARGET/evidence/katana.txt
```

- Good for: paths and params the UI reaches, plus endpoints inside JS (`-jc`).
- Bad for: authenticated flows without a cookie (`-H 'Cookie: ...'`), and anything behind a form submit.
- RISK: a crawler will submit forms if you let it. Do not enable form filling on a live app — it writes data.

**gau** — passive URL history. No traffic to the target at all.

```bash
gau --threads 2 --subs TARGET --blacklist png,jpg,jpeg,gif,svg,woff,woff2,ttf,css \
  > /root/pentest/targets/TARGET/evidence/gau.txt
```

- Good for: dead parameters that still work, old endpoints, forgotten hosts.
- Bad for: current state. Every URL is a hypothesis; confirm with `httpx`.
- Note: output includes hosts that may be out of scope. Filter against `scope.md` before probing anything.

**arjun** — hidden parameter discovery.

```bash
arjun -u 'https://TARGET/api/search' -m GET -t 5 -d 0.2 --stable \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -oJ /root/pentest/targets/TARGET/evidence/arjun-search.json
```

- Good for: parameters nothing references. Direct input to ledger rows.
- Bad for: JSON-body-only endpoints and anything with strict CSRF. Run `-m POST`/`-m JSON` separately.
- `--stable` costs requests but kills false positives. Use it.

### Injection

**sqlmap** — SQL injection confirmation and bounded extraction.

```bash
sqlmap -u 'https://TARGET/api/search?q=test' \
  --batch --level 2 --risk 1 \
  --delay 0.2 --threads 1 --timeout 15 --retries 1 \
  --technique=BEUS \
  --time-sec 3 \
  --headers='X-Bug-Bounty: HANDLE' \
  --proxy='http://127.0.0.1:8080' \
  --output-dir=/root/pentest/targets/TARGET/evidence/sqlmap
```

`--level` and `--risk`, plainly:

| Setting | What it adds | Use |
|---|---|---|
| `--level 1` | query/body params only | first pass |
| `--level 2` | + cookies | when cookies are a ledger vector |
| `--level 3` | + `User-Agent`, `Referer` | header vectors (`00-surface-and-ledger.md` 2.3 item 7) |
| `--level 4-5` | huge payload set, very noisy | only if the operator approves; it will trip WAFs and rate limits |
| `--risk 1` | safe payloads | default, and usually enough |
| `--risk 2` | + heavy time-based queries | only after boolean fails, and it conflicts with the 3-probe limit — prefer manual probes from `03-bypass-and-blind.md` B.8 |
| `--risk 3` | + `OR`-based payloads that can match every row, and `UPDATE`-shaped tests | **never.** An `OR`-based test against an UPDATE statement modifies data. Forbidden by `CLAUDE.md` 2 |

`--technique=BEUS` = boolean, error, union, stacked-detection. Drop `S` if stacked queries could reach a
write. Drop `T` (time) unless nothing else works, and then cap `--time-sec 3`.

RISK — flags that break ROE, never use: `--os-shell`, `--os-pwn`, `--os-cmd`, `--file-write`, `--file-dest`,
`--sql-shell` for anything but `SELECT`, `--dump-all`, `--all`, `--exclude-sysdbs=false` sweeps, `--dbms-cred`
brute forcing, `--crawl` with `--forms` (submits data), `--eval` with side effects, `--tamper` chains you have
not read. Extraction stops at `--banner --current-db --current-user --dbs --tables --columns`, plus at most
`--dump -T <table> -C <col> --start 1 --stop 1` for a single proof value (`03-bypass-and-blind.md` B.9).

Always: reproduce the sqlmap finding with one hand-built `curl` before it is `confirmed`.

**nuclei** — templated checks. Injection and disclosure templates only, per `CLAUDE.md` 1.

```bash
nuclei -u 'https://TARGET' \
  -t /root/nuclei-templates/http/vulnerabilities/ \
  -t /root/nuclei-templates/http/exposures/ \
  -t /root/nuclei-templates/http/misconfiguration/ \
  -etags dos,fuzz,intrusive,brute-force,default-login \
  -severity low,medium,high,critical \
  -rl 5 -c 5 -timeout 10 -retries 1 \
  -H 'X-Bug-Bounty: HANDLE' \
  -je /root/pentest/targets/TARGET/evidence/nuclei.json
```

- Good for: known CVEs on a fingerprinted stack, exposed files, source maps, git dirs, swagger, debug endpoints.
- Bad for: anything app-specific. It will not find your target's own SQLi.
- RISK: `-etags dos,fuzz,intrusive` is mandatory. The DoS templates crash things; the fuzzing templates ignore
  your rate limit. Never run `-t /root/nuclei-templates/` wholesale, and never `-as` (automatic scan) without
  reading what it selected.
- Findings are `suspicious` until reproduced by hand.

**dalfox** — XSS (as an injection sink).

```bash
dalfox url 'https://TARGET/api/search?q=test' \
  --delay 200 --worker 5 --timeout 10 \
  --header 'X-Bug-Bounty: HANDLE' \
  --proxy 'http://127.0.0.1:8080' \
  --skip-bav --report --output /root/pentest/targets/TARGET/evidence/dalfox-search.txt
```

- Good for: reflected/DOM XSS with parameter mining and context detection.
- Bad for: stored/blind XSS. For those, plant a canary and use `03-bypass-and-blind.md` B.7 plus the
  render-site table in `templates/coverage.md`.
- `--skip-bav` skips the "basic another vulnerability" probes so you stay inside the two in-scope classes.
- Blind XSS mode: `-b https://<canary>.<oast-domain>` with a canary label from 3.7.

**commix** — command injection.

```bash
commix -u 'https://TARGET/api/ping?host=127.0.0.1' \
  --batch --level 1 --technique=c --time-sec 3 \
  --delay 0.2 --timeout 15 \
  --proxy='127.0.0.1:8080' \
  --output-dir=/root/pentest/targets/TARGET/evidence/commix
```

- Good for: finding the injection and the separator that works.
- RISK — never use: `--os-cmd` with anything beyond `id`/`whoami`/`hostname`, `--file-write`, `--file-upload`,
  `--os-pwn`, any shell/meterpreter option. Proof stops at `id` (`CLAUDE.md` 2).
- Prefer the DNS canary payloads in `03-bypass-and-blind.md` B.7 for blind cases — cleaner evidence, less noise.

**tplmap** — SSTI.

```bash
tplmap -u 'https://TARGET/render?name=test' --level 1 --technique=R
```

- Good for: identifying the template engine and confirming evaluation.
- Bad for: modern sandboxed engines and Node template libs. Hand payloads from `01-injection.md` and
  `03-bypass-and-blind.md` B.7 cover more.
- RISK — never use: `--os-shell`, `--os-cmd` beyond `id`, `--upload`, `--download`, `--reverse-shell`,
  `--bind-shell`. `--technique=R` keeps it to rendering, not code execution.

**crlfuzz** — CRLF injection (header injection sink).

```bash
crlfuzz -u 'https://TARGET/redirect?url=test' -c 1 -s \
  -H 'X-Bug-Bounty: HANDLE' -x http://127.0.0.1:8080 \
  -o /root/pentest/targets/TARGET/evidence/crlfuzz.txt
```

- Good for: `%0d%0a` in redirect/location params, which hands you response splitting and cookie injection.
- Bad for: rate limiting — it has no rate flag, so use `-c 1` and feed it one URL at a time, never a list.

### Disclosure

**trufflehog** — secrets in code, bundles, and git history.

```bash
# on files you have already downloaded (JS bundles, source maps, git-dumper output)
trufflehog filesystem /root/pentest/targets/TARGET/evidence/js/ \
  --no-verification --json > /root/pentest/targets/TARGET/evidence/trufflehog.json
```

- Good for: high-confidence secret detection with typed detectors.
- Bad for: context. It will not tell you whether a key is live or a placeholder.
- RISK: **`--no-verification` is mandatory by default.** Verification sends the found credential to the
  third-party API that issued it. That is traffic to a third party (`CLAUDE.md` 2, no third parties) and it
  uses a credential you found (`CLAUDE.md` 2, keep it yours). Report the secret; do not test it. If the
  program explicitly asks for proof of validity, ask the operator first.

**jsluice** — extract URLs, params, and secrets from JavaScript.

```bash
# URLs and parameters -> ledger rows
cat /root/pentest/targets/TARGET/evidence/js/*.js | jsluice urls \
  > /root/pentest/targets/TARGET/evidence/jsluice-urls.json
# secret-shaped strings
cat /root/pentest/targets/TARGET/evidence/js/*.js | jsluice secrets \
  > /root/pentest/targets/TARGET/evidence/jsluice-secrets.json
```

- Good for: parameter names and API paths no crawler sees. Best single source for ledger rows from bundles.
- Bad for: minified dynamic construction. Read the bundle by hand around every hit.
- Runs offline on files you already fetched. Zero target traffic.

**git-dumper** — reconstruct an exposed `.git`.

```bash
git-dumper 'https://TARGET/.git/' /root/pentest/targets/TARGET/evidence/gitdump \
  --jobs 2 --retry 1 --timeout 10 \
  --header 'X-Bug-Bounty: HANDLE'
```

- Good for: full source from an exposed repo. Usually the highest-value disclosure finding there is.
- RISK: it makes many requests. `--jobs 2` keeps it inside ROE; the default parallelism does not. Confirm
  `/.git/HEAD` returns a real file by hand first — do not point it at a 404 and generate hundreds of requests.
- After dumping: `trufflehog filesystem <dir>` and read the log for internal hostnames and endpoints. New
  surface goes back into the ledger (`00-surface-and-ledger.md` 2.6).

**graphql-cop** — GraphQL misconfiguration audit.

```bash
graphql-cop -t 'https://TARGET/graphql' -o json \
  > /root/pentest/targets/TARGET/evidence/graphql-cop.json
```

- Good for: introspection enabled, field suggestions, GET-based queries, verbose errors — all disclosure.
- RISK: it includes denial-of-service checks (alias overloading, array-based batching, field duplication,
  circular query depth). Those are DoS and forbidden by `CLAUDE.md` 2. Read the output for the disclosure
  results and **do not re-run or amplify the DoS checks.** If the tool version cannot skip them, run
  introspection by hand instead:

```bash
curl -s -X POST 'https://TARGET/graphql' -H 'Content-Type: application/json' \
  -H 'X-Bug-Bounty: HANDLE' \
  --data '{"query":"{__schema{types{name fields{name}}}}"}'
```

**wpscan** — WordPress enumeration.

```bash
wpscan --url 'https://TARGET' \
  --enumerate vp,vt,tt,cb,dbe \
  --plugins-detection passive \
  --throttle 200 --max-threads 2 --request-timeout 15 \
  --user-agent 'HANDLE-bugbounty' \
  --api-token 'WPSCAN_TOKEN' \
  -o /root/pentest/targets/TARGET/evidence/wpscan.txt
```

- Good for: vulnerable plugin/theme versions, exposed backups (`dbe`), config leftovers, user enumeration.
- `--plugins-detection passive` avoids hammering paths. `aggressive` is hundreds of requests — only with
  operator approval and a slower `--throttle`.
- RISK — never use: `--passwords` / `--usernames` password attacks (brute force, forbidden), and do not enumerate
  users to then log in (`CLAUDE.md` 2, keep it yours).

### Support

**interactsh-client** — OOB listener. Setup in 1.1, payloads and canary scheme in
`03-bypass-and-blind.md` B.7.

```bash
interactsh-client -json -o /root/pentest/targets/TARGET/evidence/oob.log
```

Leave it running for the whole session. A callback can arrive hours after the request that caused it.

**wafw00f** — identify the WAF product, which picks your bypass family.

```bash
wafw00f -a 'https://TARGET' -o /root/pentest/targets/TARGET/evidence/wafw00f.txt
```

- Good for: naming the product so you can go straight to the right row of `03-bypass-and-blind.md` B.5.
- RISK: it works by sending obviously malicious probes. It will show up in the target's logs and may get you
  a short block. Run it once, early, and note the result. Do not re-run it to "check".
- `-a` tests all known WAFs (more requests but one pass). Also read the block page yourself — the manual
  fingerprints in 3.2 and 3.5 are often more accurate.

**jwt_tool** — inspect and test JWTs.

```bash
# offline: decode and list issues. No target traffic.
jwt_tool 'eyJ...' -T
# offline: check for known weaknesses in the token itself
jwt_tool 'eyJ...' -M pb    # playbook scan, requires -t for the live checks
```

- Good for: reading claims (they leak internal IDs, roles, tenant names, emails — disclosure), spotting `alg`
  confusion, and finding claim fields that reach a sink (a `sub` or `name` claim that lands in SQL or a
  template is a ledger row).
- In scope framing: JWT signature bypass on its own is auth bypass — out of scope per `CLAUDE.md` 1, one line
  in `out-of-scope.md`. It is in scope only as a delivery mechanism for an injection or disclosure bug, and
  then the finding is written as that bug.
- RISK: `-C -d <wordlist>` cracks the signing key. Local CPU only, no target traffic, so it is permitted — but
  do not use a cracked key to forge a token and log in as another user. That is lateral movement
  (`CLAUDE.md` 2). Stop at the key, report it as a disclosure.

## 1.4 Safe-flag cheatsheet

Flags that keep you inside ROE:

| Flag | Tool | Reason |
|---|---|---|
| `-rate 5` / `-rl 5` / `--throttle 200` / `--delay 0.2` | ffuf, httpx, katana, nuclei, wpscan, sqlmap, commix | the 5 req/s ceiling |
| `-t 5` / `-c 5` / `--threads 1` / `--max-threads 2` / `--jobs 2` | all | one concurrent job, no thread storms |
| `-timeout 10` + `-retries 1` | all | a hung target is not retried into the ground |
| `-mc all -fc 404 -ac` | ffuf | baseline calibration, so soft 404s do not become 900 false rows |
| `--batch` | sqlmap, commix | no interactive prompt silently picking an aggressive option |
| `--level 1-2 --risk 1` | sqlmap | safe payload set only |
| `--technique=BEUS` | sqlmap | no time-based unless you chose it |
| `--time-sec 3` | sqlmap, commix | under the 5s DoS line |
| `-etags dos,fuzz,intrusive` | nuclei | excludes the templates that break things |
| `--no-verification` | trufflehog | does not send found secrets to third parties |
| `--plugins-detection passive` | wpscan | avoids hundreds of path probes |
| `--skip-bav` | dalfox | stays inside the two in-scope classes |
| `--technique=R` | tplmap | render detection, not code execution |
| `-H 'X-Bug-Bounty: HANDLE'` | all | the program can identify you instead of banning you |
| `--proxy http://127.0.0.1:8080` | all | every probe lands in Burp and is reproducible |
| `-o <file>` in `evidence/` | all | evidence saved as you go (`CLAUDE.md` 8) |

Flags to never use:

| Flag | Tool | Why not |
|---|---|---|
| `--os-shell`, `--os-pwn`, `--os-cmd` beyond `id` | sqlmap, commix, tplmap | RCE past proof. `CLAUDE.md` 2 |
| `--file-write`, `--file-dest`, `--upload`, `INTO OUTFILE` | sqlmap, commix, tplmap | writes to the target |
| `--dump-all`, `--all` | sqlmap | mass data extraction. Schema only |
| `--risk 3` | sqlmap | `OR`-based tests can modify rows |
| `--reverse-shell`, `--bind-shell` | commix, tplmap | lateral movement |
| `--passwords`, `--usernames`, any `-d <wordlist>` against a login | wpscan, hydra-likes | brute force |
| `-rate 0`, `-t 200`, unbounded `--threads` | any | DoS |
| `-t /root/nuclei-templates/` with no exclusions, `-as` | nuclei | pulls in DoS and fuzzing templates |
| `--crawl` with `--forms`, crawler form submission | sqlmap, katana | submits data into the app |
| Verification of found secrets | trufflehog | third-party traffic with someone's credential |
| `-i`/`--interactive` anything | any | an unread prompt default is how ROE gets broken |
| Any tool pointed at a host not in `scope.md` | any | `CLAUDE.md` 2, no third parties |

## 1.5 Wordlists

Kali paths. Verify once per box with `ls`; seclists reorganises between versions, and a wrong path is a silent
zero-result run.

| Job | Path |
|---|---|
| SQLi, quick | `/usr/share/seclists/Fuzzing/SQLi/quick-SQLi.txt` |
| SQLi, generic | `/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt` |
| SQLi, blind | `/usr/share/seclists/Fuzzing/SQLi/Generic-BlindSQLi.fuzzdb.txt` |
| SQLi, per-DBMS | `/usr/share/seclists/Fuzzing/Databases/` |
| XSS | `/usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt`, `/usr/share/seclists/Fuzzing/XSS/XSS-Somdev.txt` |
| XSS polyglots | `/usr/share/seclists/Fuzzing/XSS/XSS-Bypass-Strings-BruteLogic.txt` |
| SSTI | `/usr/share/seclists/Fuzzing/template-engines-expression.txt`, `/usr/share/seclists/Fuzzing/template-engines-special-vars.txt` |
| Command injection | `/usr/share/seclists/Fuzzing/command-injection-commix.txt` |
| LFI, mixed | `/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt` |
| LFI, Linux | `/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt` |
| LFI, Windows | `/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt` |
| XXE | `/usr/share/seclists/Fuzzing/XXE-Fuzzing.txt` |
| Special chars / breakers | `/usr/share/seclists/Fuzzing/special-chars.txt`, `/usr/share/seclists/Fuzzing/big-list-of-naughty-strings.txt` |
| Unicode / normalisation | `/usr/share/seclists/Fuzzing/alphanum-case-extra.txt` (build the rest from `03-bypass-and-blind.md` B.3) |
| Parameter names | `/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt` |
| Header names | `/usr/share/seclists/Discovery/Web-Content/BurpSuite-ParamMiner/lowercase-headers` |
| API endpoints | `/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt`, `.../api/objects.txt`, `.../api/actions-lowercase.txt` |
| Directories, small | `/usr/share/seclists/Discovery/Web-Content/common.txt` |
| Directories, medium | `/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt` |
| Files | `/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt` |
| Quick disclosure hits | `/usr/share/seclists/Discovery/Web-Content/quickhits.txt` |
| Backup / DB dumps | `/usr/share/seclists/Discovery/Web-Content/Common-DB-Backups.txt` |
| Backup extensions | `/usr/share/seclists/Discovery/Web-Content/web-extensions.txt`, `/usr/share/seclists/Discovery/Web-Content/raft-medium-extensions.txt` |
| Config / env files | `/usr/share/seclists/Discovery/Web-Content/Common-PHP-Filenames.txt`, `/usr/share/seclists/Discovery/Web-Content/quickhits.txt` |
| Vhosts / subdomains | `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt` |

Secret regexes: seclists coverage here is thin and moves around. Use the built-in detectors instead —
`trufflehog` (typed, verified-off) and `jsluice secrets` — plus `nuclei` `http/exposures/tokens/`. If you need
a regex list on disk, check `/usr/share/seclists/Miscellaneous/` and `/usr/share/nuclei-templates/http/exposures/`
and read what you find before trusting it.

Wordlist discipline: one concurrent job (`CLAUDE.md` 2). Start with the small list; only escalate to a bigger
one if the small one found structure. A `raft-large` run on a rate-limited target is hours of traffic and will
read as an attack.

## 1.6 Not installed

`CLAUDE.md` 4: **ask the operator to install it. Do not hand-roll a worse substitute.**

Concretely, if a tool is missing:

1. Stop that line of work. Do not start it with a different tool.
2. One or two lines to the operator: which tool, what for, the install command.
3. Move to another ledger row while you wait. Leave the blocked row `untested` and write the reason in the
   `blocked / need operator` section at the top of `notes.md`.

What not to do, with the reason:

| Missing | Do not substitute with | Why |
|---|---|---|
| sqlmap | hand-rolled loop of 40 payloads | you will miss techniques and generate more traffic |
| interactsh / Collaborator | "it did not reflect, so it is negative" | violates `CLAUDE.md` 8 |
| trufflehog | ad-hoc `grep` for `key=` | misses typed secrets, floods you with false positives |
| jsluice | `grep -o 'http[^"]*'` | loses parameter names, the actual product |
| Burp / Burp MCP | a crawler | the operator's history is the surface map (`00-surface-and-ledger.md` 2.1) |
| wafw00f | guessing from one block page | wrong WAF means the wrong bypass family for hours (3.5) |
| git-dumper | fetching `.git` files by hand | hundreds of unstructured requests |

Install lines, for the few things Kali may not ship:

```bash
# ProjectDiscovery tools, if a newer version is needed than the packaged one
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest
go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest
pipx install arjun
pipx install graphql-cop
pipx install git-dumper
nuclei -update-templates
```

Run installs only after the operator says yes.
