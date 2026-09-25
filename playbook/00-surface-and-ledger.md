# Phase 2 — Surface Map and Coverage Ledger

Goal: a complete list of every place user input enters the app, written to `targets/<target>/coverage.md`
before any probing starts. If the ledger is wrong, everything downstream misses.

## 2.1 Pull what already exists first

Cheapest surface comes free. Do these before crawling.

1. **Burp proxy history** (Burp MCP). The user has already browsed. Ask Burp for:
   - all in-scope hosts
   - all distinct paths
   - all parameters seen (query, body, JSON, cookie, header)
   - all `Content-Type`s used in requests
   - every 3xx/4xx/5xx — errors leak, redirects take URLs
   Read it all before you send a single request of your own.
2. **JS bundles.** Fetch every `.js` the app loads. Extract API paths, parameter names, feature flags,
   role names, internal hostnames. This is where the endpoints the UI never calls live.
3. **Source maps.** For each bundle try `<bundle>.js.map`. If present, you get original source.
4. **API specs.** Try: `/swagger.json` `/swagger/v1/swagger.json` `/openapi.json` `/api-docs` `/v2/api-docs`
   `/api/swagger-ui.html` `/graphql` (introspection) `/.well-known/` `/actuator` `/actuator/mappings`
5. **Archive.** `gau` / `waybackurls` / `katana` for historical URLs and parameters. Old parameters often
   still work and are unpatched.
6. **robots.txt, sitemap.xml, security.txt.** Free path list.

Write the union of all of it into the ledger. Do not filter yet.

## 2.2 Fingerprint the stack

You need this to pick payloads. Do not guess from one signal — collect several.

| Signal | Where |
|---|---|
| Server / X-Powered-By / X-AspNet-Version | response headers |
| Cookie names | `PHPSESSID`=PHP, `JSESSIONID`=Java, `ASP.NET_SessionId`=.NET, `connect.sid`=Express, `csrftoken`+`sessionid`=Django, `_session_id`=Rails, `laravel_session`=Laravel |
| Error page style | Whitelabel Error Page=Spring Boot, Werkzeug=Flask, Django debug page, Rails exception page, PHP warning format |
| URL / extension | `.php` `.aspx` `.jsp` `.do` `.action`=Struts, `.cfm`=ColdFusion |
| Static asset paths | `/_next/`=Next.js, `/static/js/`=CRA, `/wp-content/`=WordPress, `/assets/`=Rails/Vite |
| 404 body fingerprint | distinctive per framework |
| `OPTIONS` / `TRACE` response | allowed methods, sometimes verbose |
| Favicon hash | maps to known products |
| `wafw00f` | WAF product — decides bypass family |

Record in `notes.md`:
```
Stack guess: <lang> / <framework> / <db guess> / <WAF or none>
Confidence: low|medium|high
Signals: <list>
```

Then load the matching payload family from `01-injection.md`. Keep testing the others anyway — stack guesses
are wrong often, and polyglots are cheap.

## 2.3 Input vector catalog — the full list

Walk this list for every endpoint. Agents test 1-4 and stop. Most missed bugs live in 5-14.

1. **URL query parameters** — including ones not in the UI (from JS, archive, `arjun`).
2. **Body parameters** — form-encoded.
3. **JSON body values** — every leaf, including nested objects and array elements.
4. **JSON body keys** — rename a key, add an unexpected key, inject into the key string itself.
5. **Path segments** — `/api/user/123` → inject into `123`, and into `user`. Try extra segments,
   `..`, encoded slashes, `;param=x` matrix params (Java), `.json`/`.xml` suffixes.
6. **Cookies** — values and names. Cookies are frequently unsanitised because devs think they are trusted.
7. **Headers** — `User-Agent`, `Referer`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Original-URL`,
   `X-Rewrite-URL`, `Host`, `Origin`, `Accept-Language`, `Content-Type`, `Authorization` (the token body),
   custom `X-*` headers you saw in JS. Headers land in logs, SQL, templates, and email.
8. **Multipart uploads** — the `filename=`, the field name, the `Content-Type` per part, and the file
   *content* (a CSV with a formula, an SVG with script, an XML with a DTD, a filename with `../`).
9. **XML / SOAP bodies** — element text, attribute values, element names, the DTD, and the encoding declaration.
10. **GraphQL** — variables, field arguments, aliases, directive arguments, operation name, and the query string.
11. **WebSocket / SSE messages** — same matrix as JSON, usually zero server-side validation.
12. **Second-order inputs** — anything stored and rendered later: profile fields, filenames, comments,
    org names, ticket titles. Rendered where? HTML page, CSV export, PDF, XLSX, email, log viewer, admin panel,
    webhook payload, mobile API. Enumerate every render site.
13. **Out-of-band inputs** — email subject/body the app parses, filenames from an S3 upload, values from a
    third-party OAuth profile, webhook bodies the app accepts.
14. **Client-side routing values** — hash fragments and route params that get sent back to an API later.

## 2.4 Build the baseline

Before fuzzing an endpoint, save a normal request/response and record:

```
endpoint: POST /api/search
baseline: 200 | len 1843 | 120ms | hash a91f...
error shape: 400 {"error":"invalid"} | len 31
```

Store in `coverage.md`. Injection detection is diff detection. Without this you will miss:
- a 3-byte length change from a swallowed error
- a 200 that became a 200-with-different-content
- a 40ms timing delta that is a real blind SQLi

## 2.5 Write the ledger

Copy `templates/coverage.md`. One row per (vector, sink type). Fill `untested` everywhere.

### Sink shortlist by shape

`../CLAUDE.md` 6.4. Classify each vector by the *shape* of data it carries, then open those rows. Shape comes
from what the input is, never from its name. An `email` field that carries a short string in a WHERE clause is
shape S1 and gets S1's list.

| Shape | Looks like | Mandatory rows | Card |
|---|---|---|---|
| S1 string in a query, filter, search, sort | `q`, `name`, `email`, `status`, any short text that changes which rows come back | SQLi, NoSQLi | 3.1, 3.2 |
| S2 numeric or opaque id | `id`, `page`, `limit`, `uuid`, `ref` | SQLi (numeric context, no quotes), type confusion (`[]`, object, string↔int) | 3.1 |
| S3 key, field or map name | `labels[].key`, `filter[x]`, `sort=COL`, `fields=`, any user-defined key | SQLi identifier + JSON-path context, NoSQLi | 3.1 high-yield vector, 3.2 |
| S4 URL, host or callback | `url`, `redirect`, `webhook`, `callback`, `image_src`, `import_from` | SSRF, CRLF | 3.11, 3.12 |
| S5 filename, path or template name | `file`, `path`, `template`, `theme`, `locale`, `view`, upload `filename=` | traversal/LFI, command injection (argument injection) | 3.10, 3.3 |
| S6 free text that gets stored and rendered later | bio, comment, ticket title, org name, profile fields | XSS, SSTI, CSV formula, second-order | 3.16, 3.4, 3.17, 3.21 |
| S7 structured blob | XML, SOAP, base64 that decodes to a serialized object, any `Content-Type: */xml` | XXE, deserialization | 3.6, 3.7 |
| S8 header or cookie | `User-Agent`, `Referer`, `X-Forwarded-*`, `Host`, cookie values and names | SQLi, CRLF, log injection, SSTI, Host header | 3.1, 3.12, 3.18, 3.13 |
| S9 anything reflected in the response | your value appears in the body, a header, or the DOM | XSS, SSTI | 3.16, 3.4 |

A vector can be more than one shape. A `?template=` parameter is S5 and S1 — open both lists.

Escalation to the full matrix is not optional. Any anomaly on any row — error, 500, length or status off
baseline, timing delta, WAF block, unexpected reflection — and that vector gets every card, not its shortlist.
Note the trigger in the row so the escalation is auditable.

### Ledger budget

Rough sanity check, not a target. Vectors × shortlist ≈ 3-6 rows per vector, times auth contexts. 60 vectors
and 3 contexts is roughly 600-1000 rows. If your ledger is in the tens of thousands you are matrixing
everything and it will not get finished; if it is under 100 on a real app you have missed surface, go back to
2.3. A ledger nobody can finish gets faked, and a faked ledger is worse than none (`../CLAUDE.md` 3).

Rules:
- A vector is not one row. It is one row per sink type you will try against it.
- Do not delete rows you think are irrelevant. Mark them `tested-negative` with the payload you used.
- `suspicious` rows get worked before you add new surface.
- The ledger is done when no row says `untested`. Report coverage as a count, e.g.
  "142 rows, 138 negative, 3 suspicious, 1 confirmed", not as "finished testing".

## 2.6 Re-enter this phase when

- You find a new endpoint mid-sweep → add rows, do not just test it ad hoc.
- A disclosure finding (source map, swagger, git) hands you new parameters → add rows.
- The app has a second role/tenant you gain access to → the ledger doubles; same vectors, different auth.
