# Reference — Implementation Quirks

Behaviour that decides whether a payload can work, and that is recalled **unreliably**. This is the
memorisation-heavy layer: exactly the content not worth trusting to memory.

Numbering is §Q.x. `2.x`, `3.x`, `4.x`, `B.x`, `F.x` belong to the sibling files.

## How this file relates to F.10

`04-false-negatives.md` F.10 is the *protocol* — which one-request check to run. This file is the *reference* —
what the answer means. Run F.10 to learn which behaviour you have, come here to learn what it implies.

Neither replaces the other. A behaviour you did not verify is a guess, and a verified behaviour you cannot
interpret is a wasted request.

## The bar for what is in here

If a capable model produces it unprompted, it is not here. No basic syntax, no payload lists. Only precedence,
defaults that changed between versions, behaviour that differs between the **driver** and the **server**, engines
with near-identical syntax and different semantics, and the cases where the obvious mental model is wrong.

Every row should change what you send or how you read the response. If it does not, it should not be here.

---

## Q.1 Quoting, escaping and comments

| Behaviour | Detail | Why it decides a test |
|---|---|---|
| Backslash escaping | MySQL/MariaDB treat `\` as an escape character in string literals. Postgres does not, in ordinary literals — `standard_conforming_strings` has been `on` by default since 9.1 | A backslash-based payload that works on MySQL does nothing on modern Postgres. A clean result is the wrong-family negative in F.5.1, not a negative |
| Dollar quoting | Postgres `$$text$$` and `$tag$text$tag$` are string literals with no quote character in them | A quote-free string primitive. Survives filters that only look for `'` |
| Versioned comments | MySQL executes the body of `/*!50000 ... */` when the server version is at or above the encoded version, and `/*! ... */` always. Other engines treat both as ordinary comments | Doubles as a fingerprint and as a way to carry text past a filter that strips plain comments |
| `--` needs a terminator | MySQL requires whitespace or a control character after `--` for it to start a comment. Postgres and MSSQL do not | `-- -` is the portable form. A bare `--` failing on MySQL is not evidence about the sink |
| `#` comment | MySQL only | Useful as a positive fingerprint, useless elsewhere |
| Identifier quoting | Postgres/Oracle/SQLite `"col"`. MySQL backtick by default, `"col"` when `ANSI_QUOTES` is set. MSSQL `[col]`, where `]]` is a literal `]` | The identifier-context negative in F.5.4. Only one character is right and the others read as clean |
| String concatenation | Oracle/Postgres/SQLite `\|\|`. MSSQL `+`. MySQL `CONCAT()`, and `\|\|` means logical OR unless `PIPES_AS_CONCAT` is set | The single cheapest engine discriminator. MySQL returning `0` where Postgres returns a joined string tells you the family in one request |
| Expressions need a table | Oracle requires `FROM dual` for a bare expression. Others do not | An Oracle payload written for MySQL fails on syntax, not on the sink |
| Row limiting | MySQL/Postgres/SQLite `LIMIT`. MSSQL `TOP` or `OFFSET/FETCH`. Oracle `ROWNUM`, or `FETCH FIRST n ROWS ONLY` on 12c and later | Matters when the sink is the limit clause itself, which no driver binds — see Q.3 |

## Q.2 Stacked queries — who actually allows them

A rejected second statement is one of the most-misread results in testing. It says something about the driver
and protocol, and usually nothing about whether the sink is injectable (F.5.6).

| Engine | Stacking | Detail |
|---|---|---|
| MySQL / MariaDB | Usually **no** | The common single-statement APIs reject it. Multi-statement support is opt-in at connection or API level, and PDO with emulation can behave differently. *(verify)* |
| PostgreSQL | **Depends on protocol, not the server** | The simple query protocol accepts several statements in one string. The extended protocol — the one used for parameterised queries — does not. So a sink inside a genuinely parameterised statement will refuse stacking even though the injection is real |
| MSSQL | Usually **yes** | The common case where stacking works, which is why MSSQL examples make stacking look normal |
| Oracle | **No** | Not in a single statement. An anonymous `BEGIN ... END;` block is the equivalent, and needs the injection point to tolerate it |
| SQLite | **API-dependent** | The multi-statement entry point allows it; the prepare-one-statement path does not *(verify)* |

The useful inversion: on Postgres, **stacking being refused is weak evidence that the statement is prepared**,
which tells you to go looking for the part of it that could not be bound (Q.3, and F.1.1).

## Q.3 Prepared statements that are not

The class behind the highest-value finding this kit has seen. A parameterised call is not a parameterised
statement.

**What no driver can bind, in any language.** These are structure, not values, so a placeholder is not legal
there and the developer had to build the string:

- table and column names
- `ORDER BY` target and direction
- `LIMIT` / `OFFSET` in several drivers
- JSON and JSONB paths and keys
- an `IN (...)` list built by joining
- `LIKE` pattern metacharacters — escaping for SQL does not escape `%` and `_` (Q.5)

| Stack | The trap |
|---|---|
| PHP PDO | Emulated prepares build the statement client-side, so it is string interpolation with escaping rather than a server-side prepare. Whether emulation is on depends on driver and version, and there is a known interaction with certain multibyte connection charsets that can consume the escape character. Treat as *(verify)* and test the position directly |
| Java JDBC | `Statement` concatenates, `PreparedStatement` binds. Both appear in the same codebase. Spring `@Query(nativeQuery=true)` with string building, and `Sort`/`Pageable` reaching `ORDER BY`, are the usual escapes |
| Python | `cursor.execute(sql, params)` binds; `.format()`, `%`, and f-strings do not. psycopg2 offers `sql.Identifier()` / `sql.SQL()` for safe identifier composition and it is routinely skipped in favour of concatenation |
| Node | Parameterised query APIs exist in every driver and coexist with template literals. ORM escape hatches (`.query()`, raw fragments, `literal()`) are the common sink |
| Go `database/sql` | Placeholder dialect differs by driver: `?` for MySQL and SQLite, `$1` for Postgres drivers, and others use named or `@pN` forms. A dialect-mismatch error in a response is a free driver fingerprint |
| .NET | `SqlCommand` with string concatenation vs `Parameters.Add`. Dapper binds anonymous objects but interpolated SQL inside the call is still concatenated |

**The reading rule.** A bound value adjacent to an unbindable position is *weak evidence for* injection in that
position, not against it. It means the developer reached for a parameterised API and had to concatenate whatever
that API could not bind. F.1.1 is the entry; 3.1's high-yield vector is the payload side.

## Q.4 Type coercion and comparison surprises

| Behaviour | Detail | Why it decides a test |
|---|---|---|
| MySQL string-to-number comparison | Comparing a string to a numeric column coerces the string; a leading-numeric string compares equal to its numeric prefix. Non-strict mode warns, strict mode errors. Strict is the default from 5.7 | Explains an auth or filter bypass that works with no SQL metacharacters at all, and why the same input errors on Postgres |
| Postgres strictness | The same comparison raises an invalid-input error rather than coercing | A Postgres **error** where MySQL is silent is a positive fingerprint, and an error-based channel in F.7 |
| Silent truncation | With strict mode off, over-length values are truncated with a warning instead of rejected | Your payload can be cut mid-statement and the result looks like a clean negative. This is F.3.4 |
| PHP loose comparison | `==` between a string and a number changed in PHP 8: earlier versions coerced the string to a number, PHP 8 compares as strings when the string is not numeric. Also two strings in exponent-zero form compare equal | The version boundary decides whether an auth comparison is bypassable. *(verify the target's major version)* |
| JavaScript coercion | `==` coerces across types, and `[]` / `{}` reaching a query builder become structure rather than a value | The route by which an operator object survives into a document query — and Q.7's body-parser setting decides whether nesting arrives at all |
| Collation and case | Postgres `citext` and case-insensitive collations change what a comparison matches without any code looking case-insensitive | A "unique" lookup can match a value you did not expect |

## Q.5 Unicode, normalisation and case — order of operations

**The only rule that matters: normalisation *after* validation is a bypass. Before validation, it is not.**
Everything below is a way to test which order this target uses.

| Behaviour | Detail | Why it decides a test |
|---|---|---|
| NFKC folding | Compatibility normalisation maps fullwidth and small-form characters to ASCII equivalents — fullwidth apostrophe and parentheses being the useful ones | If only the pre-normalised form passes the filter, validation runs first and you have a bypass. Families in B.3 |
| Locale-sensitive case folding | Case conversion without an explicit locale uses the system default. In Turkish locale, dotted and dotless `i` do not round-trip: uppercasing `i` and lowercasing `I` produce characters outside ASCII | A denylist or allowlist built on a locale-less `toLowerCase()` can be sidestepped, and the same string can compare unequal to itself across two comparisons. Rare, real, and almost never tested |
| MySQL `utf8` is 3-byte | The historical `utf8` charset is `utf8mb3` and cannot store 4-byte characters; `utf8mb4` can | A payload containing a 4-byte character can be truncated or rejected at that character, which looks like the sink ignoring you |
| Overlong UTF-8 | Strict decoders reject non-shortest-form encodings; lenient ones accept and fold them | Where two layers disagree, the front one sees nothing and the back one sees your character |
| Combining characters | A single logical character can be several code points, so a length check counts differently than a human does | Gets a payload past a length cap that looked too small (F.3.4) |
| `LIKE` metacharacters | `%` and `_` are pattern syntax and need escaping *for `LIKE` specifically*, separately from SQL escaping | A correctly-escaped value can still alter which rows match. Low severity on its own, and a clean oracle for inference |

## Q.6 Template engines that look alike

Do not re-derive 3.4's identify table. This section is only the confusions.

| Confusion | The distinction |
|---|---|
| Twig vs Jinja2 | Syntax is near-identical; semantics follow the host language. Twig coerces a numeric string like PHP, Jinja2 repeats it like Python. So multiplying by a numeric string splits them in one request |
| Twig vs Nunjucks | Both yield the PHP-style answer above, because JS coerces the same way. Split them on method access: a native JS string method resolves in Nunjucks and fails in Twig, which uses filter syntax instead |
| Handlebars and Mustache | Logic-less. No infix arithmetic at all. An arithmetic probe can never identify them — use a block helper | 
| Go `text/template` vs `html/template` | Neither evaluates infix arithmetic; both use function calls and pipelines. `html/template` adds contextual auto-escaping, `text/template` adds none. So the same template is safe in one and an injection sink in the other |
| Thymeleaf attribute vs inline | `${...}` inside an attribute, `[[${...}]]` inline and escaped, `[(${...})]` inline and unescaped. The unescaped inline form is the interesting one |
| Freemarker vs Velocity | Both use `${...}` for interpolation and differ in directives — angle-bracket-hash versus plain-hash forms. The interpolation probe cannot tell them apart; the directive probe can |
| Razor vs classic ASP | `@` and `@(...)` versus `<%= %>`. A Razor app does not respond to the classic form at all |
| Smarty versions | `{$var}` interpolation is stable; the inline-PHP facility was deprecated and then removed across major versions, so its absence is not evidence the engine is not Smarty *(verify against the version)* |

## Q.7 Framework defaults that change the answer

| Default | Detail | Why it decides a test |
|---|---|---|
| Spring Boot Actuator | Boot 1.x exposed most management endpoints over HTTP by default. Boot 2.x moved them under an `/actuator` prefix and exposes only health and info by default | Decides whether to probe bare paths or the prefixed set, and whether exposure is a misconfiguration or a default. `02-` F.7 covers the path-by-path point |
| Django `DEBUG` | Debug pages carry settings, installed apps and the traceback. `ALLOWED_HOSTS` is not enforced the same way while debug is on | The difference between an informational error page and a configuration leak |
| Express body parsing | The urlencoded parser has an `extended` flag: extended uses the richer parser that supports nested bracket syntax, non-extended does not. The query parser also has depth and array limits | Decides whether a nested structure — including a pollution vector — can even arrive. A negative on a non-extended endpoint says nothing about a JSON endpoint on the same app |
| Rails strong parameters | Attributes must be permitted explicitly; a blanket permit re-opens everything | Where over-permissive assignment survives in an otherwise strict app |
| PHP request superglobal | Which of GET, POST and cookie wins in the combined superglobal is configuration-controlled | A payload placed in the losing source silently never arrives *(verify)* |
| Werkzeug debug console | Protected by a PIN derived from host-specific values. Presence of the console is a finding on its own | Do not attempt to brute force it. Report the exposure (`../CLAUDE.md` 2, 4) |
| SSR data payloads | Next.js and Nuxt embed the server-rendered props in the HTML document | Fields the UI never renders are still in the response body — the excess-data card in `02-` |

## Q.8 HTTP-layer behaviour

`03-bypass-and-blind.md` B.4 owns parser differentials. Only the quirk-shaped items are here.

| Behaviour | Detail |
|---|---|
| Header name vs value casing | Names are case-insensitive, values are not. A filter that lowercases a whole header line changes the value it was protecting |
| Duplicate headers | Most are defined to combine with a comma; `Set-Cookie` does not. Implementations disagree, and which one your target follows is a one-request test |
| Bare LF as a terminator | Some servers accept a lone `\n` where the spec wants `\r\n`. Where a proxy and an app disagree, that is a differential (B.4) |
| Path normalisation order | Whether normalisation happens before or after routing and authorisation decides whether an encoded traversal reaches the router. Per-framework, and worth testing rather than assuming |

## Q.9 This file goes stale

Versions move, defaults change, and a wrong quirk costs more than a missing one. So:

- Anything marked *(verify)* is not to be used as evidence until you have checked it on the target.
- Anything **not** marked *(verify)* is still a claim about software that changes. If a row decides a ledger
  state, run the F.10 check rather than citing this file.
- Prefer "here is how to test which behaviour I have" over "here is the behaviour". Where this file failed to do
  that, fix it rather than working around it.
- When you learn a behaviour the hard way, add the row here and the false negative it caused to
  `04-false-negatives.md`. Phase 6 in `../CLAUDE.md` 5. A behaviour is only useful attached to the mistake it
  produces.
