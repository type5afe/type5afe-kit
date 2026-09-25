# Phase 4 — Information Disclosure

Driven by the ledger in `../targets/<target>/coverage.md`, not by curiosity. Every host, path and parameter in
the ledger gets a disclosure pass the same way it gets an injection pass. Rules of engagement, stop-and-ask
triggers and rate limits are in `../CLAUDE.md` — they are not repeated here. Surface enumeration and stack
fingerprinting are in `00-surface-and-ledger.md`. Payload families and sinks are in `01-injection.md`.
WAF bypass, parser differentials and out-of-band channels are in `03-bypass-and-blind.md`.

Most disclosure reports are closed as informational. That is correct behaviour by the program, not bad luck.
This file exists to say which ones are worth writing up, and what turns the rest into real findings.

## 4.1 Payability triage — read this before you report anything

The verdict column is the *typical* outcome on a mature program with no escalation.

| Disclosure | Typical verdict | Payable when |
|---|---|---|
| Verbose stack trace | Informational | It leaks credentials, an internal hostname you can reach, a framework signing key, or a full file path that makes an LFI/traversal exploitable |
| `Server:` / `X-Powered-By` version banner | Informational, often N/A | The version maps to a confirmed unauthenticated RCE or auth bypass (confirm it exists, do not exploit) |
| Directory listing of static assets | Informational | The listing reveals a backup, source, dump or config file you then fetch |
| `.git/` exposed | Medium–High | Source recovers; credentials or internal endpoints in history; escalates into further in-scope bugs |
| `.env` / `appsettings.json` / `application.properties` exposed | High–Critical | It contains live secrets for an in-scope asset. Severity tracks the secret, not the file |
| Source map (`.js.map`) | Low–Informational | Recovered source yields a hardcoded secret, an unreferenced privileged endpoint, or logic you then break |
| Swagger / OpenAPI exposed | Informational | It documents privileged endpoints that are actually reachable |
| GraphQL introspection on | Informational | The schema exposes mutations or PII fields reachable without authorisation |
| Actuator `/env`, `/configprops` | Medium | An unmasked secret value, or internal service URLs you can reach |
| Actuator `/heapdump` | High–Critical | Almost always: live session tokens, credentials, decrypted config, in-flight request bodies |
| `phpinfo()` | Low | Absolute paths that enable another bug, or `$_ENV` secrets |
| `.DS_Store` / `Thumbs.db` | Informational | A recovered filename leads to a real unlisted file |
| Backup file (`.bak`, `.zip`, `.sql`) | Medium–Critical | It contains source, credentials, or database contents |
| Extra fields in an API response | Low → **Critical** | Password hash, MFA secret, reset token, another user's PII, another tenant's data |
| User / account enumeration | Informational, usually N/A | Membership itself is sensitive, or the oracle returns an arbitrary account's email or phone |
| CORS reflected origin + credentials | Medium–High | You can read authenticated response data cross-origin with a working PoC |
| Web cache deception | Medium–High | An authenticated response with user data is served from cache to an unauthenticated request |
| EXIF GPS in served uploads | Low–Medium | Other users' photos leak precise location on a platform that implies privacy |
| Token in a URL leaked via `Referer` | Medium | The token is a session, reset or invite token, and it reaches a third party you can name |
| Internal IP / hostname in a header | Informational, often N/A | The host is reachable from your position, or it is the origin behind the WAF |
| Timing delta | Informational | It is a reliable existence oracle with an impact story, or a comparison leak in token validation |
| Error text usable as an extraction channel | Informational alone | It becomes the exfil channel for a blind injection — then it is part of that injection report (§4.20) |
| Secret found on GitHub / paste / SaaS board | Varies by policy | The secret is live and grants access to an in-scope asset. Scope caution in §4.18 |

Two rules from `../CLAUDE.md` dominate this whole file:

- **Never use a credential you found.** Logging in to validate it is the boundary. Report it instead.
- **Real user data: stop reading and report.** One redacted record is evidence. Ten is hoarding.

## 4.2 Ledger wiring

Disclosure rows use the same ledger and the same states (`untested` / `tested-negative` / `suspicious` /
`confirmed`), with the exact columns from `../templates/coverage.md`. The `Sink type` column takes the card
number from this file; `Payload used` takes the literal path or probe you sent.

| ID | Endpoint | Method | Vector (type + name) | Auth ctx | Sink type | State | Payload used | Evidence ref | Notes |
|---|---|---|---|---|---|---|---|---|---|
| R0121 | `/` | GET | host root `app.target.com` | A0 | 4.4 vcs-config | `tested-negative` | `GET /.git/HEAD`, `/.git/config`, `/.env` | `evidence/git-probe-1.txt` | All 404 / len 1143 = SPA catch-all. Verified against `/.git/HEADzzz` → same 1143, so the 404 is generic, not a real file check |
| R0122 | `/static/js/main.4f2a.js` | GET | bundle path | A0 | 4.6 source-maps | `confirmed` | `GET /static/js/main.4f2a.js.map` | `evidence/sourcemap-1.txt` | 200 / 1.2MB / `sourcesContent` present. 41 original files recovered. Feeds new rows per `00-surface-and-ledger.md` §2.6. Finding `findings/sourcemap-exposure.md` |
| R0123 | `/api/v2/users/{id}` | GET | json response body | A1 | 4.11 excess-response-fields | `suspicious` | baseline GET, own user id | `evidence/excess-fields-1.txt` | Response carries `password_reset_token` and `internal_notes`; UI renders neither. Need A3 (second tenant) to show cross-user reach before this is payable — operator action |
| R0124 | `/actuator` | GET | host root | A0 | 4.8 debug-endpoints | `untested` | — | — | Spring Boot confirmed from `Whitelabel` 404. Probe the §4.8 path list, heapdump last and only if small |

Note on `R0121`: the negative is only trustworthy because of the control request. A 404 with the same length
for `/.git/HEADzzz` proves the server answers everything that way. Without that control, the row is `untested`.

Two things make disclosure rows different from injection rows:

0. Disclosure negatives are the easiest in the kit to get wrong, because a 404 or a 200 can both be generic.
   `04-false-negatives.md` F.7 is the disclosure-specific trap list, and F.9 is the checklist to run before
   writing `tested-negative`.
1. A negative needs the exact path, the status **and the length**. A 200 that is the SPA's `index.html` is a
   negative; a 200 that is 24 bytes of `ref: refs/heads/main` is a finding. Length is what proves which.
2. Disclosure findings feed §2.6 of `00-surface-and-ledger.md`. A recovered source map, spec or repo adds rows.
   Do not test the new endpoints ad hoc — add them to the ledger first.

## 4.3 Stack-first checklist

Fetch these before any wordlist. One request each, no brute force, highest hit rate per request.

| Stack | First fetches |
|---|---|
| PHP generic | `/.env` `/info.php` `/phpinfo.php` `/config.php.bak` `/.htpasswd` `/composer.json` `/composer.lock` `/vendor/composer/installed.json` |
| Laravel | `/.env` `/.env.bak` `/telescope/requests` `/horizon/api/stats` `/storage/logs/laravel.log` `/_ignition/health-check` |
| WordPress | `/wp-config.php.bak` `/wp-config.php~` `/wp-content/debug.log` `/wp-json/wp/v2/users` `/?rest_route=/wp/v2/users` `/wp-content/uploads/` |
| Java / Spring Boot | `/actuator` `/actuator/env` `/actuator/heapdump` `/actuator/mappings` `/error` `/WEB-INF/web.xml` `/META-INF/MANIFEST.MF` `/v3/api-docs` |
| .NET | `/appsettings.json` `/appsettings.Development.json` `/web.config` `/web.config.bak` `/trace.axd` `/elmah.axd` `/*.asmx?WSDL` |
| Django | `/settings.py` `/admin/` `/api/?format=api` (DRF browsable) `/static/` |
| Flask | `/console` `/debug` `/openapi.json` `/apidocs` `/apispec_1.json` |
| Rails | `/rails/info/routes` `/rails/info/properties` `/config/database.yml` `/log/production.log` `/assets/.sprockets-manifest*.json` |
| Node / Express | `/.env` `/package.json` `/package-lock.json` `/server.js` `/.npmrc` `/debug` |
| Next.js | `/_next/static/<buildId>/_buildManifest.js` `/_next/static/<buildId>/_ssgManifest.js`, then the chunks they name |
| Go | `/debug/pprof/` `/debug/pprof/cmdline` `/debug/vars` `/metrics` `/healthz` |
| SPA + object storage | bundle + `.js.map`, bucket root listing, `/config.json` `/env.js` `/runtime-config.json` |
| GraphQL-first | `/graphql` `/graphiql` `/playground` `/v1/graphql` `/api/graphql`, introspection, `graphql-cop` |

---

## 4.4 Card 1 — Exposed VCS and config

**What it is.** The deploy shipped the repository or a config file into the webroot. Whole-source recovery and
live credentials, both from a single GET.

**Where it hides.** The webroot of every host and vhost, not just the main app. Staging, `dev.`, `old.`, CI
artifact hosts, and any path that looks like a separate deploy (`/admin/`, `/api/`, `/blog/`, `/v1/`). Test each
app root, not only `/`.

**Detect.** VCS:

```
/.git/HEAD           /.git/config        /.git/index        /.git/packed-refs
/.git/logs/HEAD      /.git/ORIG_HEAD     /.git/description  /.git/COMMIT_EDITMSG
/.git/refs/heads/main   /.git/refs/heads/master   /.gitignore   /.gitattributes   /.gitmodules
/.svn/entries        /.svn/wc.db         /.svn/pristine/
/.hg/requires        /.hg/store/00manifest.i
/.bzr/branch/last-revision
/CVS/Root            /CVS/Entries
```

Config and secrets:

```
/.env            /.env.local     /.env.dev      /.env.development   /.env.prod
/.env.production /.env.staging   /.env.test     /.env.bak           /.env.save
/.env.example    /env.js         /config.json   /runtime-config.json
/docker-compose.yml   /docker-compose.override.yml   /Dockerfile   /.dockerignore
/.npmrc   /.yarnrc   /.yarnrc.yml   /.pypirc   /pip.conf
/.aws/credentials   /.aws/config   /.s3cfg   /.boto
/web.config   /appsettings.json   /appsettings.Development.json   /connectionstrings.config
/application.properties   /application.yml   /application-dev.yml   /bootstrap.yml
/wp-config.php.bak   /wp-config.php~   /wp-config.php.save   /wp-config.php.orig   /wp-config.php.txt
/settings.py   /local_settings.py   /instance/config.py
/config/database.yml   /config/secrets.yml   /config/master.key   /config/credentials.yml.enc
/.htpasswd   /.htaccess   /nginx.conf   /httpd.conf
/id_rsa   /id_rsa.pub   /id_ed25519   /.ssh/id_rsa   /.ssh/authorized_keys   /.ssh/known_hosts
/.netrc   /_netrc   /.pgpass   /.my.cnf   /.mysql_history   /.bash_history   /.zsh_history
/.kube/config   /terraform.tfstate   /terraform.tfvars   /.terraform/terraform.tfstate
/secrets.yaml   /secrets.json   /credentials.json   /serviceaccount.json   /firebase-adminsdk.json
```

CI files — they leak internal registries, deploy hosts, runner names, and named-but-masked secrets:

```
/.gitlab-ci.yml   /.github/workflows/   /.github/workflows/deploy.yml   /.github/workflows/ci.yml
/Jenkinsfile   /Jenkinsfile.groovy   /.travis.yml   /.circleci/config.yml
/azure-pipelines.yml   /bitbucket-pipelines.yml   /buildspec.yml   /cloudbuild.yaml
/.drone.yml   /Procfile   /app.yaml   /vercel.json   /netlify.toml   /Makefile   /deploy.sh
```

Breadth sweep, rate-limited per `../CLAUDE.md` §2:

```
ffuf -u https://TARGET/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200,206,301,302,401,403 -fs <baseline-404-len> \
  -rate 5 -t 5 -H 'X-Bug-Bounty: <handle>' \
  -o /root/pentest/targets/<target>/evidence/ffuf-common.json -of json

nuclei -u https://TARGET -tags exposure,config,backup,files -rl 5 -c 5 -H 'X-Bug-Bounty: <handle>'
```

A scanner hit is `suspicious` until you re-fetch it by hand with `curl -i`.

**Confirm.**

| File | Confirmation |
|---|---|
| `/.git/HEAD` | Body starts `ref: refs/heads/`, tens of bytes, not an HTML page |
| `/.git/config` | Contains `[core]` and a `url =` remote |
| `/.git/index` | First 4 bytes are `DIRC` — `curl -s .../.git/index \| head -c 4 \| xxd` |
| `/.env` | `KEY=value` lines and a non-`text/html` content type |
| `/appsettings.json` | Valid JSON with `ConnectionStrings` or `Logging` |
| `/web.config` | `<configuration>` root element |

The standard false positive is a SPA or framework catch-all returning `index.html` with 200 for every path.
Always compare against a bogus sibling (`/.git/HEADzzz`, `/.envzzz`). Same length and body = negative.

Recover the repo:

```
git-dumper https://TARGET/.git/ /root/pentest/targets/<target>/evidence/gitdump
cd /root/pentest/targets/<target>/evidence/gitdump && git log --oneline -20 && git status
```

If listing is off but `/.git/config` reads, `git-dumper` still works from `index` and `packed-refs`. If those
404, walk objects by hand from commit ids in `/.git/logs/HEAD`:
`/.git/objects/<first2>/<remaining38>`.

**Escalate.**

1. `git log -p -S password`, `-S secret`, `git log --all`, `git stash list` — deleted secrets survive history.
2. `trufflehog git file:///path/to/gitdump` and `trufflehog filesystem --results=verified,unknown <dir>`.
3. Internal hostnames and API base URLs from source → ledger rows → test reachability from your position only.
4. Absolute filesystem paths → the missing piece for LFI/traversal. Hand to `01-injection.md`.
5. Signing keys (`APP_KEY`, `SECRET_KEY`, `machineKey`, `secret_key_base`, JWT HMAC secret) — the highest-value
   config leak short of DB credentials. Report as forgeable-session impact. **Do not forge another user's session.**
6. Cloud credentials: report the key id and the source. Do not call the cloud API with it.

RISK: `git-dumper` is hundreds of requests and ignores your rate limit. Run it once with `--threads 2`, never
against a host that has already throttled you. For a first confirmation, `/.git/config` plus `/.git/logs/HEAD`
by hand is enough for the report.

RISK: `.bash_history`, `.mysql_history` and `terraform.tfstate` routinely contain live production credentials
and real data. Identify the file type, then stop and report (`../CLAUDE.md` §4).

**Commonly missed.**

- `.git` on a subdirectory app (`/blog/.git/HEAD`) when the root is clean.
- `.env` under the app path rather than the host root: `/api/.env`, `/backend/.env`, `/laravel/.env`.
- `/.git/` present but `HEAD` blocked by a WAF string rule → `/.git//HEAD`, `/.git/./HEAD`, `/%2egit/HEAD`,
  `/.GIT/HEAD` on case-insensitive filesystems. Then `03-bypass-and-blind.md`.
- CI files naming a self-hosted runner or internal package registry — that is new in-scope surface.
- Lockfiles (`composer.lock`, `package-lock.json`, `Gemfile.lock`, `yarn.lock`, `requirements.txt`): exact
  dependency versions. Informational alone, useful for payload choice in `01-injection.md`.

---

## 4.5 Card 2 — Backup, temp and editor leftovers

**What it is.** The same file the app serves, in a copy the server no longer executes. `config.php` runs;
`config.php.bak` is served as text.

**Where it hides.** Next to every file you already know exists. That is the whole trick — you do not need a
wordlist, you need the app's own file list plus a suffix matrix.

**Detect.** Extension and suffix matrix, applied to every known file:

| Class | Variants |
|---|---|
| Suffix | `.bak` `.bk` `.old` `.orig` `.original` `.save` `.saved` `.sav` `.tmp` `.temp` `.copy` `.new` `.backup` `.dist` `.default` `.sample` `.example` `.txt` `.inc` `.src` `.disabled` |
| Numeric / dated | `.1` `.2` `.0` `-1` `-old` `-bak` `-copy` `_old` `_bak` `_backup` `_copy` `_v1` `_2023` `.20240101` |
| Editor | `~` `.swp` `.swo` `.swn` `.un~` `.kate-swp` `#file#` `.#file` `file.php.save.1` |
| Archive | `.zip` `.tar` `.tar.gz` `.tgz` `.tar.bz2` `.rar` `.7z` `.gz` `.bz2` `.xz` |
| Data | `.sql` `.sql.gz` `.sql.bz2` `.dump` `.bak.sql` `.mdb` `.sqlite` `.sqlite3` `.db` `.csv` `.xlsx` |
| Log | `.log` `.log.1` `.log.gz` `.out` `.err` plus `debug.log` `error.log` `access.log` |
| Patch leftovers | `.rej` `.patch` `.diff` `.orig` |

Generate candidates from files you actually saw, not from a generic wordlist:

```
# known.txt = one path per line, from the ledger / crawl / JS mining
while read -r p; do
  for s in .bak .old .orig .save .swp .swo '~' .tmp .copy .1 .zip .tar.gz .sql .sql.gz .dump .log .txt .inc .dist; do
    printf '%s%s\n' "$p" "$s"
  done
done < known.txt | sort -u > /root/pentest/targets/<target>/evidence/backup-candidates.txt

ffuf -u https://TARGET/FUZZ -w /root/pentest/targets/<target>/evidence/backup-candidates.txt \
  -mc 200,206 -fs <baseline-404-len> -rate 5 -t 5 -o evidence/ffuf-backup.json -of json
```

Whole-app archives, at host root and app root:

```
/backup.zip /backup.tar.gz /backup.sql /backup.sql.gz /www.zip /site.zip /web.zip /html.zip
/app.zip /source.zip /src.zip /release.zip /deploy.zip /public_html.tar.gz /dist.zip
/db.sql /dump.sql /database.sql /mysql.sql /pg_dump.sql /latest.sql.gz
/<target-domain>.zip   /<target-domain>.sql   /<appname>.zip   /<appname>-backup.tar.gz
```

Editor and IDE artifacts:

```
/.vscode/settings.json  /.vscode/launch.json  /.vscode/sftp.json  /.vscode/ftp-sync.json
/.idea/workspace.xml  /.idea/modules.xml  /.idea/dataSources.xml  /.idea/dataSources.local.xml
/.idea/misc.xml  /.idea/deployment.xml  /.idea/webServers.xml  /.project  /.settings/
/nbproject/project.properties  /.sublime-project  /.sublime-workspace
/Thumbs.db  /desktop.ini  /.DS_Store            # .DS_Store parsing is §4.10
```

`.idea/dataSources.local.xml` and `.vscode/sftp.json` carry DB and SFTP credentials in plaintext more often
than anything else in this card.

Vim swap recovery:

```
curl -s https://TARGET/.index.php.swp -o /tmp/x.swp
strings /tmp/x.swp | head -50
vim -r /tmp/x.swp        # then :w /tmp/recovered.php
```

Swap names are dotted and hidden. For `index.php` try `/.index.php.swp`, `/.index.php.swo`, `/index.php.swp`,
`/.index.php.un~`.

**Confirm.** `curl -i`: status 200, a `Content-Type` that is not the app's HTML, and a body that is source or
data. Diff against the bogus-path baseline. For archives, check the magic bytes and the size:

```
curl -s -r 0-3 https://TARGET/backup.zip | xxd          # 504b0304 = PK..
curl -sI https://TARGET/backup.tar.gz | grep -iE 'content-(type|length)'
```

**Escalate.** Same ladder as §4.4: credentials → signing keys → internal hosts → absolute paths → new
endpoints. A `.sql` dump is the one case where the finding is the *contents*: confirm the schema and one
redacted row, then stop.

RISK: a multi-GB archive is a bandwidth event for the target and a data-handling problem for you. `HEAD` first.
Over ~50 MB, do not download it — range-request 4 KB to prove the type, report the URL and the size, let the
program pull it:

```
curl -s -r 0-4095 https://TARGET/backup.sql.gz -o evidence/backup-head.bin
```

RISK: a database dump is real user data. `../CLAUDE.md` §4 applies — stop reading, report what you have.

**Commonly missed.**

- The "same filename, different extension" trick on *known app files*, not generic words: `login.php` →
  `login.php.bak`, `login.phps`, `login.php.txt`, `login.bak`, `login.php~`, `login.php.orig`.
- `.phps` and `.php.txt` render PHP as source on some configs.
- `index.php~` — `index.php` was never in a wordlist because it was the default document.
- Gzip-only variants served when the plain file 404s: `main.js.gz`, `app.css.gz`.
- WordPress `/wp-content/debug.log` and `/wp-content/uploads/<year>/<month>/` holding migration exports and
  form-plugin CSVs of submitted PII.
- Laravel `/storage/logs/laravel-YYYY-MM-DD.log` — one file per day, so iterate recent dates.
- Merge leftovers in production: `config.php.orig`, `config.php.rej`.
- The archive one level above the webroot but still served through a bad alias — traversal handling in
  `01-injection.md`.

---

## 4.6 Card 3 — Source maps and JS bundle mining

**What it is.** The front end ships its own documentation. Bundles name every API route, role string and
feature flag. Source maps hand you the original files, comments included.

**Where it hides.** Every `<script src>` on every page, plus lazily loaded chunks that never appear in the HTML,
service workers, web workers, and inline config blobs.

**Detect.** Collect the bundle list:

```
katana -u https://TARGET -jc -jsl -d 3 -rl 5 -o evidence/katana.txt
grep -Eo 'https?://[^"'"'"' ]+\.m?js' evidence/katana.txt | sort -u > evidence/js-urls.txt
gau --subs TARGET | grep -E '\.m?js(\?|$)' | sort -u >> evidence/js-urls.txt
sort -u evidence/js-urls.txt -o evidence/js-urls.txt
```

Chunk lists the crawler will not see:

```
/_next/static/<buildId>/_buildManifest.js    # Next.js: every route and its chunks
/_next/static/<buildId>/_ssgManifest.js
/asset-manifest.json                         # CRA
/static/js/main.<hash>.js   /static/js/*.chunk.js
/manifest.json  /precache-manifest.*.js  /service-worker.js  /sw.js  /workbox-*.js
/runtime.<hash>.js  /polyfills.<hash>.js  /vendor.<hash>.js      # Angular
/build/manifest.json  /mix-manifest.json                        # Laravel Mix / Vite
```

Source maps:

```
# explicit pointer at the tail of the bundle
curl -s https://TARGET/static/js/main.abc123.js | tail -c 200 | grep -o 'sourceMappingURL=.*'

# blind try, per bundle
while read -r u; do
  printf '%s %s.map\n' "$(curl -s -o /dev/null -w '%{http_code}' "$u.map")" "$u"
done < evidence/js-urls.txt
```

Also try `<bundle>.map`, `/maps/<bundle>.js.map`, and the `//# sourceMappingURL` value resolved relative to the
bundle's directory. A `data:` inline map means the sources are already in the file you have.

Unpack `sourcesContent` with no extra tooling:

```
curl -s https://TARGET/static/js/main.abc123.js.map -o /tmp/m.map
jq -r '.sources | length' /tmp/m.map
jq -r '.sources[]' /tmp/m.map | head -50
mkdir -p /root/pentest/targets/<target>/evidence/srcmap
jq -r '.sources as $s | .sourcesContent as $c | range(0; ($s|length)) as $i
       | "=== " + $s[$i] + "\n" + ($c[$i] // "<no content>")' /tmp/m.map \
  > /root/pentest/targets/<target>/evidence/srcmap/main.txt
```

If `sourcesContent` is null you still get original file and directory names — an internal path disclosure and a
structure map.

Mine bundles and recovered source:

```
jsluice urls -R https://TARGET evidence/js/*.js | jq -r '.url' | sort -u
jsluice secrets evidence/js/*.js
jsluice endpoints evidence/js/*.js
trufflehog filesystem --results=verified,unknown evidence/js/
trufflehog filesystem --results=verified,unknown evidence/srcmap/
```

Non-secret greps (these feed the ledger, not a report):

```
grep -hoE '"/(api|v[0-9]|graphql|internal|admin)[a-zA-Z0-9_/{}.-]*"' evidence/js/*.js | sort -u
grep -hoiE '(role|permission|scope|can[A-Z][a-zA-Z]*|is[A-Z][a-zA-Z]*)["'"'"' :=]{1,3}[a-zA-Z_.:]+' evidence/js/*.js | sort -u
grep -hoiE '(feature|flag|toggle|experiment)[a-zA-Z_]*\s*[:=]\s*(true|false|"[^"]+")' evidence/js/*.js | sort -u
grep -hoiE '\b[a-z0-9-]+\.(internal|local|corp|intra|lan|svc|cluster\.local)\b' evidence/js/*.js | sort -u
grep -hoE '(https?:)?//[a-z0-9.-]+\.[a-z]{2,}' evidence/js/*.js | sort -u
grep -hoE '/\*[^*]{20,}\*/|//\s*(TODO|FIXME|HACK|XXX|NOTE|temporary|remove before)[^\n]{0,120}' evidence/js/*.js
```

**Secret regex starter set.** Save as `evidence/secrets.grep`, then `grep -hoEn -f evidence/secrets.grep <files>`.
Run it against bundles, maps, recovered source, HTML, and JSON responses.

| Provider | Regex |
|---|---|
| AWS access key id | `\b((A3T[A-Z0-9])\|AKIA\|ASIA\|ABIA\|ACCA)[A-Z0-9]{16}\b` |
| AWS secret key (contextual) | `(?i)aws[^\n]{0,24}['"][A-Za-z0-9/+=]{40}['"]` |
| AWS session token | `(?i)aws_session_token['" :=]{1,6}[A-Za-z0-9/+=]{100,}` |
| Google API key | `AIza[0-9A-Za-z_-]{35}` |
| Google OAuth client id | `[0-9]{10,14}-[0-9a-z_]{32}\.apps\.googleusercontent\.com` |
| GCP service account | `"type":\s*"service_account"` |
| Slack token | `xox[abprse]-[0-9A-Za-z-]{10,72}` |
| Slack webhook | `https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z_]{20,}` |
| Stripe secret / restricted | `(sk\|rk)_(live\|test)_[0-9a-zA-Z]{20,}` |
| GitHub token | `gh[pousr]_[0-9A-Za-z]{36,255}` |
| GitHub fine-grained PAT | `github_pat_[0-9a-zA-Z_]{22,}` |
| GitLab PAT | `glpat-[0-9A-Za-z_-]{20,}` |
| JWT | `eyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}` |
| Private key header | `-----BEGIN ((RSA\|EC\|DSA\|OPENSSH\|PGP\|ENCRYPTED) )?PRIVATE KEY( BLOCK)?-----` |
| Firebase | `[a-z0-9-]+\.firebaseio\.com\|[a-z0-9-]+\.firebasedatabase\.app\|firebaseConfig\s*=` |
| Firebase FCM server key | `AAAA[0-9A-Za-z_-]{7}:[0-9A-Za-z_-]{140,}` |
| Mapbox secret token | `sk\.eyJ[0-9A-Za-z_-]{20,}` |
| Twilio SID / API key | `AC[0-9a-fA-F]{32}\|SK[0-9a-fA-F]{32}` |
| SendGrid | `SG\.[0-9A-Za-z_-]{16,32}\.[0-9A-Za-z_-]{16,64}` |
| Mailgun | `key-[0-9a-f]{32}` |
| Azure storage conn string | `DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[0-9A-Za-z+/=]{60,}` |
| Azure SAS | `[?&]sig=[0-9A-Za-z%/+=]{30,}` with `se=` present |
| npm token | `npm_[0-9A-Za-z]{36}` |
| PyPI token | `pypi-AgEIcHlwaS5vcmc[0-9A-Za-z_-]{50,}` |
| Algolia admin key (contextual) | `(?i)algolia[^\n]{0,20}['"][0-9a-f]{32}['"]` |
| Basic auth in a URL | `[a-z][a-z0-9+.-]*://[^/\s:@]{2,}:[^/\s:@]{2,}@` |
| DB connection string | `(?i)(postgres(ql)?\|mysql\|mongodb(\+srv)?\|redis\|amqp\|mssql)://[^\s"'<>]{8,}` |
| Generic assignment | `(?i)\b(api[_-]?key\|apikey\|secret\|token\|passwd\|password\|auth\|bearer\|private[_-]?key\|client[_-]?secret)\b["'\s]{0,3}[:=]["'\s]{1,3}[0-9A-Za-z+/=_-]{16,}` |
| Generic high entropy (review by hand) | `["'][0-9A-Za-z+/]{32,}={0,2}["']` |

**Public by design — do not report these as secret leaks.** Google Maps browser key, Firebase web `apiKey`,
Stripe `pk_live_`, Mapbox `pk.`, Sentry DSN, Algolia *search-only* key, reCAPTCHA site key, Intercom app id,
Segment write key. They are in the bundle because they must be. They become findings only with a second fact:
the Maps key has no referrer restriction and is billable, the Firebase rules are world-readable, the Algolia key
turns out to be admin, the Segment key allows identity spoofing. Prove the second fact or leave it out.

**Confirm.** For a secret: the file, the line, and a redacted value (`AKIAIOSFODNN****`). For an endpoint: one
request showing it exists and what it returns. For a source map: the `sources[]` list and one recovered file.

**Escalate.**

- Unreferenced endpoints and parameters → ledger rows → the full sink matrix in `01-injection.md`.
- Role and permission strings → the authorisation model. Access control is out of scope (`../CLAUDE.md` §1)
  unless it is the delivery mechanism for a disclosure, e.g. a parameter that widens an API response (§4.11).
- Commented-out code and `TODO` lines naming a bypass, a test account, or a legacy endpoint.
- Recovered source showing how a value reaches a sink — turns a blind guess into a targeted payload.
- Admin-only chunks (`admin.<hash>.js`) downloadable by a low-privileged user. The chunk is informational; the
  endpoints inside it are the finding.

**Commonly missed.**

- Lazy chunks never loaded in a normal session. Enumerate from `_buildManifest.js` / `asset-manifest.json`,
  not from the DOM.
- Older bundle hashes still cached at the CDN. `gau`/Wayback give you old hashes, and the old bundle often
  holds the secret that was removed from the current one.
- `.mjs`, `.cjs`, and dynamic `import()` targets built as separate files.
- `sw.js` precache manifests listing every route in the app.
- `env.js` / `config.js` / `runtime-config.json` fetched at boot — server config shipped to the browser.
- `.css.map` exposing SCSS structure and internal component names.
- Bundles on a different host (`cdn.`, `assets.`, an S3 bucket). Check scope before probing that host.
- Vendor-code comments giving the exact library version for `01-injection.md`.

---

## 4.7 Card 4 — Verbose errors and stack traces

**What it is.** The app describes its internals when it breaks. Two separate values: the content of the trace,
and the *fact* that an error is reachable, which is an oracle (§4.20).

**Where it hides.** Anywhere input is parsed. Highest yield: type-coerced parameters, id parameters, uploads,
date and number fields, and any endpoint with a `Content-Type` requirement.

**Detect — how to force an error.** Work the ledger parameter by parameter with the §2.4 baseline next to you.

| Technique | Literal | Typically breaks |
|---|---|---|
| Type confusion, array | `?id[]=1` · `?id[]=1&id[]=2` | PHP, Express (`qs`), Rails |
| Type confusion, object | `?id[x]=1` · JSON `{"id":{"$ne":1}}` | PHP, Node, Mongo drivers |
| Type confusion, JSON | `{"id":"abc"}` where int expected · `{"id":[1]}` · `{"id":null}` · `{"id":true}` | typed backends (Java, .NET, Go, pydantic) |
| Empty vs missing | `?id=` versus dropping `id` entirely | validation layers |
| Oversized value | 10 000 `A`s in one parameter (**not** 10 MB) | column and regex limits |
| Huge / negative / boundary | `2147483648` `-1` `9223372036854775808` `1e309` `0x41` `NaN` `Infinity` `-0` | int parsing, DB column type |
| Number format | `1.0` `1,0` `01` `+1` `1 ` (trailing space) | strict parsers |
| Invalid encoding | `%` `%zz` `%u0041` `%c0%ae` `%ff` | URL decoders |
| Malformed UTF-8 | `%c3%28` `%e2%28%a1` `%f0%28%8c%28` | strict decoders, DB charset |
| Overlong / surrogate | `%ed%a0%80` · `\ud800` in JSON | JSON and DB layers |
| Null byte | `%00` in a value and in a filename | PHP, Java, filesystem calls |
| Control chars | `%0a` `%0d` `%09` `%1a` | log, header and CSV parsers |
| Wrong `Content-Type` | JSON body sent as `text/plain`, `application/xml`, or with no header | framework body parsers |
| Malformed JSON | `{"a":1,}` · `{"a":1` · `{'a':1}` · `[{]` · `{"a":undefined}` | parser error with an offset, sometimes the body echoed |
| Deep nesting (careful) | 30 levels of `[[[...]]]` | parser limits. **Stop at 30** |
| Missing required field | drop one key from a working request | validation errors naming every field |
| Extra unexpected field | `{"id":1,"zzz":1}` · `{"__proto__":{"x":1}}` | strict schema validators |
| Unexpected method | `PUT` / `DELETE` / `PATCH` / `TRACE` / `FOO` on a `GET` route | routing errors listing routes |
| Wrong `Accept` | `Accept: application/xml` on a JSON API | content negotiation errors |
| Path suffix | `/api/user/1.json` `/api/user/1.xml` `/api/user/1/` `/api/user/1;x=1` | route resolution |
| Bad auth material | truncated JWT, altered base64, expired token, `Authorization: Bearer` with no value | auth middleware traces |
| Duplicate params | `?id=1&id=2`, duplicate JSON keys, duplicate headers | parser differentials → `03-bypass-and-blind.md` |
| Bad `Host` / `X-Forwarded-*` | `Host: x` · `X-Forwarded-Host: x"` | vhost and URL-building errors |
| Multipart breakage | missing boundary, boundary mismatch, no `filename=`, filename `a".jpg` | upload handlers |

RISK: oversized values and deep nesting shade into DoS. Cap at 10 000 characters and 30 nesting levels, send
each once, and stop the moment response time grows or a 5xx repeats. `../CLAUDE.md` §2 and §4: repeated 5xx
means stop and report, not push harder.

**Per-framework debug signatures.**

| Signature in the response | Framework | What it leaks | Note |
|---|---|---|---|
| `Werkzeug Debugger`, `Traceback (most recent call last)` | Flask / Werkzeug | full traceback, local variables, source excerpts, absolute paths, `/console` link | Check `/console`: "Console Locked" = PIN-protected, a live prompt = unauthenticated RCE. **RISK: do not brute the PIN and do not execute anything — report the unlocked console as-is** |
| `You're seeing this error because you have DEBUG = True`, `Request Method:` + `Django Version:` | Django | settings (partly masked), installed apps, middleware, SQL queries, absolute paths, sometimes `SECRET_KEY` | `DEBUG=True` in production is a real finding; severity follows what the dump contains |
| `ActionView::Template::Error`, `Full Trace` / `Application Trace` tabs | Rails | gem versions, app paths, SQL, source lines; `better_errors` adds a live REPL | A `better_errors` console is RCE. Report it, do not use it |
| `Whitelabel Error Page`, `There was an unexpected error (type=` | Spring Boot | little by default; `/error` with `server.error.include-stacktrace=always` gives the full Java trace, package names, library versions | Pair with §4.8 Actuator |
| `Server Error in '/' Application`, `Version Information: Microsoft .NET Framework` | ASP.NET (YSOD) | stack, `.cs`/`.vb` source lines, absolute paths, sometimes connection strings | `customErrors mode="Off"`. Also `/trace.axd`, `/elmah.axd` |
| `An unhandled exception occurred while processing the request` + `Stack Query Cookies Headers` tabs | ASP.NET Core dev page | full trace, environment variables, headers, routing | `ASPNETCORE_ENVIRONMENT=Development` in production |
| `Whoops, looks like something went wrong`, Ignition UI, `Illuminate\` frames | Laravel | env dump (`APP_KEY`, DB and mail credentials), full source, queries with bindings | Highest-value framework debug page after a heapdump. `APP_KEY` = forgeable signed cookies |
| `Error: ...` + `at Layer.handle`, `at Function.process_params` | Express | absolute paths, module names, sometimes the request body | Usually only when `NODE_ENV!=production` |
| `Warning:` / `Notice:` / `Fatal error: ... in /var/www/... on line N` | PHP | absolute path, function name, sometimes SQL and argument values | The path enables LFI targeting |
| `java.lang.NullPointerException` + package names, `org.apache.catalina` | Tomcat / Java | class and package names, library versions, JSP paths | `/examples/`, `/manager/html` worth one check |
| `panic:` + `goroutine 1 [running]:` + `/go/src/` | Go | source paths, module names, struct field names | |
| `X-Debug-Token` / `X-Debug-Token-Link` header | Symfony | `/_profiler/<token>` = full request dump, config, queries, session | See §4.8 |
| `Cannot GET /xyz` | Express router | confirms Express; enumerate routes by diffing | |
| `NoMethodError`, `undefined method`, `Uncaught mysqli_sql_exception` | mixed | SQL error text is an injection oracle | Hand to `01-injection.md` |
| `Internal Server Error` with only `Request Id: <guid>` | cloud front door | nothing useful; the guid is for the vendor | Not a finding |

**Confirm.** Save the request and response to `evidence/`. A trace is confirmed only with the request that
produced it. Note whether it is deterministic — a one-off trace during a deploy is not a finding.

**Escalate.** The trace alone is informational. It becomes payable when it hands you one of:

| Found in the trace | Becomes |
|---|---|
| DB credentials, API keys, `APP_KEY` / `SECRET_KEY` / `machineKey` | Secret leak, severity of the secret |
| Absolute filesystem path | The missing piece for LFI, traversal, or an upload-path bug → `01-injection.md` |
| Internal hostname or IP you can reach | Internal surface disclosure. Test reachability only, do not pivot (`../CLAUDE.md` §2) |
| Full SQL query containing your input | Confirmed injection context → `01-injection.md` |
| Another user's data in the error context | PII disclosure. Stop reading, redact, report |
| A live debug console (Werkzeug unlocked, better_errors, Ignition solutions) | Report as RCE-capable exposure, without executing |
| Source code lines | Source disclosure; mine them like §4.6 |
| Library versions | Informational, unless a confirmed unauthenticated critical CVE applies |

**Commonly missed.**

- Errors that appear only on a non-default `Content-Type` or a non-default `Accept`.
- Errors on the *second* step of a flow, because the first step set state.
- Errors surfaced in an export or an email instead of the HTTP response — `../CLAUDE.md` §6 rule 7.
- A 500 with an empty body but a leaking header (`X-Debug-Token`, `X-Error`, `X-Exception`).
- A sanitised page on `/` while a subdomain or `/api/v1` still has debug on. Test per host and per app prefix.
- Errors that only fire for an authenticated user, because validation runs deeper after auth.
- The JSON error object with a `trace`, `detail`, `debug` or `exception` key that a browser never displays.
- Different error *shapes* for the same failure class — that difference alone is the oracle in §4.20.

---

## 4.8 Card 5 — Debug endpoints and admin consoles

**What it is.** Operational surface exposed to the internet. The best disclosure findings in this file live
here, because they are unauthenticated and they dump everything at once.

**Where it hides.** Main host, every subdomain, non-standard ports on in-scope hosts, and behind path prefixes a
reverse proxy forgot to block (`/api/actuator`, `/backend/debug`).

**Detect — Spring Boot Actuator.** Base path is `/actuator` (2.x) or `/` (1.x). Try both.

```
/actuator              /actuator/health        /actuator/info
/actuator/env          /actuator/configprops   /actuator/beans      /actuator/mappings
/actuator/heapdump     /actuator/threaddump    /actuator/loggers    /actuator/metrics
/actuator/httptrace    /actuator/httpexchanges /actuator/auditevents /actuator/sessions
/actuator/scheduledtasks  /actuator/caches     /actuator/conditions
/actuator/jolokia      /actuator/jolokia/list  /actuator/prometheus /actuator/gateway/routes
# 1.x flat paths
/env /configprops /beans /mappings /heapdump /dump /trace /autoconfig /metrics /loggers /jolokia
```

| Endpoint | Leaks | Value |
|---|---|---|
| `/heapdump` | Everything in memory: session tokens, `Authorization` headers, decrypted config, DB credentials, in-flight request bodies with other users' data | **Highest.** Masking in `/env` does not apply to memory |
| `/env`, `/configprops` | Every property key; values partly masked as `******`, but URLs, hostnames, usernames and paths are usually plain | High |
| `/mappings` | Every route, including undocumented and admin ones | High for surface, informational alone |
| `/httptrace`, `/httpexchanges` | The last N requests with headers — other users' cookies and bearer tokens | High |
| `/sessions` | Active session ids | High |
| `/jolokia`, `/jolokia/list` | JMX MBean read access: config, datasources, sometimes credentials | High |
| `/threaddump` | Thread and class names, sometimes request URLs with tokens | Medium |
| `/auditevents` | Usernames and login events | Medium |
| `/gateway/routes` | Internal route targets — SSRF surface (out-of-scope class; note it) | Medium |
| `/beans`, `/loggers`, `/metrics` | Class graph, package map, route names, tenant ids in tags | Low |
| `/shutdown`, `/restart`, `/refresh` | **Destructive. Do not send them** | — |

RISK: `/actuator/shutdown`, `/restart`, `/refresh`, and any Jolokia `exec` or `write` operation stop or change
the service. Never send them. To prove `/shutdown` is exposed, show it in `/actuator`'s own `_links` output, or
use `OPTIONS`. That is sufficient evidence.

RISK: heapdumps are commonly 100 MB–2 GB. Size first, download at most once, never in parallel:

```
curl -sI https://TARGET/actuator/heapdump | grep -i content-length
```

Over ~200 MB, do not pull it. Prove exposure with the `HEAD` (200, `application/octet-stream`, the size) and
report. If you do pull one, confirm the *class* of secret and stop:

```
strings -n 12 heapdump | grep -aiE 'password=|secret=|Bearer |AKIA[A-Z0-9]{16}|jdbc:' | head -20
```

RISK: a heapdump *is* real user data. `../CLAUDE.md` §4 applies the moment you see a session token or PII: stop,
redact, report, and state in the report that you did not enumerate the dump. Delete it once the report is
accepted, unless the program asks for it.

**Detect — everything else.**

| Path | Stack | Notes |
|---|---|---|
| `/console`, `/console?__debugger__=yes&cmd=resource&f=debugger.js` | Flask / Werkzeug | Locked versus unlocked; the resource fetch confirms presence without executing |
| `/admin/`, `/admin/login/` | Django | A login page alone is informational. Check `?next=` reflection |
| `/api/` + `?format=api` | Django REST | Browsable API enumerates serializer fields, including write-only ones |
| `/telescope`, `/telescope/requests`, `/telescope/queries`, `/telescope/dumps` | Laravel | Full request and response bodies, SQL with bindings, session data. Highest-value Laravel exposure |
| `/horizon`, `/horizon/api/stats`, `/horizon/api/jobs/failed` | Laravel | Queue payloads, job arguments, sometimes tokens |
| `/_ignition/health-check`, `/_ignition/execute-solution` | Laravel | Presence of Ignition. **RISK: `execute-solution` is RCE. Do not send it** — prove with the health check |
| `/rails/info/routes`, `/rails/info/properties`, `/rails/mailers` | Rails | Full route table; `/rails/mailers` previews real email templates with data |
| `/_profiler/`, `/_profiler/latest`, `/_wdt/<token>` | Symfony | Full request dump, config, DB queries, session |
| `/debug/pprof/`, `/debug/pprof/heap`, `/debug/pprof/goroutine?debug=2`, `/debug/pprof/cmdline`, `/debug/vars` | Go | `cmdline` gives flags and sometimes secrets; `/debug/vars` gives the environment |
| `/metrics`, `/actuator/prometheus`, `/-/metrics` | Prometheus | Internal hostnames, job names, route templates, tenant ids |
| `/status`, `/stats`, `/healthz`, `/readyz`, `/version`, `/varz` | mixed | `/version` and `/status` often carry a commit hash and build host |
| `/server-status`, `/server-status?auto` | Apache mod_status | **Live request URLs of other users, including tokens in query strings.** High value |
| `/server-info` | Apache mod_info | Full module config, absolute paths |
| `/nginx_status`, `/haproxy?stats` | nginx / HAProxy | Connection stats. Low |
| `/phpinfo.php`, `/info.php`, `/i.php`, `/test.php`, `/pi.php` | PHP | Absolute paths, extensions, `$_ENV` secrets, `doc_root`, disabled functions |
| `/.well-known/openid-configuration`, `/.well-known/apple-app-site-association`, `/.well-known/assetlinks.json`, `/.well-known/security.txt`, `/.well-known/change-password` | mixed | `openid-configuration` names internal IdP endpoints; app-site-association leaks internal URL patterns and bundle ids |
| `/graphiql`, `/playground`, `/altair`, `/voyager`, `/graphql/console` | GraphQL | See §4.9 |
| `/swagger-ui.html`, `/swagger/index.html`, `/api-docs`, `/redoc`, `/docs`, `/scalar` | mixed | See §4.9 |
| `/adminer.php`, `/phpmyadmin/`, `/pma/`, `/dbadmin/` | PHP | DB console. Login page = informational, version banner only. **Do not attempt credentials** |
| `:9200/`, `:9200/_cat/indices?v`, `:9200/_cluster/health` | Elasticsearch | Index names and mappings. **RISK: `_all/_search` returns real data — one document maximum, then stop** |
| `:5601/api/status`, `:5601/app/kibana` | Kibana | Version, index patterns |
| `:8080/manager/html`, `/host-manager/html` | Tomcat | Login realm plus version |
| `:2375/version`, `:2375/containers/json` | Docker API | **Critical if open.** Read-only calls, report immediately |
| `:6379` `:27017` `:11211` `:5432` `:3306` | data stores | Only if the port is in scope. Banner and version only, no queries |

Sweep discipline:

```
httpx -l hosts.txt \
  -path /actuator,/actuator/env,/actuator/heapdump,/debug/pprof/,/metrics,/server-status,/telescope/requests,/_profiler/,/rails/info/routes,/console,/phpinfo.php \
  -mc 200,401,403 -rl 5 -threads 5 -sc -cl -title -o evidence/httpx-debug.txt

nuclei -l hosts.txt -tags exposure,misconfig,springboot,debug -rl 5 -c 5
```

**Confirm.** 200 plus a body that is the real thing, not a login page or an SPA fallback. Prove it is
unauthenticated: resend from a clean session with no cookies and no `Authorization` header, and save that
response.

**Escalate.**

- `/env` masked values → `/actuator/env/<property.name>` single-property view sometimes returns unmasked;
  `/configprops` often shows what `/env` masks.
- `/mappings` → new endpoints → ledger → `01-injection.md`.
- `/httptrace` or `/server-status` containing another user's token → that is the escalation, and also the point
  where you stop reading and report.
- `phpinfo` `doc_root` and `_SERVER` → LFI targeting.
- Internal service URLs → reachability test only, no pivoting.

**Commonly missed.**

- Actuator on a non-standard base path: `/manage`, `/monitoring`, `/internal/actuator`, `/admin/actuator`,
  `/api/actuator`. A Spring JSON 404 body differs from a proxy 404 — read the 404, do not just count it.
- Actuator reachable only via a header the proxy trusts (`X-Forwarded-Prefix`, `X-Original-URL`) →
  `03-bypass-and-blind.md`.
- Debug endpoints on an in-scope staging host that the UI never links.
- `POST` allowed where `GET` returns 405 (`/actuator/loggers/<name>`). A 405 is not "not there".
- `/debug/pprof/` needing the trailing slash.
- `/server-status` reachable on the origin IP but blocked at the CDN (§4.12).

---

## 4.9 Card 6 — API docs and schema disclosure

**What it is.** The machine-readable description of the API. Rarely payable alone. Almost always the thing that
makes the rest of the engagement work, because it hands you the parameter list for the ledger.

**Where it hides.** Doc UIs, raw spec files, and framework-generated schema routes.

**Detect — OpenAPI / Swagger:**

```
/swagger.json /swagger.yaml /swagger/v1/swagger.json /swagger/v2/swagger.json /swagger/docs/v1
/swagger-ui.html /swagger-ui/index.html /swagger/index.html
/swagger-resources /swagger-resources/configuration/ui /swagger-resources/configuration/security
/openapi.json /openapi.yaml /openapi/v3 /api/openapi.json /api-docs /api/api-docs
/v2/api-docs /v3/api-docs /v3/api-docs/swagger-config
/api/v1/swagger.json /api/v2/swagger.json /docs /docs/json /redoc /rapidoc /scalar
/apidocs /apispec_1.json /apispec.json          # flasgger
/api/schema/ /api/schema/?format=json /api/schema.yaml    # drf-spectacular
/api/documentation /docs/api-docs.json /api/doc.json      # NelmioApiDoc
/graphql/schema.json /.well-known/openapi.json
/postman.json /collection.json /insomnia.json
```

Pull every path and parameter into the ledger:

```
curl -s https://TARGET/v3/api-docs -o evidence/openapi.json
jq -r '.paths | to_entries[] | .key as $p | .value | to_entries[] | "\(.key|ascii_upcase) \($p)"' \
  evidence/openapi.json | sort > evidence/openapi-routes.txt
jq -r '[.. | objects | select(has("name")) | .name] | unique[]' evidence/openapi.json \
  > evidence/openapi-params.txt
jq -r '.components.schemas | keys[]' evidence/openapi.json
```

**Detect — GraphQL.** Endpoints: `/graphql` `/graphql/` `/api/graphql` `/v1/graphql` `/graphql/v1` `/query`
`/gql` `/api/gql` `/graphql.php` `/index.php?graphql` `/v1/relay`.

```
curl -s https://TARGET/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{queryType{name} mutationType{name} types{name kind}}}"}' | jq .

graphql-cop -t https://TARGET/graphql -o json > evidence/graphql-cop.json
```

Full SDL dump when introspection is on:

```
curl -s https://TARGET/graphql -H 'Content-Type: application/json' -d @- <<'Q' > evidence/graphql-schema.json
{"query":"query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}"}
Q
```

Partial-introspection tricks when the full query is blocked:

| Trick | Payload |
|---|---|
| Minimal probe | `{"query":"{__typename}"}` |
| Type list only | `{"query":"{__schema{types{name}}}"}` |
| Single type | `{"query":"{__type(name:\"User\"){fields{name type{name}}}}"}` |
| Newline after `__schema` (naive regex filters) | `{"query":"query{__schema\n{types{name}}}"}` |
| GET instead of POST | `/graphql?query={__schema{types{name}}}` |
| Form-encoded body | `query={__schema{types{name}}}` with `Content-Type: application/x-www-form-urlencoded` |
| Batched | `[{"query":"{__typename}"},{"query":"{__schema{types{name}}}"}]` |
| Directive smuggling | `{"query":"{__schema @skip(if:false){types{name}}}"}` |

**Recovering a schema when introspection is off — field suggestion mining (clairvoyance-style).**

1. Send a wrong field and read the suggestion: `{"query":"{user{emai}}"}` →
   `Cannot query field "emai" on type "User". Did you mean "email"?`
2. That error is your oracle. Feed candidate names, keep every suggestion.
3. The wordlist is the *app's own vocabulary*: identifiers mined from the bundle (§4.6), nouns from the UI,
   names from an OpenAPI spec. A generic 10k list is the wrong tool here.
4. Type names come from error text too: `{"query":"{user{x}}"}` names the type, then
   `{"query":"{__type(name:\"User\"){name}}"}` may still answer with field introspection disabled.
5. Argument and operation names: `{"query":"{user(i:1){id}}"}` → `Unknown argument "i" ... Did you mean "id"?`;
   `{"query":"mutation{updateUsr}"}` → suggestion for `updateUser`.
6. If suggestions are off, check whether the error *text* still differs between a nonexistent field and a
   valid-but-unauthorised field. Same oracle, weaker form.

RISK: suggestion brute force is request-heavy. Keep it at 5 req/s, keep the candidate list to a few hundred
entries, and stop once you have the fields you need.

**Detect — SOAP / WSDL / gRPC:**

```
/service?wsdl  /service?WSDL  /Service.asmx?WSDL  /Service.asmx?disco  /Service.asmx
/soap  /soap/  /ws  /ws/  /services  /axis2/services/listServices  /axis/services
/*.svc  /*.svc?wsdl  /*.svc?singleWsdl       # WCF
/wsdl  /api/soap?wsdl  /cgi-bin/soap
grpcurl -plaintext HOST:PORT list
grpcurl -plaintext HOST:PORT describe <service>
grpcurl -insecure HOST:443 list              # grpc over TLS
```

`.asmx` without `?WSDL` returns an HTML method list, and each method page shows a sample SOAP request with
parameter names and types. That is your XML injection surface — hand it to `01-injection.md`.

**Confirm.** Save the spec. Then confirm the documented endpoints actually respond: a spec can describe a
service that is not deployed. Note which endpoints require auth and which do not.

**Escalate.**

- Every path and parameter goes into the ledger. That is the main value of this card.
- Endpoints in the spec that the UI never calls, especially with `admin`, `internal`, `export`, `bulk`, `debug`,
  `impersonate` or `sudo` in the name.
- Schema fields that are PII or secrets and are selectable → §4.11.
- `securitySchemes` declaring which endpoints are public → compare with reality.
- `example:` values in specs are sometimes real: production hostnames, real emails, live API keys.
- GraphQL mutations reachable without auth. RISK: mutations write data (`../CLAUDE.md` §2). Probe with an
  invalid argument so validation rejects it before execution, and report the reachability, not a completed write.

**Commonly missed.**

- Swagger UI present, spec at a path only its JS knows — read the UI HTML for `url:` / `configUrl:`, including
  a multi-spec dropdown.
- `/swagger-resources` listing several API groups when only one is linked.
- Old spec versions: `/v1/api-docs` while the app runs v3.
- Introspection off on `/graphql` but on at `/graphql/v1`, `/api/graphql`, or on staging.
- GraphQL over GET when POST is protected.
- WSDL only answering the exact case `?WSDL`.
- A public Postman collection carrying the same schema plus live tokens (§4.18).

---

## 4.10 Card 7 — Directory listing and file indexing

**What it is.** The server enumerates files for you, or a stray index file does it.

**Where it hides.** Static asset directories, upload directories, and any path whose default document is missing.

**Detect.** Autoindex signatures:

| Signature in the body | Server |
|---|---|
| `<title>Index of /` plus `<address>Apache/` | Apache `Options +Indexes` |
| `<h1>Index of /` plus `<pre>` and a `../` link, no `<address>` | nginx `autoindex on` |
| `<title>Directory Listing -- /` or a table with `[To Parent Directory]` | IIS |
| `<title>Directory Listing For /` plus an `Apache Tomcat` footer | Tomcat |
| `<title>Directory listing for /` | Python `http.server` |
| `Directory: /` plus `Powered by Jetty` | Jetty |
| `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">` | S3 |
| `<EnumerationResults ContainerName=` | Azure Blob |
| `<ListBucketResult` referencing `storage.googleapis.com` | GCS |
| JSON array of `{"name":...,"type":"file"}` | Node `serve-index` or custom |

Candidate paths:

```
/ /assets/ /static/ /public/ /files/ /uploads/ /upload/ /media/ /images/ /img/ /docs/ /doc/
/tmp/ /temp/ /backup/ /backups/ /old/ /archive/ /data/ /db/ /logs/ /log/ /dump/ /export/ /exports/
/attachments/ /downloads/ /dl/ /content/ /storage/ /cache/ /vendor/ /node_modules/
/wp-content/uploads/ /sites/default/files/ /app/uploads/ /.well-known/ /cgi-bin/ /includes/ /inc/
/js/ /css/ /fonts/ /test/ /tests/ /dev/ /staging/ /demo/ /sandbox/ /admin/ /private/
```

Request the parent of every file you know. If `/assets/img/logo.png` exists, request `/assets/img/`, `/assets/`
and `/`.

Index residue and container internals:

```
/.DS_Store   /<any-dir>/.DS_Store   /Thumbs.db   /desktop.ini   /ehthumbs.db
/WEB-INF/web.xml  /WEB-INF/classes/application.properties  /WEB-INF/classes/config.properties
/WEB-INF/classes/hibernate.cfg.xml  /WEB-INF/classes/log4j.properties  /WEB-INF/lib/
/META-INF/MANIFEST.MF  /META-INF/context.xml  /META-INF/maven/  /META-INF/resources/
/robots.txt /sitemap.xml /sitemap_index.xml /crossdomain.xml /clientaccesspolicy.xml
/feed /rss /atom.xml        # sometimes enumerate unlisted content
```

Parse `.DS_Store` — it names the files that were in the directory when it was created, including ones now
missing from the listing:

```
curl -s https://TARGET/assets/.DS_Store -o /tmp/ds
file /tmp/ds                                              # "Apple Desktop Services Store"
strings -el /tmp/ds | sort -u                             # names are UTF-16LE
strings /tmp/ds | grep -aoE '[A-Za-z0-9._-]{3,}' | sort -u # fallback
```

Then fetch each recovered filename.

`WEB-INF` is normally blocked by the servlet container but often reachable through proxy path confusion:
`//WEB-INF/web.xml`, `/./WEB-INF/web.xml`, `/%2557EB-INF/web.xml`, `/..;/WEB-INF/web.xml`. That is bypass
territory — `03-bypass-and-blind.md`.

Buckets:

```
curl -s 'https://BUCKET.s3.amazonaws.com/?list-type=2&max-keys=20'
curl -s 'https://storage.googleapis.com/BUCKET/?max-results=20'
curl -s 'https://ACCOUNT.blob.core.windows.net/CONTAINER?restype=container&comp=list&maxresults=20'
```

RISK / scope: a bucket is in scope only if the program names it, or it is provably the target's asset (named in
their HTML, in their DNS, or serving their content). If you are unsure it is out of scope — one line in
`../targets/<target>/out-of-scope.md` and ask (`../CLAUDE.md` §2, §4). Never test write access: an upload is a
data-modification action even on a bucket you were invited to test. `max-keys=20` is deliberate — read the
listing, take one object as proof, stop.

**Confirm.** Save the listing. Then fetch one file from it that is clearly not meant to be public and save that
too. A listing of minified CSS is not a finding; a listing containing `db-backup-2024.sql.gz` is.

**Escalate.** Listing → backup, source or dump (§4.5) → credentials (§4.4). Uploads listing → other users'
files → PII and §4.17 metadata. Stop at one file as proof.

**Commonly missed.**

- Listing enabled on a sub-path only (`/assets/` blocked, `/assets/vendor/` open).
- `?C=M;O=D` on an Apache listing — sort by date, the newest file is the interesting one.
- `.DS_Store` in the root of an SPA build, naming source directories.
- Bucket listing via the S3 website endpoint when the REST endpoint 403s, and the reverse.
- `/uploads/` with predictable filenames even when listing is off (§4.17).
- `crossdomain.xml` with `allow-access-from domain="*"` — usually informational now, but it is still a
  cross-origin read policy.

---

## 4.11 Card 8 — Excess data in API responses

**What it is.** The server returns more than the UI renders. The most commonly missed disclosure class and the
most likely to pay, because the impact is direct: real fields, real users, no chaining needed.

**Where it hides.** Every JSON response. Especially list endpoints, `/me`, profiles, search, autocomplete,
notifications, webhooks, exports, GraphQL, and anything an SPA calls on page load.

**Detect.** This is method, not tooling. For each endpoint in the ledger:

1. Capture the response and enumerate every field path:

```
curl -s https://TARGET/api/v2/users/me -H 'Authorization: Bearer <token>' -o evidence/me.json
jq -r 'paths(scalars) | map(tostring) | join(".")' evidence/me.json | sort -u
jq -r '[paths(scalars)|.[-1]] | unique[]' evidence/me.json          # leaf names only
```

2. Compare with what the UI shows. Anything in the JSON that never reaches the screen is a candidate. Confirm by
   grepping the bundles from §4.6 for the field name — if the app's own JS never references it, the UI cannot be
   rendering it.

3. Grep field names for the sensitive set:

```
jq -r 'paths(scalars)|join(".")' evidence/*.json | grep -oiE \
 'pass(word|wd)?|hash|salt|bcrypt|argon|secret|token|api_?key|private|otp|mfa|totp|2fa|recovery|backup_?code|
  ssn|social|tax|dob|birth|gender|salary|balance|iban|card|cvv|routing|
  phone|mobile|email|address|street|zip|postal|lat|lon|geo|ip_?addr|
  is_?(admin|staff|super|internal|test|banned|deleted)|role|perm|scope|ability|
  internal|debug|raw|source|query|sql|stack|trace|
  deleted_at|archived_at|banned_at|suspended|shadow|
  tenant|org_?id|account_?id|customer_?id|owner_?id|created_by|
  stripe|braintree|paypal|plaid|invite|reset|verification|confirm' | sort | uniq -c | sort -rn
```

4. Widen the response deliberately:

| Parameter family | Try |
|---|---|
| Sideload / expand | `?include=user,owner,account,payments,notes` `?expand=all` `?expand=user.email` `?embed=` `?with=` `?populate=*` `?_embed` `?load=` |
| Field selection | `?fields=*` `?fields[users]=*` `?select=*` `?attributes=*` `?columns=*` `?props=*` |
| OData | `?$expand=Owner&$select=*` |
| JSON:API | `?include=author&fields[user]=email,phone` |
| Verbosity flags | `?verbose=1` `?debug=1` `?full=1` `?detail=all` `?view=admin` `?raw=1` `?_debug=true` |
| Representation | `?format=api` (DRF) `?format=xml` `?csv=1` `?export=1` |
| Version downgrade | `/api/v1/...` when the UI uses `/api/v3/...` — old serializers leak more |
| Legacy header | `X-API-Version: 1`, `Accept: application/vnd.api+json;version=1` |
| Pagination | `?limit=` `?per_page=` `?page_size=` `?take=` `?first=` `?max=` |
| Sort as a field oracle | `?sort=password_hash` `?order_by=is_admin` — an error naming valid columns leaks the schema; a working sort proves the column exists |
| Filter as an oracle | `?filter[email]=a@b.c` on a field the UI cannot search |

5. GraphQL over-fetch. Take a query the app sends, then add fields from the schema (§4.9):

```
{ user(id:"<your-own-id>"){ id email phone passwordHash isAdmin roles{name}
    internalNotes twoFactorSecret sessions{token ip userAgent} } }
```

Then traverse: `{ me { organization { members { email phone } } } }`.

6. Role diff — the same object, two accounts the user owns:

```
curl -s -H 'Authorization: Bearer <low-role-token>'   https://TARGET/api/v2/projects/42 -o evidence/p42-low.json
curl -s -H 'Authorization: Bearer <admin-role-token>' https://TARGET/api/v2/projects/42 -o evidence/p42-admin.json
diff <(jq -r 'paths(scalars)|join(".")' evidence/p42-low.json | sort) \
     <(jq -r 'paths(scalars)|join(".")' evidence/p42-admin.json | sort)
```

Fields present for admin and absent for the low role are the serializer working as intended. Fields present for
**both** when only admin should see them are the bug. Use the user's own test accounts only (`../CLAUDE.md` §2).

RISK: `?limit=100000` is both a DoS risk and a pile of other people's data. Cap at 200. Stop if response time
climbs or the body exceeds a few MB. The finding is "the field is present" or "the limit is not enforced", which
200 records prove as well as 100 000 — and you report it with two redacted records.

**Confirm.** Show (a) the request, (b) the field path with a redacted value, (c) the grep proving the UI never
references the field, and (d) that an account which should not see it can, if that is the claim.

**Escalate.**

| Extra field | Escalation |
|---|---|
| Password hash | Offline-crack exposure. Report the hash type and a redacted prefix. **Do not crack it** |
| `reset_token` / `invite_token` / `verification_code` | Account-takeover primitive. Prove the format; never use another user's token |
| MFA / TOTP secret | MFA bypass. Report, do not enrol |
| `is_admin` / `role` / `permissions` | Discloses the authz model. Flipping it is access control — out of scope (`../CLAUDE.md` §1), one line in `out-of-scope.md` |
| Another user's email, phone, address | Direct PII disclosure. One record, redacted, stop |
| Another tenant's data | Highest severity in this card. Stop immediately, report |
| Soft-deleted or archived records | Content the user believes is deleted. Real finding on privacy-sensitive apps |
| Internal or sequential ids | Informational alone; feeds §4.13 |
| Internal hostnames, S3 keys, signed URL templates | New surface; reachability check only |
| Raw SQL, query plans, `debug` blocks | Injection context → `01-injection.md` |

**Commonly missed.**

- `GET /api/users?q=a` autocomplete returning full user objects when the dropdown shows only a name.
- The 403/404 *error* body that still embeds the object: `{"error":"forbidden","resource":{...}}`.
- `PATCH` / `PUT` responses returning more fields than the matching `GET`.
- Webhook payloads sent to a URL you control — usually the fattest serializer in the app.
- CSV, XLSX and PDF exports carrying columns the web table hides.
- Search endpoints returning documents the user cannot open, because the search index has no ACL.
- `included` / `relationships` blocks in JSON:API responses.
- WebSocket and SSE frames: same serializer, zero inspection. Check them explicitly.
- The mobile variant of the endpoint (`/mobile/v1/`, `X-Client: ios`) returning more.
- Undocumented `?include=` values accepted because the ORM resolves relationship names dynamically — try names
  from §4.9 and §4.6.
- `ETag` / `Last-Modified` on a 403 resource, confirming existence and change time.

---

## 4.12 Card 9 — Headers and infrastructure leakage

**What it is.** The transport layer talking about the stack. Mostly informational, occasionally the key to the
origin behind a WAF.

**Where it hides.** Every response, including 3xx, 4xx, 5xx, `OPTIONS`, and the CDN's own error pages.

**Detect.**

```
curl -sI https://TARGET/
curl -sI -X OPTIONS https://TARGET/api/v2/users
curl -sI https://TARGET/nonexistent-zzz
curl -s -D - -o /dev/null -L https://TARGET/login       # keep every header set in the redirect chain
httpx -l hosts.txt -sc -cl -title -server -tech-detect -include-response-header -rl 5 -o evidence/httpx-headers.txt
```

| Header | Leak | Verdict |
|---|---|---|
| `Server: Apache/2.4.29 (Ubuntu)` | product, version, distro | Informational |
| `X-Powered-By: PHP/7.2.24` / `Express` / `ASP.NET` | runtime and version | Informational |
| `X-AspNet-Version`, `X-AspNetMvc-Version` | exact .NET version | Informational |
| `X-Generator`, `X-Drupal-Cache`, `X-Redirect-By` | CMS and plugin set | Informational |
| `X-Runtime` (Rails) | server-side time per request → §4.19 for free | Informational alone |
| `X-Debug-Token`, `X-Debug-Token-Link` | Symfony profiler → §4.8 | Medium if the profiler is reachable |
| `X-Request-Id`, `X-Correlation-Id`, `X-Trace-Id` | tracing ids; sometimes encode host or pod names | Informational |
| `X-Served-By`, `X-Backend-Server`, `X-Node`, `X-Upstream`, `X-Server-Name` | internal hostname or pod name | Informational unless reachable |
| `Via`, `X-Varnish`, `X-Cache`, `Age`, `CF-Cache-Status` | cache topology and behaviour | Feeds §4.15 |
| `X-Amz-Cf-Id`, `X-Amz-Request-Id`, `X-Amz-Bucket-Region` | AWS presence, bucket region | Informational |
| `X-Forwarded-For` / `X-Real-IP` echoed back | internal client IP or proxy chain | Informational |
| `Location: http://10.0.3.14:8080/...` | **internal host and port** | Medium if reachable from you |
| `Content-Security-Policy` | internal domains in `connect-src` / `frame-src`, full vendor list | Feeds surface; informational alone |
| `Access-Control-Allow-Origin` echoing input | → §4.14 | Medium–High |
| `WWW-Authenticate: Basic realm="internal-admin"` | internal system name | Informational |
| `Server-Timing: db;dur=42, cache;desc="redis-prod-2"` | internal component names plus timing | Informational; also a free timing oracle |
| `Report-To`, `NEL` | reporting endpoints, sometimes internal | Informational |
| `X-Sourcemap`, `SourceMap` | source map location → §4.6 | Low |
| `X-Envoy-Upstream-Service-Time`, `x-envoy-*` | service mesh and upstream names | Informational |
| `X-Pod-Name`, `X-Kubernetes-*` | cluster internals | Informational |

Internal-host leakage beyond headers:

```
curl -s -o /dev/null -D - -L 'https://TARGET/redirect?url=/' | grep -i '^location:'
curl -sI https://TARGET/ -H 'X-Forwarded-Host: zzz.example'      # URL rebuilt from the header
curl -sI https://TARGET/ -H 'Host: internal.target.com'          # second vhost on the same IP
# headers of an email the app sent you: Received: chain, X-Mailer, internal relay names
```

Origin IP disclosure — passive first:

| Source | How |
|---|---|
| Historical DNS | A records from before the CDN was added |
| SPF / TXT / MX | `dig +short TXT target.com`, `dig +short MX target.com` — `ip4:` blocks and mail hosts are often the same network |
| Certificate transparency | `https://crt.sh/?q=%25.target.com` — hosts that were never proxied |
| Non-proxied subdomains | `dig +short dev.target.com` |
| Favicon / body hash | Shodan `http.favicon.hash:<hash>`, Censys body hash |
| `/cdn-cgi/trace` | Confirms Cloudflare and the colo |
| App-sent email | The `Received:` chain gives the sending host |

RISK: with a candidate origin IP, one request is enough to prove WAF bypass:
`curl -k -H 'Host: target.com' https://<ip>/`. Do not run scanners against the origin and do not touch
neighbouring IPs — that is almost certainly out of scope (`../CLAUDE.md` §2).

**Confirm.** Headers confirm with `curl -i`. For an internal host, confirmation means one of: it resolves, a
connection attempt from your position gets a TCP/TLS response, or the app renders content from it. "It appears
in a header" is the informational version — say so.

**Escalate.**

- Internal hostname → reachable → in-scope internal surface → new ledger rows.
- Origin IP → WAF bypass → re-run payloads the WAF blocked → `03-bypass-and-blind.md`.
- CSP internal domains → subdomain list → scope check → new rows.
- A `Location` header carrying a session id or one-time code → token leak, §4.16.
- WAF and LB fingerprints (`wafw00f`) choose the bypass family in `03-bypass-and-blind.md`. Not a finding.

**Commonly missed.**

- Headers present only on error responses or only on `OPTIONS`.
- Headers present on the origin and stripped by the CDN.
- `X-Forwarded-For` echoed into the *body* ("your IP is" widgets, log viewers) — that is also an injection sink.
- The `Location` on a login 302 carrying a one-time code in the query string.
- HTTP/1.1 versus HTTP/2 header differences (`curl --http1.1`).
- `Server-Timing` naming internal services, added by an APM agent and never reviewed.

---

## 4.13 Card 10 — User and resource enumeration

**What it is.** A response difference that tells you whether an account, email, phone, org or object exists.

**Where it hides.** Login, register, password reset, email change, invite, "check availability", 2FA entry,
OAuth link, unsubscribe, and any `GET /api/<thing>/<id>` that distinguishes 403 from 404.

**Detect.** Differentials to measure per flow, with a known-good and a known-bad value:

| Signal | What to record |
|---|---|
| Status code | 200 / 400 / 401 / 403 / 404, and the 302 target |
| Body text | the exact differing string ("no account found" versus "wrong password") |
| Body length | byte count; a 3-byte delta counts |
| Field set | a JSON key present in one case only (`{"mfa_required":true}`) |
| `Set-Cookie` | a cookie issued only for existing users |
| Redirect target | `/login?error=nouser` versus `/login?error=badpass` |
| Rate limiting | the throttle fires only on real accounts |
| Timing | §4.19 — bcrypt runs only when the user exists |
| Reflected data | a reset page showing a masked email or phone for the account |
| Header | `X-RateLimit-Remaining` decrementing only on hits |

Probe shape — two values you own plus one that cannot exist:

```
for u in real@yours.tld notexist-zzz1@yours.tld notexist-zzz2@yours.tld; do
  printf '%s ' "$u"
  curl -s -o /tmp/r -w '%{http_code} %{size_download} %{time_total}\n' \
    -X POST https://TARGET/api/auth/login \
    -H 'Content-Type: application/json' -d "{\"email\":\"$u\",\"password\":\"Wrong-Passw0rd!\"}"
done
```

Common enumeration endpoints:

```
POST /api/auth/login          POST /api/auth/register      POST /api/auth/forgot-password
POST /api/auth/reset          POST /api/users/check-email   GET  /api/users/exists?email=
GET  /api/users/availability?username=   POST /api/invite   POST /api/auth/magic-link
POST /api/2fa/verify          POST /graphql (userByEmail)   GET  /api/orgs/<slug>
GET  /u/<username>            GET  /api/profiles/<handle>   POST /api/newsletter/subscribe
POST /oauth/token             GET  /.well-known/webfinger?resource=acct:user@target
GET  /api/v2/users?email=     WordPress: /?author=1  /wp-json/wp/v2/users  /?rest_route=/wp/v2/users
```

RISK: do not iterate a wordlist of real people's email addresses. Prove the oracle with two values you control
plus one that does not exist. Enumerating real users is data collection you cannot justify, and it is noisy.

**Confirm.** Show the two requests side by side with the differing bytes highlighted, and state the oracle in
one line: "a registered email returns 200 with `mfa_required: true`; an unregistered email returns 200 with
`mfa_required: false`".

**Escalate — this card is only payable with a real impact story.** What that story looks like:

- **Sensitive membership.** The user list is itself confidential: a medical service, a dating or adult site, an
  addiction-support app, a whistleblowing portal, an HR or layoff tool, a debt or background-check service, a
  private beta, a paid members-only community. "This person has an account here" is the harm. Name who would
  care and why.
- **PII from a non-secret input.** The flow returns the account's full or masked-but-recoverable email, phone,
  display name or photo when you supply only a username. The oracle is now a data source, not a yes/no.
- **It defeats a protection the app clearly intends.** Registration deliberately says "if an account exists we
  have emailed you", but `/api/users/check-email` answers directly. The program's own design says this matters.
- **No rate limiting on the oracle, plus one of the above** — one answer becomes a bulk list.
- **It feeds an in-scope chain you can show.** The oracle gives you the exact internal id or tenant slug you
  then use for a §4.11 finding.
- **Resource enumeration that leaks a name.** `GET /api/documents/<id>` returns 403 *with the document title*
  for real ids and 404 otherwise. The title is the leak, not the existence.

What does not pay: a login form distinguishing "no such user" from "wrong password" on a general-purpose
consumer app, with rate limiting in place, and nothing else. File it as informational or leave it out. Do not
dress it up.

**Commonly missed.**

- The oracle in the *third* step of a flow — the email is accepted, then the 2FA step differs.
- A difference visible only in whether the email is actually sent, which you can only see with an address you own.
- `Set-Cookie` or `X-RateLimit-*` differing while status and body are identical.
- GraphQL `userByEmail(email:)` returning `null` versus an error.
- 403-versus-404 on object ids — the same oracle for resources.
- Registration rejecting an email as taken only after a CAPTCHA, while the API accepts it without one.
- WordPress `/?author=N` redirecting to `/author/<username>/` — username enumeration by design.
- A `HEAD` request answering differently from `GET`.

---

## 4.14 Card 11 — CORS and cross-origin data theft

**What it is.** The server tells the browser that an attacker's page may read an authenticated response. That is
a disclosure bug with a working exploit, not a config nit — provided credentials are in play.

**Where it hides.** API hosts rather than the web host. Also legacy `/api/v1`, download endpoints, token
endpoints, and the SSO host.

**Detect.** One request per origin variant, against an endpoint that returns data worth reading:

```
T=https://api.target.com/v2/users/me
for o in https://evil.com null https://target.com.evil.com https://eviltarget.com \
         https://sub.target.com http://target.com https://target.com:1337 \
         'https://target.com_.evil.com'; do
  printf '=== %s\n' "$o"
  curl -sI "$T" -H "Origin: $o" -H 'Cookie: <your-session>' \
    | grep -iE 'access-control-allow-(origin|credentials|methods|headers)|access-control-expose|vary'
done
```

| Origin sent | Response | Verdict |
|---|---|---|
| `https://evil.com` | `ACAO: https://evil.com` + `ACAC: true` | **Payable.** Any site reads the victim's data |
| `https://evil.com` | `ACAO: *`, no `ACAC` | Informational, unless the response is sensitive without cookies (API keys, signed URLs, tokens) |
| `https://evil.com` | `ACAO: *` + `ACAC: true` | Browsers reject this pair. Not exploitable — say so |
| `Origin: null` | `ACAO: null` + `ACAC: true` | **Payable.** Reachable from a sandboxed iframe or a `data:` URL |
| `https://target.com.evil.com` | reflected | **Payable.** `startsWith` / prefix check |
| `https://eviltarget.com` | reflected | **Payable.** `endsWith` check with no dot |
| `https://target.com_.evil.com` (or `-`, `{`, `}`, `^`, `` ` ``, `\|`, `~`, `!` in the label) | reflected | **Payable.** Regex-escape plus browser-tolerated characters |
| `https://sub.target.com` | reflected (wildcard subdomain trust) | Payable only with a real foothold on that subdomain: XSS, takeover, or user-controlled content. Both are out-of-scope classes — if one exists it is the delivery mechanism (`../CLAUDE.md` §1) |
| `http://target.com` | reflected + `ACAC: true` | Payable with a MITM precondition. State the precondition |
| `https://target.com:1337` | reflected | Port-insensitive check; payable if any service on any port there is attacker-influenced |
| any | no `ACAO` | Negative **for this endpoint**. Record the endpoint, not "CORS is fine" |
| any | reflected, no `Vary: Origin`, response cacheable | Combine with §4.15 — the permissive header can be served from cache |

Check the preflight too, because a permissive preflight can enable a header-authenticated read:

```
curl -sI -X OPTIONS "$T" -H 'Origin: https://evil.com' \
  -H 'Access-Control-Request-Method: GET' \
  -H 'Access-Control-Request-Headers: authorization,x-api-key' | grep -i '^access-control'
```

**Confirm.** The headers are not the proof — the read is. Minimal PoC, run against your own account:

```html
<!-- poc.html - open locally, logged in to the target in the same browser -->
<script>
fetch('https://api.target.com/v2/users/me', {credentials:'include'})
  .then(r => r.text())
  .then(t => { document.body.textContent = t.slice(0,200); });   // 200 chars is enough
</script>
```

For `Origin: null`:

```html
<iframe sandbox="allow-scripts" srcdoc="
<script>
fetch('https://api.target.com/v2/users/me',{credentials:'include'})
 .then(r=>r.text()).then(t=>parent.postMessage(t.slice(0,200),'*'));
</script>"></iframe>
```

RISK: do not exfiltrate to a third-party host. Render the result in the page and screenshot it, or post it to
your own listener. Never send another person's data anywhere — use your own test account (`../CLAUDE.md` §2).

**Escalate.**

- Severity follows what is readable: session token or API key > PII > account metadata > nothing sensitive.
- Sweep the whole API host once one endpoint reflects. Per-route CORS middleware is common and one route may
  expose far more than another.
- `Access-Control-Expose-Headers` letting the attacker read a token out of a response header.
- If a token is readable, state exactly what it authorises and stop. Do not use it.

**Commonly missed.**

- Only the `OPTIONS` preflight reflects and nobody re-checks the actual `GET`. Check both.
- Reflection only when a `Cookie` or `Authorization` header is present, because the middleware runs only for
  authenticated requests.
- Reflection on `/api/v1` while `/api/v2` is fixed.
- Reflected by the origin, overwritten by the CDN on cache hits — test with a cache buster.
- `ACAO: *` on an endpoint returning a pre-signed S3 URL: no credentials needed, still a leak.
- A WebSocket handshake with no `Origin` check — same data-read impact.
- `crossdomain.xml` / `clientaccesspolicy.xml` wildcards (§4.10).

---

## 4.15 Card 12 — Cache-based disclosure

**What it is.** A cache stores a response containing one user's data and serves it to someone else, or stores a
response for a URL it should never have cached.

**Where it hides.** Anywhere a CDN or reverse proxy sits in front of a dynamic app. Look for `Age`, `X-Cache`,
`CF-Cache-Status`, `X-Varnish`, `Via`, `X-Served-By`.

**Detect — web cache deception.** Take an authenticated page that shows your own data (`/account`,
`/api/v2/users/me`, `/dashboard`) and append something the cache treats as static:

```
/account.css                    # extension appended directly
/account/x.css                  # extra path segment the app ignores
/account%0a.css                 # newline
/account%23.css   /account%3F.css     # encoded # and ?
/account;x.css    /account%3bx.css    # semicolon (Java, Tomcat)
/account/..%2fx.css             # normalised by the cache, not by the origin
/account//x.css   /account.css?x=1
/api/v2/users/me/x.css  /api/v2/users/me;x.js  /api/v2/users/me/nonexistent.js
```

Extensions worth trying: `.css .js .jpg .png .gif .svg .ico .woff .woff2 .ttf .map .txt .pdf .json .xml .html`.

Safe test loop:

```
CB=$RANDOM$RANDOM
U="https://TARGET/account/${CB}.css"
# 1. authenticated: does the origin still return YOUR data at this URL?
curl -s -o /tmp/auth.html -w 'auth %{http_code} %{size_download}\n' "$U" -H 'Cookie: <your-session>'
grep -c 'your-own-email@yours.tld' /tmp/auth.html
# 2. unauthenticated, same URL: is it served from cache?
curl -s -o /tmp/anon.html -D /tmp/anon.hdr -w 'anon %{http_code} %{size_download}\n' "$U"
grep -iE 'x-cache|^age:|cf-cache-status|x-varnish' /tmp/anon.hdr
grep -c 'your-own-email@yours.tld' /tmp/anon.html
```

Confirmed when step 2, with no credentials, returns your own account data and the headers show a cache hit.

**Detect — cached authenticated responses, no deception needed.**

```
curl -sI https://TARGET/account -H 'Cookie: <your-session>' \
  | grep -iE 'cache-control|pragma|expires|vary|^age|x-cache|surrogate-control'
```

Red flags on a response containing user data: `Cache-Control: public`, a positive `max-age` without `private`,
no `Vary: Cookie` (or no `Vary: Authorization` on a token API), `Cache-Control` absent entirely,
`Surrogate-Control: max-age=` set for the CDN.

**Detect — cache key confusion.** Which parts of the request are *not* in the cache key:

| Unkeyed candidate | Probe |
|---|---|
| `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server` | send with a unique `?cb=`, see if the response changes and then persists |
| `X-Original-URL`, `X-Rewrite-URL` | a routing override that gets cached |
| `X-Forwarded-Scheme` / `-Proto` | a cached redirect loop |
| Extra query parameters | `?utm_x=1` — is the key the full query or just the path? |
| Parameter order and duplicates | `?a=1&b=2` versus `?b=2&a=1`; `?a=1&a=2` |
| Fat GET (a body on a GET) | ignored by the cache, honoured by the origin |
| `Accept-Encoding`, `Accept-Language`, cookie subsets | check `Vary` |

That is cache *poisoning*. Technique lives in `03-bypass-and-blind.md`; it belongs to this card only when the
payload is "someone else's data" or "a response the victim should not see".

RISK — this is the one card where a mistake harms other users. Rules:

- Always append a unique cache buster (`?cb=<random>`, or a random path segment) so your cached entry is one
  only you will request. Never test on a bare shared URL like `/` or `/login`.
- Use your own account's data as the marker. Never use another user's page as the source.
- Never inject an active payload (script, redirect) into a cached response. The proof is "my data was served
  unauthenticated at this URL", not "I made the homepage pop an alert for everyone".
- If you do land a cached response containing another user's data: stop, do not refresh, purge if the app
  documents a purge, and report immediately (`../CLAUDE.md` §4).
- A handful of requests per URL. This is not a fuzzing exercise.

**Confirm.** Save three things: the authenticated response, the unauthenticated response to the same URL, and
the cache headers of the second. State the TTL you observed (`Age` growing across two requests) and the cache
product from the headers.

**Escalate.** Severity tracks what was cached: session or CSRF token > full account page with PII > email
address only > nothing sensitive. Also state whether the URL is attacker-requestable or requires the victim to
visit it — a deception URL the victim must visit is the weaker case. Say which it is.

**Commonly missed.**

- `.css` failing while `/x.js` or `;x.css` works. Try the matrix, not one variant.
- API endpoints, not just HTML pages. `/api/v2/users/me/x.json` is the high-value one.
- Missing `Vary: Origin` on a CORS response (§4.14) — the permissive `ACAO` gets cached and served broadly.
- A cached `Set-Cookie` on a response with an `Age` header: session sharing, high severity. Look for it on purpose.
- Cached 401/403 responses: an availability quirk, not a disclosure. Do not report it as one.
- Browser-cache-only findings (`no-store` missing) are usually informational — the shared-computer story is
  weak. Do not inflate it.

---

## 4.16 Card 13 — Token and secret leakage in transit

**What it is.** The app moves a secret through a channel that records or forwards it.

**Where it hides.** URLs, `Referer`, third-party requests the page makes, client telemetry, logs, and the
token's own contents.

**Detect — secrets in URLs.** Grep everything you already have (proxy history, `gau`, JS, emails):

```
grep -ohiE '[?&](token|access_token|id_token|refresh_token|auth|authorization|api_?key|apikey|key|secret|session|sid|sessionid|jwt|code|state|password|passwd|pwd|otp|pin|reset|reset_token|invite|invitation|confirmation_token|signature|sig|email)=[^&[:space:]"]{6,}' \
  evidence/gau.txt evidence/katana.txt evidence/js/*.js | sort -u
```

Then work out whether the URL actually leaks:

| Channel | Check |
|---|---|
| `Referer` to third parties | Does the page whose URL holds the token load any third-party resource (analytics, fonts, maps, chat, ads)? `grep -oE 'src="https?://[^"]+"' page.html` |
| `Referrer-Policy` | `curl -sI <page>` — absent, `unsafe-url` or `no-referrer-when-downgrade` sends the full URL. `strict-origin-when-cross-origin` (the modern browser default) strips the path, which weakens the finding. Say so honestly |
| User-chosen links / `target=_blank` | A link on the token page sends the full URL to a destination the user picks |
| Click-trackers in email | `click.<vendor>/...?url=https://target/reset?token=` — the tracker sees the token. Real leak |
| Server and proxy logs | `/server-status` (§4.8), log files (§4.5), log viewers. A token in a log you can read is the strong version |
| Browser history, bookmarks, pasted links | Real but low severity on its own |
| Client telemetry | below |

**Detect — client telemetry payloads.** List the outbound third-party targets, then read the payloads:

```
grep -ohiE 'https?://[a-z0-9.-]*(sentry|bugsnag|rollbar|datadog|newrelic|segment|amplitude|mixpanel|fullstory|hotjar|logrocket|smartlook|clarity|intercom|google-analytics|googletagmanager|analytics|track|telemetry)[a-z0-9.-]*/[^"'"'"' ]*' \
  evidence/js/*.js | sort -u
```

Check each payload for: the full URL with a token, the user's email, the `Authorization` header, request bodies,
form values, and session-replay content.

| Item | Verdict |
|---|---|
| Sentry DSN in the bundle | Public by design. Informational. Payable with a second fact: it is a legacy DSN with a secret half (`https://key:secret@`), or the project is internal-only and you can show event injection |
| Sentry / LogRocket / FullStory capturing a password or token field | Real finding: secrets forwarded to a third party. Show the outbound request, value redacted |
| GA / GTM receiving `document.location` containing a token | Real finding, same shape |
| Session replay recording PII with no masking | Real finding on a privacy-sensitive app. State what was captured |
| Analytics receiving a user id or email | Usually informational unless the program's policy says otherwise |

**Detect — the token's own contents.** Decode, never crack:

```
T='eyJhbGciOi...'
for p in 1 2; do echo "$T" | cut -d. -f$p | tr '_-' '/+' | base64 -d 2>/dev/null | jq . ; done
```

| In the JWT | Meaning |
|---|---|
| `alg: none`, or `HS256` with a key you found in §4.4 | Forgeable. Report it; do not forge another user's token |
| Internal emails, employee ids, department names | PII and internal structure disclosure |
| `roles`, `scopes`, `permissions`, feature flags | The authz model, for free |
| `iss` / `aud` naming an internal IdP host | Internal surface; reachability check only |
| `kid` containing a path (`../../keys/x`) | Injection into key lookup → `01-injection.md` |
| `jku` / `x5u` pointing at an internal or attacker-controllable URL | SSRF plus key confusion. SSRF is out of scope (`../CLAUDE.md` §1) — one line in `out-of-scope.md`; the *disclosure* is the internal URL |
| The whole user record in the claims | Excess data (§4.11), and it is in every request log |
| Long or absent expiry | Session management, not this class. Leave it out |
| A non-JWT blob that decodes to internal JSON | Session structure disclosure. Useful, usually low |

Also compare: OAuth `code` / `state` / `id_token` in the query (logged) versus the fragment (not logged), and
`?access_token=` accepted as an alternative to the `Authorization` header on an API.

**Confirm.** Show the request or outbound payload containing the secret, redacted after the first few
characters. For a `Referer` leak, show both facts: the third-party resource the page loads, and the
`Referrer-Policy` header or its absence. Do not assert a leak you have not observed.

**Escalate.** A reset, invite or magic-link token in a leakable URL is the payable version — it is an
account-takeover primitive. State whether the token is single-use and how long it lives, tested with your *own*
token, twice. A session token in a URL is next. An email address in a URL is low. Internal claims are low.

**Commonly missed.**

- The token in the URL only on the first redirect and then stripped — still logged, still in history.
- `?token=` accepted alongside the documented header, so the UI is clean but the API is not. Check explicitly.
- The token echoed in a `Location` header on an error path.
- Password values reaching an error reporter because the form serialiser grabs every field.
- Tokens in `localStorage` readable by a third-party script the page loads. Keep the claim observable: the
  script has access.
- WebSocket URLs carrying the token in the query string (`wss://api/?token=`), which proxies log.
- A `state` parameter carrying a return URL that contains a session id.

---

## 4.17 Card 14 — File metadata and content leakage

**What it is.** Files the app serves carry more than their visible content.

**Where it hides.** Profile pictures, attachments, exported reports, generated PDFs, uploaded documents, and the
app's own static assets.

**Detect.** Fetch, then inspect. Start with your *own* upload to learn what the app strips, then check one file
served from another user. RISK: that second file is real user data — one file, then stop.

```
curl -s https://TARGET/uploads/avatars/12345.jpg -o /tmp/a.jpg
exiftool -G -a -u -ee /tmp/a.jpg
exiftool -gps:all -Make -Model -SerialNumber -Software -Artist -OriginalDocumentID -UserComment /tmp/a.jpg
exiftool -b -ThumbnailImage /tmp/a.jpg > /tmp/thumb.jpg && exiftool /tmp/thumb.jpg
strings -n 8 /tmp/a.jpg | head -40
```

| Format | Command | Typical leak |
|---|---|---|
| JPEG / HEIC / TIFF | `exiftool -G -a -u` | GPS coordinates, device make/model/serial, capture time, owner name, original filename, software, embedded thumbnail (the pre-edit image) |
| PNG | `exiftool`, `pngcheck -v` | `tEXt`/`iTXt` chunks with software, author, sometimes a source path |
| PDF | `exiftool`, `pdfinfo -meta`, `strings` | Author, Creator/Producer (internal tool names), `Title` with an internal path, creation host, XMP block, earlier revisions |
| PDF redaction | `pdftotext -layout file.pdf -`, `mutool draw -F txt`, `qpdf --qdf` | Text under a black rectangle is still extractable |
| DOCX / XLSX / PPTX | `unzip -o f.docx -d /tmp/d && cat /tmp/d/docProps/core.xml /tmp/d/docProps/app.xml` | `dc:creator`, `cp:lastModifiedBy` (employee names), `Company`, `Template` (a UNC path like `\\fileserver\templates\`), `TotalTime` |
| DOCX changes / comments | `grep -o 'w:author="[^"]*"' /tmp/d/word/document.xml`, `/tmp/d/word/comments.xml` | Deleted text and internal reviewer comments |
| XLSX hidden data | `/tmp/d/xl/workbook.xml` (hidden sheets), `sharedStrings.xml`, `externalLink*.xml` | Hidden sheets with source data, links to internal shares and DB connections |
| SVG | `grep -iE '<!--\|<metadata\|inkscape\|sodipodi' f.svg` | Editor metadata, absolute paths, comments |
| Video | `exiftool`, `mediainfo` | GPS, device, editing software |
| Server-generated PDF / Office | `exiftool` | The *server's* absolute paths, hostname, and library version — feeds `01-injection.md` |
| ZIP / archive | `unzip -l` | Original directory structure and usernames in paths (`/Users/jsmith/...`) |

**Confirm.** Show the command output with the sensitive value redacted (GPS truncated to a coarse location,
names masked). If the claim is that the file is public, show that it was served by an in-scope host with no
authentication.

**Escalate.**

- Precise GPS from other users' images on a platform that implies location privacy → real privacy finding.
- Employee names plus internal UNC paths and hostnames from generated documents → internal surface.
- An embedded thumbnail or a PDF text layer recovering content the user cropped or redacted → the strongest
  version of this card, because the user deliberately removed it.
- Server-generated PDFs embedding temp paths and the hostname → LFI/traversal targeting.
- Predictable upload URLs plus unstripped metadata → a bulk story. RISK: prove the predictability with two of
  *your own* uploads. Do not enumerate other users' files to build a list.

**Commonly missed.**

- The app strips EXIF from the resized image but still serves the original at a second URL (`/uploads/orig/`,
  `?size=full`, `_original.jpg`, or a signed S3 URL inside the JSON response).
- Thumbnails generated *before* a crop, so the thumbnail shows the cropped-out region.
- `exiftool -ee` finding a second full image embedded in the first.
- PDF incremental updates: `qpdf --qdf` or `strings` revealing earlier revisions of a "final" document.
- Generated invoices and reports carrying a full address the web UI masks.
- `Content-Disposition: attachment; filename="/var/app/tmp/xyz/report.pdf"` — a path leak in a header.

---

## 4.18 Card 15 — Third-party and passive sources

**What it is.** The leak is not on the target's host. It is on GitHub, in an archive, on a SaaS board, in a
package registry, or on a paste site.

**Where it hides.** Everywhere the target's developers work.

**Detect — code search.**

```
gh search code --owner TARGETORG 'password'
gh search code --owner TARGETORG 'BEGIN RSA PRIVATE KEY'
gh search code --owner TARGETORG --filename .env
gh search code --owner TARGETORG --filename .npmrc '_authToken'
gh search code --owner TARGETORG --filename Jenkinsfile 'credentials('
gh search code --owner TARGETORG --language yaml 'AWS_SECRET_ACCESS_KEY'
gh search code '"api.target.com" api_key'
gh search code '"target.com" "Authorization: Bearer"'
gh search code '"@target.com" password'
gh search code '"internal.target.com"'
gh search code '"jdbc:mysql://" target'

trufflehog github --org=TARGETORG --results=verified,unknown
trufflehog github --repo=https://github.com/TARGETORG/REPO --since-commit=HEAD~500
```

Also search commits and issues (`gh search commits`, `gh search issues`), gists by employee handles, and forks
of the org's repos — a fork can retain a commit the org force-pushed away.

**Detect — archives and history.**

```
gau --subs target.com --threads 5 > evidence/gau.txt
grep -Ei '\.(bak|old|sql|zip|tar\.gz|log|env|json|xml|txt|yml|conf|ini)(\?|$)' evidence/gau.txt | sort -u
grep -E '\?' evidence/gau.txt | sed 's/=[^&]*/=/g' | sort -u > evidence/old-params.txt
curl -s 'https://web.archive.org/cdx/search/cdx?url=target.com/*&output=text&fl=original,timestamp&collapse=urlkey&limit=5000' \
  -o evidence/cdx.txt
```

Everything in `old-params.txt` goes into the ledger. Old parameters are often still accepted and unpatched.

**Detect — infrastructure search.**

```
# Shodan
ssl.cert.subject.CN:"target.com"
ssl:"Target Inc"
http.favicon.hash:<hash>
http.title:"Target Admin"
org:"Target Inc" port:9200,5601,2375,6379,27017
# Censys
services.tls.certificates.leaf_data.subject.common_name: "target.com"
services.http.response.html_title: "Target Admin"
# Certificate transparency
https://crt.sh/?q=%25.target.com&output=json
```

**Detect — DNS.**

```
dig +short TXT target.com          # SPF ip4: blocks and vendor verification records
dig +short MX target.com
dig +short CNAME status.target.com # SaaS vendor per subdomain
dig +short TXT _dmarc.target.com
```

SPF `include:` and verification TXT records give you the vendor list: which CRM, support desk, CI, error
tracker. That tells you which SaaS boards to look for, and which third-party logins the app trusts.

**Detect — public SaaS boards and docs** (search engines only, no requests to the target):

```
site:trello.com "target.com"              site:trello.com "Target" password
site:*.atlassian.net "target"             site:target.atlassian.net
site:confluence.* "target" credentials
site:*.postman.co "target.com"            site:documenter.getpostman.com "target.com"
site:docs.google.com "target.com"         site:drive.google.com "target"
site:*.notion.site "target"               site:notion.so "target.com"
site:*.sharepoint.com "target"            site:pastebin.com "target.com"
site:gist.github.com "target.com"         site:jsfiddle.net "target.com"
site:codepen.io "api.target.com"          site:replit.com "target.com"
site:stackoverflow.com "target.com" api_key
"target.com" filetype:env | filetype:sql | filetype:log | filetype:bak | filetype:xls
```

**Detect — package registries.**

```
curl -s 'https://registry.npmjs.org/-/v1/search?text=scope:targetorg' | jq -r '.objects[].package.name'
npm view @targetorg/somepkg
pip download somepkg --no-deps -d /tmp/p && tar tzf /tmp/p/*.tar.gz
```

Look for: an internal package published by accident containing source or a token; a package whose dependencies
name an internal-only package, which names an internal registry; an `.npmrc` with `_authToken` inside a
published tarball.

RISK: an unclaimed internal package name is a dependency-confusion *attack* if you publish it. Do not publish
anything. Report the unclaimed name and the evidence that the target depends on it. Publishing is an attack on a
build system you were not authorised to touch.

**Confirm.** Archive the evidence: the search query, the repo/commit/file path, a screenshot, and the redacted
secret. Then decide whether it is live **without using it**:

- Identify the service from the key prefix and format.
- Check whether the file is still present and when it was committed.
- Note the in-scope asset it belongs to from surrounding context (a hostname next to the key, the README).
- For a cloud key, the program validates it. Do not run `sts get-caller-identity`. Do not authenticate.
  `../CLAUDE.md` §2: never use a credential you found.

**Scope caution — read before reporting.** These hosts are not the program's assets.

1. If the policy covers "our secrets, found anywhere", report it. Most do, under leaked credentials.
2. If the policy is silent, report the secret, say exactly where you found it and that you did not use it, and
   frame the impact in terms of the *in-scope* asset it unlocks.
3. If the finding is only "this SaaS board is public" and nothing touches an in-scope asset, it is out of scope:
   one line in `../targets/<target>/out-of-scope.md`, move on.
4. Never probe, authenticate to, brute force or scan the third-party host (`../CLAUDE.md` §2, "No third
   parties"). Reading a public page is fine.
5. Employee personal repos and accounts: read what is public, report the secret, do not investigate the person,
   and keep their personal details out of the report beyond what identifies the leak.
6. Unsure whether the asset is in scope → stop and ask (`../CLAUDE.md` §4).

**Escalate.** A passive-source finding is only payable when you can tie it to an in-scope asset. The chain you
have to write is: *this secret* → *this service* → *this in-scope host or account*. Without the third link it
closes as informational, or out of scope.

| What you found | Informational | Payable when |
|---|---|---|
| Leaked cloud key (AWS/GCP/Azure) | key format alone | you can name the in-scope asset it administers, from surrounding code or config |
| Leaked API token (Stripe, Slack, SendGrid, Twilio) | a test/sandbox key, a public publishable key | it is a live secret key, and the account is the target's production account |
| DB connection string | `localhost` / `example` values | the host resolves to an in-scope asset, or the credentials match a pattern used in a reachable service |
| Source in a public repo or old bundle | generic framework code | it reveals an auth check, a signing secret, an internal endpoint, or a hardcoded account you can then reach |
| Internal hostname (CT log, SPF, repo) | a name that does not resolve | it resolves and serves an in-scope app, which becomes new surface (`00-surface-and-ledger.md` §2.6) |
| Public SaaS board / Postman collection | marketing or roadmap content | it carries a live token, an internal URL, or credentials for an in-scope system |
| Unclaimed internal package name | the name alone | you can show the target's build depends on it — report the name, publish nothing |

Ceiling: a confirmed live production credential for an in-scope system is the top of this card, and you reach it
**without authenticating**. Identify, redact, report. `../CLAUDE.md` §2 — never use a credential you found, and
§4 — real data means stop and report.

Escalation that is *not* yours to do: once you hand over a live key, the program rotates and validates it. Do
not verify it yourself to strengthen the report. An unverified-but-well-evidenced key is a good report; a
verified one you authenticated with is a policy violation.

**Commonly missed.**

- The secret is in an old commit of a still-public repo, not in `HEAD`. Use full history.
- A second GitHub org from an acquisition (`targetlabs`, `target-oss`).
- Wayback copies of a bundle holding a secret that was later removed (§4.6).
- A public Postman collection with an environment file containing a live token.
- A Grafana, Kibana or Metabase dashboard indexed by a search engine.
- A `.env` baked into a public Docker image: `docker history --no-trunc <image:tag>`.
- SPF `include:` naming a vendor whose subdomain is a forgotten in-scope host.
- CT logs naming `*.internal.target.com` hosts that never appear in public DNS.

---

## 4.19 Card 16 — Timing and side-channel oracles

**What it is.** The response time answers a question the body will not.

**Where it hides.** Authentication (a hash computed only for existing users), token and signature comparison
(non-constant-time `==`), cache hit versus database miss, an internal lookup that happens only for valid input,
and blind injection (`01-injection.md`).

**When a timing delta is a real disclosure.**

| Situation | Real? |
|---|---|
| Login: existing user +180 ms because bcrypt runs; unknown user returns fast | Yes — an existence oracle. Payability then follows §4.13's impact story |
| Password reset sending mail synchronously only for real accounts | Yes, same |
| Token or HMAC comparison time varying with the number of matching leading bytes | Yes, and the strongest form — it can recover a secret. Prove the gradient on a token you own |
| 2FA code verification differing for a valid versus invalid prefix | Yes, high value |
| Registration hitting a remote vendor only for new addresses | Yes |
| Cached versus uncached object | Technically yes, low value — `Age`/`X-Cache` already told you |
| Internal host reachable versus timing out | Yes for internal mapping; the SSRF class itself is out of scope, note it |
| 30 ms delta on a public endpoint with no secret behind it | No |
| A delta that disappears when you re-measure later | No — that was load |
| A delta explained by response size | No — measure `time_starttransfer`, or normalise by bytes |

**How to measure credibly.** One request proves nothing. Interleave, use medians, report n.

```
: > /tmp/a.txt; : > /tmp/b.txt
for i in $(seq 1 20); do
  curl -s -o /dev/null -w '%{time_starttransfer}\n' -X POST https://TARGET/api/auth/login \
    -H 'Content-Type: application/json' -d '{"email":"real@yours.tld","password":"Wrong-Passw0rd!"}' >> /tmp/a.txt
  sleep 0.25
  curl -s -o /dev/null -w '%{time_starttransfer}\n' -X POST https://TARGET/api/auth/login \
    -H 'Content-Type: application/json' -d '{"email":"nope-zzz@yours.tld","password":"Wrong-Passw0rd!"}' >> /tmp/b.txt
  sleep 0.25
done
stat() { sort -n "$1" | awk '{v[NR]=$1} END {
  m=(NR%2)?v[(NR+1)/2]:(v[NR/2]+v[NR/2+1])/2;
  printf "%s n=%d median=%.3f p25=%.3f p75=%.3f min=%.3f max=%.3f\n", FILENAME, NR, m, v[int(NR*0.25)+1], v[int(NR*0.75)+1], v[1], v[NR] }'; }
stat /tmp/a.txt; stat /tmp/b.txt
```

Rules for a credible claim:

- **n >= 20 per class**, interleaved A/B/A/B so load and drift cancel out.
- **Report the median and the IQR.** Never one request, never the mean — one outlier destroys a mean.
- The delta must exceed the p25–p75 overlap. If the ranges overlap, you have nothing.
- Use `time_starttransfer` (server think time), not `time_total` (includes body download).
- Re-run at a different time of day before reporting. A delta that does not reproduce is noise.
- Control for status code and response size. Different codes or sizes mean you are measuring something else —
  report *that* instead.
- Behind a CDN, confirm you hit the same edge (`X-Served-By` / `CF-RAY` consistency) or you are measuring
  geography.

RISK: `../CLAUDE.md` §2 caps *time-based injection probes* at 3 per parameter, because those force the server to
sleep. This measurement injects no delay — it is passive observation — so that cap does not apply, but the
5 req/s cap does. Keep it to 20+20 samples with `sleep 0.25`, and do not run a timing harness against an auth
endpoint for minutes: it looks like credential stuffing and will get you blocked.

**Confirm.** In the report: both request bodies, the harness, n, both medians, both IQRs, and the second run's
numbers. State the mechanism you believe causes it (bcrypt, a remote lookup, a non-constant-time compare).

**Escalate.** A timing existence oracle inherits §4.13's rules — it needs the same impact story. A
comparison-leak oracle on a token or HMAC is different: that is secret recovery and it is payable on its own.
Prove the gradient with a token you own, then stop. Do not recover anyone else's secret.

**Commonly missed.**

- Measuring `time_total` on responses of different sizes and calling it a timing leak.
- Only testing unauthenticated endpoints. The interesting comparisons are usually post-auth.
- A timing signal in a webhook or email delivery rather than the HTTP response.
- `X-Runtime` and `Server-Timing` handing you the server-side time with zero measurement noise (§4.12). Check
  for those before building a harness.
- A `HEAD` request giving a cleaner signal than `GET`.

---

## 4.20 Card 17 — Error-message oracles as extraction channels

**What it is.** The bridge to `01-injection.md`. A disclosure primitive that is worthless as a standalone report
becomes the exfiltration channel that makes a blind injection confirmable. Read this card whenever an injection
row is `suspicious` with no visible output.

**Where it hides.** In the differentials you already found while working §4.7, §4.9 and §4.13.

**Channel inventory — pick the highest-bandwidth one available.**

| Channel | Bits per request | Notes |
|---|---|---|
| Verbose error echoing a value | Whole strings | Fastest. Type-cast, XPath and XML errors print data |
| Error naming a column, field or table | Many | Schema extraction with no data access |
| Field-suggestion error (GraphQL "Did you mean") | Many | §4.9, schema only |
| Distinct error *types* | log2(classes) | e.g. syntax versus type versus auth error |
| Error / no error | 1 | The universal fallback |
| Response length delta | 1+ | Needs the §2.4 baseline |
| Status code delta (200 versus 500) | 1 | Watch for a WAF answering instead of the app |
| Ordering / sort difference | 1 per comparison | `ORDER BY` with a conditional |
| Timing | 1 | Slowest and noisiest. §4.19. Last resort |
| Out-of-band (DNS / HTTP callback) | Many | Best when available — `03-bypass-and-blind.md` |

**Build the channel.** Prove a true/false pair before extracting anything:

```
true  -> ...&id=1 AND 1=1     -> baseline response
false -> ...&id=1 AND 1=2     -> different response
then  -> ...&id=1 AND (SELECT SUBSTR(current_user,1,1))='a'
```

Error-text channels by sink. Payload detail stays in `01-injection.md`; this is the channel, not the exploit.

| Sink | Channel |
|---|---|
| MySQL | `EXTRACTVALUE(1,CONCAT(0x5c,(SELECT DATABASE())))`, `UPDATEXML`, duplicate-key `floor(rand())` |
| PostgreSQL | `CAST((SELECT current_database()) AS int)` → `invalid input syntax for integer: "..."` |
| MSSQL | `CONVERT(int,(SELECT db_name()))` → `Conversion failed when converting the varchar value '...'` |
| Oracle | `CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))`, `TO_NUMBER((SELECT ...))` |
| SQLite | `CAST(... AS int)` errors |
| XPath / XML | A malformed expression echoing the node value |
| XXE | Error-based DTD reflecting file content in the parser error. **Use an OOB DTD, never a billion-laughs payload** (`../CLAUDE.md` §2) |
| SSTI | Template error rendering the object's repr — often the whole config object |
| LDAP | Differential on filter validity; rarely verbose |
| Deserialisation | Class-not-found errors naming the classpath |
| Path / file | `No such file or directory: '/var/www/app/<input>'` — absolute path plus traversal confirmation |
| ORM | Validation errors naming model fields and types |
| Regex / parser | The offset in the message is a position oracle |

**Confirm.** The oracle is confirmed when a controlled true/false pair reproduces and you can answer a question
whose answer you already know (`SUBSTR(version(),1,1)='5'` versus `='9'`). Save both responses.

**Escalate.** This card *is* the escalation. Constraints:

- Extract **schema, not contents** (`../CLAUDE.md` §2). Database name, version, current user, table and column
  names. That is a complete injection report.
- One record maximum if a value is genuinely needed to prove that sensitive data is reachable. Redacted.
- Character-at-a-time extraction is request-heavy. Stay at 5 req/s, extract the shortest sufficient string, stop.
- `sqlmap` is acceptable for confirmation with `--technique=BE --level=2 --risk=1 --delay=0.2 --threads=1` and an
  explicit `--dbms` once you know it. Never `--dump`, `--os-shell` or `--file-write`.

**Write-up rule.** The disclosure is not a separate report. Ledger it as a channel:

```
host: app.target.com | vector: /search?q= | sink: sqli-blind | state: confirmed
  channel: 4.20 error-text (Postgres CAST) — evidence/sqli-search-3.txt
  fallback channel: response-length delta (baseline len 1843 vs 1840)
```

Record both the verbose channel and a fallback. If the program patches the error page but not the injection, a
retest must not lose you the bug.

**Commonly missed.**

- Reporting the verbose error alone when the injection behind it was the actual bug.
- Abandoning a sink because it returns a generic 500, without checking length, status, ordering and timing.
- Mistaking a WAF block page for a backend oracle. A 403 from a WAF says nothing about the backend —
  `../CLAUDE.md` §6 rule 6, then `03-bypass-and-blind.md`.
- The oracle living in a second-order render site (an export, an admin view, an email) rather than the immediate
  response — `../CLAUDE.md` §6 rule 7.
- Two error shapes that both read "invalid input" and differ by 2 bytes.

---

## 4.21 Proof and redaction discipline

Proving a leak does not require collecting the leak. Minimum viable evidence, per class:

| Finding | Minimum evidence | Do not |
|---|---|---|
| `.git` exposed | `GET /.git/HEAD` request and response, the `/.git/config` remote, `git log --oneline -10` | Publish the source dump or push it anywhere |
| `.env` / config leak | Request and response with every value masked after 4 characters, plus the key names | Paste live credentials unredacted unless the program asks |
| Secret (any source) | Service name, key prefix (`AKIAIOSFODNN****`), where and how you found it | Authenticate with it. Ever |
| Source map | `sources[]` count, five filenames, one recovered snippet | Attach the whole recovered tree |
| Stack trace | The request, the trace, and the one line that matters (path, credential, host) | Fuzz until you have 50 traces |
| Heapdump | `HEAD` showing 200 and the size, plus a count like "412 strings match `Bearer `" | Attach the dump, enumerate sessions, or keep it after the report |
| Excess API fields | One request, the field path, a redacted value, and the grep showing the app's JS never references it | Pull 1000 records "to show scale" |
| Another user's data | One record, masked to the minimum that proves it is not yours (`j***@g***.com`, last 2 digits of a phone) | Collect a second record |
| Directory listing | The listing plus one fetched file that should not be public | Download the directory |
| CORS | Headers plus a screenshot of the PoC reading *your own* account | Run the PoC against another user |
| Web cache deception | Authenticated response, unauthenticated response, cache headers | Test a shared URL or leave a poisoned entry behind |
| Enumeration | 3 requests (2 values you own, 1 nonexistent) with the diff marked | Enumerate real users |
| EXIF / metadata | `exiftool` output with GPS truncated and names masked | Download a gallery |
| Timing | Harness, n, both medians, both IQRs, run twice | Recover a real token |
| Bucket listing | Listing with `max-keys=20` plus one object as proof | List the whole bucket, or test writes |

Rules:

1. **Stop reading the moment you know.** The finding is "this endpoint returns other users' email addresses",
   and one record proves it. `../CLAUDE.md` §4: real user data means stop and report.
2. **Redact in the evidence file, not only in the report.** `evidence/` gets attached. Mask as you save. If you
   must keep a raw capture, name it `<slug>-RAW-DO-NOT-ATTACH.txt` and note it in `notes.md`.
3. **Redaction pattern** — keep enough to prove the type, not enough to use:
   `AKIAIOSFODNN****` · `eyJhbGciOiJIUzI1NiJ9.<redacted>.<redacted>` · `j***.d**@c*****.com` ·
   `+1-***-***-**41` · `$2y$10$<redacted 53 chars>` · GPS `37.77xx, -122.41xx`.
4. **Never authenticate with what you found** — not the DB credential, not the API key, not a leaked session,
   not another account's reset token. That is the line between a report and unauthorised access.
5. **Do not keep what you do not need.** Delete heapdumps, backup archives and DB dumps once the report is
   accepted. Note the deletion in `notes.md`.
6. **Crop and mask screenshots** before they go in a report. A screenshot is evidence, not a raw dump.
7. **Say what you did not do.** "I did not enumerate the dump." "I did not use the credential." It tells the
   triager you behaved, and it sets the impact honestly.
8. **One finding per file with a reproducible `curl`** (`../CLAUDE.md` §6 rule 9). A disclosure report without
   the exact request is not a report.

## 4.22 Severity honesty

Disclosure is where inflation is most tempting and most obvious to a triager. Use this table. Zero inflation.

| Raises severity | Does not raise severity |
|---|---|
| A live credential for an in-scope asset | "An attacker could use this to plan further attacks" |
| Another user's or another tenant's data, demonstrated | Your own data appearing in your own response |
| No authentication required | A version number with no confirmed exploitable CVE |
| No user interaction required | An RFC1918 address in a header that you cannot reach |
| Reachable from the public internet | An internal hostname that does not resolve and is not routable |
| A signing key or session secret (forgeable sessions) | A public-by-design key (Firebase web key, Stripe `pk_`, Maps browser key, Sentry DSN) with no second fact |
| Full source recovery | A directory listing of minified CSS and fonts |
| A working PoC a third party can run (CORS, cache) | A header configuration with no demonstrated read |
| A demonstrated *pattern* of bulk exposure | A theoretical bulk claim extrapolated from one record |
| A token that is still valid, with its lifetime stated | An expired or already-rotated token |
| The leak is the missing piece of another confirmed in-scope bug | The leak *might* help with a bug you did not find |
| Sensitive-by-context data (health, finance, adult, minors, HR) | An email address the user publishes on the site anyway |
| The program's policy names this class as valued | Your own view that it "should" be valued |
| Data the user actively deleted or redacted, recovered | Data the user chose to make public |
| Persistent exposure, still there on retest | A one-off error during a deploy window |

Phrasing discipline:

- Name the class plainly: "verbose stack trace on `POST /api/v2/search`", not "critical information disclosure".
- State the escalation you achieved, and separately the one you did not: "the trace leaks the absolute webroot
  path; I did not find a file-read primitive to pair it with".
- If you think it is informational, say so, and file it anyway if the program wants informational reports. Do
  not pad it to Medium.
- Severity measures impact, not effort. A hard-to-find informational is still informational.
- If the program uses CVSS, show the vector string and be able to defend every metric. `AC:L`, `PR:N`, `UI:N`
  are claims, not decorations.






