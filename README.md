# ngx_http_waf_module — an nginx edge firewall

A lean, fast **edge firewall** for vanilla nginx, built as a dynamic C module
plus the stock `ngx_mail` proxy, sharing a single IP-reputation core. It is
*not* a heavy WAF — it is a slim edge filter: scanner path blocking,
User-Agent classification (the `$waf_type` variable), Apache fingerprint
spoofing, libloc-based geo/reputation filtering (block- **or** allow-list),
and HTTP + SMTP + stream (L4) protection driven by the same reputation engine.

It replaces a legacy `nginx-firewall.conf` (~130 location-based scanner
rules riddled with over-broad prefixes, unanchored substring matches, and
dead rules) with compiled, anchored, hot-reloadable rules.


## Goals & design constraints

- **Edge filtering, not deep inspection.** Block known scanner/bot paths,
  reject bad IP reputation early, and hide the server fingerprint.
- **HTTP/3 (QUIC) + 0-RTT** via native OpenSSL QUIC — this is why OpenSSL
  3.5.x is bundled (the host OpenSSL 3.0.2 is too old for native QUIC).
- **No shared writable state.** Deliberately *out of scope*: custom
  rate-limiting (stock `limit_req`/`limit_conn` suffice), Hyperscan (PCRE2
  with JIT is enough for ~130 rules), a MaxMind/libloc library dependency
  (the geo reader is an embedded nanolibloc adaptation, libc-only), request
  body inspection, dynamic auto-ban, and TLS fingerprint spoofing.
  **Consequence:** there is no slab, no rbtree, no shared memory. The geo
  database is read-only (shared across workers via fork copy-on-write),
  every list/pattern is resolved at configuration time, and workers are
  stateless with respect to each other.
- **One reputation engine, three heads.** The HTTP `PREACCESS` handler, the
  SMTP `auth_http` endpoint, and the stream (L4) `ACCESS` handler all call
  the *same* `ngx_http_waf_reputation_check()` on the client IP. The inputs
  live in a shared `ngx_waf_rep_conf_t` embedded in each head's config.


## Repository layout

```
.
├── CMakeLists.txt               super-build: fetch + build OpenSSL/zlib-ng/nginx
├── cmake/Versions.cmake         pinned PKG_* versions, URLs, SHA256 hashes
├── modules/ngx_http_waf/        the dynamic module
│   ├── config                   nginx addon build descriptor (one .so, 2 modules)
│   ├── scanners.list            scanner path patterns (hot-reloadable)
│   ├── lists/                   UA signature lists (hot-reloadable)
│   │   ├── scanner-ua.list         security tools  -> $waf_type=scanner
│   │   ├── ai-crawler.list         LLM/AI crawlers -> $waf_type=ai-crawler
│   │   ├── crawler.list            search engines  -> $waf_type=crawler
│   │   └── bot.list                social/monitor/HTTP libs -> $waf_type=bot
│   └── src/
│       ├── ngx_http_waf_module.c  HTTP module glue: directives, phases, merge
│       ├── ngx_http_waf.h         shared HTTP types / loc_conf
│       ├── waf_match.{c,h}         scanner regex buckets + UA classification
│       ├── waf_spoof.{c,h}         Apache Server header + error-page spoof
│       ├── waf_geo.{c,h}           libloc location.db mmap reader
│       ├── waf_rep.h               shared rep_conf + reputation prototypes
│       ├── waf_reputation.{c,h}    shared reputation core + config helpers
│       ├── waf_authhttp.{c,h}      ngx_mail auth_http content handler
│       └── waf_stream.c            ngx_stream_waf_module (L4 reputation head)
├── geodb/
│   ├── location.db              IPFire libloc database (uncompressed)
├── reference/                   nanolibloc.c (basis), loctest.c (geo oracle)
├── sandbox/                     runnable test env AND the build install prefix
│   ├── nginx.conf               full HTTP + mail example config   (tracked)
│   ├── certs/                   self-signed test cert/key          (tracked)
│   ├── html/                    test documents                     (tracked)
│   ├── sbin/nginx               installed by the build             (generated)
│   ├── modules/*.so             installed by the build             (generated)
│   └── conf/ logs/ *_temp/      nginx runtime dirs                 (generated)
```


## Building

The toolchain is a **CMake super-build**. From a clean checkout it downloads
version-pinned sources (OpenSSL, zlib-ng, nginx), builds them, and installs
the nginx binary + WAF module into the runnable `sandbox/` tree — no vendored
trees, no manual `./configure` dance.

### Prerequisites

- CMake ≥ 3.16, a C toolchain (gcc/clang), `make`, and network access
  (sources are fetched at build time).
- PCRE2 dev headers (linked dynamically) and the usual nginx build deps.
- Everything else is fetched and built by CMake:
  - **OpenSSL 3.5.7** — built from source and statically linked, because
    native QUIC needs OpenSSL ≥ 3.5 (the host's 3.0.2 is too old). nginx
    builds it in-tree via `--with-openssl=<src>`.
  - **zlib-ng 2.3.3** — built statically (`--zlib-compat --static`) and
    linked in place of the system dynamic zlib.
  - **nginx 1.30.2** — configured with the full flag set and the WAF module
    as a dynamic add-on.

Versions/URLs/hashes are pinned in [`cmake/Versions.cmake`](cmake/Versions.cmake);
bump a `PKG_*` there (or pass `-DPKG_*_VERSION=…`) to change a dependency.

### One-shot build

```sh
cmake -B build -S .
cmake --build build -j
```

This installs, into the `sandbox/` tree (the nginx prefix), at stable
repo-relative paths:

- `sandbox/sbin/nginx` — the binary (OpenSSL 3.5.7 + static zlib-ng)
- `sandbox/modules/ngx_http_waf_module.so` — the WAF dynamic module

(`sandbox/` doubles as the build install prefix and the runnable test env;
the generated `sbin/`, `modules/`, `conf/`, `logs/`, `*_temp/` are gitignored,
while `nginx.conf`, `certs/`, and `html/` are tracked.)

> **Note — clean-build stamp race.** On a *fresh* checkout the very long
> in-tree OpenSSL compile can make the first `cmake --build` step report a
> spurious non-zero exit before CMake writes its stamp. If that happens, just
> run `cmake --build build -j` **again** — the second pass finds the build
> done and proceeds to `make install`. Incremental builds are unaffected.

### Fast module iteration

Day-to-day module edits should not re-run the whole chain. After the first
full build, rebuild just the `.so` and refresh `sandbox/modules/` with:

```sh
cmake --build build --target waf_module
```

It runs `make modules` in the already-built nginx tree and copies the fresh
`ngx_http_waf_module.so` into `sandbox/modules/`.

### Verifying the build

```sh
sandbox/sbin/nginx -V                 # OpenSSL 3.5.7, --with-http_v3_module, --with-mail
ldd sandbox/sbin/nginx                # no libz.so -> zlib-ng is static
strings sandbox/sbin/nginx | grep -i zlib-ng
```

### ⚠️ Gotchas (read before you build)

1. **The OpenSSL-rebuild trap (handled).** Re-running nginx's `./configure`
   bumps `objs/Makefile`'s mtime, and the next `make` then tries a *full*
   OpenSSL rebuild. The super-build guards against this: before each nginx
   `make` it touches `<openssl-src>/.openssl/include/openssl/ssl.h` if
   present (a no-op on the first build). You do not need to do this by hand.

2. **A new module source file requires a re-configure.** Adding a `.c` to
   `modules/ngx_http_waf/config` is not picked up by the `waf_module` fast
   target alone — the nginx tree must be re-configured. Drop the configure
   stamp so the nginx ExternalProject re-runs `./configure` + `make` on the
   next build (without re-downloading the sources):

   ```sh
   rm -f build/nginx_ext-prefix/src/nginx_ext-stamp/nginx_ext-configure
   cmake --build build -j
   ```

   (Or wipe `build/` entirely for a clean, re-downloading run.)

3. **A dynamic `.so` is NOT hot-reloaded.** `nginx -s reload` does not load
   new module *code*. After rebuilding the `.so`, do a full **stop + start**
   of the running nginx. (Config and the scanner list / geo DB *are*
   reloadable — see below; only the compiled module code is not.)


## Configuration

### Loading the module

```nginx
load_module /path/to/sandbox/modules/ngx_http_waf_module.so;
```

### Directive reference

The directives below are the **HTTP** set: valid in `http`, `server`, and
`location` contexts, inheriting downward (merge), **except** `waf_mail_auth`,
which is `location`-only. `waf_blocklist`/`waf_allowlist`/`waf_trusted_proxy`
take a single CIDR each but may be repeated to build up a list. The reputation
and geo directives are mirrored in the **stream** context for the L4 head —
see [Stream (L4) protection](#stream-l4-protection). UA classification always
runs and is exposed as the [`$waf_type`](#user-agent-classification-waf_type)
variable, independent of `waf` / `waf_bot_block`.

| Directive | Args | Default | Purpose |
|---|---|---|---|
| `waf` | `on`\|`off` | `off` | Master switch for the HTTP `POST_READ` + `PREACCESS` handlers (reputation, UA block, scanner). Does **not** gate spoofing or `$waf_type` classification. |
| `waf_bot_block` | `on`\|`off` | `off` | Block only **hostile** User-Agents: `scanner` tools and empty/missing UA (→ 404). `crawler`/`ai-crawler`/`bot` are classified into `$waf_type` but **never** blocked by this flag. |
| `waf_scanner_list` | `<path>` | — | Load scanner **path** patterns from a file (compiled into action buckets). |
| `waf_scanner_ua_list` | `<path>` | — | UA signatures for security tools → `$waf_type=scanner`. |
| `waf_ai_crawler_list` | `<path>` | — | UA signatures for LLM/AI crawlers → `$waf_type=ai-crawler`. |
| `waf_crawler_list` | `<path>` | — | UA signatures for search-engine/archival crawlers → `$waf_type=crawler`. |
| `waf_bot_list` | `<path>` | — | UA signatures for social/monitor/feed/HTTP-library clients → `$waf_type=bot`. |
| `waf_server_token` | `<string>` | `Apache/2.4.68 (Unix)` | The fake `Server:` token and the error-page fingerprint. |
| `waf_geo_db` | `<path>` | — | Path to the libloc `location.db` (mmap'd read-only). |
| `waf_geo_block` | `<CC> …` | — | Block these country codes (ISO-3166 two-letter, plus IPFire specials A1/A2/A3/T1/XD) → 403. |
| `waf_geo_whitelist` | `<CC> …` | — | **Allow only** these countries; every other country and any IP with no geo record → 404. Wins over `waf_geo_block`. Repeatable / multi-arg. |
| `waf_flag_block` | `<flag> …` | — | Block by libloc network flag: `anonymous-proxy` (alias `anon`), `satellite`, `anycast`, `tor`, `drop`. |
| `waf_trusted_proxy` | `<cidr>` | — | Trust `X-Forwarded-For` only from these peers when deriving the canonical client IP. |
| `waf_blocklist` | `<cidr>` | — | Statically deny this network (→ 403). Repeatable. |
| `waf_allowlist` | `<cidr>` | — | Allow this network, short-circuiting all reputation checks. Repeatable. |
| `waf_mail_auth` | *(none)* | — | Turn this `location` into the `ngx_mail` `auth_http` endpoint. |
| `waf_mail_backend` | `<ip> <port>` | — | Upstream MTA returned as `Auth-Server`/`Auth-Port` on allow. **Numeric IP only** (the mail proxy cannot resolve hostnames). |
| `waf_status` | *(none)* | — | `location`-only. Turn this `location` into the lock-free statistics endpoint (see [Statistics / status endpoint](#statistics--status-endpoint)). Wrap it in an access-restricted location. |

### Scanner list file format

One PCRE2 pattern per line, with an optional trailing action token:

```
<pattern>[ <action>]        # action ∈ { 404 (default), 403, 444 }
```

- Lines are trimmed; blank lines and `#` comments are ignored.
- **Anchor every pattern with `^`.** Patterns match the normalized request
  URI (`r->uri`) case-insensitively; an unanchored pattern can match
  mid-URI and block legitimate paths.
- Patterns sharing an action are concatenated into **one** anchored
  alternation regex and JIT-compiled once, so matching is a single regex
  exec per action bucket at request time — not one exec per pattern.
- Actions map to: `404` → `NGX_HTTP_NOT_FOUND`, `403` → `NGX_HTTP_FORBIDDEN`,
  `444` → `NGX_HTTP_CLOSE` (drop the connection).
- The file is **hot-reloadable**: `nginx -s reload` re-reads and recompiles
  it; the old regex is freed with the old config pool.

Example:

```
^/wp-
^/xmlrpc\.php$
^/\.git
^/phpmyadmin/ 403
^/owa 444
```

### User-Agent classification (`$waf_type`)

Every request's `User-Agent` is classified into exactly one bucket, exposed
as the **`$waf_type`** nginx variable. Classification is **decoupled from
blocking**: it always runs (even under `waf off`), and the operator decides
what to do with each class.

| `$waf_type` | Source | Blocked by `waf_bot_block`? |
|---|---|---|
| `scanner` | `waf_scanner_ua_list` (sqlmap, nikto, nmap, nuclei, …) | **yes** → 404 |
| `ai-crawler` | `waf_ai_crawler_list` (GPTBot, ClaudeBot, CCBot, Bytespider, …) | no (flag-only) |
| `crawler` | `waf_crawler_list` (Googlebot, bingbot, Baiduspider, …) | no (flag-only) |
| `bot` | `waf_bot_list` (facebookexternalhit, curl, python-requests, …) | no (flag-only) |
| `regular` | no signature matched (assume human) | no |
| `empty` | missing / empty `User-Agent` | **yes** → 404 |

Lists are matched in **priority order** scanner → ai-crawler → crawler → bot;
the first hit wins (so `Applebot-Extended` resolves to `ai-crawler`, not the
`Applebot` token in `crawler.list`). `spider` is **not** a separate class —
industry practice treats spider ≡ crawler, so spider tokens live in
`crawler.list`.

**UA list file format** — one case-insensitive PCRE2 fragment per line; blank
lines and lines starting with `#` are ignored; the whole trimmed line is the
pattern. Note there is **no** action token and **no inline comments** (`#`
only starts a comment at the beginning of a line). Each list compiles to one
alternation regex (a single exec per category) and is **hot-reloadable**.

```
# bot.list (excerpt) -- full-line comments only, one fragment per line
facebookexternalhit
python-requests
curl/
^Java/
Apache-HttpClient
```

In the excerpt above, `curl/` matches `curl/8.5.0` (the `/` is a literal), and
`^Java/` anchors at the start of the UA so it matches `Java/1.8` but not a
browser that merely mentions "java" elsewhere.

> **Watch-outs.** Tokens are regex fragments: `.` and `/` are significant
> (escape `\.` for a literal dot when you need precision — over-matching is
> usually harmless). **Never** seed a bare `bot`, `spider`, `crawl`, or
> `Mozilla` token — they false-positive on legitimate clients and on each
> other. Use the distinctive product/library name.

The `$waf_type` variable is `NOCACHEABLE` and works in `if`, `add_header`,
`log_format`, `map`, etc. — use it to tag, route, or rate-limit by class
without blocking:

```nginx
# surface the classification to upstreams / logs
add_header X-WAF-Type $waf_type always;
proxy_set_header X-Client-Class $waf_type;

# e.g. send AI crawlers to a thin/204 location instead of blocking them
if ($waf_type = ai-crawler) { return 204; }
```

Seed lists ship in [`modules/ngx_http_waf/lists/`](modules/ngx_http_waf/lists/),
distilled from Matomo `bots.yml`, monperrus/crawler-user-agents,
ai.robots.txt, and CrawlerDetect. They drift (AI crawlers especially) — a
config reload recompiles them, so updates are a reload, not a rebuild.

### Verdict variables (`$waf_country`, `$waf_reason`)

Two further `NOCACHEABLE` log variables sit alongside `$waf_type`, sharing the
same per-request verdict decision (so there is at most **one** geo lookup per
request even when geo blocking, the per-country counter and `$waf_country` are
all active):

| Variable | Value |
|---|---|
| `$waf_country` | The client's ISO-3166 two-letter geo country (or an IPFire special A1/A2/A3/T1/XD). Resolves to *not found* (`-` in logs) when no geo record exists or `waf_geo_db` is unset. |
| `$waf_reason` | The verdict token: `none` (allowed), `allowlist`, `blocklist`, `geo`, `geo_whitelist`, `flag`, `scanner_ua`, `empty_ua`, `scanner_path`. |

```nginx
log_format waf '$remote_addr $status type=$waf_type '
               'country=$waf_country reason=$waf_reason';
access_log /var/log/nginx/access.log waf;
```

### Geo / reputation

The geo database is the **IPFire libloc** database. Fetch and decompress it:

```sh
curl -fsSL -o geodb/location.db.xz \
    https://location.ipfire.org/databases/1/location.db.xz
xz -dk geodb/location.db.xz       # -> geodb/location.db
```

Reputation is evaluated in this fixed order (allowlist wins over everything;
the first deny wins):

1. **allowlist** match → allow (short-circuit).
2. **blocklist** match → 403 (`static blocklist`).
3. **no geo record** → allow — **unless** a whitelist is set, then 404
   (`geo not whitelisted`).
4. **geo network flag** match (`flag_mask`) → 403 (`network flag`). Applies in
   both block and whitelist modes.
5. **geo country**:
   - **block mode** (`waf_geo_block`): country in the block list → 403
     (`geo country`).
   - **whitelist mode** (`waf_geo_whitelist`, which *wins* when set): country
     **not** in the allow list → 404 (`geo not whitelisted`); `block_cc` is
     not consulted for the country decision.

The code split is deliberate: **403** for an explicit deny (blocklist / flag /
geo-block), **404** for a whitelist miss — hide the resource so the client
cannot tell it is geo-gated. A geo-DB miss in whitelist mode is also a 404.
The CIDR blocklist and the network-flag check still run **first**, so a
flagged or blocklisted IP is denied even from a whitelisted country.

The database is `mmap`'d read-only and `munmap`'d on reload, so updating
it is a config reload — replace `geodb/location.db` atomically and run
`nginx -s reload` (no restart needed for a DB swap).

`waf_flag_block` is a convenience: each flag also adds the corresponding
IPFire special country code to the block list (`anonymous-proxy`→A1,
`satellite`→A2, `anycast`→A3, `drop`→XD). `tor` adds only the T1 country
code (Tor exits carry no dedicated flag bit). Note: the public IPFire DB
does not populate every special CC (e.g. Tor/T1 is typically absent).

### Client IP behind a proxy

With `waf_trusted_proxy` set and an `X-Forwarded-For` header present, the
`POST_READ` handler derives the canonical client address from XFF — but
**only** when the socket peer is itself a trusted proxy. Otherwise the
socket peer is used. The reputation check runs against this canonical
address.

### Mail (SMTP) protection

The stock `ngx_mail` proxy authenticates connections against an `auth_http`
endpoint. This module serves that endpoint: it reads the `Client-IP`
request header (the real SMTP peer, injected by `ngx_mail` from
`s->connection->addr_text` — unspoofable), runs the shared
`reputation_check`, and returns a header-only response:

- **Allow:** `Auth-Status: OK` + `Auth-Server`/`Auth-Port` (from
  `waf_mail_backend`). Both are mandatory or `ngx_mail` errors out.
- **Deny:** `Auth-Status: <reason>` — `ngx_mail` prepends its SMTP error
  code, e.g. `535 5.7.0 static blocklist`.
- **Fail-open:** missing/unparseable `Client-IP` → allow + a warning log,
  so a format error cannot break the whole mail flow.

**Critical:** the `auth_http` `location` must be on a server/location with
`waf off`. Otherwise the HTTP `PREACCESS` handler runs against the
*connection* peer (the loopback mail proxy) and can 403 the auth request
before the content handler runs. With `waf off`, `PREACCESS`/`POST_READ`
skip, but the content handler's `reputation_check` still uses the
location's `waf_blocklist`/`waf_geo_*` data (reputation is independent of
the `waf` flag). Bind the endpoint to `127.0.0.1` so it cannot be called
externally.

### Stream (L4) protection

The third head, `ngx_stream_waf_module`, guards **raw TCP/UDP** stream
connections — not application traffic. It ships in the *same* `.so` as the
HTTP module (one `load_module`, see [the build descriptor](modules/ngx_http_waf/config));
nginx must be built `--with-stream` (it is, in this repo).

At the stream `ACCESS` phase it runs the shared `reputation_check` on the
connection **peer** (`s->connection->sockaddr`) and closes the connection
(`NGX_STREAM_FORBIDDEN`) on any non-allow verdict. There is **no
X-Forwarded-For at L4** — the peer address is used verbatim (already rewritten
by the stream realip / `proxy_protocol` machinery if you configured it).
Trusted-proxy / XFF handling is HTTP-only.

The directives live in the `stream` / `server` (stream) context and reuse the
same reputation/geo semantics as the HTTP head:

| Directive | Args | Purpose |
|---|---|---|
| `waf_stream` | `on`\|`off` | Master switch for the stream `ACCESS` handler (default `off`). |
| `waf_geo_db` | `<path>` | libloc `location.db` for this stream head (mmap'd read-only). |
| `waf_geo_block` | `<CC> …` | Block these countries → connection dropped. |
| `waf_geo_whitelist` | `<CC> …` | Allow only these countries (and known IPs); else dropped. Wins over `waf_geo_block`. |
| `waf_flag_block` | `<flag> …` | Block by libloc network flag (`anycast`, `anonymous-proxy`, …). |
| `waf_blocklist` | `<cidr>` | Statically deny this network. Repeatable. |
| `waf_allowlist` | `<cidr>` | Allow this network, short-circuiting reputation. Repeatable. |

There is no UA / scanner / spoofing in the stream head — L4 has no headers or
request line; it is pure IP reputation. A denied verdict is logged as
`waf: stream reputation block (<reason>)`.

```nginx
stream {
    waf_geo_db     /etc/nginx/geodb/location.db;
    waf_flag_block anycast;

    server {
        listen        9000;
        waf_stream    on;
        waf_blocklist 203.0.113.0/24;   # dropped at the ACCESS phase, pre-proxy
        proxy_pass    backend:5432;     # e.g. shield a database / SMTP / game port
    }
}
```

### Statistics / status endpoint

`waf_status;` turns a `location` into a lock-free statistics endpoint, analogous
to `stub_status`. All workers share **one** always-on shared-memory zone of
`ngx_atomic_t` counters; the request hot path only ever does an atomic add (no
slab, no rbtree, no mutex), and the counters are **bounded by construction**
(a closed-set country table, a config-time per-vhost array) — never per-IP.

The handler runs in the **content phase**, *after* the access phase, so an
`allow`/`deny` on the location is enforced before any counter is rendered.
Restrict it — the endpoint exposes operational counters only (no client IPs,
no PII), but it should not be world-readable:

```nginx
location /waf/stat {
    waf_status;
    allow 127.0.0.1;
    allow 10.0.0.0/8;     # your monitoring network
    deny  all;
}
```

The **last path segment** selects the format (default `plain`); only `GET` and
`HEAD` are accepted (else `405`):

| URL | Format | Content-Type |
|---|---|---|
| `/waf/stat/plain` (or any unknown suffix) | `stub_status`-style `key value` lines | `text/plain` |
| `/waf/stat/json` | nested JSON object (RFC 8259) | `application/json` |
| `/waf/stat/prometheus` | Prometheus text exposition | `text/plain` |

```console
$ curl -s http://127.0.0.1/waf/stat/prometheus | head
waf_up 1
waf_uptime_seconds 3812
waf_http_requests_total 19443
waf_http_blocked_total{reason="blocklist"} 51
waf_http_blocked_total{reason="scanner_path"} 1208
waf_http_blocked_total{reason="flag",flag="anycast"} 17
waf_country_blocked_total{country="CN"} 904
```

What is tracked: global HTTP verdict counters (requests / allowed / allowlist
hits / blocked-per-reason), the scanner-path 404/403/444 split, response-code
counters, the `$waf_type` UA distribution, the per-flag breakdown, a bounded
open-addressed **per-country** table (total + blocked, with a `cc_overflow`
guard), a **per-vhost** block breakdown (labelled by `server_name`), the STREAM
(L4) globals (`stream_connections_total` / `stream_allowed` /
`stream_denied`-per-reason), and a geo-DB health block (network count + mapped
size only — **never** the database path). When nginx is built with
`--with-http_stub_status_module`, the core connection table
(`active`/`reading`/`writing`/`accepted`/…) is re-exported too.

All attacker-influenceable bytes (geo-DB country codes, `server_name` values)
are **escaped unconditionally** at the serializer boundary — JSON per RFC 8259,
Prometheus label values per the text-exposition rules — so a hostile geo
database or an odd `server_name` cannot break or inject into the output.

Counters live in the shm zone, so they **survive `nginx -s reload`** as long as
the `server{}` count is unchanged (the zone size is derived from it; changing
the count forces a fresh segment and resets the counters). A rebuilt `.so`
still needs a full stop+start — `-s reload` does not reload module code.

### Example configuration

A complete, runnable example lives in [`sandbox/nginx.conf`](sandbox/nginx.conf).
It wires up all three heads: the WAF on a public HTTP/2 + HTTP/3 server
(ports 8080/8443) with the four UA lists loaded, an `X-WAF-Type $waf_type`
test header, and a `location = /geo-whitelist` demoing whitelist mode; a
localhost-only `auth_http` endpoint (8081); two SMTP heads — an inbound MX
(`smtp_auth none`, pure IP reputation) and a submission listener (STARTTLS +
SMTP AUTH); and a `stream {}` block with two L4 servers (`:9090` blocklisted
→ dropped, `:9091` allowlisted → proxied). The sandbox uses high ports
(2525/5870, 8080/8443/9090) because the test nginx runs unprivileged;
**production binds 25/587** (needs root or `CAP_NET_BIND_SERVICE`).

Minimal HTTP example:

```nginx
load_module .../sandbox/modules/ngx_http_waf_module.so;

http {
    waf               on;
    waf_bot_block     on;
    waf_scanner_list  /etc/nginx/scanners.list;

    # UA classification ($waf_type) — always on, blocking is separate
    waf_scanner_ua_list /etc/nginx/lists/scanner-ua.list;
    waf_ai_crawler_list /etc/nginx/lists/ai-crawler.list;
    waf_crawler_list    /etc/nginx/lists/crawler.list;
    waf_bot_list        /etc/nginx/lists/bot.list;

    waf_geo_db        /etc/nginx/geodb/location.db;
    waf_geo_block     CN RU;                 # block mode (403); or, instead:
    # waf_geo_whitelist HU DE;               # allow-only mode (else 404)
    waf_flag_block    anycast anonymous-proxy;
    waf_trusted_proxy 127.0.0.1;

    server {
        listen 443 ssl;
        listen 443 quic reuseport;
        http2  on;
        # ...
        location / {
            add_header Alt-Svc    'h3=":443"; ma=86400';
            add_header X-WAF-Type $waf_type always;   # surface the class
        }
    }
}
```


### Smoke tests

Against the running sandbox (`sandbox/sbin/nginx -p <abs>/sandbox/ -c
<abs>/sandbox/nginx.conf`). `waf_trusted_proxy 127.0.0.1` lets the loopback
tester spoof the client IP via `X-Forwarded-For` for the geo checks.

```sh
# --- UA classification ($waf_type via the X-WAF-Type test header) ---------
curl -sI -A 'Googlebot/2.1'        localhost:8080/ | grep -i x-waf-type  # crawler
curl -sI -A 'GPTBot/1.0'           localhost:8080/ | grep -i x-waf-type  # ai-crawler
curl -sI -A 'python-requests/2.0'  localhost:8080/ | grep -i x-waf-type  # bot
curl -so/dev/null -w '%{http_code}\n' -A 'sqlmap/1.5' localhost:8080/    # 404 (scanner)
curl -so/dev/null -w '%{http_code}\n' -H 'User-Agent;' localhost:8080/    # 404 (empty)

# --- geo whitelist (location = /geo-whitelist allows HU DE) ----------------
curl -so/dev/null -w '%{http_code}\n' -H 'X-Forwarded-For: 84.206.34.1' \
     localhost:8080/geo-whitelist        # 200  (HU, whitelisted)
curl -so/dev/null -w '%{http_code}\n' -H 'X-Forwarded-For: 12.0.0.1' \
     localhost:8080/geo-whitelist        # 404  (US, not whitelisted)
curl -so/dev/null -w '%{http_code}\n' -H 'X-Forwarded-For: 1.2.4.8' \
     localhost:8080/                     # 403  (CN, block mode at /)

# --- stream (L4) head ------------------------------------------------------
curl -so/dev/null -w '%{http_code}\n' --max-time 5 127.0.0.1:9091/  # 200 (allowlisted -> proxied)
curl -so/dev/null -w '%{http_code}\n' --max-time 5 127.0.0.1:9090/  # 000, exit 56 (blocklisted -> dropped)
```

To pick known-country test IPs, build the geo oracle and query the DB:
`cc -O2 -o /tmp/loctest reference/loctest.c && /tmp/loctest geodb/location.db 8.8.8.8`
(prints `CC=`, `flags=` — note `flags=0x0004` is `anycast`, which the flag
check denies *before* the country decision).

## Runtime behavior

**HTTP head:**

- **`POST_READ` phase:** resolve the canonical client IP (peer, or XFF from
  a trusted proxy) and stash it for the reputation check.
- **`PREACCESS` phase** (cheap → expensive): IP reputation → UA classification
  (`$waf_type`) → scanner path regex. Classification always sets `$waf_type`;
  `waf_bot_block` only *acts* on `scanner`/`empty`. The first deny finalizes
  the request. `$waf_type` is also computed lazily by the variable
  get-handler, so it is correct even when referenced under `waf off`.
- **Header/body filters:** the `Server:` token is overridden to
  `waf_server_token` and built-in nginx error pages are rewritten to an
  Apache-style fingerprint. These filters install in `postconfiguration`
  and run **process-wide** (they will also stamp the `auth_http` response,
  which is harmless — `ngx_mail` ignores it).
- Subrequests and internal redirects are never re-scanned.

**Mail head:** the `auth_http` content handler runs `reputation_check` on the
`Client-IP` header that `ngx_mail` supplies — see
[Mail (SMTP) protection](#mail-smtp-protection).

**Stream head:** the stream `ACCESS` phase handler runs `reputation_check` on
the connection peer and closes the connection on any deny — see
[Stream (L4) protection](#stream-l4-protection).


## Notes & limitations

- HTTP/3 client handshake is not exercised in the sandbox (the host curl
  has no QUIC backend); the QUIC listener comes up and HTTP/1.1 + HTTP/2
  are verified.
- Docker is not used in this environment; everything builds from source.
- `waf_mail_backend` does not validate that the MTA is reachable — it only
  validates that the address is a numeric IP and the port is in range.
- `waf_geo_whitelist` without a `waf_geo_db` denies everyone (every request
  is "not whitelisted" → 404); a config-time warning is emitted in that case.
- The stream (L4) head does pure IP reputation — no UA, scanner-path, or
  spoofing logic (L4 has no headers or request line).


## Reference

The `reference/` directory keeps the two source files the geo subsystem was
developed against — they are not compiled into the build, but document where
the embedded reader came from and how it is validated:

- **`reference/nanolibloc.c`** — the minimal, dependency-free libloc
  (`location.db`) reader by **arpi_esp**, from
  [`gereoffy/ipstat46`](https://github.com/gereoffy/ipstat46/blob/main/nanolibloc.c).
  The module's `waf_geo.c` is an in-tree adaptation of it (mmap'd, read-only,
  libc-only). Credit and thanks to arpi_esp for the original nanolibloc.
- **`reference/loctest.c`** — a standalone geo oracle: it resolves IPs against
  `location.db` independently of nginx, used to cross-check the module's
  country / network-flag lookups during development.

The seed UA signature lists in `modules/ngx_http_waf/lists/` were distilled
from these public catalogues (all permissively licensed); refresh against them
periodically — AI-crawler UAs in particular drift fast:

- **Matomo Device Detector** — [`bots.yml`](https://github.com/matomo-org/device-detector/blob/master/regexes/bots.yml)
- **monperrus/crawler-user-agents** — [`crawler-user-agents.json`](https://github.com/monperrus/crawler-user-agents)
- **ai.robots.txt** — [AI crawler list](https://github.com/ai-robots-txt/ai.robots.txt)
- **CrawlerDetect** — [`Crawlers.php`](https://github.com/JayBizzle/Crawler-Detect)
- libloc / IPFire location DB — [location.ipfire.org](https://location.ipfire.org/)
