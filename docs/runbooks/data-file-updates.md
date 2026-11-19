---
name: data-file-updates
type: runbook
status: active
title: Updating heavybag data files (lists, JA4 table, geo DB) on a running server
description: Which directives read which files, the exact list formats and their failure modes, the reload-only update model, the step-by-step repo-to-production procedure with dry run and rollback, the geo DB cron and its known size-floor failure, and what a reload does to shared zones.
sources:
  - modules/ngx_http_heavybag/src/heavybag_match.c
  - modules/ngx_http_heavybag/src/heavybag_match.c:ngx_http_heavybag_read_file
  - modules/ngx_http_heavybag/src/heavybag_match.c:ngx_http_heavybag_next_line
  - modules/ngx_http_heavybag/src/heavybag_match.c:ngx_http_heavybag_scanner_compile
  - modules/ngx_http_heavybag/src/heavybag_match.c:ngx_http_heavybag_ua_list_compile
  - modules/ngx_http_heavybag/src/heavybag_match.c:ngx_http_heavybag_ja4_list_compile
  - modules/ngx_http_heavybag/src/heavybag_match.c:ngx_http_heavybag_verified_bot_compile
  - modules/ngx_http_heavybag/src/heavybag_geo.c:ngx_http_heavybag_geo_open
  - modules/ngx_http_heavybag/src/heavybag_reputation.c
  - modules/ngx_http_heavybag/src/heavybag_rate.c
  - modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c
  - modules/ngx_http_heavybag/tools/regen-ja4-list.py
  - modules/ngx_http_heavybag/tests/run-config-tests.sh
  - cmake/Tests.cmake
verified:
  commit: cc3d722
  date: 2026-11-19
links:
  - overview
  - threat-intel-sources
  - threat-model
  - build-matrix
---

# Updating heavybag data files (lists, JA4 table, geo DB) on a running server

## The update model in one paragraph

heavybag reads its data files only while nginx parses its configuration, inside
the directive handlers: list files through `ngx_http_heavybag_read_file`
`modules/ngx_http_heavybag/src/heavybag_match.c:ngx_http_heavybag_read_file`,
the geo DB through `ngx_http_heavybag_geo_open`
`modules/ngx_http_heavybag/src/heavybag_geo.c:ngx_http_heavybag_geo_open`.
There is no file watching, no mtime polling, no timer and no runtime reload
API; `/waf/status` accepts only GET/HEAD. The only way to pick up a changed
file is `nginx -t` followed by `nginx -s reload` (SIGHUP). Every loader error is
fatal to the parse, so a reload with a bad file is refused and the old workers
keep serving the old data. Data-file updates never need a restart; a new
module `.so` always does (see [what needs a restart](#what-needs-a-restart-instead)).

## Inventory: which directive reads which file

| Directive | File type | Bad line | Missing file |
|---|---|---|---|
| `waf_scanner_list` | action-bucket regex list (URI) | EMERG, reload refused | EMERG |
| `waf_args_list`, `waf_cookie_list`, `waf_referer_list` | action-bucket regex list | EMERG | EMERG |
| `waf_scanner_ua_list`, `waf_ai_crawler_list`, `waf_crawler_list`, `waf_bot_list` | UA regex list | EMERG (bad regex) | EMERG |
| `waf_ja4_list` | JA4 → family table | WARN, line skipped | EMERG |
| `waf_verified_bot <crawler\|ai_crawler> <path>` | CIDR list | EMERG | EMERG |
| `waf_geo_db` (http and stream) | IPFire libloc binary | EMERG | EMERG |

All are valid in http main/srv/loc (`waf_geo_db` also in stream main/srv). A
child level inherits a list only if it names none itself; a child that names an
empty file owns the category and matches nothing. Relative paths resolve
against the nginx conf directory. Declaring the same directive twice at one
level is rejected as duplicate.

Not file-backed (values inline in nginx.conf; use `include` to keep them in
separate files): `waf_blocklist`, `waf_allowlist`, `waf_trusted_proxy`,
`waf_geo_block`, `waf_geo_whitelist`, `waf_asn_block`, `waf_flag_block`,
`waf_method_allow` / `waf_method_deny`. The descriptive UA parser
(`$waf_ua_*`) is compiled in; changing it means rebuilding the module.

## File formats and their traps

Shared line handling (`ngx_http_heavybag_next_line`): split on `\n`, a trailing
`\r` is dropped (CRLF is fine), leading/trailing blanks are trimmed, blank lines
and lines whose first non-blank character is `#` are skipped. A `#` elsewhere on
a line is not a comment as far as the splitter is concerned. No size, line
length or entry-count limit exists in the loader; PCRE2's "regular expression
is too large" is the practical ceiling. Every list line is compiled
case-insensitively.

**Action-bucket lists** (scanner, args, cookie, referer). Syntax:
`<regex>[<blank><action>][<blank># comment]`
`modules/ngx_http_heavybag/src/heavybag_match.c:ngx_http_heavybag_scanner_compile`.

- The regex ends at the first space or tab, so it cannot contain a literal
  space. Write `\s` or `\x20`.
- The action is exactly `403`, `444` or `404`; omitted means 404. Anything else
  (including `403 extra`) aborts the config with
  `heavybag: unknown action "…" in scanner list`. The message says "scanner
  list" for args/cookie/referer too.
- An inline `# comment` after the action is allowed; a `#` inside the regex is
  safe.
- Patterns are not anchored for you. Same-action lines are joined into one
  alternation; buckets are tried 404 → 403 → 444, first match wins.

**UA lists** (scanner-ua, ai-crawler, crawler, bot). The whole trimmed line is
one regex fragment, matched unanchored against the raw User-Agent. Spaces are
part of the regex. An inline `# …` is also part of the regex, and that is a
silent bug: the line then only matches UAs that literally contain `#…`. Use
whole-line comments only. Category priority is scanner → ai-crawler → crawler
→ bot.

**JA4 list.** Syntax: `<ja4-key><blank><family>`
`modules/ngx_http_heavybag/src/heavybag_match.c:ngx_http_heavybag_ja4_list_compile`.
The family is the whole rest of the line, compared case-insensitively against
`chromium|firefox|safari|tool|bot`. A trailing comment or extra token turns the
family into UNKNOWN, which never triggers a spoof verdict, and nothing warns
about it. A line with no family is skipped with a WARN. Keys are not validated;
duplicates are kept.

**Verified-bot CIDR list.** One CIDR per line, IPv4 or IPv6. The whole trimmed
line goes to `ngx_ptocidr`, so an inline comment aborts the config with
`invalid network address`. Host bits below the prefix give a WARN and are
accepted. A file with no usable CIDR loads with a WARN and switches the
fake-bot check off for that class. The two `verified-crawler*.list` files in
the repo are test fixtures (documentation ranges and loopback), not real
crawler ranges, and nothing in the repo generates a real one
(see [threat-intel-sources](../threat-intel-sources.md)).

**Geo DB** (IPFire `location.db`, used as downloaded). The loader checks size
(4200 B to 512 MiB), magic, a mandatory ECDSA P-521/SHA-512 signature against
the IPFire key compiled into the module, block bounds and the network-tree walk
`modules/ngx_http_heavybag/src/heavybag_geo.c:ngx_http_heavybag_geo_open`. A
truncated or tampered file cannot load. If IPFire rotates its signing key the
module must be rebuilt.

The file is mmap'd and stays mapped for the life of the config cycle.
**Replace it only by writing a new file and `rename(2)`-ing it over the live
path.** Never `cp` onto it, `curl -o`/`wget -O` onto it, `> file` or
`rsync --inplace`: shrinking the mapped file kills workers with SIGBUS
mid-request. For text lists the same rule is advisable, because a reload that
reads a half-written file fails or loads it truncated.

## What a reload does

- Every list is re-read and recompiled, and the geo DB is re-mapped and
  re-verified (twice if `waf_geo_db` is set in both http and stream).
- All parsed data lives in the cycle pool, one copy per reload; nothing
  list-derived is in shared memory.
- `waf_status` counters survive the reload if the zone size and the vhost count
  are unchanged. A changed vhost count resets them (NOTICE
  `vhost count changed …, counters reset`).
- `waf_rate` token buckets survive a reload at the same zone size. The README
  says resizing `waf_rate_zone` needs a full restart; the nginx core code
  allocates a fresh, zeroed segment instead. This is untested here, so treat a
  resize as a restart.
- The reload time is visible as `last_reload` in the status JSON and as
  `heavybag_last_reload_timestamp` in the Prometheus output.

## Procedure: repo → production

The repository is the source of truth for `modules/ngx_http_heavybag/lists/`.
Edit there, never only on the server. The commands below use these
placeholders; set them for your deployment:

```sh
HOST=edge.example.net                     # ssh target of the nginx box
CONF=/etc/nginx                           # directory holding nginx.conf and lists/
NGX=/usr/sbin/nginx                       # the nginx binary that loads heavybag
ARGS="-p /var/lib/nginx -c $CONF/nginx.conf"  # the -p/-c the service runs with
```

1. **Edit and test locally.** Run the suites that exercise the committed lists:
   `ctest --test-dir build -R 'heavybag_(config|regression|replay|protocol|unit)' --output-on-failure`.
   `heavybag_replay`'s false-positive gate (every baseline path must yield
   reason=none) is the important one after touching scanner or signature
   lists. `heavybag_config` V33 loads all committed lists plus the real geo DB
   in one `nginx -t`.
2. **Commit**, then diff against the server so you know exactly what changes:
   ```sh
   mkdir -p /tmp/hblive && scp "$HOST:$CONF/lists/*.list" /tmp/hblive/
   diff -r /tmp/hblive modules/ngx_http_heavybag/lists
   ```
   Lines only on the server mean someone edited it by hand; fold them into
   the repo first instead of overwriting them. Before shipping new scanner or
   UA patterns, it is worth replaying them against the server's own access log
   (requests heavybag passed and the backend answered with 2xx): a new pattern
   that matches served traffic is a false positive the fixture-based replay
   gate cannot see.
3. **Stage** the files the server's config actually references (do not ship
   the `verified-crawler*.list` test fixtures):
   ```sh
   ssh $HOST 'mkdir -p ~/hb-lists-stage'
   scp modules/ngx_http_heavybag/lists/{scanners,scanner-ua,ai-crawler,crawler,bot,args,cookie,referer,ja4}.list $HOST:hb-lists-stage/
   ```
4. **Dry run without root.** Copy the live config to a scratch directory, point
   the list directives at the staged files, and parse it with `-e stderr` so the
   NOTICE lines reach the terminal (run on the host with the variables set):
   ```sh
   rm -rf /tmp/hbdry && cp -r $CONF /tmp/hbdry
   sed -i -e "s#$CONF/lists/#$HOME/hb-lists-stage/#" -e "s#^pid .*#pid /tmp/hbdry/t.pid;#" /tmp/hbdry/nginx.conf
   $NGX -t -e stderr -p /var/lib/nginx -c /tmp/hbdry/nginx.conf 2>&1 | grep -E 'heavybag|emerg|warn'
   ```
   Expected: one `heavybag: loaded N …` line per list with the entry counts you
   expect. If TLS keys are root-only, the parse then stops at a single EMERG
   `cannot load certificate … Permission denied`: the heavybag loaders all run
   before certificates are loaded, so that EMERG only means the dry run is not
   root. Any other EMERG or a heavybag WARN is a real problem. Without
   `-e stderr`, `nginx -t` prints only WARN and above; the NOTICE lines go to
   the compile-time default error log.
5. **Swap and reload as root.** In a root shell on the host, keep a dated
   backup, rename each file into place, then test the real config and reload:
   ```sh
   L=$CONF/lists
   B=$L/../lists.bak-$(date +%Y%m%d-%H%M)
   cp -a $L $B
   for f in ~<deploy-user>/hb-lists-stage/*.list; do
       n=$(basename $f)
       install -m 644 -o root -g root $f $L/.$n.new && mv -f $L/.$n.new $L/$n
   done
   $NGX -t $ARGS && $NGX -s reload $ARGS || { rm -rf $L; mv $B $L; echo ROLLED BACK; }
   ```
   If `-t` fails, nothing was reloaded and the old directory is restored.
6. **Verify.** The live error log (level `notice` or lower) gets the same
   `heavybag: loaded N …` lines with the reload timestamp. Then confirm
   `last_reload` moved on the status endpoint.
7. **Rollback** at any later point is the same swap with the `lists.bak-*`
   directory, followed by `nginx -t` and `nginx -s reload`.

## Geo DB refresh

The repository ships no fetcher; README.md has the manual download. For an
unattended refresh, a daily cron job should: download conditionally
(`curl -z <previous .xz>`, 304 → no-op), check `xz -t` and the `LOCDBXX`
magic, write the new file next to the live one and `rename(2)` it into place,
run `nginx -t`, then reload, or restore the previous file if the test fails.

Do not rely on a hard size floor as an integrity check. On 2026-10-18 the
upstream DB shrank from about 50 MB to 39.5 MB (the network count fell from
1 007 293 to 121 574), and a 40 MiB floor silently rejected every update for
a month. The shrink is upstream aggregation, not data loss: comparing the old
and new DB over 31 759 addresses with `reference/geolookup.c`, the country
changed for 0.54% and the ASN for 0.88%, all plausible reassignments. The
module's mandatory signature check is the real integrity gate; a floor, if
any, should be far below the current size.

Two traps when changing such a cron script. Editing it with `sed -i` does not
affect an instance that is already running: it holds the old inode and
finishes with the old code. And if the job sleeps a random spread while
holding its lock, a manual run in that window just skips.

Watch for silent stalls: if the newest successful update in the job's log is
more than a few days old, the job is not doing its work.

Manual refresh, following the same rename rule:

```sh
cd $CONF/geodb
curl -fsS -o .new.xz https://location.ipfire.org/databases/1/location.db.xz
xz -dc .new.xz > .new.db && cp -a location.db location.db.prev && mv -f .new.db location.db
$NGX -t $ARGS && $NGX -s reload $ARGS      # on failure: mv -f location.db.prev location.db
```

After a DB swap, re-run `heavybag_mailauth` and `heavybag_repprec` locally:
they check expected verdicts against the current DB and SKIP if it drifted.

## JA4 table regeneration

`modules/ngx_http_heavybag/tools/regen-ja4-list.py <in.csv> [<in2.csv> …] <out>`
builds `ja4.list` from the Niicolaa/ja4db-export `ja4_fingerprint.csv` and the
FoxIO `ja4plus-mapping.csv` (both fetched by hand; URLs in the script header).
It keeps only well-formed keys, derives the family from the application/library
label with a UA fallback, and drops keys claimed by more than one family. It
writes straight onto `<out>`, so point it at a temporary path and rename. The
upstream export has been frozen since 2026-05-15, so a re-run reproduces the
current 982-entry table.

## What needs a restart instead

- A new module `.so`: `nginx -s reload` does not load new module code. The
  `.so` is bound to the exact nginx version it was built against; rebuild it
  for every nginx version (see [build-matrix](build-matrix.md)) and swap the
  binary and the module together. Under a systemd unit with `Type=simple` and
  `Restart=always`, a USR2 hot binary upgrade is not clean (the new master is
  a child of the old one, and systemd restarts the service when the old one
  exits), so use a plain restart there.
- Resizing `waf_rate_zone` (conservative reading, see above).
- A status zone layout change (EMERG `status zone layout changed across
  reload; a full restart is required`).
