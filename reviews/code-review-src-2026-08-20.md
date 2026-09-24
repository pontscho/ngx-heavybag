# Code Review: modules/ngx_http_heavybag/src/

| Property | Value |
|----------|-------|
| Target | modules/ngx_http_heavybag/src/ |
| Files | 23 |
| Language | C (nginx HTTP+STREAM WAF module) |
| Lines | 10 342 |
| Date | 2026-08-20 04:47:00 (overnight serialized run, finished 08:11) |
| Pipeline | Find→Verify→Synthesize (8 lenses, 1-vote recall verify; serialized overnight: 8 finders → 34 raw candidates → 26 unique → 24 verified after budget → 22 findings after root-cause dedup) |

## Quality Assessment: NEEDS IMPROVEMENT (3/8)

Severity floor also applies: 7 HIGH findings independently cap the band at NEEDS IMPROVEMENT.

### Metrics

| Dimension | Score | Notes |
|-----------|-------|-------|
| Correctness | 1/8 | 7 CONFIRMED + 4 PLAUSIBLE correctness defects (raw 8−27 → floored at 1) |
| Consistency | 5/8 | 2 CONFIRMED (unprefixed extern data symbols; comment asserting the opposite of the code) |
| Reuse/DRY | 1/8 | 5 CONFIRMED duplication clusters, incl. an already-drifted HTTP/stream merge pair (raw 0.5 → floored at 1) |
| Simplicity/Altitude | 2/8 | 4 CONFIRMED (11-site epilogue paste, half-caching getters, dead branch, triple serializer) |
| Conventions | 8/8 | No CLAUDE.md governs this repo; no violation chargeable |
| **Overall** | **3/8** | half-up mean of raw values (1, 5, 1, 2, 8 → 3.4 → 3) |

## Findings

### High (correctness + CONFIRMED)

#### 1. Stat-shm per-vhost array diverges from config after reload: OOB /status read + silently dropped / misattributed counters  (CONFIRMED)
- **File:** modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c:2720 + modules/ngx_http_heavybag/src/heavybag_status.c:822 (render loops :384/:568/:734)
- **Dimension:** Correctness
- **Merged from:** V1 + V2 — same root cause, two facets needing two fixes.
- **Failure scenario:** Reload adding server{} blocks typically leaves the page-aligned zone size unchanged (base + 4 pages slack), so nginx reuses the old segment and `stat_init_zone` adopts the old struct after checking only the compile-time layout signature — never `osh->nvhosts` vs the new `wmcf->nvhosts`. The renderers then index the shm trailing array with the NEW config's count, never clamping to `sh->nvhosts`: GET /waf/status reads 152 B per extra vhost past the slab allocation (garbage to monitoring, possible worker crash). Independently, new servers' `stat_index >= sh->nvhosts` fails the hot-path guard → their counters stay zero forever until full restart; after remove/reorder each surviving server inherits another server's accumulated totals.
- **Verifier evidence:** Reload branch (module.c:2720–2729) checks only `osh->layout != HEAVYBAG_STAT_SHM_LAYOUT`; `stat_assign_vhosts` renumbers purely by new server order (:2839–2844); renderers clamp only to `wmcf->nvhosts`/`cmcf->servers.nelts` (status.c:820–824) — the sole violators of the contract documented at heavybag_status.h:155–158 that every hot-path caller honors (:668, :726, :956, :1320).
- **Fix direction:** clamp all three render loops to `sh->nvhosts` AND reject/re-init the reused segment when `osh->nvhosts != wmcf->nvhosts` (fold nvhosts into the layout signature, or re-create the zone).

#### 2. `waf_flag_block` merge asymmetry: child config silently drops parent's Tor blocking  (CONFIRMED)
- **File:** modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c:1450 (identical: heavybag_stream.c:347–356)
- **Dimension:** Correctness
- **Failure scenario:** The `tor` token sets only `flag_cc` ("T1", no flag bit — heavybag_reputation.c:333–335), every other token sets both. The merge inherits `flag_cc` only when NULL and `flag_mask` only when 0, so override-vs-merge semantics depend on which token was used: `location { waf_flag_block anonymous-proxy; }` under `server { waf_flag_block tor drop; }` silently stops blocking Tor exits in that location, while the inverse nesting keeps both. Flagged sources pass unblocked, contrary to what the config reads as.
- **Verifier evidence:** T1 matched only via flag_cc (reputation.c:141–142); `flag_mask == 0` sentinel ambiguous because `tor` legitimately leaves it 0; deterministic from the code.

#### 3. Allowlisted client is rate-limited at L4/SMTP while the identical HTTP config exempts it  (CONFIRMED)
- **File:** modules/ngx_http_heavybag/src/heavybag_stream.c:265 (+ heavybag_authhttp.c:128–155)
- **Dimension:** Correctness
- **Failure scenario:** The stream head gates the rate stage only on `denied`, never on `verdict.reason` — an allowlist hit (NGX_DECLINED + reason ALLOWLIST) falls into `rate_check`; under load the trusted IP gets NGX_STREAM_FORBIDDEN / mail deny. The HTTP head explicitly skips the rate stage for allowlist-FULL ("trusted == trusted", lifecycle-v01, module.c:1016–1020). Divergent semantics, undocumented.
- **Verifier evidence:** stream.c:265 `if (!denied && sscf->rate_rules != NULL)`; NGX_BUSY → FORBIDDEN (:302); mail head always enforces (authhttp.c:123).

#### 4. Empty UA-list file cannot disable inherited signatures: parent regex silently re-inherited  (CONFIRMED)
- **File:** modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c:1389
- **Dimension:** Correctness
- **Failure scenario:** An empty/comments-only UA list compiles to a NULL `ua_re[cat]` slot (heavybag_match.c:486–489) with `nginx -t` success ("loaded 0 UA pattern(s)"); the merge re-inherits the parent's compiled regex on NULL with no path sentinel (unlike sig/scanner/verified_bot/ja4 lists), and the duplicate-directive guard is dead for the same reason. The operator's explicit "turn signatures off here" config silently keeps blocking.
- **Verifier evidence:** `set_ua_list` stores no path (module.c:1609–1626) — contrast `set_sig_list` :1597, `set_ja4_list` :1649; merge :1389–1392 has no `.data == NULL` gate — contrast sig :1409–1414.

#### 5. Mail auth head breaks the exported counter invariant; mail reputation blocks invisible to monitoring  (CONFIRMED)
- **File:** modules/ngx_http_heavybag/src/heavybag_authhttp.c:144 (+ :110)
- **Dimension:** Correctness
- **Merged from:** V4 + V5 — one accounting hole, two symptoms.
- **Failure scenario:** The rate-limit deny bumps `http_blocked[RATE_LIMIT]` + `http_resp_429` with no matching `http_requests_total` (the file itself recommends `waf off` on the auth location, which skips PREACCESS counting) — breaking the documented invariant `requests_total == allowed + sum(blocked)` (observability-01) in every serializer; block-ratio dashboards go >100%/negative. The reputation-deny path books nothing at all: SMTP sessions rejected with zero trace in /waf/status — a mail-borne attack is invisible to alerting.
- **Verifier evidence:** authhttp.c:144–146 are the only counter writes in the file; rep-deny path :110–119 only logs + sets Auth-Status; invariant documented at module.c:721–725; with `waf on` it breaks in the other direction (double count via :1316).

#### 6. Android WebView "wv" probe destroys Chrome version and pre-empts HeadlessChrome detection  (CONFIRMED)
- **File:** modules/ngx_http_heavybag/src/heavybag_ua_parse.c:328
- **Dimension:** Correctness
- **Failure scenario:** `HEAVYBAG_HAS(ua,n,"Chrome") && HEAVYBAG_HAS(ua,n,"wv")` — unanchored, case-insensitive 2-byte "wv" anywhere — returns CHROME before the HeadlessChrome/ and Chrome/ branches without version extraction. Every Android WebView UA loses $waf_ua_browser_version; a HeadlessChrome UA containing an incidental "wv" is misreported as plain chrome, weakening the headless-automation signal. The file's own ordering comment (:285–288, "HeadlessChrome is tested first") is contradicted.
- **Verifier evidence:** :328 returns with vs/vl still NULL/0 (:295–296).

#### 7. `libmpv` version extraction always empty  (CONFIRMED)
- **File:** modules/ngx_http_heavybag/src/heavybag_ua_parse.c:359
- **Dimension:** Correctness
- **Failure scenario:** Token "libmpv" passed without the trailing '/' (neighbors curl/, Wget/, Lavf/ have it); '/' is outside the version charset, so the slice starts on '/' and `*vlen = 0` — deterministically, for every `libmpv/x.y.z` UA.
- **Verifier evidence:** slice starts at p+tlen (:185), charset check (:190–191), `*vlen = 0` (:198).

### Medium

#### 8. IPv4-mapped trie-root descent ignores the nxt==0 terminator: corrupt-but-signed DB yields bogus ipv4root, wrong geo for all IPv4 clients  (PLAUSIBLE)
- **File:** modules/ngx_http_heavybag/src/heavybag_geo.c:387
- **Dimension:** Correctness
- **Failure scenario:** The 96-step descent never tests the fetched child for 0 (the walker's own end-of-path contract, `} while (nxt)` :446); an early-terminating ::ffff:0:0/96 chain wraps back to node 0 (always passes the bounds check) and keeps descending from the root — bogus nonzero `ipv4root`, no load failure, every IPv4 lookup walks the wrong subtree. The signature gate (:365) verifies integrity, not trie structure. Trigger is a data-producer condition; confirmable via the HEAVYBAG_GEO_UNIT_TEST harness.

#### 9. Rate-zone worker re-attach adopts `shpool->data` with zero validation — the status zone validates the identical path  (PLAUSIBLE)
- **File:** modules/ngx_http_heavybag/src/heavybag_rate.c:539
- **Dimension:** Correctness
- **Failure scenario:** `shm.exists` path (:537–541) has no layout signature / NULL / nslots sanity check; garbage `hdr->nslots` scales `slots[(idx+p)%n]` CAS writes (:194/:236/:240) → OOB atomic writes on platforms where shm outlives the process (Windows named mapping / SysV — the exact scenario the status zone's own HEAVYBAG_STAT_SHM_LAYOUT check at module.c:2740–2748 was added for; the rate header has no layout field at all).

#### 10. Geo DB mmap has no protection against in-place truncation: SIGBUS worker death  (PLAUSIBLE)
- **File:** modules/ngx_http_heavybag/src/heavybag_geo.c:322
- **Dimension:** Correctness
- **Failure scenario:** `mmap(PROT_READ, MAP_PRIVATE)` sized from a prior fstat, dereferenced all cycle with bounds checks only against the load-time size; an update job that truncates/rewrites location.db in place (instead of write-new + rename) leaves unbacked pages — next lookup SIGBUSes the worker, repeatedly, until reload. Operator-action trigger; worth a docs warning + (optionally) a fstat/mtime guard or copy-in.

#### 11. `snap = *sh`: ~13 KB non-atomic copy of live lock-free shm — torn 64-bit counters in /status  (PLAUSIBLE)
- **File:** modules/ngx_http_heavybag/src/heavybag_status.c:818
- **Dimension:** Correctness
- **Failure scenario:** Plain struct assignment of a multi-KB struct of `ngx_atomic_t` while ~30 lock-free writers run in other workers; wide/byte-wise copy has no per-field 64-bit atomicity → a scrape can render a torn counter (transient wild value), firing rate()-based alerts spuriously. Codegen/timing-dependent — classic race.

#### 12. HTTP/stream rep-conf merge + geo-db validation duplicated — and the two heads have ALREADY drifted  (CONFIRMED, quality)
- **File:** modules/ngx_http_heavybag/src/heavybag_stream.c:341 (vs ngx_http_heavybag_module.c:1435–1479)
- **Dimension:** Reuse/DRY
- **Failure scenario (cost):** The 8-field NULL-inherit block + byte-identical fail-closed error string exist twice; no shared merge/validate helper in heavybag_reputation.c. The verifier found the drift is not hypothetical: the HTTP head validates before inheriting blocklist/allowlist, the stream head after all inherits. Any new rep field must be hand-mirrored or L4 silently diverges (config rejected by http{} accepted by stream{} → fails open).

### Low

(none)

## Beyond the display cap — verified, scored, not individually rendered (10 × quality-CONFIRMED, all MEDIUM)

- ngx_http_heavybag_module.c:1000 — enforce-path `cc_bump` epilogue pasted at **11** block points; belongs inside `finalize_decision` (which already does the detect-path bump, :739–742).
- heavybag_stream.c:533 — seven stream directive setters line-for-line duplicate the HTTP setters (~300 lines, ~14 near-identical functions).
- ngx_http_heavybag_module.c:928 — ctx fetch-or-pcalloc idiom verbatim ×8 across two files; `ua_ctx_parsed` factors it for only 4 getters (its own comment admits it).
- heavybag_authhttp.c:323 — headers_in `ngx_list_part` walk duplicates the cookie-lookup walk (module.c:866–883) line-for-line.
- heavybag_ja4.c:319 — `ja4_compute_is_grease` byte-identical to the unconditionally-compiled `ja4_is_grease` (:27) in the same TU; the "needs no core helper" comment does not hold.
- ngx_http_heavybag_module.c:2404/2315 — country/asn variable getters each cache half of one full geo lookup → two trie walks on non-preaccess paths; contradicts the ":2288 at most ONE geo lookup" doc.
- heavybag_ua_parse.c:434 — Nintendo DSi/Wii device fallback provably dead (try_os consumes the identical substrings first).
- heavybag_status.c:202 — every counter hand-rendered in three serializers + the literal 128-line headroom constant; truncation is silent (`ngx_snprintf` clamps, no log). A per-metric descriptor table would derive all four.
- ngx_http_heavybag_module.c:51/:67 — `heavybag_type_str`/`heavybag_reason_str` are the only module-owned externs without the `ngx_http_heavybag_` prefix; `ngx_dlopen` uses RTLD_GLOBAL → interposition risk.
- ngx_http_heavybag_module.c:1109–1110 — comment claims counting "including each internal-redirect hop"; the code (sh forced NULL on `r->internal`, :950–951) implements the exact opposite (observability-02).

## Refuted (verifier-rejected candidates)

None — 0 of 24 verified candidates were refuted.

## Dropped by verify budget (24-cap), for transparency — not verified, not scored

- heavybag_spoof.c:19 — spoof filter's saved next-filter pointers use the generic nginx sample names (`ngx_http_next_header_filter`) instead of the module-prefixed convention used elsewhere in the same .so.
- heavybag_status.c:110 — comment cross-references `waf_flag_bits[]` but the actual symbol is `heavybag_flag_bits[]` (stale name), weakening the only lockstep guard on the flag label/bit arrays.

## Scoring math (auditable)

- deduction = base(class) × multiplier(verdict); base: correctness 3, quality 1.5; multiplier: CONFIRMED 1.0, PLAUSIBLE 0.5; per-dimension raw = max(1, 8 − Σ); overall = round_half_up(mean(raw)).
- Correctness: 7 CONF + 4 PLAUS → 8 − (21 + 6) = −19 → **1.0**
- Reuse/DRY: 5 CONF → 8 − 7.5 = 0.5 → **1.0**
- Simplicity/Altitude: 4 CONF → 8 − 6 = **2.0**
- Consistency: 2 CONF → 8 − 3 = **5.0**
- Conventions: 0 findings → **8.0**
- Overall: mean(1, 1, 2, 5, 8) = 3.4 → half-up → **3** → NEEDS IMPROVEMENT (severity floor concurs: 7 HIGH).

## Project Rules Applied

- No CLAUDE.md exists at user or repo level — Conventions dimension uncharged; consistency findings judged against the module's own internal idioms only.
