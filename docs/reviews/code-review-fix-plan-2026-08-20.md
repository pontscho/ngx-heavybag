# Fix Plan — code review 2026-08-20 (modules/ngx_http_heavybag/src/)

Source review: `docs/reviews/code-review-src-2026-08-20.md` (7 HIGH, 15 MEDIUM, 0 LOW; 24 verified, 0 refuted).
Execution model: **parallel "raid" of Opus builder agents in waves.** Within a wave every task is
**file-disjoint** — a file appears in exactly one task per wave. Waves are sequential barriers
(wave N+1 starts only when wave N is green). One raider = one task.

## Ground rules for every raider (copy into each brief)

- Surgical scope: fix ONLY what the task lists; match surrounding style (comment density, naming,
  early-return idiom). No drive-by refactors.
- **No new source files** — new shared helpers go into existing TUs (`heavybag_reputation.c`,
  `heavybag_match.c`, …). A new `.c` would require an nginx reconfigure (project rule).
- Build: `forge_call` build target `heavybag_module` (fallback: `cmake --build build --target
  heavybag_module`). `-Werror` — warnings fail the build.
- Tests: run the full ctest suite (14 suites) after the change; every finding fix MUST land with a
  regression test (unit via ctest.h where the logic is pure; note below where only a comment/doc
  changes). Coverage knob `HEAVYBAG_COVERAGE=1`, TSan knob `HEAVYBAG_TSAN=1` where relevant.
- Tools: Read for reading, purity_call (search/list/clangd) for navigation, purity/Edit for writes.
  Never shell text tools (cat/sed/awk/grep/find/ls).
- nginx idioms: ngx_str_t is not NUL-terminated; per-request state must survive internal redirects
  (no POST_READ-only population); `ngx_snprintf` does not NUL-terminate.
- Config-surface naming stays `waf_*`; C symbols stay `heavybag`/`ngx_http_heavybag_`.

## Verification tail (after the last wave — non-negotiable)

Per Zoltán's review-heavy workflow: after all waves are green, run in parallel
(1) `p:minion-inspector-implementation` against this plan, (2) `p:minion-inspector-security-officer`
PHASE: triage on the diff, (3) re-run the Waldorf verification for each HIGH finding on the fixed
code (expect REFUTED = fixed). Then full ctest + sandbox smoke (deployed .so md5 noted).

---

## Wave 1 — independent leaf fixes (4 tasks, fully parallel)

### T1 — UA parser fixes  [files: heavybag_ua_parse.c + its ctest suite]

**T1.a (HIGH #6, ua_parse.c:328) — Android WebView probe.**
Evidence: `HEAVYBAG_HAS(ua,n,"Chrome") && HEAVYBAG_HAS(ua,n,"wv")` returns CHROME before the
HeadlessChrome/ (:330) and Chrome/ (:332) branches, with vs/vl still NULL/0 (:295–296); "wv" is an
unanchored case-insensitive 2-byte scan; the ordering comment (:285–288) claims HeadlessChrome is
tested first.
Fix: (1) move the HeadlessChrome/ probe ABOVE the webview probe (restores the documented order);
(2) anchor the webview signal to the real Android token `"; wv)"` (or at minimum `" wv)"`) instead
of bare "wv"; (3) after classifying webview, still run `HEAVYBAG_VER(ua, n, "Chrome/", vs, vl)` so
the version survives.
Tests: WebView UA (`...; wv) ... Chrome/119.0.0.0 ...`) → browser chrome + version "119.0.0.0";
HeadlessChrome UA containing an incidental "wv" → headless, not chrome; plain Chrome unaffected.

**T1.b (HIGH #7, ua_parse.c:359) — libmpv version.**
Evidence: token `"libmpv"` lacks the trailing '/'; '/' is outside the version charset (:190–191) →
`*vlen = 0` always (:198). Neighbors curl/, Wget/, Lavf/ carry the slash.
Fix: `"libmpv"` → `"libmpv/"` in both the HAS probe and the VER slice (match the neighbors).
Test: `libmpv/0.38.0` → browser libmpv, version "0.38.0".

**T1.c (MED-Q, ua_parse.c:434) — delete the dead Nintendo DSi/Wii fallback.**
Evidence: provably unreachable — try_os (:265–266) maps the identical substrings to NINTENDO* which
the CONSOLE switch arm (:388–404) consumes; reaching :434 requires os==UNKNOWN, mutually exclusive.
Fix: delete the branch + its LCOV_EXCL comment. No test needed (dead code removal); keep the
existing console classification tests green.

### T2 — geo loader hardening  [files: heavybag_geo.c (+ geo unit harness)]

**T2.a (MED #8, geo.c:387) — ipv4root descent terminator.**
Evidence: the 96-step descent (:386–397) never tests the fetched child for 0, though the runtime
walker's contract is `} while (nxt)` (:446); an early-terminated ::ffff:0:0/96 chain wraps to node
0 (root, always passes the bounds check) and yields a bogus nonzero ipv4root; the signature gate
(:365) validates integrity, not structure.
Fix: inside the loop, after fetching `nxt`, treat `nxt == 0` before step 96 as a hard load failure
(`ngx_log_error(NGX_LOG_EMERG, ...)` + return NULL), same as the existing bounds-check path. Do NOT
silently fall back — fail closed at config time.
Test: extend the HEAVYBAG_GEO_UNIT_TEST harness (loader compiled in under the unit-test guard,
:406) with a synthetic DB whose /96 chain has a zero child at depth < 96 → load must FAIL.

**T2.b (MED #10, geo.c:322) — mmap vs in-place truncate.**
Evidence: mmap PROT_READ/MAP_PRIVATE sized from fstat (:292–299), held all cycle (:338–339),
lookups deref raw (:414, :504); no SIGBUS guard.
Fix (proportionate — the trigger is an operator error): (1) add a loud comment at the mmap site +
a README/docs note: location.db MUST be replaced via write-new + rename(2), never truncated in
place; (2) cheap belt: after mmap, `ngx_fd_info` again and reject if size changed under us (closes
the load-time race only — document that runtime truncation remains fatal by design, as in nginx's
own mmap usage). No SIGBUS handler — out of proportion for an nginx module.
Test: doc-only + load-race check; unit test optional (racy to test meaningfully).

### T3 — rate zone re-attach validation + JA4 GREASE dedup  [files: heavybag_rate.c, heavybag_rate.h, heavybag_ja4.c]

**T3.a (MED #9, rate.c:539).**
Evidence: `if (shm_zone->shm.exists) { shm_zone->data = shpool->data; return NGX_OK; }`
(:537–541) — no signature/NULL/nslots check; garbage `hdr->nslots` scales `slots[(idx+p)%n]`
(:194, :236) with a CAS write (:240). The status zone validates the identical path
(module.c:2740–2748, HEAVYBAG_STAT_SHM_LAYOUT); the rate header (:105–109) has no layout field.
Fix: mirror the status-zone pattern — add a `layout` field to the rate table header, stamp it at
init (`MAGIC ^ sizeof(header) ^ sizeof(slot) ^ nslots-formula`), and on the `shm.exists` path
reject NULL data or a mismatched layout with NGX_ERROR (fail closed, same wording style as the
status zone). Note: header layout change bumps the signature by construction.
Test: unit-test the validation predicate (pure function over a fake header) in the rate ctest
suite; assert re-attach with wrong layout → error, with correct layout → OK.

**T3.b (MED-Q, ja4.c:319) — GREASE predicate dedup.**
Evidence: `ja4_compute_is_grease` (:318–323) is byte-identical to the unconditionally-compiled
`ja4_is_grease` (:27–30) in the same TU; the "needs no core helper" comment is false (the extract
unit-test guard :309 skips only includes).
Fix: delete `ja4_compute_is_grease`, call `ja4_is_grease` from the extractor, drop the stale
comment. Existing JA4 e2e extractor vector test must stay green.

### T4 — mail auth-http head: accounting + allowlist/rate  [files: heavybag_authhttp.c]

**T4.a (HIGH #5, authhttp.c:144 + :110) — counter symmetry.**
Evidence: rate deny bumps `http_blocked[RATE_LIMIT]` + `http_resp_429` (:144–146) — the only
counter writes in the file; reputation deny (:110–119) books nothing; nothing bumps
`http_requests_total`/`http_allowed` (recommended `waf off` skips PREACCESS counting, module.c:955);
invariant documented module.c:721–725 (observability-01).
Fix: make the mail head a first-class citizen of the SAME invariant: at the top of the auth
content handler (once per auth request, after `sh` resolution) bump `http_requests_total`; on
reputation deny bump `http_blocked[<reason>]`; on rate deny keep the existing blocked/429 bumps;
on allow bump `http_allowed`. (Deliberately reuses the existing HTTP counters — no new shm fields,
no serializer changes, no shm layout bump. If Zoltán later wants segregated mail_* counters, that
is a separate feature.) Update the file-top comment documenting the accounting contract.
Test: extend the auth-http ctest/e2e coverage: after N mail requests with mixed
allow/rate-deny/rep-deny outcomes, assert `requests_total == allowed + Σ blocked` from the
serialized status (the stress harness already parses /waf/status).

**T4.b (HIGH #3, mail half; authhttp.c:128–155) — allowlist bypasses rate.**
Evidence: after `rc == NGX_DECLINED` the rate check runs unconditionally; comment :123 "always
enforces".
Fix: skip the rate stage when the reputation verdict's reason is HEAVYBAG_REASON_ALLOWLIST —
mirroring the HTTP head's lifecycle-v01 rule (module.c:1016–1020). Keep enforce-always for
non-allowlisted traffic.
Test: allowlisted peer + exhausted bucket → Auth-Status OK; non-allowlisted peer + exhausted
bucket → deny (existing behavior).

---

## Wave 2 — rep-config layer + status zone (2 tasks, parallel; starts after wave 1 is green)

### T5 — reputation config consolidation + sentinel fixes  [files: heavybag_reputation.c, heavybag_rep.h, ngx_http_heavybag_module.c (merge/setter region only), heavybag_stream.c (merge/setter region only)]

This task fixes TWO HIGHs at the right altitude: the shared helper IS the sentinel fix's home.

**T5.a (MED-Q #12 / V14+V15) — shared merge/validate/setters.**
Evidence: stream.c:341–364 + :375–386 duplicate module.c:1435–1479 verbatim (byte-identical error
string); the heads ALREADY drifted (HTTP validates before inheriting blocklist/allowlist, stream
after — pick ONE order: validate AFTER all inherits, i.e. the stream order, which sees the full
effective config; preserve the exact error string). Seven setter pairs are line-for-line duplicates
(stream 507–653 vs HTTP 1714–1992).
Fix: add to heavybag_reputation.c: `ngx_http_heavybag_rep_conf_merge(prev, conf)` (8-field
NULL/0-inherit) + `ngx_http_heavybag_rep_conf_validate(cf, rep)` (geo-dependency fail-closed) +
shared directive setters taking `ngx_heavybag_rep_conf_t *` (each head keeps a 2-line wrapper that
dereferences its own conf struct — avoids cmd->offset gymnastics across two conf types). Both
merge functions and all 14 setters delegate.

**T5.b (HIGH #2, module.c:1450 + stream.c:347–356) — flag_mask/flag_cc sentinel.**
Evidence: `tor` sets only flag_cc ("T1", no bit — reputation.c:333–335), others set both
(:315–331); merge inherits flag_cc when NULL, flag_mask when 0 → tor-only child inherits parent's
mask, non-tor child drops parent's T1 (reputation.c:141–142: T1 matched only via flag_cc).
Fix: treat `flag_cc` and `flag_mask` as ONE policy unit with an explicit set-marker: add
`unsigned flag_block_set:1` to `ngx_heavybag_rep_conf_t`, set it in the waf_flag_block parser;
merge rule (inside the new shared merge helper): if the child never used waf_flag_block, inherit
BOTH fields; if it did, inherit NEITHER (clean override). Document the override semantics in one
comment. This makes the tor-vs-other asymmetry irrelevant.
Tests: conf-merge unit tests (the reputation suite has 100% coverage to preserve): parent
`tor drop` + child `anonymous-proxy` → child blocks A1 only, and the parent level still blocks
T1+XD; child with no waf_flag_block → inherits both; tor-only child → overrides both.

**T5.c (HIGH #4, module.c:1389) — ua_re empty-list sentinel.**
Evidence: empty/comments-only list → `*out = NULL` (match.c:486–489) + NOTICE "loaded 0 UA
pattern(s)"; set_ua_list stores no path (:1609–1626; contrast sig :1597, ja4 :1649); merge
(:1389–1392) re-inherits on NULL with no `.data` gate (contrast sig :1409–1414); duplicate guard
dead for the same reason.
Fix: mirror the sig-list pattern — store the list path per category (`ua_list[cat]` ngx_str_t) in
set_ua_list; duplicate-guard on the path; merge `ua_re[i]` only when `ua_list[i].data == NULL`.
An explicitly configured empty list then genuinely disables that category (ua_re stays NULL).
Decide + document: keep the "loaded 0 UA pattern(s)" NOTICE (it is now meaningful, not a trap).
Tests: merge unit test — child empty bot list → no bot classification in child, parent unaffected;
duplicate directive at same level → "is duplicate" config error.

### T6 — status zone render + snapshot  [files: heavybag_status.c, heavybag_status.h]

**T6.a (HIGH #1, render half; status.c:822 / :384 / :568 / :734).**
Evidence: all three renderers clamp only to `wmcf->nvhosts`/`cmcf->servers.nelts` (:820–824),
never `sh->nvhosts` — sole violators of the status.h:155–158 contract.
Fix: add the third clamp — `if (nvhosts > sh->nvhosts) { nvhosts = sh->nvhosts; }` at the single
spot where nvhosts is computed (:820–824). Defense-in-depth independent of T7's init fix.
Test: unit-test the clamp helper if extractable; otherwise the reload e2e in T7 covers it.

**T6.b (MED #11, status.c:818) — snapshot tearing.**
Evidence: `snap = *sh` — unlocked multi-KB copy of live ngx_atomic_t fields; ~30 concurrent
lock-free writers.
Fix (proportionate): replace the bulk struct copy with an explicit field-wise snapshot of the
scalar counters via `ngx_atomic_t` reads (a small static `stat_snapshot()` function; arrays copied
per-element — element reads of aligned ngx_atomic_t are atomic on supported platforms). Document
the guarantee in the comment: per-counter atomicity yes, cross-counter consistency no (that is
acceptable for monitoring and matches the previous intent).
Test: TSan run (`HEAVYBAG_TSAN=1`) of the rate-stress suite extended to hammer status rendering
concurrently — must stay clean.

**T6.c (trivial, status.c:110) — fix the stale `waf_flag_bits[]` → `heavybag_flag_bits[]`
cross-reference comment** (budget-dropped candidate; one-line comment fix).

---

## Wave 3 — module.c core + stream gate + cleanups (2 tasks, parallel; starts after wave 2)

### T7 — stat zone reload reconciliation + stream allowlist gate  [files: ngx_http_heavybag_module.c (stat section), heavybag_stream.c (preaccess handler region)]

**T7.a (HIGH #1, root half; module.c:2720–2729).**
Evidence: reload-reuse checks only the compile-time layout signature (status.h:153 — sizeof-based,
cannot see nvhosts); assign_vhosts renumbers by new server order (:2839–2844); hot paths guard on
old sh->nvhosts (:668, :956) → silent zero counters for new vhosts + wrong-server attribution on
remove/reorder.
Fix: on the reuse path, compare `osh->nvhosts` with the new cycle's `wmcf->nvhosts`; on mismatch,
re-initialize the segment in place (re-slab the struct with the new trailing-array size, reset
counters, log NOTICE "heavybag: vhost count changed (old→new), counters reset") — counter reset on
topology change is honest and self-describing; silently remapping old slots to new indices would
fabricate history. ALSO handle same-count-but-reordered: cheap and sufficient is to accept that
equal-count reorder keeps slot identity by index (document it); full server_name fingerprinting is
out of scope — note it as a known limitation in the code comment.
Test: sandbox e2e — start with N servers, reload with N+2, GET /waf/status in all three formats:
no OOB (ASan build), new vhosts present with zero counters, NOTICE logged. Plus unit test of the
decision predicate if factored pure.

**T7.b (HIGH #3, stream half; stream.c:265).**
Evidence: rate stage gated only on `denied`; HTTP head skips for ALLOWLIST + scope FULL
(module.c:1016–1020, default scope FULL :1384–1385).
Fix: same gate in the stream preaccess: skip rate_check when `verdict.reason ==
HEAVYBAG_REASON_ALLOWLIST` (respect allowlist_scope if the stream conf has it; if the stream head
has no scope directive, follow the HTTP default = FULL and note it in the comment).
Test: stream ctest — allowlisted peer over-limit → connection allowed; non-allowlisted → denied.

### T8 — module.c quality cleanups  [files: ngx_http_heavybag_module.c (handler/getter/symbol regions), heavybag_spoof.c]

**T8.a (MED-Q, 11× cc_bump epilogue → finalizer; module.c:1000 et al.).**
Evidence: the 4-line `if (verdict.geo_valid) stat_cc_bump(...)` tail is verbatim at 11 sites
(1000, 1037, 1051, 1084, 1147, 1169, 1199, 1236, 1263, 1281, 1301); finalize_decision (:687,
"single chokepoint" :676) already does the detect-path bump (:739–742) and has the equivalent
state; the enforce bump fits the `if (count)` branch (:751).
Fix: move the enforce-path cc_bump into finalize_decision; delete all 11 tails. Take care to
preserve exact counting semantics (geo_valid ↔ ctx->geo_done equivalence is established at
:971–977; keep the r->internal gating via the sh-NULL convention).
Test: existing per-CC counter assertions in the stress/e2e suites must stay green (they pin the
counting semantics).

**T8.b (MED-Q, ctx idiom ×8; module.c :546, :928, :2258, :2301, :2357, :2395, :2521 + spoof.c:237).**
Fix: one `ngx_http_heavybag_get_ctx(r)` (fetch-or-pcalloc-or-set, NULL on alloc failure) in
module.c, declared in ngx_http_heavybag.h; replace all 8 sites (spoof.c returns NULL vs NGX_ERROR —
map at call site). Zero behavior change.

**T8.c (MED-Q, country/asn getters half-caching; module.c:2310–2324, :2404–2417).**
Evidence: each getter discards the other half of the SAME `geo_result_t` and sets only its own
done flag; preaccess fills both from one lookup (:974–984); doc :2288 promises "at most ONE geo
lookup per request".
Fix: one shared `resolve_geo_into_ctx(r, ctx, wlcf)` helper that performs the lazy fallback once
and stores country+asn+both flags; both getters call it. Restores the documented contract.
Test: unit/e2e — `waf off` + log $waf_country + $waf_asn → exactly one lookup (assert via the
ctx flags; or count via the unit harness).

**T8.d (MED-Q, symbol hygiene; module.c:51/:67 + status.h:188–189 + status.c uses).**
Fix: rename `heavybag_type_str`/`heavybag_reason_str` → `ngx_http_heavybag_type_str`/
`ngx_http_heavybag_reason_str` (mechanical, clangd-verified rename across the 3 files).
NOTE: status.c/h are frozen in wave 2's T6 — this is why the rename sits in wave 3.

**T8.e (MED-Q, lying comment; module.c:1109–1110).**
Fix: rewrite to state the truth: counted once per client request; sh is NULL on internal-redirect
hops (observability-02), like every other sh-guarded counter above.

**T8.f (trivial, spoof.c:19) — rename the generic `ngx_http_next_header_filter`/
`ngx_http_next_body_filter` statics to `ngx_http_heavybag_next_{header,body}_filter`**
(budget-dropped candidate; mechanical, spoof.c is already open in this task).

---

## Deliberately deferred (needs a product decision, not a raid)

- **status.c serializer descriptor table (MED-Q, status.c:202).** Real cost, but a structural
  refactor of all three renderers + the FIXED_LINES bound; do it as its own reviewed feature.
  Interim mitigation ships free with T6/T7 work: none needed — current headroom ~90 lines.
- **Segregated mail_* counters** (instead of T4's reuse of the http_* counters) — shm layout bump +
  serializer additions; decide after the security review.

## Wave/task → finding coverage matrix

| Finding (severity) | Task |
|---|---|
| H1 stat-shm reload (OOB + drop/misattribution) | T6.a (render clamp) + T7.a (root fix) |
| H2 flag merge asymmetry | T5.b |
| H3 allowlist vs rate (stream + mail) | T7.b (stream) + T4.b (mail) |
| H4 ua_re empty-list inherit | T5.c |
| H5 mail counters | T4.a |
| H6 Chrome/wv | T1.a |
| H7 libmpv | T1.b |
| M8 geo ipv4root | T2.a |
| M9 rate re-attach | T3.a |
| M10 geo SIGBUS | T2.b |
| M11 torn snapshot | T6.b |
| M12 rep merge/setter duplication | T5.a |
| Q: cc_bump ×11 | T8.a |
| Q: ctx ×8 | T8.b |
| Q: country/asn half-cache | T8.c |
| Q: GREASE dup | T3.b |
| Q: dead Nintendo branch | T1.c |
| Q: extern prefix | T8.d |
| Q: lying redirect comment | T8.e |
| Q: serializer table | DEFERRED |
| (dropped) spoof filter statics naming | T8.f |
| (dropped) stale flag_bits xref | T6.c |

Raid size: wave 1 = 4 raiders, wave 2 = 2, wave 3 = 2. Every wave ends with: build green
(-Werror), full ctest green, then proceed. Final gate = the verification tail at the top.
