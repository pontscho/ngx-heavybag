# Unified Fix Task-List — heavybag WAF (`modules/ngx_http_heavybag/src/`)

**Date:** 2026-08-28  
**Merges:** `reviews/code-review-src-2026-08-20.md` (S6 code review — 7 HIGH + 15 MEDIUM) + `reviews/security-review-src-2026-08-24.md` (S7 security review — 9 VERIFIED / 3 ESCALATED / 10 SUPPRESSED).  
**Skeleton:** the S6 fix-plan (`reviews/code-review-fix-plan-2026-08-20.md`, waves T1–T8) is the raid scaffold; the security findings are overlaid onto it (severity reconciled, CWE added, new security-only subtasks folded into the owning file-task).  
**Execution model:** parallel **raid** of Opus builder agents in **file-disjoint waves**. A file appears in exactly one task per wave. Waves are sequential barriers (wave N+1 starts only when wave N is green: `-Werror` build + full ctest). One raider = one task.  
**IMPORTANT:** this is the task-list only — **do NOT implement the fixes yet**. ~~3 ESCALATED items~~ **SV11 is now RESOLVED** (2026-08-28, partner: multi-tenant host → shared-secret trust model, folded into T4.d). Two ESCALATED items remain (SV13, SV19) in the **DECISION NEEDED** section and must be settled by a human before any code change on their surface.

---

## 0. Dedup ledger (read first)

The two reviews overlap on **five** seeds, not four. Each must be covered by **one** task so two raiders never rewrite the same line:

| Seed | Code-review | Security | Owning task | Reconciled severity |
|---|---|---|---|---|
| stat-shm /status OOB read (render half) | #1 (HIGH) | **SV1** | **T6.a** | sec **LOW** (bounded over-read inside mapped zone); correctness half (reload reconciliation) = **T7.a**, correctness-only |
| `waf_flag_block` Tor merge asymmetry | #2 (HIGH) | **SV8** | **T5.b** | sec **MEDIUM** / correctness HIGH |
| allowlist not bypassing rate on L4/mail | #3 (HIGH) | **SV9** | **T7.b** (stream) + **T4.b** (mail) | sec **MEDIUM** (self-DoS of trusted infra) |
| empty UA-list re-inherits parent regex | #4 (HIGH) | **SV10** | **T5.c** | sec **LOW** (fails closed / over-block, not silent) |
| **rate-zone re-attach unvalidated** | **#9 / M9** | **SV16** | **T3.a** | sec **MEDIUM → HIGH on persisted-shm** — *this is the 5th seed the earlier note undercounted; T3.a already carries the exact remediation* |

Three more code-review MEDIUMs have a **suppressed** security twin (defense-in-depth, keep the code-review fix, no security escalation): geo terminator #8 ≡ SV3 (T2.a), geo SIGBUS #10 ≡ SV5 (T2.b), torn snapshot #11 ≡ SV17 (T6.b).

**New security-only real findings** (no code-review equivalent) folded into the owning file-task: **SV14** (reputation.c → T5.d, MEDIUM), **SV4** (geo.c → T2.c, LOW), **SV12** (authhttp.c → T4.c, LOW), **SV21** (ua_parse.c → T1.d, LOW/optional).

---

## 1. Master severity-ranked index (all actionable items, deduped)

Priority order for the raid = dependency-safe waves below; this table is the at-a-glance ranking.

| # | Item | Source | File:line | CWE | Severity | Task |
|---|---|---|---|---|---|---|
| 1 | rate-zone shm re-attach: no layout/nslots validation | SV16 = M9 | heavybag_rate.c:538 → :238/240/296/339 | 665→125/787 | **MED → HIGH (persisted-shm)** | T3.a |
| 2 | `waf_flag_block` merge asymmetry — child drops parent's Tor | #2 / SV8 | ngx_http_heavybag_module.c:1441/1450 + heavybag_stream.c:347/356 | 284 | **MED** (sec) / HIGH (corr) | T5.b |
| 3 | Tor `flag_block` fails open for IP absent from geo DB | SV14 | heavybag_reputation.c:102 | 636 | **MED** | T5.d |
| 4 | allowlist bypasses rate only on HTTP (stream+mail throttle trusted IP) | #3 / SV9 | ngx_http_heavybag_module.c:1016 vs heavybag_stream.c:265 + heavybag_authhttp.c:128 | 284 | **MED** | T7.b + T4.b |
| 5 | stat-shm reload divergence: OOB /status read + zero/misattributed counters | #1 / SV1 | heavybag_status.c:822 (+:385/:569/:735); ngx_http_heavybag_module.c:2720 | 125 | **HIGH (corr)** / LOW (sec) | T6.a + T7.a |
| 6 | mail auth head breaks exported counter invariant; rep-blocks invisible | #5 | heavybag_authhttp.c:144 + :110 | — | **HIGH (corr)** | T4.a |
| 7 | Chrome/`wv` probe destroys version + pre-empts HeadlessChrome | #6 | heavybag_ua_parse.c:328 | — | **HIGH (corr)** | T1.a |
| 8 | `libmpv` version extraction always empty | #7 | heavybag_ua_parse.c:359 | — | **HIGH (corr)** | T1.b |
| 9 | empty UA-list cannot disable inherited signatures | #4 / SV10 | ngx_http_heavybag_module.c:1389 + heavybag_match.c:485 | 284 | **HIGH (corr)** / LOW (sec) | T5.c |
| 10 | geo ipv4-mapped descent ignores `nxt==0` terminator | #8 / SV3 | heavybag_geo.c:387 | 1284/20 | **MED (corr)**; sec suppressed (DiD) | T2.a |
| 11 | rep-conf merge/validate/setters duplicated + already drifted | #12 | heavybag_stream.c:341 vs ngx_http_heavybag_module.c:1435 | — | **MED (dup)** | T5.a |
| 12 | geo mmap vs in-place truncate → SIGBUS | #10 / SV5 | heavybag_geo.c:322 | 703 | **MED (corr)**; sec suppressed (ops) | T2.b |
| 13 | `snap = *sh` non-atomic multi-KB copy → torn /status counters | #11 / SV17 | heavybag_status.c:818 | 362 | **MED (corr)**; sec suppressed (cosmetic) | T6.b |
| 14 | geo block-table bounds check: ILP32 integer overflow | SV4 | heavybag_geo.c:375 | 190→125 | **LOW** | T2.c |
| 0★ | mail `auth_http` trusts client-supplied `Client-IP` from any loopback/unix peer (multi-tenant → WAF-evasion) | SV11 | heavybag_authhttp.c:188 + :181–183 → :108/:134 | 290/348 | **MED** (confirmed real; RESOLVED → shared-secret) | T4.d |
| 15 | `waf_mail_failopen` default-on: missing Client-IP allowed unjudged | SV12 | heavybag_authhttp.c:80 (default module.c:1383) | 636 | **LOW** (subsumed by T4.d fail-closed) | T4.c |
| 16 | naive O(hlen×nlen) UA substring scan ~100×/req | SV21 | heavybag_ua_parse.c:144 | 407 | **LOW (optional)** | T1.d |
| Q | 11× `cc_bump` epilogue paste → finalizer | Q | ngx_http_heavybag_module.c:1000 et al. | — | quality | T8.a |
| Q | ctx fetch-or-pcalloc idiom ×8 | Q | ngx_http_heavybag_module.c:928 + spoof.c:237 | — | quality | T8.b |
| Q | country/asn getters half-cache one geo lookup | Q | ngx_http_heavybag_module.c:2310/2404 | — | quality | T8.c |
| Q | unprefixed extern data symbols (RTLD_GLOBAL interposition) | Q | ngx_http_heavybag_module.c:51/:67 | — | quality | T8.d |
| Q | comment claims opposite of code (internal-redirect counting) | Q | ngx_http_heavybag_module.c:1109 | — | quality | T8.e |
| Q | JA4 GREASE predicate byte-duplicated | Q | heavybag_ja4.c:319 | — | quality | T3.b |
| Q | provably-dead Nintendo DSi/Wii fallback | Q | heavybag_ua_parse.c:434 | — | quality | T1.c |
| Q | stale `waf_flag_bits[]` xref comment | Q(dropped) | heavybag_status.c:110 | — | trivial | T6.c |
| Q | spoof filter statics use generic nginx names | Q(dropped) | heavybag_spoof.c:19 | — | trivial | T8.f |

**Deferred (product decision, not a raid task):** status.c serializer descriptor table (#Q status.c:202); segregated `mail_*` counters (alternative to T4.a's reuse). See §5.

---

## 2. Ground rules for every raider (copy into each brief)

- **Surgical scope:** fix ONLY what the task lists; match surrounding style (comment density, naming, early-return idiom). No drive-by refactors.
- **No new source files** — new shared helpers go into existing TUs (`heavybag_reputation.c`, `heavybag_match.c`, …). A new `.c` requires an nginx reconfigure (project rule).
- **Build:** `cmake --build build --target heavybag_module` (no `project-forge.yaml` in root → cmake is the correct path). `-Werror` — warnings fail the build.
- **Tests:** run the full ctest suite (14 suites) after the change; every finding fix MUST land with a regression test (unit via `ctest.h` where the logic is pure; noted per task where only a comment/doc changes). Coverage knob `HEAVYBAG_COVERAGE=1`, TSan knob `HEAVYBAG_TSAN=1` where relevant.
- **Tools:** Read for reading, `purity_call` (search/list/clangd) for navigation, purity/Edit for writes. Never shell text tools (cat/sed/awk/grep/find/ls). Docker FORBIDDEN.
- **nginx idioms:** `ngx_str_t` is not NUL-terminated; per-request state must survive internal redirects (no POST_READ-only population); `ngx_snprintf` does not NUL-terminate.
- **Naming:** config-surface stays `waf_*`; C symbols stay `heavybag`/`ngx_http_heavybag_`.
- **clangd landmine:** a generated `build/compile_commands.json` exists; if clangd returns garbage (ghost `ngx_http_waf` from the rename), note it and fall back to careful Read — never text-grep guesses.

---

## 3. The waves

### Wave 1 — leaf files, fully parallel (4 raiders, no shared-helper dependency)

#### T1 — UA parser  [file: `heavybag_ua_parse.c` + its ctest suite]

**T1.a — Android WebView probe destroys Chrome version / pre-empts HeadlessChrome.** `#6` (HIGH, correctness). ua_parse.c:328.  
*Fix:* (1) move the `HeadlessChrome/` probe ABOVE the webview probe (restores the :285–288 documented order); (2) anchor the webview signal to the real Android token `"; wv)"` (min `" wv)"`) instead of bare `"wv"`; (3) after classifying webview, still run `HEAVYBAG_VER(ua, n, "Chrome/", vs, vl)` so the version survives.  
*Regression test:* `...; wv) ... Chrome/119.0.0.0 ...` → browser chrome + version `119.0.0.0`; a HeadlessChrome UA with incidental `wv` → headless (not chrome); plain Chrome unaffected.

**T1.b — `libmpv` version always empty.** `#7` (HIGH, correctness). ua_parse.c:359.  
*Fix:* `"libmpv"` → `"libmpv/"` in both the HAS probe and the VER slice (match neighbors curl/, Wget/, Lavf/).  
*Regression test:* `libmpv/0.38.0` → browser libmpv, version `0.38.0`.

**T1.c — delete dead Nintendo DSi/Wii fallback.** Q (quality). ua_parse.c:434.  
*Fix:* delete the provably-unreachable branch + its LCOV_EXCL comment (try_os :265 maps the substrings to NINTENDO* consumed by the CONSOLE arm :388). No new test; keep existing console tests green.

**T1.d — UA naive substring scan (defense-in-depth).** SV21 (LOW, **optional**, CWE-407). ua_parse.c:144 (`heavybag_ua_find`).  
*Fix (optional):* only material if an operator raises per-header buffers to multi-MB; sub-ms/req at default 8k. Either (a) an early UA-length clamp before the ~119 probes, or (b) a `memmem`/Boyer-Moore primitive. **Recommend: skip unless the partner wants the hardening** — note it in the code comment and move on.  
*Regression test (if done):* assert classification unchanged on the existing UA corpus (behaviour-preserving).

#### T2 — geo loader  [file: `heavybag_geo.c` + geo unit harness]

**T2.a — ipv4root descent terminator.** `#8` / SV3 (MED correctness; security-suppressed = defense-in-depth, source is ECDSA-signature-gated). geo.c:387.  
*Fix:* inside the 96-step descent, after fetching `nxt`, treat `nxt == 0` before step 96 as a hard load failure (`ngx_log_error(NGX_LOG_EMERG, …)` + return NULL) — parity with the runtime walker's `} while (nxt)` (:446). Fail closed at config time; do NOT silently fall back.  
*Regression test:* extend `HEAVYBAG_GEO_UNIT_TEST` with a synthetic DB whose `/96` chain has a zero child at depth < 96 → load must FAIL.

**T2.b — mmap vs in-place truncate (SIGBUS).** `#10` / SV5 (MED correctness; security-suppressed = operational hardening). geo.c:322.  
*Fix (proportionate — trigger is operator error):* (1) loud comment at the mmap site + a README/docs note: `location.db` MUST be replaced via write-new + `rename(2)`, never truncated in place; (2) cheap belt: after mmap, `ngx_fd_info` again and reject if size changed under us (closes the load-time race only — document that runtime truncation stays fatal by design, as in nginx's own mmap usage). No SIGBUS handler (out of proportion).  
*Regression test:* doc-only + load-race check; unit test optional (racy to test meaningfully).

**T2.c — ILP32 integer overflow in block-table bounds check.** SV4 (LOW, CWE-190→125). geo.c:375.  
*Fix:* width-independent check `if (off > size || len > size - off)` (consistent with the module's existing ILP32 hardening, e.g. reputation.c:270). LP64 is already safe; this closes the 32-bit build.  
*Regression test:* unit test the predicate with `off=0xFFFFFFF0, len=0x20` against a small `size` → must reject (pre-fix wraps and passes).

#### T3 — rate zone re-attach + JA4 GREASE dedup  [files: `heavybag_rate.c`, `heavybag_rate.h`, `heavybag_ja4.c`]

**T3.a — rate-zone re-attach validation.** `#9 / M9` **= SV16** (MED → **HIGH on persisted-shm**, CWE-665→125/787). rate.c:538 → sinks :238/240/296/339.  
*This is the highest-severity code+security item that is a pure code fix (the decisions aside).* The re-attach branch `if (shm_zone->shm.exists) { shm_zone->data = shpool->data; return NGX_OK; }` adopts a persisted segment with no magic/layout/nslots check; the rate header (rate.c:101–105) has no layout field, and `rate_check` uses `hdr->nslots` as the sole modulo/index bound → OOB read + OOB CAS-write on a desynced segment.  
*Fix:* mirror the status zone — add a `layout`/magic word to `ngx_http_heavybag_rate_hdr_t`, stamp it at init (`MAGIC ^ sizeof(header) ^ sizeof(slot) ^ nslots-formula`), and on the `shm.exists` path reject NULL data / mismatched layout / an `nslots`-vs-zone-size violation with `NGX_ERROR` (fail closed, same wording style as the status zone at module.c:2737–2748). Header layout change bumps the signature by construction.  
*Regression test:* unit-test the validation predicate (pure function over a fake header) in the rate ctest suite; re-attach with wrong layout → error, correct layout → OK.

**T3.b — JA4 GREASE predicate dedup.** Q (quality). ja4.c:319.  
*Fix:* delete `ja4_compute_is_grease` (byte-identical to the unconditionally-compiled `ja4_is_grease` :27 in the same TU), call `ja4_is_grease` from the extractor, drop the stale "needs no core helper" comment.  
*Regression test:* existing JA4 e2e extractor vector must stay green.

#### T4 — mail auth-http head  [file: `heavybag_authhttp.c`]

> **Dependency note (RESOLVED):** SV11 (D1) is decided — multi-tenant host, shared-secret trust model. Its code change lands in this same file and is folded in as **T4.d** below. All of T4 (a/b/c/d) is one raider, one file, wave 1. No pre-wave gate remains.

**T4.a — counter symmetry / mail accounting.** `#5` (HIGH, correctness). authhttp.c:144 + :110.  
*Fix:* make the mail head a first-class citizen of the same invariant `requests_total == allowed + Σ blocked` (observability-01, documented module.c:721–725). At the top of the auth content handler (once per auth request, after `sh` resolution) bump `http_requests_total`; on reputation deny bump `http_blocked[<reason>]`; on rate deny keep the existing blocked/429 bumps; on allow bump `http_allowed`. Reuse the existing HTTP counters — **no new shm fields, no serializer changes, no shm layout bump** (segregated `mail_*` counters are a separate feature, see §5). Update the file-top accounting comment.  
*Regression test:* extend auth-http ctest/e2e — after N mail requests with mixed allow/rate-deny/rep-deny, assert `requests_total == allowed + Σ blocked` from the serialized /waf/status (the stress harness already parses it).

**T4.b — allowlist bypasses rate (mail half).** `#3` / SV9 (MED). authhttp.c:128–155.  
*Fix:* skip the rate stage when the reputation verdict's reason is `HEAVYBAG_REASON_ALLOWLIST` — mirror the HTTP head's lifecycle-v01 rule (module.c:1016–1020). Keep enforce-always for non-allowlisted traffic.  
*Regression test:* allowlisted peer + exhausted bucket → Auth-Status OK; non-allowlisted peer + exhausted bucket → deny.

**T4.c — `waf_mail_failopen` default-on.** SV12 (LOW, CWE-636). authhttp.c:80 (default module.c:1383).  
*Context:* largely **subsumed by T4.d** — once `Client-IP` is only trusted on the shared-secret-authenticated channel, a forged/omitted `Client-IP` from an unauthenticated local process no longer reaches the fail-open path. Residual: a genuinely authenticated proxy request that omits `Client-IP`.  
*Fix (minimal):* document the fail-open default prominently at the directive + in docs. Whether to flip the default to fail-closed is now lower-stakes but still a product call — if flipped, change `ngx_conf_merge_value(..., 1)` → `0` at module.c:1383 and update `tests/run-mailauth-fuzz.sh` #9. Recommend: document, and align the default with T4.d's fail-closed philosophy (flip to off) since the feature is greenfield (no back-compat cost).  
*Regression test:* `tests/run-mailauth-fuzz.sh` #9 already exercises `waf_mail_failopen off`; add an assertion for the chosen default.

**T4.d — mail `auth_http` Client-IP trust model (shared secret).** SV11 (**MED**, CWE-290/348) — **RESOLVED design, security-only, greenfield**. authhttp.c:188 (loopback gate) + :181–183 (AF_UNIX gate) + the headers_in walk (~:323) + the peer-trust helper (:64/:175–208).  
*Decision (partner, 2026-08-28):* host **can run other local processes** → the blanket "any loopback / any AF_UNIX" trust is a real WAF-evasion primitive. A bare `localhost:port` does **not** fix it (any co-located process can `connect()` and forge `Client-IP`). Chosen model: **authenticate the caller with a shared secret**, transport-agnostic.  
*Fix:*
1. New directive `waf_mail_trusted_secret <token>;` on the auth_http location (store in the mail/authhttp conf).
2. On the mail side the operator sets `auth_http_header X-WAF-Key "<token>";` so ngx_mail attaches it to every auth request.
3. In the auth handler, trust the forwarded `Client-IP` (and `Client-Host`) **only** when: (a) the peer is loopback/unix (keep the cheap first filter), **AND** (b) the request carries `X-WAF-Key` whose value **constant-time-equals** the configured secret (fixed-time compare over equal lengths — guard against the CWE-208 timing side-channel; do NOT use `ngx_strcmp`/`memcmp` early-exit).
4. **Default = fail-closed:** if no secret is configured, or the header is missing / mismatched, do NOT trust `Client-IP` — judge the real connection peer (the existing else-arm behaviour, :96–100). This also closes SV12/T4.c by construction.
5. Narrow/replace the current sole gate (127/8 + every AF_UNIX) so the secret is the actual authenticator, not the peer class.  
*Regression tests:*
- correct `X-WAF-Key` + `Client-IP: <spoofed-allowlisted>` from loopback → judged on the forwarded IP (feature works);
- **missing/wrong `X-WAF-Key`** from loopback → `Client-IP` ignored, judged on the real peer (evasion closed);
- no `waf_mail_trusted_secret` configured → `Client-IP` never trusted (fail-closed);
- remote (non-loopback) peer → unchanged (real peer judged);
- timing: assert the constant-time primitive is used (unit test the compare helper; equal-length differing tokens take the same path).  
*Note:* extend `tests/run-mailauth-fuzz.sh` with the forged-header-without-secret vector.

---

### Wave 2 — rep-config layer + status zone (2 raiders; starts after wave 1 green)

#### T5 — reputation config consolidation + sentinel/fail-open fixes  [files: `heavybag_reputation.c`, `heavybag_rep.h`, `ngx_http_heavybag_module.c` (merge/setter region only), `heavybag_stream.c` (merge/setter region only)]

> This task owns the merge/setter REGIONS of module.c and stream.c. Wave 3's T7/T8 own DIFFERENT regions of the same files — the wave barrier keeps them disjoint in time.

**T5.a — shared merge/validate/setters.** `#12` (MED, dup — already drifted). stream.c:341–386 duplicate module.c:1435–1479 (byte-identical error string); the heads already drifted (HTTP validates before inheriting blocklist/allowlist, stream after).  
*Fix:* add to `heavybag_reputation.c`: `ngx_http_heavybag_rep_conf_merge(prev, conf)` (8-field NULL/0-inherit) + `ngx_http_heavybag_rep_conf_validate(cf, rep)` (geo-dependency fail-closed) + shared directive setters taking `ngx_heavybag_rep_conf_t *`. Pick ONE validation order — **validate AFTER all inherits** (the stream order, which sees the full effective config); preserve the exact error string. Each head keeps a 2-line wrapper dereferencing its own conf struct. Both merges + all 14 setters delegate.  
*Regression test:* the reputation suite is at 100% coverage — keep it; add a merge-order test asserting a child with its own geo DB + a rep field validates identically on both heads.

**T5.b — flag_mask/flag_cc sentinel.** `#2` / SV8 (HIGH corr / **MED sec**, CWE-284). module.c:1441/1450 + stream.c:347/356.  
*Fix:* treat `flag_cc` and `flag_mask` as ONE policy unit with an explicit set-marker — add `unsigned flag_block_set:1` to `ngx_heavybag_rep_conf_t`, set it in the `waf_flag_block` parser; merge rule (inside the new shared merge helper): if the child never used `waf_flag_block`, inherit BOTH; if it did, inherit NEITHER (clean override). One comment documenting the override semantics. This makes the tor-vs-other asymmetry irrelevant.  
*Regression test:* conf-merge unit tests — parent `tor drop` + child `anonymous-proxy` → child blocks A1 only AND the parent level still blocks T1+XD; child with no `waf_flag_block` → inherits both; tor-only child → overrides both.

**T5.c — ua_re empty-list sentinel.** `#4` / SV10 (HIGH corr / **LOW sec**, CWE-284). module.c:1389 + match.c:485.  
*Fix:* mirror the sig-list pattern — store the list path per category (`ua_list[cat]` `ngx_str_t`) in `set_ua_list`; duplicate-guard on the path; merge `ua_re[i]` only when `ua_list[i].data == NULL`. An explicitly configured empty list then genuinely disables that category. Keep the meaningful "loaded 0 UA pattern(s)" NOTICE.  
*Regression test:* merge unit test — child empty bot list → no bot classification in child, parent unaffected; duplicate directive at same level → "is duplicate" config error.

**T5.d — Tor `flag_block` fails open for a no-geo-record IP.** SV14 (**MED**, CWE-636) — **NEW, security-only**. reputation.c:102.  
*Fix:* in block mode (`!rep->allow_cc`), the `if (!res.found) return NGX_DECLINED` at :102 short-circuits BEFORE the `flag_mask` gate (:106) and `flag_cc`/T1 gate (:141). When any flag/flag_cc **deny** policy is configured, the no-record path must fail closed (or emit an audit signal) rather than allow. Whitelist mode (`allow_cc`) already fails closed — preserve it.  
*Regression test:* reputation unit test — `waf_flag_block tor` + a source IP with no geo record → denied (pre-fix: allowed); with no flag policy configured → still `NGX_DECLINED` (unchanged); `allow_cc` mode unchanged.

#### T6 — status zone render + snapshot  [files: `heavybag_status.c`, `heavybag_status.h`]

**T6.a — /status render clamp (H1 render half).** `#1` / SV1 (HIGH corr / **LOW sec**, CWE-125). status.c:822 (+:385/:569/:735).  
*Fix:* clamp the per-vhost loop to the already-captured `snap.nvhosts` (currently captured at :818 but unused) — i.e. add the third clamp `if (nvhosts > sh->nvhosts) nvhosts = sh->nvhosts;` at the single spot nvhosts is computed (:820–824). Defense-in-depth independent of T7.a's init fix; honours the status.h:155 contract.  
*Regression test:* unit-test the clamp helper if extractable; otherwise the reload e2e in T7.a covers it (ASan build, no OOB after N→N+2 server reload).

**T6.b — snapshot tearing.** `#11` / SV17 (MED corr; security-suppressed = cosmetic). status.c:818.  
*Fix (proportionate):* replace the bulk `snap = *sh` struct copy with an explicit field-wise snapshot of the scalar counters via `ngx_atomic_t` reads (a small static `stat_snapshot()`; arrays copied per-element — aligned `ngx_atomic_t` element reads are atomic on supported platforms). Document: per-counter atomicity yes, cross-counter consistency no (acceptable for monitoring; matches prior intent). Fix the overstated ":817 consistent snapshot" comment.  
*Regression test:* TSan run (`HEAVYBAG_TSAN=1`) of the rate-stress suite extended to hammer status rendering concurrently — must stay clean.

**T6.c — stale `waf_flag_bits[]` xref comment.** trivial. status.c:110.  
*Fix:* `waf_flag_bits[]` → `heavybag_flag_bits[]` in the comment (the only lockstep guard on the flag label/bit arrays). No test.

---

### Wave 3 — module.c core + stream gate + cleanups (starts after wave 2 green)

> **RAID CONSTRAINT — module.c collision.** In the original fix-plan, wave 3 ran T7 and T8 in parallel, but **both edit `ngx_http_heavybag_module.c`** (T7 the stat section, T8 the handler/getter/symbol regions) — that violates the file-disjoint rule. **Resolution: serialize within wave 3 — T7 first, then T8** (module.c is single-owner at a time). T7's stream.c edit (:265) and T8's spoof.c edit are disjoint, so nothing else conflicts. Alternatively merge T7+T8 into one module.c raider; serializing is simpler and keeps the H1 root fix isolated.

#### T7 — stat zone reload reconciliation + stream allowlist gate  [files: `ngx_http_heavybag_module.c` (stat section), `heavybag_stream.c` (preaccess handler region)]

**T7.a — stat zone reload reconciliation (H1 root half).** `#1` (HIGH, correctness; the OOB-read security facet is SV1/T6.a). module.c:2720–2729.  
*Fix:* on the reuse path, compare `osh->nvhosts` with the new cycle's `wmcf->nvhosts`; on mismatch, re-initialize the segment in place (re-slab with the new trailing-array size, reset counters, log NOTICE "heavybag: vhost count changed (old→new), counters reset") — an honest, self-describing reset (silently remapping old slots to new indices would fabricate history). Same-count-but-reordered: accept that equal-count reorder keeps slot identity by index (document it); full `server_name` fingerprinting is out of scope — note as a known limitation in the comment.  
*Regression test:* sandbox e2e — start with N servers, reload with N+2, GET /waf/status in all three formats: no OOB (ASan build), new vhosts present with zero counters, NOTICE logged. Plus a unit test of the decision predicate if factored pure.

**T7.b — stream allowlist gate (H3 stream half).** `#3` / SV9 (MED). stream.c:265.  
*Fix:* skip `rate_check` in the stream preaccess when `verdict.reason == HEAVYBAG_REASON_ALLOWLIST` — mirror the HTTP head (module.c:1016–1020). Respect `allowlist_scope` if the stream conf has it; if not, follow the HTTP default (FULL) and note it in the comment.  
*Regression test:* stream ctest — allowlisted peer over-limit → connection allowed; non-allowlisted → denied.

#### T8 — module.c quality cleanups  [files: `ngx_http_heavybag_module.c` (handler/getter/symbol regions), `heavybag_spoof.c`]  *(runs after T7 — same file)*

**T8.a — 11× `cc_bump` epilogue → finalizer.** Q. module.c:1000 + 10 more sites (1037, 1051, 1084, 1147, 1169, 1199, 1236, 1263, 1281, 1301).  
*Fix:* move the enforce-path `cc_bump` into `finalize_decision` (which already does the detect-path bump :739–742); delete all 11 tails. Preserve exact counting semantics (geo_valid ↔ ctx->geo_done equivalence :971–977; keep r->internal gating via the sh-NULL convention).  
*Regression test:* existing per-CC counter assertions in the stress/e2e suites must stay green (they pin the semantics).

**T8.b — ctx idiom ×8.** Q. module.c:546, 928, 2258, 2301, 2357, 2395, 2521 + spoof.c:237.  
*Fix:* one `ngx_http_heavybag_get_ctx(r)` (fetch-or-pcalloc-or-set, NULL on alloc failure) in module.c, declared in `ngx_http_heavybag.h`; replace all 8 sites (spoof.c returns NULL vs NGX_ERROR — map at call site). Zero behaviour change.  
*Regression test:* behaviour-preserving; existing suites cover it.

**T8.c — country/asn getters half-caching.** Q. module.c:2310–2324, 2404–2417.  
*Fix:* one shared `resolve_geo_into_ctx(r, ctx, wlcf)` that performs the lazy fallback once and stores country+asn+both flags; both getters call it. Restores the ":2288 at most ONE geo lookup per request" contract.  
*Regression test:* `waf off` + log `$waf_country` + `$waf_asn` → exactly one lookup (assert via ctx flags or the unit harness).

**T8.d — extern symbol hygiene.** Q. module.c:51/:67 (+ status.h:188–189 + status.c uses).  
*Fix:* rename `heavybag_type_str`/`heavybag_reason_str` → `ngx_http_heavybag_type_str`/`ngx_http_heavybag_reason_str` (mechanical, clangd-verified rename across the 3 files; `ngx_dlopen` uses RTLD_GLOBAL → interposition risk). *Sits in wave 3 because status.c/h are frozen by T6 in wave 2.*  
*Regression test:* build green (-Werror); no behaviour change.

**T8.e — lying internal-redirect comment.** Q. module.c:1109–1110.  
*Fix:* rewrite to the truth — counted once per client request; `sh` is NULL on internal-redirect hops (observability-02), like every other sh-guarded counter. No test.

**T8.f — spoof filter statics naming.** trivial. spoof.c:19.  
*Fix:* rename generic `ngx_http_next_header_filter`/`ngx_http_next_body_filter` → `ngx_http_heavybag_next_{header,body}_filter`. No test.

---

## 4. DECISION NEEDED (ESCALATED — human call before any code change)

Each turns on deployment topology / production config / build policy. **Do not raid them blind.** Ranked by the security review's priority.

### D1 — SV11: SMTP `auth_http` trusts a client-supplied `Client-IP` from any loopback/unix peer  — ✅ **RESOLVED 2026-08-28 → T4.d**
- **Severity:** MEDIUM. CWE-290/348, OWASP A01/A07. File: `heavybag_authhttp.c:188` (all 127/8) + :181–183 (every AF_UNIX) → reputation_check :108 + rate_check :134.
- **Decision:** partner confirmed the host **can run other local processes** alongside the mail proxy → the blanket trust is a **genuine WAF-evasion primitive**, not the safe single-tenant contract. The mail `auth_http` feature is **greenfield (not deployed anywhere yet)**, so the trust model is designed fresh. A bare `localhost:port` was rejected (does not authenticate the caller). **Chosen: shared-secret header** — trust `Client-IP` only when `X-WAF-Key` constant-time-equals a configured `waf_mail_trusted_secret`; default fail-closed. Full spec in **T4.d** (wave 1, folded into T4). This also subsumes SV12 (T4.c).

### D2 — SV13: subrequests skip the WAF pipeline (config-audit)
- **Severity:** LOW. CWE-284, OWASP A01. File: `ngx_http_heavybag_module.c:918` (`if (r != r->main) return NGX_DECLINED;`, mirrored :536).
- **The skip is real** (handlers registered only at POST_READ :2957 + PREACCESS :2964) **but** heavybag inspects `r->main` content at POST_READ/PREACCESS, which run *before* `mirror` (PRECONTENT) and `auth_request` (ACCESS) — so a subrequest replays content already inspected/blocked on the main request; `mirror` also discards its response.
- **Decision:** audit the shipped/production `nginx.conf` for `mirror` / `auth_request` / SSI whose subrequest target is a real client-facing backend carrying heavybag rules the operator *assumed* apply. If none exist → this is an inherent nginx subrequest-architecture limitation to **document**, not an exploitable bypass (no code change).

### D3 — SV19: PCRE1 build arm applies regex with no match-limit (ReDoS)
- **Severity:** LOW as-shipped, ~MEDIUM on a PCRE1 rebuild. CWE-1333, OWASP A05/A06. File: `heavybag_match.c:329` (`ngx_regex_exec(re, s, NULL, 0)`, no match/depth limit).
- **The `#else` arm is DEAD in the canonical build:** `CMakeLists.txt:120` pins PCRE2 10.47 (`--with-pcre=<pcre2-src> --with-pcre-jit`, `cmake/Versions.cmake:29`) → `NGX_PCRE2` defined → the bounded 100000/1000 arm (match.c:291–322) runs. The unbounded arm ships only on a downstream PCRE1 rebuild + a pathological operator pattern.
- **Decision:** either (a) bound the PCRE1 path too via `pcre_extra->match_limit`/`match_limit_recursion` (the comment's "no match-limit knob" is true only of nginx's PCRE1 *wrapper*, not PCRE1 itself), or (b) document/enforce PCRE2 as a build requirement so the `#else` arm can never ship. Recommend (b) unless PCRE1 support is a real requirement — it's the smaller surface.

---

## 5. Deliberately deferred (product decision, not a raid task)

- **status.c serializer descriptor table** (Q, status.c:202): real cost but a structural refactor of all three renderers + the FIXED_LINES bound — do it as its own reviewed feature. Interim: none needed (current headroom ~90 lines).
- **Segregated `mail_*` counters** (alternative to T4.a's reuse of `http_*`): shm layout bump + serializer additions. T4.a intentionally reuses the existing counters (no layout bump); revisit only if the partner wants mail broken out separately.
- **SV21 UA scan hardening** (T1.d): optional, only material under non-default multi-MB header buffers.
- **Suppressed hardening nits** (all defense-in-depth, no attacker vector at default config): SV6 geo-style 512 MiB cap on list-file loader (match.c:373); SV15 expose `waf_trusted_proxy_recursive` directive (module.c:507); SV20 explicit cookie-count cap (module.c:858); SV2 JA4 defensive NULL guard (ja4.c:356). Batch these into a single optional "hardening" task only if the partner asks.

---

## 6. Raid summary & verification tail

| Wave | Raiders | Files (disjoint) |
|---|---|---|
| 1 | 4 | T1 ua_parse.c · T2 geo.c · T3 rate.c+rate.h+ja4.c · T4 authhttp.c |
| 2 | 2 | T5 reputation.c+rep.h+module.c(merge)+stream.c(merge) · T6 status.c+status.h |
| 3 | 1→1 (serial) | T7 module.c(stat)+stream.c(preaccess) **then** T8 module.c(quality)+spoof.c |

**Pre-wave-1 gate:** ~~resolve D1 (SV11)~~ **cleared** — D1 resolved (shared-secret model); SV11 is now T4.d inside the T4 raider (`heavybag_authhttp.c`, wave 1). No separate gate. D2/D3 remain human decisions but do not block their files' other tasks (module.c/match.c work in T5/T7/T8 does not touch the D2/D3 lines).

**Each wave ends with:** `-Werror` build green + full ctest (14 suites) green before the next wave starts.

**Verification tail (after the last wave — non-negotiable, per Zoltán's review-heavy workflow):** in parallel — (1) `p:minion-inspector-implementation` against this list; (2) `p:minion-inspector-security-officer` PHASE:triage on the diff; (3) re-run the Elliot PHASE:verify for each MEDIUM/HIGH finding on the fixed code (SV8/SV9/SV14/SV16 + H1/H5/H6/H7 → expect REFUTED = fixed). Then full ctest + sandbox smoke, deployed `.so` md5 noted.

**Out of raid scope:** commit + push (partner does it — SSH key); the `reviews/` artifacts are untracked.
