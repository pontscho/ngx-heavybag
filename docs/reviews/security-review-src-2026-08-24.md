# Security Review: modules/ngx_http_heavybag/src/

| Property | Value |
|----------|-------|
| Target | modules/ngx_http_heavybag/src/ |
| Files | 23 |
| Language | C (nginx HTTP+STREAM WAF module) |
| Lines | ~10 300 |
| Date | 2026-08-24 (overnight cron-sliced run) |
| Pipeline | Elliot (p:minion-inspector-security-officer) — FIND (5 OWASP/threat-surface lanes) → VERIFY (paranoid per-finding, fresh context) → Synthesize |
| Method | Token-economy cron-sliced fan-out: 5 find lanes (one heavy officer per hourly slot) → 25 raw → 1 merge → 2 dropped → 22 verified |
| Lens | Security only (exploitability, attacker-reachability, CWE, CVSS) — companion to the code-review at docs/reviews/code-review-src-2026-08-20.md |
| Scope note | This module runs as an EDGE firewall in front of a forward-proxy; all request-derived bytes are hostile input. Owner-authorized audit of a public open-source repo. |

## Overall security posture: SOUND, with hardening work

**No CRITICAL. No unconditional HIGH.** One finding (SV16, rate-zone shm re-attach) rises to HIGH *only* on a persisted-shm platform (Windows named / SysV) that the default Linux/BSD build does not use.

The module's core defensive machinery held up well under a paranoid, data-flow-traced audit:

- **The parsers are bounded.** The UA classifier, the JA4 ClientHello builder/extractor, and the signature/decode paths clamp every read to the input length, slice into (never copy out of) the request buffers, and never assume NUL-termination. The one plausible NULL-deref (JA4 cipher extractor) is unreachable under the OpenSSL API contract.
- **The untrusted-file parsers are signature-gated.** The embedded nanolibloc `location.db` reader verifies the whole file byte-for-byte against a pinned IPFire ECDSA P-521 key *before* trusting any offset, so the DB-internal parse defects (ipv4root terminator, ILP32 overflow, SIGBUS) are defense-in-depth against a malformed-but-signed artifact, not attacker-reachable.
- **The regex engine is capped.** The canonical build pins PCRE2 10.47 with a per-exec step/depth cap, and the signature dispatch fail-closes on the first budget-exhausting exec — so the ReDoS / algorithmic-amplification findings collapse to bounded, O(input) cost.
- **XFF trust is opt-in and default-off**, delegated to nginx's own `trusted_proxy` gate.

What remains are **real but bounded defects**, clustered in three recurring patterns the partner asked to surface ("where did I go wrong"):

1. **Head divergence.** The HTTP / stream / mail enforcement points diverge in allowlist semantics (SV9) and counter discipline — policy an operator believes is uniform is not.
2. **shm-integrity asymmetry.** The status zone validates its layout signature on re-attach; the rate zone does not (SV16). The same threat the codebase explicitly guards against in one place is unguarded in the sibling.
3. **Fail-open on "unknown".** A named deny control (`waf_flag_block tor`) fails open when the source IP is absent from the geo DB (SV14) or when a coupled directive's two fields are inherited independently (SV8) — both config-invisible (`nginx -t` clean).

The single most important item is **SV11 (ESCALATED)**: the SMTP `auth_http` endpoint trusts a client-supplied `Client-IP` header from *any* loopback or unix-socket peer. On a single-tenant host this is the documented, safe `auth_http` contract; on a **multi-tenant / sidecar / co-located** host it is a genuine WAF-evasion primitive. This one turns on your deployment topology and needs a human decision.

### Verified-finding count by severity

| Severity | Count | IDs |
|----------|-------|-----|
| CRITICAL | 0 | — |
| HIGH | 0 (1 conditional) | SV16 only on Windows/SysV persisted-shm |
| MEDIUM | 4 | SV8, SV9, SV14, SV16 |
| LOW | 5 | SV1, SV4, SV10, SV12, SV21 |
| **Verified total** | **9** | |
| Escalated (human decision) | 3 | SV11, SV13, SV19 |
| Suppressed | 10 | SV2, SV3, SV5, SV6, SV7, SV15, SV17, SV18, SV20, SV22 |

---

## Verified findings (ranked by severity)

### MEDIUM

#### SV16 — `waf_rate` shm zone re-attaches without layout/nslots validation (the status zone does)  — MEDIUM (→ HIGH on persisted-shm)
- **File:** modules/ngx_http_heavybag/src/heavybag_rate.c:538 (re-attach) → sinks :238 (OOB read), :240/:296/:339 (OOB CAS-write)
- **CWE:** CWE-665 (improper init of shared segment) → CWE-125 (OOB read) + CWE-787 (OOB write) · **OWASP:** A05 · **CVSS band:** MEDIUM ~6.5 (LP64 anon-mmap: not reachable) / HIGH ~7.5 (Windows named / SysV persisted-shm)
- **Data-flow:** `ngx_http_heavybag_rate_init_zone` re-attach branch `if (shm_zone->shm.exists) { shm_zone->data = shpool->data; return NGX_OK; }` adopts the persisted segment with **no** magic/layout/nslots check. The rate header (`ngx_http_heavybag_rate_hdr_t`, rate.c:101-105) has no layout field at all. `rate_check` then reads `n = hdr->nslots` (only an `n==0` fail-open) and uses it as the sole modulo/index bound: `cand = &slots[(idx+p)%n]` → OOB read of `cand->key` and OOB `ngx_atomic_cmp_set` writes past the slab allocation.
- **Attacker scenario:** On a platform where shm outlives the process (Windows named mapping / SysV shm), a binary upgrade that changes the header/slot layout re-adopts the stale segment. After that, **every rate-limited request** (HTTP preaccess or stream connection) drives the OOB read + atomic write — worker crash or adjacent-shm corruption, deterministically, not a race. On the default Linux/BSD anonymous-mmap build the segment is fresh per master generation, so a worker re-attach only ever maps the header the current master just initialized — not reachable there.
- **Why this is a real defect, not a non-issue:** the sibling **status** zone validates `sh->layout == HEAVYBAG_STAT_SHM_LAYOUT` on both reload (module.c:2721) and re-attach (:2737), and its own comment (heavybag_status.h:133-148) names *exactly* this threat model ("a Windows named mapping or SysV shm can outlive the process ... laid out by an incompatible build is then rejected"). The rate zone omits the guard the codebase already deemed necessary.
- **Remediation:** mirror the status zone — add a `layout`/magic word to `ngx_http_heavybag_rate_hdr_t`, and validate it (plus an `nslots`-vs-zone-size bound) in the `shm.exists` re-attach branch, failing with `NGX_ERROR` on mismatch.

#### SV8 — `waf_flag_block` merge asymmetry silently drops the parent's Tor block in a child config  — MEDIUM
- **File:** modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c:1441 + :1450 (identical on the stream head: heavybag_stream.c:347 + :356)
- **CWE:** CWE-284 (Improper Access Control) · **OWASP:** A01 · **CVSS band:** MEDIUM ~5.3
- **Data-flow:** `waf_flag_block` populates two coupled fields — `flag_mask` (bit-carrying codes) and `flag_cc` (CC-only codes). The `tor` token sets **only** `flag_cc = "T1"` (no flag bit — reputation.c:333-336); every other token sets both. The merge inherits them **independently**: `flag_cc` only when NULL (:1441), `flag_mask` only when 0 (:1450). Reputation gates them as two separate checks (flag_mask :106, flag_cc/T1 :141-153).
- **Attacker scenario:** `server { waf_flag_block tor; }` (→ flag_cc=[T1], flag_mask=0) with `location /api { waf_flag_block anonymous-proxy; }` (→ flag_cc=[A1], flag_mask=ANON). The child's non-NULL flag_cc suppresses inheritance of the parent's [T1], so **Tor exits reach `/api`** despite an explicit server-level `waf_flag_block tor`. `nginx -t` is clean (the geo-db guard at :1465 passes a child with its own db + policy) — the bypass is config-invisible. Duplicated on the L4 stream head.
- **Why MEDIUM not HIGH:** the drop direction coincides with nginx's idiomatic array-replace-not-append merge semantics (bounding likelihood), and the impact is a reputation-filter bypass (Tor reaches the location), not RCE / auth-bypass / data exfiltration. The genuine bug is the *hybrid* independent-field merge of one coupled directive — which also leaks half the parent policy in the reverse config direction.
- **Remediation:** merge the two fields as a unit (a single sentinel meaning "this directive was set at this level"), or track a per-level "flag policy defined" flag so a child either fully overrides or fully inherits the coupled pair.

#### SV9 — allowlist bypasses rate-limit only on the HTTP head; stream + mail still throttle an allowlisted IP  — MEDIUM
- **File:** modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c:1016 (HTTP skip) vs heavybag_stream.c:265 + heavybag_authhttp.c:128
- **CWE:** CWE-284 (inconsistent enforcement across enforcement points) · **OWASP:** A01 · **CVSS band:** MEDIUM ~5.3 (availability of trusted infra)
- **Data-flow:** an allowlist hit returns `NGX_DECLINED` + `verdict.reason = HEAVYBAG_REASON_ALLOWLIST` (reputation.c:46-53). HTTP honors `waf_allowlist_scope full` and `goto allowed`, skipping the rate block (module.c:1016-1020). Stream computes `denied = (rc != NGX_DECLINED)` → allowlist makes `denied=0` → `if (!denied && sscf->rate_rules) rate_check(...)` runs anyway (stream.c:265/270); mail is the same (authhttp.c:128/134). The stream/mail heads never inspect `verdict.reason`.
- **Attacker scenario:** *(over-restriction, not attacker bypass)* an allowlisted partner/monitoring IP that is exempt from throttling on HTTP is still rate-limited on the stream and SMTP heads — a trusted mail relay's `auth_http` requests get denied under load (delivery failure), a self-DoS of trusted infrastructure, invisible to the operator who configured a uniform allowlist.
- **Remediation:** honor the allowlist reason on all three heads — give stream/mail the same `allowlist_scope`-aware short-circuit the HTTP head has, or at minimum skip the rate stage when `verdict.reason == ALLOWLIST`.

#### SV14 — `waf_flag_block tor` fails open for a Tor exit absent from the geo DB  — MEDIUM
- **File:** modules/ngx_http_heavybag/src/heavybag_reputation.c:102 (early `return NGX_DECLINED` inside `if (!res.found)`)
- **CWE:** CWE-636 (Not Failing Securely) · **OWASP:** A04 · **CVSS band:** MEDIUM ~5.3
- **Data-flow:** in block mode (`!rep->allow_cc`), the no-record path returns `NGX_DECLINED` (allow) **before** the `flag_mask` gate (:106) and the `flag_cc`/T1 gate (:141) are consulted — both require `res.found`. A source IP with no geo record is therefore allowed regardless of an explicit flag deny.
- **Attacker scenario:** an attacker picks a Tor exit (or anon-proxy IP) that is missing or stale in the embedded libloc DB; the request is allowed despite `waf_flag_block tor`. Reachability holds (the attacker chooses the source IP). MEDIUM not HIGH because it defeats a defense-in-depth deny (not a gate on protected data) and hinges on DB coverage/freshness the attacker cannot directly manipulate — Tor exits are among the best-catalogued libloc entries, narrowing the window to stale-DB / newly-rotated exits. Whitelist mode (`allow_cc`) correctly fails **closed**.
- **Remediation:** when any flag/flag_cc deny policy is configured, the no-record path should fail closed (or emit an audit signal) rather than `NGX_DECLINED`.

### LOW

#### SV1 — /status per-vhost render over-reads the shm trailing array after a server-adding reload  — LOW
- **File:** modules/ngx_http_heavybag/src/heavybag_status.c:822 (bound) + render loops :385/:569/:735; reload reuse module.c:2720-2730
- **CWE:** CWE-125 (OOB read) · **OWASP:** A01 · **CVSS band:** LOW ~3.1
- **Data-flow:** the render clamps the per-vhost loop to `min(wmcf->nvhosts, cmcf->servers.nelts)`, never to `sh->nvhosts` (the array's real length); `snap = *sh` captures `snap.nvhosts` at :818 but never uses it. After a reload that adds `server{}` blocks, the reused segment keeps the old smaller `sh->nvhosts` → the loop indexes past it. Violates the contract documented at heavybag_status.h:155 that every hot-path writer honors.
- **Why LOW (downgraded from the code-review's implied HIGH):** nginx reuses the old segment **only** when the page-aligned zone size is byte-identical (the `ngx_init_cycle` size gate), and the zone carries 4 spare pages (module.c:2802) that guarantee `sizeof(struct) + new_nvhosts*sizeof(vhost) < mapped size`. So the over-read **stays inside the mapped shm zone** — no SIGSEGV, no cross-mapping leak. The disclosed bytes are counter / zeroed-slab memory in a single-allocation zone (not secrets), and the trigger is an operator reload, not attacker input.
- **Remediation:** clamp the render loop to the already-captured `snap.nvhosts` (one-line fix). (The counter-misattribution half of the code-review's V1+V2 finding is a correctness issue tracked there, not a security one.)

#### SV4 — ILP32 integer overflow in the geo block-table bounds check  — LOW
- **File:** modules/ngx_http_heavybag/src/heavybag_geo.c:375
- **CWE:** CWE-190 → CWE-125 · **OWASP:** A08 · **CVSS band:** LOW ~3.7
- **Data-flow:** `if ((size_t) off + len > size)` with `uint32_t off, len` — on a 32-bit build `(size_t)off + len` wraps mod 2^32 (e.g. off=0xFFFFFFF0, len=0x20 → 0x10 ≤ size), passing the guard while `db->block[i] = base + off` points outside the ≤512 MiB mapping; dereferenced per-request via `geo_walk`/`geo_lookup`. LP64-safe (len promotes to 64-bit).
- **Attacker scenario:** requires **both** a 32-bit (ILP32) build **and** a validly-signed-but-malformed DB (signing-key compromise or a buggy DB generator — the header is signature-gated at geo.c:365 before parse); worst case is a worker SIGSEGV (DoS), not attacker-controlled read/RCE.
- **Remediation:** width-independent check `if (off > size || len > size - off)` (consistent with the module's existing ILP32 hardening notes, e.g. reputation.c:270).

#### SV10 — empty child UA list cannot disable an inherited category (parent regex re-inherited)  — LOW
- **File:** modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c:1389 (merge) + heavybag_match.c:485 (NULL-on-empty)
- **CWE:** CWE-284 · **OWASP:** A01 · **CVSS band:** LOW ~3.1
- **Data-flow:** `ua_re[]` is merged on the compiled-regex pointer (`conf->ua_re[i] == NULL`), with **no path sentinel** — unlike scanner/sig/verified_bot/ja4 which gate on `*.data`. An empty/comment-only child list compiles to a NULL slot (compile_bucket, match.c:485), which the merge reads as "unset" and re-inherits the parent's regex.
- **Attacker scenario:** *(loss of operator control, fails CLOSED)* an operator pointing a child location at an empty UA list to *lift* a parent category instead keeps the parent's classification (and any `waf_bot_block` keyed on it). This is over-enforcement, not a bypass, and — correcting the finder — it is **not silent**: `ua_list_compile` emits a config-time NOTICE "loaded 0 UA pattern(s)" (match.c:707).
- **Remediation:** give `ua_re[]` the same path sentinel the four peer lists use, so "defined empty" is distinguishable from "unset".

#### SV12 — `waf_mail_failopen` default-on: a trusted-peer request with missing/unparseable Client-IP is allowed unjudged  — LOW
- **File:** modules/ngx_http_heavybag/src/heavybag_authhttp.c:80 (default set at module.c:1383)
- **CWE:** CWE-636 · **OWASP:** A04 · **CVSS band:** LOW ~3.3
- **Data-flow:** with `mail_failopen` on (default), a missing/unparseable `Client-IP` yields `Auth-Status: OK` with no reputation/rate verdict (authhttp.c:80-85). The entire path is gated by `authhttp_peer_trusted` (loopback / unix only); a remote peer takes the else-arm (:96-100) and is judged on the real connection peer — no fail-open.
- **Attacker scenario:** local-only, and marginal over SV11 — an actor with loopback reach to the endpoint can already send an arbitrary Client-IP; "omit the header" is a simpler variant of the same local capability. Documented backward-compat with an explicit fail-closed opt-out (`waf_mail_failopen off`, exercised by tests/run-mailauth-fuzz.sh #9).
- **Remediation:** document the fail-open default prominently; consider making fail-closed the default.

#### SV21 — naive O(hlen×nlen) UA substring scan invoked ~100× per request  — LOW
- **File:** modules/ngx_http_heavybag/src/heavybag_ua_parse.c:144 (`heavybag_ua_find`)
- **CWE:** CWE-407 · **OWASP:** A04 · **CVSS band:** LOW ~3.3
- **Data-flow:** `heavybag_ua_find` is a naive substring search called by 119 `HEAVYBAG_HAS`/`HEAVYBAG_VER` probes on the same attacker-controlled UA. Cost is bounded: needles are compile-time literals (nlen ≤ ~22 via `sizeof(lit)-1`), and the UA is capped by `large_client_header_buffers` (default 8k) → aggregate ~100 probes × 8k × ~22 ≈ tens of millions of byte-compares = sub-millisecond per request. Plain byte-compare → no ReDoS.
- **Attacker scenario:** reachable from the UA header but non-catastrophic at default config; becomes material only if an operator raises the per-header buffer to multi-MB.
- **Remediation:** optional — an early UA-length clamp or a Boyer-Moore/`memmem` primitive if multi-MB header buffers are ever in scope. Low priority.

---

## Escalated findings (require a human deployment/config decision)

#### SV11 — SMTP `auth_http` trusts a client-supplied `Client-IP` header from any loopback/unix peer  — ESCALATED (MEDIUM, topology-dependent)
- **File:** modules/ngx_http_heavybag/src/heavybag_authhttp.c:188 (all 127/8) + :181-183 (every AF_UNIX) gating :64 → reputation_check :108 + rate_check :134
- **CWE:** CWE-290 (Auth Bypass by Spoofing) / CWE-348 · **OWASP:** A01/A07
- **The trace is real:** the `Client-IP` request header is judged verbatim whenever the peer is loopback (the whole 127.0.0.0/8 range, v4-mapped included) or *any* unix-domain socket; that forged address drives both the reputation verdict (allowlist short-circuit) and the per-IP rate key.
- **Why it cannot be decided from code alone:** on a **single-tenant** host, loopback == the `ngx_mail` proxy and this is the documented, standard `auth_http` contract (the code fails **closed** for external peers, judging the real peer; the header comment recommends `waf off` + restricting the location). On a **multi-tenant / co-located / sidecar** host, *any* local process can connect from 127.0.0.1 and spoof `Client-IP` to hit the allowlist short-circuit or defeat the per-IP rate limit — a genuine WAF-evasion primitive. The 127/8-wide + unconditional-AF_UNIX trust is broader than the single proxy identity requires.
- **Human decision:** (1) is the `auth_http` location network-isolated to the `ngx_mail` proxy only, carrying `waf off`? (2) is the host single-tenant so no other local process can reach `loopback:auth_http`? (3) if multi-tenant / exposed, tighten the gate to the *exact* proxy peer (a specific unix-socket path / `127.0.0.1` only) rather than all of 127/8 + every AF_UNIX.

#### SV13 — subrequests skip the WAF pipeline  — ESCALATED (LOW, config-audit)
- **File:** modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c:918 (`if (r != r->main) return NGX_DECLINED;`, mirrored :536)
- **CWE:** CWE-284 · **OWASP:** A01
- **The skip is real** (handlers registered only at POST_READ :2957 + PREACCESS :2964), **but** heavybag inspects the client content on `r->main` at POST_READ/PREACCESS, which run **before** `mirror` (PRECONTENT) and `auth_request` (ACCESS). A request whose content matches a signature is blocked before the subrequest is ever spawned, so the subrequest replays content that already passed inspection; `mirror` additionally discards its response.
- **Human decision:** audit the shipped/production `nginx.conf` for `mirror` / `auth_request` / SSI whose subrequest target is a real client-facing backend carrying heavybag rules the operator *assumed* apply to that traffic. If none exist, this is an inherent nginx subrequest-architecture limitation to document, not an exploitable bypass.

#### SV19 — PCRE1 build arm applies signature/UA regex with no match-limit (ReDoS)  — ESCALATED (LOW as-shipped, ~MEDIUM on PCRE1)
- **File:** modules/ngx_http_heavybag/src/heavybag_match.c:329 (`ngx_regex_exec(re, s, NULL, 0)`, no match/depth limit)
- **CWE:** CWE-1333 · **OWASP:** A05/A06
- **The code claim is accurate but the arm is dead in the canonical build:** CMakeLists.txt:120 pins PCRE2 10.47 (`--with-pcre=<pcre2-src> --with-pcre-jit`, cmake/Versions.cmake:29), so `NGX_PCRE2` is defined and the bounded 100000/1000 arm (match.c:291-322) runs. The unbounded `#else` arm ships only on a downstream PCRE1 rebuild, and even then needs an operator list pattern prone to catastrophic backtracking.
- **Human decision:** either (a) bound the PCRE1 path too by setting `pcre_extra->match_limit`/`match_limit_recursion` directly (the code comment's "no match-limit knob" is true only of nginx's PCRE1 *wrapper*, not PCRE1 itself), or (b) document/enforce PCRE2 as a build requirement so the `#else` arm can never ship.

---

## Suppressed findings (with reason)

All suppressions rest on a concrete guard in the code or a documented framework/API contract — not on "seems unlikely".

| ID | File:line | Claim | Suppression reason |
|----|-----------|-------|--------------------|
| SV2 | heavybag_ja4.c:356-359 | JA4 cipher extractor NULL-deref (no `p != NULL` guard) | **unreachable-from-untrusted-input** — OpenSSL `SSL_client_hello_get0_ciphers` sets `*out = PACKET_data()`, non-NULL whenever `PACKET_remaining() > 0`; the deref only fires when `len >= 2`, so `p==NULL & len>=2` is impossible under the API contract. Defensive-hardening only. |
| SV3 | heavybag_geo.c:386-398 | ipv4root descent lacks the `nxt==0` terminator `walk()` has | **source-is-trusted** — the descent bytes are gated by the mandatory fail-closed ECDSA P-521 verify (geo.c:366) covering the file byte-for-byte before descent; the in-bounds guard (:390) makes it wrong-root data-integrity, not OOB. Real logic defect → add `if (nxt==0) break;` as defense-in-depth. |
| SV5 | heavybag_geo.c:322 | location.db mmap held for process life → SIGBUS on in-place truncation | **unreachable-from-untrusted-input** — needs a same-inode in-place shrink of the live DB (local FS write, higher priv than requests); the lookup IP doesn't arm it; nginx's atomic-rename reload is safe. Operational-hardening note. |
| SV6 | heavybag_match.c:373 | list-file loader sizes buffer from `fstat` with no cap | **source-is-trusted** — path + size come from the operator directive at config-load; no request/attacker/traversal surface; matches stock nginx file loading. Hardening nit: mirror the geo 512 MiB cap. |
| SV7 | heavybag_match.c:485 | empty/comment-only list → NULL slot → detection class silently disabled | **source-is-trusted** — operator-deployed file at config-load, no request source; by-design and **not** silent (NOTICE :630 / WARN :899). (Interaction with SV10 judged under SV10.) |
| SV15 | ngx_http_heavybag_module.c:507 | hardcoded recursive=1 XFF → client-IP spoof | **framework-default** — XFF is opt-in and default-off (`trusted_proxy` has no default → XFF ignored, `client_sa` = real peer; confirmed by run-stat-tests P5c); the proxy-walk trust is delegated to nginx's own `ngx_http_get_forwarded_addr` keyed on `trusted_proxy`. `recursive=1` is a LOW hardening divergence that only amplifies an already-broken CIDR. |
| SV17 | heavybag_status.c:818 | `snap = *sh` non-atomic copy → torn counters | **not-a-security-finding** — aligned 64-bit atomics don't tear; counters stay accurate + monotonic → at most sub-scrape cross-field skew, no torn value, no spurious `rate()` alert, no decision dependency. Telemetry cosmetic; the ":817 consistent snapshot" comment mildly overstates. |
| SV18 | heavybag_rate.c:252/296 | non-atomic `state`/`key` on the eviction path race the CAS loop | **by-design, non-exploitable** — static-asserted 64-bit atomic (no tearing); load-then-CAS self-correcting (:339 revalidates+retries); the `state=0` store is gated by a single-winner CAS → worst case one lost token decrement per eviction, **no amplification** (the evicted victim would refill to a full burst anyway). Not a rate-limit bypass. |
| SV20 | ngx_http_heavybag_module.c:858 | multi-Cookie fan-out → ~10^9 backtracking steps/request | **refuted twofold** — (1) cookie *count* and per-exec backtrack *budget* share the same ~32k header-byte budget (3000 tiny cookies can't each reach the 100000-step cap); (2) fail-closed early-exit — the first exec to hit the limit/match terminates the whole cookie loop (match.c:656 / module.c:886), so max-cost execs can't be chained. Alloc is pool-freed (not CWE-770). Residual ~ms linear scan. Hardening nit: explicit cookie-count cap. |
| SV22 | heavybag_match.c:638 | no per-request aggregate regex-CPU ceiling | **subsumed-and-mitigated** — PCRE2 per-exec cap + fail-closed early-exit + total subject bytes bounded by nginx header/URI buffers → aggregate O(input), no super-linear amplification; PCRE1 fully subsumed by SV19. |

### Dropped at verify-kickoff (author-declared non-findings, documented for completeness)
- **mem-safety F3** (heavybag_ja4.c:404-441) — supported_versions / sigalgs / ALPN sub-length fields: every inner length is re-clamped to the getter length before any index; the finder recorded it as evidence of coverage, not an exploitable finding.
- **shm-concurrency F5** (heavybag_stream.c:445-476) — stream head re-resolves cached shm zone pointers per reload via `init_module`; evaluated for a cross-reload stale pointer (CWE-416) and found benign.

---

## Cross-reference: code-review 2026-08-20 HIGHs → security verdict

The code-review flagged 7 HIGH correctness defects, of which 4 were security-relevant. This audit re-judged those 4 through an exploitability lens:

| Code-review HIGH | Security ID | Security verdict | Note |
|------------------|-------------|------------------|------|
| #1 stat-shm reload divergence + OOB /status read | SV1 | **VERIFIED LOW** (down from implied HIGH) | The OOB read is real but bounded **inside** the mapped zone (page-aligned reuse + 4 spare pages); counter memory, not secrets; operator-reload-triggered. The counter-misattribution half remains a correctness issue in the code-review, not a security one. |
| #2 `waf_flag_block` Tor merge asymmetry | SV8 | **VERIFIED MEDIUM** | Confirmed as a config-invisible reputation-filter bypass; attacker-traffic-triggered; duplicated on the stream head. |
| #3 allowlist not bypassing rate on L4/mail | SV9 | **VERIFIED MEDIUM** | Confirmed cross-head divergence; security direction is **over-restriction** of trusted infra (self-DoS), not an attacker bypass. |
| #4 empty UA-list re-inherits parent signature | SV10 | **VERIFIED LOW** | Confirmed merge asymmetry; fails **closed** (over-block), operator-config-only, **not** silent (a NOTICE is emitted). |

**New security findings beyond the code-review seeds** (the value-add of the security lens): SV4 (geo ILP32 overflow), SV11 (Client-IP loopback spoof — escalated), SV12 (mail fail-open), SV13 (subrequest gap — escalated), SV14 (Tor no-geo-record fail-open), SV16 (rate-zone re-attach unvalidated), SV19 (PCRE1 ReDoS — escalated), SV21 (UA naive scan), plus the suppressed hardening notes.

---

## Recommended remediation order

1. **SV11** — decide the deployment model; if not strictly single-tenant + isolated, tighten the `auth_http` peer gate to the exact proxy identity. *(Highest priority — the only finding that could be a live remote-ish evasion.)*
2. **SV16** — add a layout/magic word + `nslots` bound to the rate zone re-attach (mirror the status zone). Cheap, and closes a HIGH on persisted-shm platforms.
3. **SV8 / SV14** — fix the two config-invisible fail-open paths (coupled-directive merge; no-geo-record deny). Both are `waf_flag_block` correctness + security.
4. **SV9** — unify allowlist semantics across the three heads.
5. **SV1 / SV4 / SV10 / SV12** — the LOW hardening fixes (all one-to-few lines).
6. **SV13 / SV19** — config-audit + build-policy decisions.
7. SV21 and the suppressed hardening nits — optional / defense-in-depth.

---

*Method note: this review ran as a token-economy cron-sliced Elliot pipeline overnight — 5 FIND lanes (memory-safety, untrusted-file parsing, auth/bypass, shm/concurrency, DoS/ReDoS) each writing a per-lane findings file, then 22 per-finding VERIFY passes in fresh contexts (paranoid re-judge with framework-default FP suppression). The generous-finder / paranoid-verifier split is why several alarming raw findings (the /status "CRITICAL" OOB, the ~10^9-step cookie DoS) were correctly downgraded or refuted with evidence. Companion to docs/reviews/code-review-src-2026-08-20.md.*
