---
name: qa-test-matrix
type: analysis
status: current
title: QA Test-Matrix Round (Permanent Regression Net)
description: The seven-phase test-matrix round that codifies the 142-vector QA backlog into a permanent unit/integration/build regression net.
sources:
  - modules/ngx_http_heavybag/tests/unit/test-rate.c
  - modules/ngx_http_heavybag/tests/unit/test-geo.c
  - modules/ngx_http_heavybag/tests/unit/test_heavybag_ua_parse.c
  - modules/ngx_http_heavybag/tests/unit/test-ja4.c
  - modules/ngx_http_heavybag/tests/unit/test-match.c
  - modules/ngx_http_heavybag/tests/unit/test-ja4-extract.c
  - modules/ngx_http_heavybag/tests/unit/test-stat-cc.c
  - modules/ngx_http_heavybag/tests/unit/run-unit-tests.sh
  - modules/ngx_http_heavybag/tests/run-mailauth-fuzz.sh
  - modules/ngx_http_heavybag/tests/run-reputation-precedence.sh
  - modules/ngx_http_heavybag/tests/run-spoof-fuzz.sh
  - modules/ngx_http_heavybag/src/heavybag_authhttp.c
  - modules/ngx_http_heavybag/src/heavybag_reputation.c:ngx_http_heavybag_reputation_check
  - modules/ngx_http_heavybag/src/heavybag_ua_parse.c:ngx_http_heavybag_ua_spoof_eval
  - modules/ngx_http_heavybag/src/heavybag_status.c:ngx_http_heavybag_stat_cc_bump
  - cmake/Tests.cmake
verified:
  commit: 7a935b0
  date: 2026-06-21
links:
  - qa-findings
  - qa-subunit-inventory
  - overview
---
# QA Test-Matrix Round (Permanent Regression Net)

> The test-matrix round that converted the QA campaign's 142 code-grounded
> vectors into a permanent regression net across the unit, integration, and
> build layers (Phases 1-7, 2026-06-17..06-19). The findings that scoped this
> work live in [[qa-findings]]; the per-translation-unit risk inventory it
> closes the untested-TU gap for is in [[qa-subunit-inventory]]; [[overview]]
> maps the subsystems. The verbatim phase log follows.

## Test-matrix round (permanent regression net for the 142-vector backlog)

The Discovery campaign found **zero** attacker-triggerable corruption/crash/bypass but surfaced one structural gap: 9 of 11 TUs had no unit tests, and the three fix rounds were re-verified only ad-hoc. This round codifies the 142 code-grounded vectors as a permanent regression net, closing the untested-TU gap. Partner decision (2026-06-17): full 142, all three layers (unit / integration / build), multi-session, check-in between phases; partner commits source+tests on `main` and pushes.

Isolation pattern: each pure-core TU is `#include`d directly under a `-DHEAVYBAG_<TU>_UNIT_TEST` flag; an `#ifdef` shim block substitutes the nginx typedefs/macros **byte-for-byte** (`NGX_OK 0`/`NGX_ERROR -1`/`NGX_AGAIN -2`/`NGX_BUSY -3`/`NGX_DECLINED -5`), the nginx-coupled tail (config parsers, slab, mmap, filter chain) sits behind `#ifndef`. The real `-Werror` SSL `objs/` build (`make -f objs/Makefile modules`, md5 build==deploy, `nginx -t`) is the correctness contract — a divergent shim would make the net lie.

### Phase 1 — `rate.c` unit (16 vectors) — COMPLETED 2026-06-17

New `tests/unit/test-rate.c` (suite `rate`); guard additions to `heavybag_rate.h` (include-gate + `u_char`/`ngx_int_t`/`ngx_uint_t`/`ngx_atomic_t`/`ngx_atomic_uint_t`/`ngx_msec_t` shim, all 64-bit so the packed-state CAS + ~49-day msec wrap hit the production boundary) and `heavybag_rate.c` (runtime-symbol shim: `__sync` atomics, writable `ngx_current_msec`, no-op `ngx_log_error` + zeroed `ngx_cycle`; `rule_select`/`rule_add`/`init_zone` gated behind `#ifndef`). The table is a flat `calloc` `[hdr][slot×nslots]`; the private slot/hdr structs and the `static` FNV key fn are reachable because the test includes the `.c`.

| # | Vector | Assertion |
|---|---|---|
| V1 | `burst_fp==0` (round-2 guard) | fail-open `NGX_OK` + one-shot ALERT path exercised |
| V2 | `period_ms==0` (round-2 div-by-zero guard) | fail-open `NGX_OK`, no SIGFPE |
| V3 | NULL shm | fail-open `NGX_OK` |
| V4 | `nslots==0` | fail-open `NGX_OK` |
| V5 | unsupported family (AF_UNIX) | `key()==0` → fail-open `NGX_OK` |
| V6 | NULL sockaddr | `key(NULL)==0` → fail-open `NGX_OK` |
| V7 | exact burst boundary | Nth allow / (N+1)th deny `== NGX_BUSY` (-3) |
| V8 | sub-ms refill rounds to 0 | tokens unchanged AND stamp preserved (anti-drift) |
| V9 | 49-day uint32 msec wrap mid-bucket | wrap-safe elapsed → small refill, not 2^32 |
| V10 | clock skewed backwards | uint32 underflow → refill to burst, never stuck/UB |
| V11 | FNV key-equality gating | colliding probe does not mutate the victim's bucket |
| V12 | v4-mapped IPv6 == native IPv4 | identical key |
| V13 | native IPv6 /64 keying | same /64 → same key; different /64 → different key |
| V14 | FNV key never 0 (sentinel) | 200k-IP sweep, always nonzero |
| V15 | probe window full (32) | evict OLDEST, fresh full bucket, `rate_overflow==0` |
| V16 | max rate/burst (P6 bound) | non-overflowing 64-bit refill + lossless uint32 downcast at elapsed=0xffffffff |

**Honest out-of-unit-scope** (documented in test-rate.c header, NOT faked): CAS-starvation fail-open (multi-worker only; covered by the `CAS_MAX` bound + integration/stress); `waf_rate` zone `MIN_SLOTS` back-off (in `init_zone`, slab-coupled → config/integration layer); exact `hash==0` remap (2^-64, not brute-forceable → asserted as the always-nonzero invariant in V14).

**Verification:** `run-unit-tests.sh` exit 0 — rate 16/16, JA4 7/7, UA 36/36 (regressions clean). Real SSL `objs/` rebuild clean `-Werror` (zero warnings), md5 build==deploy `dd921b76ac212755da40cda71e2dd7f1`, `nginx -t` binary-compatible. No production logic changed (guards take the original branch in the no-`-D` build).

**Not committed:** partner commits source+tests on main + pushes himself.

### Phase 2 — `geo.c` unit (20 vectors) — COMPLETED 2026-06-17

The highest-risk class (libloc on-disk byte layout). MANDATED header-split applied to the shared `heavybag_geo.h` (included by 4 production TUs: geo.c, reputation.c, status.c, module.c), following the `heavybag_rate.h`/`heavybag_ja4.h` pattern:

- **`heavybag_geo.h`** restructured into three regions: (1) a type-provider block — `#ifndef HEAVYBAG_GEO_UNIT_TEST` → `#include "ngx_http_heavybag.h"`, `#else` → a tiny byte-mirroring shim (`u_char`/`ngx_int_t`/`ngx_uint_t`/`ngx_str_t` + `ngx_inline`, all derived from `<stddef.h>`/`<stdint.h>`); (2) the SHARED section — block-index + per-network-flag macros and the `geo_db_t`/`geo_result_t` structs (they reference only shimmable types, so the unit test can build a synthetic in-memory db); (3) the production-only prototypes (`geo_open`/`geo_lookup`, `ngx_conf_t`/`struct sockaddr` coupled) behind `#ifndef`. The on-disk layout constants are NEVER duplicated into the shim — a divergent copy would silently drift from the real layout the walk depends on.
- **`heavybag_geo.c`** gated: top includes (`<sys/mman.h>` + OpenSSL → `#ifndef`; `<netinet/in.h>` for sockaddr/IN6_IS_ADDR_V4MAPPED/AF_* → `#else`); the signing-key static, `geo_cleanup` (munmap), `geo_verify` (OpenSSL ECDSA-P521), and `geo_open` (ngx_conf_t/mmap) all behind `#ifndef HEAVYBAG_GEO_UNIT_TEST`. The `u32`/`u16` big-endian readers, the radix-trie `geo_walk` (static), and `geo_lookup` stay ungated — they ARE the production code under test (12-byte ND-leaf with **flags at offset 8**, the `(size_t)net*12+12 > block_len[ND]` bound, the `off+12 > ntlen` node bound), never re-declared.

New `tests/unit/test-geo.c` (suite `geo`) includes `heavybag_geo.c` directly under `-DHEAVYBAG_GEO_UNIT_TEST`; hand-built 12-byte tree nodes (`[bit0-child | bit1-child | net]`, `net & 0x80000000` = internal) and 12-byte leaves (`[cc | rsv | asn | flags | rsv]`) drive `geo_walk`/`geo_lookup`. Both are reachable because the test includes the `.c`.

| # | Vector | Assertion |
|---|---|---|
| V1 | v4 native leaf decode | country + ASN read from the matched leaf, found=1 |
| V2 | flags at ND offset 8 (libloc landmine) | flags from `[8,10)`; poison `0xDEAD`@`[2,4)` / `0xBEEF`@`[10,12)` NOT read; ASN intact |
| V3 | `::ffff:1.2.3.4` (v4-mapped) == native v4 | identical leaf via `ipv4root` (distinct subtree, genuinely walked) |
| V4 | `::1.2.3.4` (v4-COMPATIBLE, not mapped) | full 16-byte v6 walk from node 0, does NOT see the v4 tree's leaf |
| V5 | genuine AF_INET6 (`8000::`) | 16-byte path, bit0==1 right-child branch; `::` → no-match |
| V6 | all-zero `::` & `0.0.0.0` | root leaf matched at depth 0 |
| V7 | `/0` default | non-zero address falls back to the root leaf |
| V8 | longest-prefix | a deeper leaf supersedes the `/0` leaf; sibling stays default |
| V9 | internal sentinel node | `net & 0x80000000` not recorded as a leaf; sentinel-only path → no-match |
| V10 | `/32` host leaf max v4 depth | reached only after all 32 bits; flip last bit → no-match |
| V11 | `/128` host leaf max v6 depth | reached only after all 128 bits; flip last bit → no-match |
| V12 | ND-leaf bound off-by-one | last leaf (`end==block_len`) accepted; index one past rejected (found=0) |
| V13 | NT-node bound off-by-one | node at exact `block_len` walkable; child one node past → walk -1, no over-read |
| V14 | leaf index near UINT32_MAX | `net=0x7FFFFFFF` → `(size_t)net*12+12` rejects, no 32-bit multiply wrap |
| V15 | child index near UINT32_MAX | `nxt=0xFFFFFFFE` → `off+12 > ntlen` rejects in size_t, no wrap/over-read |
| V16 | self-referential child | node1 bit0-child → node1; bounded by addrlen (≤32 iters), terminates, no hang |
| V17 | single-node tree (`block_len[NT]==12`) | leaf-root matches; internal-only root → no-match; no boundary over-read |
| V18 | AF_UNIX / unknown family | clean no-match, no walk |
| V19 | NULL db & NULL sockaddr | clean no-match, no crash |
| V20 | MSB-first bit direction | bit0 = MSB of byte 0: `0.0.0.0`→left leaf, `128.0.0.0`→right leaf |

**Honest out-of-unit-scope** (documented in test-geo.c header, NOT faked): the config-time `geo_open`/`geo_verify` path is behind `#ifndef` and needs `ngx_conf_t` + mmap + an ECDSA-P521/SHA-512-signed `location.db` + OpenSSL — magic check, mandatory signature verify, `size < DATA_OFF` / `> MAX_SIZE` rejection, block `offset+len > EOF` rejection, the 96-level descent to the IPv4-mapped root, and all-zero-FILE fail-closed (magic mismatch). These are covered by the **Fix-round-3 LIVE nginx test** (real FR/AU/US ground-truth lookups against the project's signed `geodb/location.db`, oracle `reference/geolookup.c`) and the config-build layer; they cannot be unit tested without nginx+OpenSSL.

**Verification:** `run-unit-tests.sh` exit 0 — **geo 20/20**, rate 16/16, JA4 7/7, UA 36/36 (regressions clean). The header touches 4 production TUs → verified byte-transparent: SSL `objs/` rebuild clean `-Werror` (zero warnings, all 4 includer TUs compile silently), md5 build==deploy `c1ddfa3b4772403e8331f843034be16d`, `nginx -t` binary-compatible; the `objs-nossl` and `objs-nostream` permutation trees also compile `heavybag_geo.c` clean. The `.so` md5 changed from Phase 1's `dd921b76…` to `c1ddfa3b…` due only to `__LINE__`/debug-info shift from the added `#ifndef` lines — the production preprocessed token stream is unchanged (the guards take the nginx branch in the no-`-D` build). No production logic changed.

**Not committed:** partner commits source+tests on main + pushes himself.

### Phase 3 — `ua_parse` extend (21 vectors) — COMPLETED 2026-06-17

The descriptive UA parser core (`heavybag_ua_parse.c`, 769 lines) already had a 36-case happy-path + ordering + clamp suite. This phase adds the **WF-3 ua-fuzz backlog (21 vectors)** as a byte-level robustness net, driving the two security-critical primitives DIRECTLY — `heavybag_ua_find()` (the bounded, case-insensitive scan; never reads past `hay+hlen`) and `heavybag_ua_version()` (the `[0-9A-Za-z._-]` version slice; the CR/LF/quote/control-char clamp is the parser's one attacker-byte sink). Both are `static` and reachable because the test `#include`s the `.c` under `-DHEAVYBAG_UA_PARSE_UNIT_TEST`. **No production source touched, no header split needed** (the existing isolation harness already pulls in the nginx-free core); the deployed SSL `.so` is byte-identical (md5 unchanged).

Three suites added to `tests/unit/test_heavybag_ua_parse.c`:

| # | Suite / test | Vector | Assertion |
|---|---|---|---|
| V1 | `ua_find/needle_longer_than_hay_no_underflow` | `nlen>hlen` (and `hlen==0`) | NULL — the size_t underflow guard (`last=hlen-nlen` never computed) |
| V2 | `ua_find/exact_length_match_last_zero` | `nlen==hlen` | match returns `hay` at `last==0`; mismatch → NULL |
| V3 | `ua_find/empty_needle_is_null` | `nlen==0` | NULL short-circuit |
| V4 | `ua_find/match_at_final_position` | match at `i==last` | returns `hay+2` (inclusive upper bound) |
| V5 | `ua_find/nul_transparent_scan` | embedded NUL mid-hay | needle after the NUL still found (length-driven, not strstr) |
| V6 | `ua_find/case_insensitive_fold` | `CHROME` vs `chrome` | `|0x20` A–Z fold matches at `hay+3` |
| V7 | `ua_version/token_at_buffer_end_zero_len` | token at EOF (`s==end`) | vlen 0, vstart==`hay+hlen`, no byte beyond end read |
| V8 | `ua_version/nul_byte_terminates_version` | NUL in version charset | slice clamps before the NUL (`"8.5"`) |
| V9 | `ua_version/high_bit_byte_terminates_version` | `>=0x80` (UTF-8 lead) | clamps at the first 8-bit byte (`"8.5.0"`) — overlong-UTF-8 passthrough blocked |
| V10 | `ua_version/full_charset_accepted` | digits `.` `_` `-` lower upper | whole `"1.2.3-rc_4Z"` sliced verbatim |
| V11 | `ua_version/absent_token_null_slice` | token not present | vstart NULL + vlen 0 (poison overwritten) |
| V12 | `ua_version/enormous_all_digit_version` | 4 KB all-digit version | vlen 4096 — zero-copy slice, NO length clamp (downstream-overflow note: consumer must bound its own copy) |
| V13 | `ua_version/space_terminates_version` | common delimiter | slice clamps at the space (`"120"`) |
| V14 | `ua_edge/empty_ua_all_fields_unknown` | empty UA | browser/os/category/vendor ALL UNKNOWN + vlen 0 (every needle hits the `nlen>hlen` guard) |
| V15 | `ua_edge/single_byte_ua_all_unknown` | 1-byte UA `"M"` | all UNKNOWN (shorter than every needle, shortest is `wv`=2) |
| V16 | `ua_edge/multi_kb_no_delimiter` | 8 KB of `'a'`, no token | UNKNOWN; every needle scan runs to `i==last` across 8 KB, no over-read |
| V17 | `ua_edge/webview_wv_no_version` | `; wv) ... Chrome/` | CHROME via the dedicated `wv` branch, which yields **vlen 0** (no version slice) |
| V18 | `ua_edge/applewebkit_without_safari_empty_version` | AppleWebKit, no `Safari/` | SAFARI with empty version (HEAVYBAG_VER on absent token → len 0), vendor apple |
| V19 | `ua_edge/crios_over_safari` | iOS Chrome (`CriOS/`) | CHROME/google before the trailing `Safari/` (ordering precedence), version `120.0.6099.119` |
| V20 | `ua_edge/harmonyos_browser_vendor_precedence` | HarmonyOS + bare Chrome | os HARMONYOS but vendor GOOGLE — browser-switch precedes the os→huawei fallback |
| V21 | `ua_edge/embedded_nul_then_token_found` | `"ab\0Chrome/120..."` explicit len | CHROME + version found end-to-end past the NUL (no NUL-truncation smuggling) |

**Honest out-of-unit-scope** (documented in the test header, NOT faked): the nginx-facing wrappers `ngx_http_heavybag_ua_parse()` (request-ctx population, `ua_parsed` latch, threat-category override) and `ngx_http_heavybag_ua_spoof_eval()` (live JA4 fetch from SSL ex-data + verified-bot CIDR signal) sit behind `#ifndef HEAVYBAG_UA_PARSE_UNIT_TEST` — they need an `ngx_http_request_t` + a TLS connection. The `ja4_signal` contradiction boolean is already mirrored in the existing `spoof` suite; the live JA4 wire walk is Phase 6b. The CR/LF/quote clamp's downstream-sink protection (log_format / add_header) is an integration concern — the core only guarantees the slice TERMINATES at the first out-of-charset byte, which is exactly what V7–V13 assert.

**Verification:** `run-unit-tests.sh` exit 0 — **UA 57/57** (was 36; +21), rate 16/16, JA4 7/7, geo 20/20 (regressions clean). Test-file-only change: no production source edited, no module rebuild, deployed SSL `.so` md5 `c1ddfa3b4772403e8331f843034be16d` (unchanged from Phase 2, build==deploy). The unit harness compiles the UA core with `-Wall` clean (no extra libs).

**Not committed:** partner commits source+tests on main + pushes himself.

### Phase 4 — `ja4` core extend (17 vectors) — COMPLETED 2026-06-17

The pure JA4 core (`ngx_http_heavybag_ja4_build`, in `heavybag_ja4.c`) already had a 7-case suite (FoxIO canonical vector, GREASE filtering, ALPN hex fallback, no-ALPN/QUIC, the two `ja4-01` empty-list canonicalizations, cipher count clamp). This phase adds the **WF-3 ja4-fuzz backlog** as a byte-level robustness + canonical-semantics net, driving `ngx_http_heavybag_ja4_build()` directly (already isolated under `-DHEAVYBAG_JA4_UNIT_TEST`, includes `heavybag_ja4.c`, links `-lcrypto` for SHA256). **No header split** (the core is already nginx-free behind the existing guard) and **no production source touched** — test-file-only. Assertions are STRUCTURAL/RELATIVE (two builds compared, or fixed byte offsets in the 37-char JA4 string) so no hand-computed SHA256 literal is needed — mirroring the existing `grease_is_filtered` style.

JA4 string layout pinned by the offsets: `[0]` proto `t|q`, `[1..2]` version, `[3]` SNI `d|i`, `[4..5]` cipher count, `[6..7]` ext count, `[8..9]` ALPN, `[10]` `_`, `[11..22]` JA4_b (cipher hash), `[23]` `_`, `[24..35]` JA4_c (ext+sigalg hash).

| # | Test | Vector | Assertion |
|---|---|---|---|
| V1 | `ext_count_clamp_99` | 150 non-GREASE exts | ext count field (`[6..7]`) clamps to `"99"` (the `next>99` clamp), mirrors the cipher-side clamp |
| V2 | `max_elems_hash_clamp` | 257 vs 256 ascending ciphers | `HEAVYBAG_JA4_MAX_ELEMS` (256) keeps the first 256 in input order before sort → JA4_b byte-identical to the 256-prefix; no over-read |
| V3 | `cipher_order_independent` | shuffled cipher list | ciphers sorted before hashing → fingerprint order-invariant (fwd == rev) |
| V4 | `ext_order_independent` | shuffled ext list | exts sorted before hashing → JA4_c order-invariant |
| V5 | `sigalg_order_preserved` | reversed sigalgs | **the behavioral pin:** sigalgs kept in ORIGINAL order → JA4_c differs while JA4_a+`_`+JA4_b (`memcmp 23`) stay byte-identical |
| V6 | `duplicate_ext_types_kept` | `{0x0005}` vs `{0x0005,0x0005}` | no de-dup: count `01`→`02`, JA4_c differs |
| V7 | `duplicate_ciphers_kept` | `{0x1301}` vs `{0x1301,0x1301}` | no de-dup: count `01`→`02`, JA4_b differs |
| V8 | `all_grease_cipher_and_ext` | all-GREASE ciphers AND exts | counts `00`/`00`, SNI `i`, JA4_b and JA4_c both the canonical literal `000000000000` |
| V9 | `alpn_zero_len_is_00` | non-NULL ALPN ptr, `alpn_len==0` | field `"00"` (the `len==0` guard, not the NULL guard) |
| V10 | `alpn_leading_nul_hex_escaped` | ALPN `{0x00,'h'}` | leading NUL non-alnum → hex `"08"` (high nibble of `0x00`, low nibble of `'h'`) |
| V11 | `alpn_interior_nul_transparent` | ALPN `{'h',0x00,'2'}` | only first/last byte drive the field → `"h2"` (interior NUL transparent, length-driven) |
| V12 | `alpn_single_byte` | ALPN `{'x'}` len 1 | `alpn[0]==alpn[len-1]` → `"xx"` |
| V13 | `version_codes_legacy` | 0x0302 / 0x0301 / 0x0300 | TLS1.1 `"11"`, TLS1.0 `"10"`, SSL3.0 `"s3"` |
| V14 | `version_codes_dtls_and_unknown` | 0xfeff/0xfefd/0xfefc/0x9999 | DTLS `d1`/`d2`/`d3`, unrecognised → `"00"` fallback |
| V15 | `sni_presence_byte` | ext 0x0000 present vs absent | byte `[3]` `'d'` vs `'i'` |
| V16 | `sni_alpn_counted_excluded_from_hash` | `{SNI,ALPN,0x000d}` vs `{0x000d}` | SNI(0x0000)+ALPN(0x0010) COUNTED in `[6..7]` (`03` vs `01`) but EXCLUDED from JA4_c → hash identical |
| V17 | `null_out_returns_error` | `out==NULL` | returns `-1`, no write (the core's one hard error) |

**Honest out-of-unit-scope** (documented in the test header, NOT faked → Phase 6b wire-walk): the inner-length-lying-past-body clamps for `supported_versions`/`signature_algorithms`/ALPN, the odd-trailing-byte / dangling-half-entry drops, and the 2-byte-per-cipher wire parse all live in `ngx_http_heavybag_ja4_compute()` behind `#if (NGX_HTTP_SSL)` — they parse raw `SSL_client_hello_*` getters into the arrays this core consumes, and require a live `SSL*`. The pure core's contract (it trusts the parsed arrays + their counts and canonicalizes deterministically) is exactly what V1–V17 pin; the extractor's length-clamping is the Phase 6b SSL-harness job. `SSL_is_quic` likewise is extractor-only (the core takes `is_quic` as a parameter — covered by the existing `no_alpn_and_quic` case).

**Verification:** `run-unit-tests.sh` exit 0 — **JA4 24/24** (was 7; +17), rate 16/16, geo 20/20, UA 57/57 (regressions clean). Test-file-only change: no production source edited, no module rebuild, deployed SSL `.so` md5 `c1ddfa3b4772403e8331f843034be16d` (unchanged from Phase 2/3, build==deploy). Build+test via p:minion-builder.

**Not committed:** partner commits source+tests on main + pushes himself.

### Phase 5 — `match.c` unit (15 vectors, full config-shim) — COMPLETED 2026-06-18

The design-risk TU: `heavybag_match.c` (596 lines) is PCRE2-opaque and the config-time parser is heavily nginx-coupled (`ngx_conf_t` / `cf->pool` / `ngx_array_*` / file I/O / `ngx_regex_compile`). Partner decision (2026-06-18, AskUserQuestion): **Option A — full config-shim** (vs a narrow regex-only harness), the heaviest shim of the campaign but the strongest permanent net — it codifies the round-2 action-parse fatal + inline-comment fix AND the round-2 ReDoS match/depth-limit fix, both of which were until now only ad-hoc runtime-tested (the throwaway `.claude/tmp/reverify2/` harness).

**Key scope finding:** the WF-3 "match-redos" backlog (11 vectors) splits across TWO translation units. The **percent-decode** half (`%2g` 3-byte delete, `%00` NUL token-break, bare trailing `%`, all-`%` contraction), the **empty args/cookie short-circuit**, the **cookie WHOLE-match** (no `;`/`=` pair-walk) and the **multi-Cookie `ngx_list` walk** do NOT live in `heavybag_match.c` — they live in `ngx_http_heavybag_module.c` (`ngx_http_heavybag_sig_lookup_decoded` :856 + `ngx_unescape_uri` :873 + the cookie loop :914), which is `ngx_http_request_t`-bound → **integration (Phase 6)**, not a unit. Verified (inspector grep): `unescape|decode|[Cc]ookie` returns 0 matches in `match.c`. The `match.c`-resident half is what Phase 5 freezes.

**Isolation (MANDATED header-split, rate/geo pattern):** `heavybag_match.h` splits `#include "ngx_http_heavybag.h"` — `#ifndef HEAVYBAG_MATCH_UNIT_TEST` → the real module header; `#else` → a type shim (`u_char`/`ngx_int_t`/`ngx_uint_t`/`ngx_str_t`/`ngx_pool_t`(opaque)/`ngx_regex_t`(opaque, cast to `pcre2_code*` exactly as production does)/`ngx_conf_t`/`ngx_array_t`/`ngx_regex_compile_t` + the action enum 404=0/403=1/444=2). The nginx-glue prototypes (`ua_list_compile`/`verified_bot_compile`/`ua_classify`/`ja4_list_compile`) are gated behind `#ifndef`. `heavybag_match.c` carries the runtime shim in its `#else` (real PCRE2 via `#define PCRE2_CODE_UNIT_WIDTH 8` + `<pcre2.h>`, `NGX_*` macros, malloc arena, minimal `ngx_array_create`/`push`, `ngx_regex_compile`→`pcre2_compile` honouring `NGX_REGEX_CASELESS`→`PCRE2_CASELESS`, `ngx_conf_log_error`→an EMERG counter, an in-memory `read_file` serving `heavybag_ut_file`); `read_file` and the glue tail (`ua_list_compile`..`ua_classify`) sit behind `#ifndef`. The tested core (the `next_line` tokenizer, `compile_bucket`, `scanner_compile`, `scanner_lookup`, and the `#if (NGX_PCRE2)` bounded-exec helper `ngx_http_heavybag_regex_exec`) stays UNGATED — it IS the production code under test, reachable because `test-match.c` includes the `.c`. **REAL `-lpcre2-8` is linked** (not a mock): a mocked engine would make the ReDoS fail-open a tautology.

New `tests/unit/test-match.c` (suite `match`); runner stanza added with `-lpcre2-8` (`pcre2.h` at `/usr/include`, no extra flags).

| # | Test | Vector | Assertion |
|---|---|---|---|
| V1 | `next_line_crlf_stripped` | CRLF line ending | trailing `\r` stripped (`le[-1]=='\r'`); two lines then NGX_DONE |
| V2 | `next_line_whitespace_trimmed` | leading+trailing space/tab | both ends trimmed → `^/x` len 3 |
| V3 | `next_line_blank_and_comment_skipped` | blank + ws-only + full-line `#` | only the significant line yielded; NGX_DONE after |
| V4 | `next_line_last_line_no_newline` | last line, no trailing `\n` (`le==end`) | still yielded len 3, then NGX_DONE |
| V5 | `next_line_hash_only_at_start_is_comment` | mid-line `#` (`^/a#b`) | `#`-skip is first-char-only → whole line preserved (boundary vs scanner_compile's action-`#` strip) |
| V6 | `action_explicit_buckets` | `403`/`404`/`444` tokens | each lands in its bucket → FORBIDDEN/NOT_FOUND/CLOSE via the real enum→`heavybag_action_code[]` map |
| V7 | `action_inline_comment_after_action` | `^/x 403 # note` (round-2) | action region truncated at `#` + right-trimmed → 403, `emerg==0` (not a typo) |
| V8 | `action_comment_only_defaults_404` | `^/x # note` | empty action token → default 404, `emerg==0` |
| V9 | `action_unknown_is_fatal` | `^/x bock` (round-2) | `NGX_ERROR` + EMERG fired (fail-closed; never silent-degrade to 404) |
| V10 | `action_hash_inside_pattern_safe` | `^/a#b` (no whitespace) | whole token is the PATTERN → `#` part of the regex, default 404, `emerg==0`, matches `/a#b` |
| V11 | `empty_list_null_buckets_declined` | comments/blank only | every bucket NULL (`compile_bucket` `nelts==0`→NULL); `scanner_lookup` skips NULL → NGX_DECLINED |
| V12 | `bucket_precedence_404_before_444` | subject in BOTH 404 and 444 bucket | `scanner_lookup` walks action order → NOT_FOUND (404 i=0) wins, not CLOSE |
| V13 | `caseless_match` | `^/admin` vs `/ADMIN` | `NGX_REGEX_CASELESS`→`PCRE2_CASELESS` honoured by real `pcre2_compile` |
| V14 | `alternation_second_pattern_matches` | 2 patterns one bucket | `(?:^/aaa)\|(?:^/bbb)` join correct — both alternatives hit via real `pcre2_match` |
| V15 | `redos_failopen_bounded` | `(a+)+$` vs 40×`a`+`X` (round-2 fix) | real `ngx_http_heavybag_regex_exec` → `pcre2_match` with `match_limit=100000`/`depth_limit=1000` trips MATCHLIMIT → negative → no-match (security fail-open), terminates; positive control `aaaa`→FORBIDDEN proves the limit never clips a real match |

**Honest out-of-unit-scope** (documented in test-match.c header, NOT faked): the percent-decode / empty-short-circuit / cookie-WHOLE-match / multi-Cookie-walk vectors live in `module.c` (`sig_lookup_decoded` + `ngx_unescape_uri` + the cookie loop), `ngx_http_request_t`-bound → Phase 6 integration. The ReDoS *timing* proof (bounded 0.020s vs an unbounded ~2⁴⁰-step hang) is the runtime layer's (Fix-round-2 `.claude/tmp/reverify2/` measured it); the unit asserts the OUTCOME the limit guarantees (fail-open no-match + terminates + legit match still fires). The nginx-glue tail (`ua_list`/`ja4`/`verified_bot`/`ua_classify`) is `#ifndef`-gated (request/cidr/ja4-table coupled) — the ja4 fingerprint table already has its own suite.

**Verification:** `run-unit-tests.sh` exit 0 — **match 15/15** (new suite), JA4 24/24, UA 57/57, rate 16/16, geo 20/20 (regressions clean). The production header+`.c` got `#ifndef` isolation guards → verified byte-transparent: **inspector PASS** (p:minion-impl-inspector — git diff against HEAD is 100% additive, ZERO deletions/modified statements; the `#if (NGX_PCRE2)` ReDoS helper sits ABOVE every unit guard = shared production code, byte-identical between builds; 15/15 CORRECT, no tautology incl. the real-engine ReDoS vector, scope-honesty confirmed). SSL `objs/` rebuild clean `-Werror` (zero warnings, all 12 objs incl. `heavybag_match.o` + every includer TU compile silently, OpenSSL NOT rebuilt), md5 build==deploy `4098d087c1b1b88873d0d5ac2494ce67`, `nginx -t` binary-compatible. The `.so` md5 changed from Phase 2-4's `c1ddfa3b…` to `4098d087…` due only to DWARF `__LINE__`/debug-info shift from the added `#ifndef` lines — the production preprocessed token stream is unchanged (guards take the nginx branch in the no-`-D` build). Build+test+inspect via minions.

**Not committed:** partner commits source+tests on main + pushes himself.

### Phase 6 — protocol-lifecycle + decode/cookie integration + ja4 extractor unit (48 vectors) — COMPLETED 2026-06-18

The live-fire phase. Where Phases 1-5 froze the pure-core contracts as standalone unit tests, Phase 6 drives the request-lifecycle paths that only exist with a real `ngx_http_request_t` / TLS handshake, plus the ja4 *extractor* clamps that a live OpenSSL handshake cannot reach. Three sub-phases, two new permanent harnesses:

- **6a/6b — `tests/heavybag-protocol-test.conf` + `tests/run-protocol-tests.sh`** (new committed integration harness, honeypot-regression style: self-contained 285xx ports, zero-proxy_pass invariant asserted, 127.0.0.1-only, `waf_reason_header on`, `waf_status` scrape). **32/32 assertions PASS** against the live sandbox nginx.
- **6c — `tests/unit/test-ja4-extract.c`** (new committed unit, mocks the 5 `SSL_client_hello_*` getters + `SSL_is_quic` and drives `ngx_http_heavybag_ja4_compute` directly). **16/16 PASS**; unit suite now **148** (JA4 24 + **ja4x 16** + UA 57 + rate 16 + geo 20 + match 15).

Partner decisions (2026-06-18, AskUserQuestion): permanent committed `tests/` harness (not throwaway `.claude/tmp/reverify`); 6c as a unit-mock extractor (not a brittle live raw-socket TLS client, since the malformed-inner-length / odd-byte clamps abort the OpenSSL handshake before the JA4 is observable on the wire).

#### Part A — protocol-lifecycle (11 assertions, live nginx)

| # | Vector | Setup | Observed |
|---|---|---|---|
| A1 | keepalive fresh ctx (both orders) | one keepalive conn, blocked-then-clean + clean-then-blocked | `/wp-login.php`=404 then `/index.html`=200; `/index.html`=200 then `/phpmyadmin/`=403 — per-request verdict independent, no ctx poisoning across reuse |
| A2 | keepalive TLS JA4 stable | 2 requests, one TLS conn | identical `$waf_ja4_hash` (`t13i3112h1_…`) on both |
| A3 | H2 multiplex | `curl --http2`, two URLs one conn | shared connection JA4 (`t13i3112h2_…`) + per-stream verdict (200 / 404) |
| A4 | internal-redirect count-once | 404 → `error_page` → `/index.html` | `http_requests_total` +1 (NOT +2), `http_allowed` +1 — confirms the observability-02 fix (`r->internal` gate) as a permanent net |
| A5 | SSI subrequest never re-scanned | SSI page `#include`s a scanner path | direct hit `blocked_scanner_path` +1, SSI-include subrequest +0 — `r != r->main` bail proven live |
| A7 | plaintext JA4 no-op | non-TLS listener, `add_header X-JA4 [$waf_ja4_hash]` | `X-JA4: []` (empty) + 200, no NULL deref / crash |
| A8 | TLS resumption | `openssl s_client -sess_out`/`-sess_in` | full JA4 `t13i310900_…`, resumed JA4 `t13i311000_…` — **FINDING:** resumption does NOT degrade to no-JA4 (the client_hello callback fires on the resumption ClientHello too), it yields a DIFFERENT JA4 (the resumption hello carries extra PSK/early-data extensions → different ext count). No crash, no NULL deref. This refines the Discovery `ja4flow-04` assumption ("resumption → no JA4") to "resumption → a distinct JA4, computed safely". |
| A9 | XFF client IP honoured | `waf_trusted_proxy` + blocklisted XFF | blocklisted XFF=403 (reason=blocklist), benign XFF=200 — client IP derived from XFF across the request (the observable core of lifecycle-09 redirect client_sa re-derivation) |
| A10 | spoof body-filter emits once | controlled runtime ja4.list maps live JA4 → tool; UA=Chrome | enforce → 403 `X-Spoof:1`, body emitted once (Content-Length 275 == bytes received); control UA=curl (tool family) → 200 `X-Spoof:0` (no false positive) |
| A12 | mail auth_http (no ctx/JA4) | `waf_mail_auth` content handler, Client-IP header | blocklisted Client-IP → `Auth-Status: static blocklist`; benign → `Auth-Status: OK` — reputation runs over plain HTTP with no request ctx / no TLS / no JA4 |
| A13 | log-phase lazy ctx | `waf off` vhost, `$waf_*` in `log_format` | 200 + `type=regular spoof=0` logged, no crash — the var getters lazily resolve ctx at LOG phase when PREACCESS was skipped |

**Not exercised (honest out-of-scope, documented in the runner header):** H3/QUIC transport — the system curl (7.81) has no HTTP/3 client; the QUIC JA4 path shares `ngx_http_heavybag_ja4_compute` with the TLS path (A2/A3 + the 6c extractor unit cover the fingerprint logic), so only the transport is unverified, not the WAF logic. HTTP/1.1 pipelining was folded into the keepalive ctx-isolation assertion (A1) since curl will not emit a pipelined burst.

#### Part B — module.c percent-decode + Cookie ngx_list walk (14 assertions)

Controlled probe lists (`corpus/protocol-args.list`: `union`→403, `'union`→404; `corpus/protocol-cookie.list`: `sqlmap`→404, `^evilcookie$`→403) make each `ngx_unescape_uri(type=0)` + `ngx_http_heavybag_sig_lookup_decoded`/`_sig_cookie_lookup` edge map to an unambiguous verdict. All assertions match the **real** `ngx_unescape_uri` semantics (traced from the nginx source, `type=0`): `%2g` → all 3 bytes deleted; `%00` → a literal NUL byte emitted (no truncation); a bare trailing `%` → dropped; `%%%%` → contracts to `%%`.

| # | Vector | Verdict | Proves |
|---|---|---|---|
| B1 | `%75nion` → `union` | 403 | basic single decode |
| B2 | `uni%2gon` → `union` | 403 | `%2g` 3-byte delete bridges "uni"+"on" |
| B3a | `%27union` → `'union` | 404 | single decode produces the literal quote |
| B3b | `%2527union` → `%27union` | 403 (via `union`, NOT 404) | **single-pass contract**: the quote stays `%27`-encoded, so the `'union`(404) pattern never fires — only `union`(403) does |
| B4a | `un%00ion` → `un\0ion` | 200 | NUL breaks the token (no `union` match) |
| B4b | `safe%00union` → `safe\0union` | 403 | **NO truncation bypass**: bytes after the NUL are still scanned (length-driven), `union` matches |
| B5 | `union%` → `union` | 403 | bare trailing `%` dropped |
| B6 | `%%%%` → `%%` | 200 | all-`%` contraction, no crash |
| B7 | no query | 200 | empty-args short-circuit (`raw->len==0` → DECLINED, no decode alloc) |
| B8a | `Cookie: a=sqlmap` | 404 | whole-value substring match |
| B8b | `Cookie: a=evilcookie` vs `^evilcookie$` | 200 | **no `;`/`=` pair-walk**: the whole value (`a=evilcookie`) cannot satisfy the anchored pattern |
| B8c | `Cookie: evilcookie` | 403 | anchored whole-value match (control for B8b) |
| B9 | `Cookie: clean=1` + `Cookie: junk=sqlmap` | 404 | multi-Cookie `ngx_list` walk reaches the 2nd header |
| B10 | `Cookie;` (empty) | 200 | empty-cookie short-circuit |

+ 2 reason-attribution spot-checks (`X-WAF-Reason: args` / `cookie`) and an error-log scan (clean: no crash/alert/emerg/alloc-fail).

#### Part C — ja4 extractor unit-mock (16 vectors, `test-ja4-extract.c`)

Isolation: a byte-mirroring nginx type shim + mock `SSL_client_hello_*` getters, then `#include heavybag_ja4.c` under `-DHEAVYBAG_JA4_EXTRACT_UNIT_TEST`. That macro makes `heavybag_ja4.{h,c}` SKIP their `<ngx_config.h>`/`<ngx_core.h>`/`<openssl/ssl.h>` includes (the test supplies the types + getters) while still pulling in the real pure core (real `<openssl/evp.h>` for SHA256, `-lcrypto`) and the real extractor `ngx_http_heavybag_ja4_compute`. Two tiny `#ifndef HEAVYBAG_JA4_EXTRACT_UNIT_TEST` guards added to production (`.h` + `.c`) — production defines NEITHER test macro → byte-transparent. Assertions are STRUCTURAL (fixed byte offsets in the 36-char JA4 string, or two builds compared) — no hand-computed SHA literal.

| # | Test | Clamp / behaviour exercised |
|---|---|---|
| 1 | `cipher_two_byte_parse` | 2-byte BE cipher decode → count `02` |
| 2 | `cipher_odd_trailing_byte_dropped` | `i+1<len` drops the dangling half-cipher → count `01` |
| 3 | `cipher_count_over_max_clamps` | 300 ciphers → `n_cip` clamps to `HEAVYBAG_JA4_MAX_ELEMS`, count field `99`, no over-read |
| 4 | `supported_versions_inner_length_lie_clamped` | ext 0x002b `list=255` vs body 3 → `end=len` clamp, the one real version (TLS1.3) parsed |
| 5 | `supported_versions_short_body_falls_back` | too-short body → no full entry → legacy version |
| 6 | `sigalgs_inner_length_lie_clamped` | ext 0x000d `list=255` clamped → 1 sigalg still feeds JA4_c (differs from no-sigalgs build) |
| 7 | `sigalgs_odd_trailing_byte_dropped` | trailing odd byte dropped (`i+1<end`) → JA4_c equals the clean-list build |
| 8 | `alpn_exact_fit` | `3+list==len` → ALPN `h2` |
| 9 | `alpn_zero_len_is_00` | `list==0` guard → no ALPN → `00` |
| 10 | `alpn_lying_length_rejected` | `3+list>len` → ALPN rejected entirely → `00`, no over-read |
| 11 | `alpn_embedded_nul_length_driven` | proto `{h,NUL,2}` length 3 → field `h2` (first/last byte, length-driven, not strlen-cut at NUL) |
| 12 | `sni_presence_byte` | ext 0x0000 present → byte[3]=`d`; absent → `i` |
| 13 | `ext_count_field` | 4 ext ids → count `04` |
| 14 | `is_quic_proto_char` | `SSL_is_quic` → proto byte `q` vs `t` |
| 15 | `ext_ids_freed` | the allocating getter's buffer is `OPENSSL_free`d on success (CWE-401) |
| 16 | `null_out_is_error` | NULL `out` (with non-NULL ssl+pool) → `NGX_ERROR`, no write |

**Honest out-of-unit-scope:** the live H3/QUIC transport (no client); the `client_hello` callback + `SSL_CTX` wiring (in module.c, not this TU). The wire-level inner-length-lie / odd-byte vectors are unreachable through a live handshake (OpenSSL aborts before the JA4 is observable) — which is exactly why they are driven here through mocked getters.

**Verification:** `run-protocol-tests.sh` 32/32 + `run-unit-tests.sh` 148/148, both exit 0. The two production guard edits are byte-transparent: SSL `objs/` rebuild clean `-Werror` (zero warnings, OpenSSL NOT rebuilt), `nginx -t` binary-compatible; deployed `.so` md5 `4098d087…` → `03a216df17d1661854e8287045050eb8` (DWARF `__LINE__` shift only; production token stream unchanged — the protocol harness re-ran 32/32 against the rebuilt `.so`, behavioral byte-transparency confirmed). Build via p:minion-builder; integration + unit runs inline (runtime harness against the built `.so`, the reverify pattern). New committed files: `tests/heavybag-protocol-test.conf`, `tests/run-protocol-tests.sh`, `tests/corpus/protocol-args.list`, `tests/corpus/protocol-cookie.list`, `tests/unit/test-ja4-extract.c`; edited: `tests/unit/run-unit-tests.sh` (+1 stanza), `src/heavybag_ja4.{h,c}` (2 byte-transparent guards).

**Not committed:** partner commits source+tests on main + pushes himself.

### Phase 7 — config-build layer: nginx -t validation + build matrix + startup/reload (64 vectors) — COMPLETED 2026-06-19

The last backlog category. Where Phases 1-6 froze the pure-core contracts (unit) and the request-lifecycle paths (integration), Phase 7 closes the **config-build** dimension: the merge-time / parse-time fail-closed decisions that only exist with the real nginx config machinery, the build-portability surface across the supported `./configure` permutations, and the two runtime vectors that only manifest in a live master/worker cycle. Partner decision (2026-06-19, AskUserQuestion): **full permutation matrix** (not just the 3 shipped-fix trees) + **reload + stream-startup runtime** (not nginx -t + build only). **Three new committed harnesses, ZERO production source touched** (test-only phase — deployed SSL `.so` md5 `03a216df17d1661854e8287045050eb8` unchanged from Phase 6, build==deploy, byte-transparent by construction). No inspector required (mirrors the Phase 3 test-file-only precedent).

**Scope split established:** the WF-3 "config-build (28)" backlog has a LIST-PARSE half already frozen byte-for-byte by the Phase 5 `match.c` unit (next_line CRLF/no-newline/blank-skip, empty->NULL bucket, inline-comment, unknown-action EMERG). Phase 7 adds the two layers a unit cannot reach — `nginx -t` integration of those same decisions PLUS the merge/build/runtime-only vectors.

#### Part A — config-validation `nginx -t` net (`tests/run-config-tests.sh`, 34 assertions)

Each vector generates a minimal self-contained conf and runs `nginx -t`, asserting accept / reject-with-specific-diagnostic / accept+WARN. A reject for the WRONG reason (e.g. a missing stream handler) FAILS the assertion because the grep targets the exact `ngx_conf_log_error` string. `nginx -t` does not bind sockets, so the loopback ports never conflict and nothing egresses. **34/34 PASS.**

| Vector(s) | What it pins |
|---|---|
| V1-V4 | `waf_geo_block`/`waf_asn_block`/`waf_geo_whitelist` without `waf_geo_db` -> EMERG `require waf_geo_db` (HTTP **and** STREAM heads — both fail-closed) |
| V5 | geo policy WITH the valid signed `geodb/location.db` -> accept (real ECDSA-P521 verify in -t) |
| V6 vs V7 | the rate-zone asymmetry: HTTP `waf_rate_limit` with no zone -> **EMERG reject**; STREAM `waf_stream_rate_limit` with no zone -> **accepts + WARN** `stream rate limiting is DISABLED` (sharedmem-03/config-02, init_module WARN landing in the error_log during -t) |
| V8 | `waf_rate_zone size=4k` (< 8 pages) -> EMERG `too-small size`; V9 size=1m -> accept |
| V10-V15 | rate_rule_add guards: `rate=0` (invalid rate count), `r/d` (invalid rate unit), `1e12 r/s` (rate is too large), missing `rate=` (requires a rate=), `>1 default rule`, `burst=0` (invalid burst) |
| V16-V18 | `for_geo=CN,US` accept; **trailing comma `CN,` accepts** (skip-comma exits the loop, no empty token — matches the WF-3 "trailing-comma OK" seed); **double comma `CN,,US` rejects** (`two letters`) |
| V19-V22 | unknown `waf_verified_bot` class; unknown `waf_flag_block` token; duplicate `waf_scanner_list`; duplicate `waf_rate_zone` |
| V23-V28 | list-parse @ integration: ja4.list malformed line -> accept+WARN-skip; invalid regex -> abort; missing file -> abort (`open() ... failed`); unknown action -> EMERG (round-2); inline-comment-after-action -> accept (round-2); **100KB single line -> bounded `pcre2 too large` reject, no OOM/hang** (graceful fail-closed) |
| V29-V32 | `waf_mail_backend` hostname rejected (numeric IP only), out-of-range port rejected, valid IP+port accepted; corrupt/unsigned geo_db rejected (fail-closed verify) |
| V33 | kitchen-sink: every major directive in one valid config -> accept (proves the harness is not merely rejecting everything) |

#### Part B — build-portability matrix (`tests/run-build-matrix.sh`, 20 assertions)

Module-only rebuild (`make -f <tree>/Makefile modules` — no `./configure` rerun, no OpenSSL-rebuild trap) across the supported permutation trees + `nm -D` symbol assertions. Self-bootstraps a missing builddir tree via `./configure --builddir` + the ssl.h touch-guard; the 3 CORE trees are required. **20/20 PASS** — and crucially **NO new build defect surfaced** (unlike Fix-round-1 which caught `ja4ssl-build-001` via the permutation test). The three shipped build fixes hold across the whole matrix:

| Permutation | Result | Symbol assertion |
|---|---|---|
| `objs` (SSL+stream+v2+v3+mail, canonical) | build clean, 0 warn | http+stream modules both exported |
| `objs-nossl` (`--without-http_ssl_module`) | build clean, 0 warn | **0 undefined `SSL_*` symbols** (config-01 + ja4ssl-build-001 hold) |
| `objs-nostream` (`--without-stream`) | build clean, 0 warn | `ngx_stream_heavybag_module` **absent** (config-build-001 holds) |
| `objs-nov2` (`--without http_v2`) | build clean, 0 warn | both modules exported (no v2 coupling) |
| `objs-nov3` (`--without http_v3`) | build clean, 0 warn | both modules exported (no v3 coupling) |
| `objs-mail` (+mail; canonical already enables it) | build clean, 0 warn | both modules exported (zero mail interference; .so 8 bytes = alignment padding vs canonical) |
| `objs-nopcre` (`--without-pcre`) | **expected nginx configure ABORT** | n/a — nginx's built-in `http_rewrite` module hard-requires PCRE; a clean `requires the PCRE library` diagnostic at configure time, BEFORE any heavybag source is reached. Not a heavybag portability defect; asserted as the expected failure mode. |

#### Part C — startup/reload runtime net (`tests/run-runtime-tests.sh` + 2 confs, 10 assertions)

Live master/worker cycle (binds 127.0.0.1 286xx). **10/10 PASS.**

| # | Vector | Setup | Observed |
|---|---|---|---|
| C1 | **stream-only startup (sharedmem-01)** | HTTP-less config (`stream{}` only, `waf_stream on` + `waf_blocklist`, proxy to a closed loopback port) | passes `nginx -t`; master **starts clean** (no size-0 `waf_status` fatal abort); a loopback connection exercises the NULL-resolved stream stat path with no crash; error log clean |
| C2 | **reload-storm (shm reuse by layout signature)** | http{} `waf_rate_zone` + `waf_status` + scanner list, stream{} `waf_stream_rate_limit` sharing the same `waf_rate` zone; warm counters then 10× SIGHUP reload | all 10 reloads accepted; master pid **stable** across the storm + alive; counters **persisted + accumulated** `http_requests_total 8 -> 18` (== R0+10, shm reused not reset; a reallocated zone would read ~10 and fail the `>= R0+8` threshold); scanner rule still enforced post-reload (`/phpmyadmin/ -> 403`); error log clean (no `not binary compatible`, no emerg, no crash) |

**Verification:** all three harnesses green against the live sandbox nginx (`run-config-tests.sh` 34/34, `run-build-matrix.sh` 20/20, `run-runtime-tests.sh` 10/10 — 64 assertions total, all exit 0). Deployed SSL `.so` md5 `03a216df17d1661854e8287045050eb8` **unchanged from Phase 6** (no production source edited; build==deploy; `nginx -t` binary-compatible). New committed files: `tests/run-config-tests.sh`, `tests/run-build-matrix.sh`, `tests/run-runtime-tests.sh`, `tests/heavybag-runtime-streamonly.conf`, `tests/heavybag-runtime-reload.conf`. Generated corpus (`tests/corpus/.config-tmp/`) is scratch (gitignore-able). No edits to any `src/*.c`/`*.h` or `tests/unit/`.

**Out of scope (documented):** a fully no-PCRE deployment (would need `--without-http_rewrite_module` too — an unrealistic target with no location regex); the critic's un-probed deep-fuzz surfaces (authhttp SMTP path, spoof self-swap, reputation verdict precedence, stat_cc table saturation) remain a separate optional round.

**Not committed:** partner commits source+tests on main + pushes himself.

---

> The remaining campaign sections below were folded in verbatim from the retired
> `qa-campaign.md` monolith (the final consolidation step): the campaign-status
> wrap-up and the four "Optional round" deep-fuzz reports that close the critic's
> un-probed surfaces. They extend this regression-net log; the Discovery findings
> they reference live in [[qa-findings]] and the subunit risk map in
> [[qa-subunit-inventory]].

## Campaign status (2026-06-19)

**Discovery (WF-1/2/3) + 3 fix rounds + 7 test-matrix phases COMPLETE.** The full 142-vector backlog is now a permanent regression net across all three layers:

- **Unit** (`tests/unit/`, 148 cases): rate 16, geo 20, ua 57, ja4-core 24, ja4-extract 16, match 15.
- **Integration** (`tests/run-*.sh`): protocol-lifecycle + decode/cookie (32), config-validation `nginx -t` (34), startup/reload runtime (10).
- **Build** (`tests/run-build-matrix.sh`, 20): the full `./configure` permutation surface, 3 shipped build-fixes netted.

**Portable runner (2026-06-19):** all harnesses are registered as CTest tests via `cmake/Tests.cmake` (included from the top `CMakeLists.txt` after `enable_testing()`). The bash harness stays the source of truth; CTest is the portable launcher. After a normal build: `ctest --test-dir build` (or `cmake --build build --target check`); filter with `ctest -L unit|integration|build` / `ctest -R config`. nginx-bound tests share a `RESOURCE_LOCK heavybag_sandbox` (never run concurrently under `ctest -j`); a harness that exits 2 (sandbox not built) is reported SKIPPED via `SKIP_RETURN_CODE 2`. Registered (10): heavybag_{unit,build_matrix,config,protocol,stat,regression,runtime,replay,honeypot,oracle_build}. `heavybag_replay` asserts the false-positive gate (its main coverage sweep is capped via `ENV "LIMIT=200"`); `heavybag_honeypot` is the read-only ASN/geo analysis pipeline (label `analysis`) and SKIPs cleanly via `SKIP_RETURN_CODE 2` when the raw access log / geo db are absent on the host. `heavybag_oracle_build` (label `build`, `tests/run-oracle-build.sh`) is a build smoke that compiles the four `reference/*.c` developer oracles (geolookup/loctest/nanolibloc libc-only; locverify against the in-tree OpenSSL) so they cannot rot silently — it asserts no behaviour. With this, EVERY runnable script under `tests/` is wired into CTest; only the `tools/*` data/fixture regenerators (which mutate committed corpora) remain intentionally hand-run.

**Relocatable harnesses (2026-06-19):** every `run-*.sh` reads its repo root from `ROOT=${HEAVYBAG_ROOT:-/mnt/nvme/imaginarium/openresty}`, and CTest injects `HEAVYBAG_ROOT=${CMAKE_SOURCE_DIR}` (the `ENVIRONMENT` test property), so a moved/renamed checkout works with no edits. The committed `.conf` files (which bake absolute paths nginx cannot env-substitute) are rendered through `sed s#<default-root>#$ROOT#` into `tests/corpus/.render/` before nginx loads them (a no-op on the default root); the runtime-generated confs already build from `$ROOT`/`$SBX` vars. Proven end-to-end: a `/tmp/hb-relocated -> repo` symlink + `HEAVYBAG_ROOT=/tmp/hb-relocated` ran config 34/34 + runtime 10/10 with the rendered conf carrying the relocated `load_module /tmp/hb-relocated/...` path.

Verdict unchanged from Discovery: **zero attacker-triggerable memory-corruption, crash, or security bypass.** Every issue the campaign found was build-portability, operator-config footgun, accounting honesty, or the one feature gap (JA4-vs-UA spoof enforcement) — all addressed in the three fix rounds and now permanently guarded by tests.

---

## Optional round — mail auth_http deep-fuzz (2026-06-19)

The campaign critic flagged four surfaces it had not fuzzed to the depth of the rest ("un-probed deep-fuzz"): **authhttp SMTP**, spoof self-swap, reputation verdict-precedence, stat_cc table saturation. None were known defects — each was a surface that Discovery saw green but did not exhaust. This round closes the **authhttp SMTP** one (the thinnest existing net: only protocol A12 + stat SMTP-auth, both trusted-loopback-peer + well-formed IPv4).

**Surface:** `modules/ngx_http_heavybag/src/heavybag_authhttp.c` — the `waf_mail_auth` content handler ngx_mail's `auth_http` calls, judging the real SMTP/IMAP peer carried in the `Client-IP` request header. New harness `tests/run-mailauth-fuzz.sh` + `tests/heavybag-mailauth-fuzz.conf` (8 vhosts, ports 286xx), registered as CTest `heavybag_mailauth` (label `integration`, `RESOURCE_LOCK heavybag_sandbox`). **32/32 PASS, 0 fail, 0 skip** on the dev host; geo edges self-validate ground truth at runtime via the `reference/geolookup.c` oracle (SKIP, not fail, if geodb is absent/drifted); the untrusted-peer edges bind a real non-loopback IPv4 (`ip route get` / `hostname -I`; SKIP on a loopback-only host).

| # | Edge | Code | Result |
|---|---|---|---|
| #1 | missing `Client-IP` | `:68-79` fail-open + WARN | allow `Auth-Status: OK` + WARN `mail auth without parseable Client-IP` logged |
| #2 | garbage / oversized / inject | `:69` `ngx_parse_addr` reject -> fail-open | 5 garbage forms + 8KB value all fail-open clean; `%0d%0aX-Injected:` payload **not reflected** (Client-IP is parsed as an address, never echoed) — no crash, no header injection |
| #3 | IPv6 `Client-IP` | `ngx_parse_addr` v6 + reputation | blocklisted `2001:db8:bad::/48` -> `static blocklist`; benign v6 -> OK; **IPv4-mapped `::ffff:203.0.113.7` matches the v4 CIDR** -> `static blocklist` (blocklist match is family-transparent) |
| #4 | multiple `Client-IP` headers | `:311` first-wins | `[blocklisted, benign]` -> deny; `[benign, blocklisted]` -> allow (the FIRST header is authoritative) |
| #5 | untrusted-peer spoof | `:154-186` trusted-check -> `:88` peer fallback | **security invariant HOLDS** (proven over a real 192.168.x peer): 5a peer-blocklisted + benign Client-IP -> deny (can't spoof clean); 5b peer-clean + blocklisted Client-IP -> ignored -> allow; WARN `mail auth from untrusted peer` logged |
| #6 | geo / asn / flag verdict | `reputation_check` step 5/6/9 | `Auth-Status` carries the non-blocklist reason: FR -> `geo country`; AS15169 -> `asn`; anycast(0x0004) -> `network flag`; each with a passing control IP |
| #7 | missing `waf_mail_backend` | `:207-211` ERR-log-but-allow | allow -> `Auth-Status: OK` with **no `Auth-Server` header** + ERR `waf_mail_backend is not set` logged; deny still works without a backend |
| #8 | rate + geo rule-select | `:117` `rate_rule_select(&verdict)` | `for_geo=FR` strict rule (burst=1) selected for an FR Client-IP -> req2 `rate limit`; a US Client-IP falls to the default lenient rule -> stays OK (proves selection gates on `verdict.geo_valid` + country) |

**Verdict:** **no production defect.** The handler is robust against every malformed/hostile `Client-IP` (clean fail-open, no crash, no reflection), the untrusted-peer trust boundary holds, the v6 path works, and all five reputation reasons map correctly into `Auth-Status`. Purely additive test coverage — **no `src/*.c`/`*.h` edited; deployed SSL `.so` md5 `03a216df17d1661854e8287045050eb8` unchanged** (build==deploy). New files: `tests/run-mailauth-fuzz.sh`, `tests/heavybag-mailauth-fuzz.conf`, +1 CTest registration in `cmake/Tests.cmake`. Unit/integration totals rise to: integration now includes mailauth (32). CTest test count 10 -> 11 (`heavybag_mailauth`).

**Still un-probed (optional, separate rounds):** spoof self-swap (the JA4↔UA family-mismatch matrix), stat_cc table saturation (513+ distinct country codes -> `cc_overflow` silent-drop path). Each is green-but-shallow, not a known bug. (reputation verdict-precedence CLOSED — see below.)

---

## Optional round — reputation verdict-precedence (2026-06-19)

Closes the critic's second un-probed surface. `ngx_http_heavybag_reputation_check()` (`heavybag_reputation.c`) is a strict **first-match-wins, early-return** pipeline; every prior reputation test was single-source (one IP matching exactly one of blocklist / geo / ASN / flag). This round builds **collisions** — one IP matching MULTIPLE sources at once — and asserts the documented order. Crucially, every collision is backed by single-source **controls** proving the lower-priority source fires alone for that IP, so a collision result genuinely proves ordering (not a silently-non-matching source).

**Surface:** the shared verdict pipeline (`heavybag_reputation.c:50/61/98/109/126/148/170/182`). New harness `tests/run-reputation-precedence.sh` + `tests/heavybag-repprec-test.conf` (one vhost, port 28701, 16 `location =` probes), registered as CTest `heavybag_repprec`. Driven over the HTTP PREACCESS path (`waf_trusted_proxy 127.0.0.1` + spoofed `X-Forwarded-For` inject the client IP; `waf_reason_header on` exposes `ctx->reason` as `X-WAF-Reason`). reputation_check is shared verbatim by the mail + stream heads, so HTTP coverage is authoritative. Each location is backed by a real `$document_root/p-<name>` file (runner-created) so an ALLOWED request is served in place — no `try_files` internal redirect that would clear `ctx->reason` (the [[nginx-ctx-cleared-on-internal-redirect]] landmine), making `X-WAF-Reason` readable for allowed verdicts too. **19/19 PASS.** Geo-centric: SKIPs (exit 2 -> CTest SKIPPED) if geodb/oracle is absent or its ground truth has drifted from the baked conf.

Ground-truth IPs (oracle-validated at runtime): `185.177.72.1` FR/AS211590/0x0000 (geo+asn, no flag bit); `8.8.8.8` US/AS15169/0x0004 anycast (flag+asn+geo); `185.220.101.1` DE/AS60729/0x0001 anonymous-proxy (flag+asn+geo).

| Vector | Setup (one IP, multiple sources) | Verdict | Proves |
|---|---|---|---|
| controls | geo US/FR; asn 15169/211590/60729; flag anycast/anon-proxy — each ALONE | each -> 403 + its own reason | every source fires independently |
| R1 | allowlist + blocklist (both list 185.177.72.1) | 200 `allowlist` | **allowlist > blocklist** (step0>step1) |
| R2 | blocklist + flag + asn + geo (all match 8.8.8.8) | 403 `blocklist` | **blocklist > flag/asn/geo** (step1 first) |
| R3 | flag(anycast) + asn(15169) on 8.8.8.8 | 403 `flag` | **flag > ASN** (step4>step5) |
| R4 | flag(anycast) + geo(US) on 8.8.8.8 | 403 `flag` | **flag > block_cc** (step4>step8) |
| R5 | asn(211590) + geo(FR) on 185.177.72.1 (0x0000) | 403 `asn` | **ASN > block_cc** (step5>step8), clean (no flag) |
| R6a | geo_whitelist HU, IP US (found, not HU) | 404 `geo_whitelist` | whitelist-miss control |
| R6b | blocklist + geo_whitelist HU on 8.8.8.8 | 403 `blocklist` | **blocklist > geo-whitelist** (step1>step7) |
| R8 | flag(anonymous-proxy) + asn(60729) on 185.220.101.1 | 403 `flag` | **flag > ASN** across a 2nd flag bit |

**Verdict:** **no production defect.** The precedence is exactly as documented and deterministic across every collision; the controls confirm each lower-priority source would otherwise fire. Purely additive: **no `src/*.c`/`*.h` edited; deployed SSL `.so` md5 `03a216df17d1661854e8287045050eb8` unchanged**. New files: `tests/run-reputation-precedence.sh`, `tests/heavybag-repprec-test.conf`, +1 CTest registration (`heavybag_repprec`; CTest count 11 -> 12).

**Still un-probed (optional):** spoof self-swap (JA4↔UA family-mismatch matrix), stat_cc table saturation (513+ distinct CCs -> `cc_overflow`). Both green-but-shallow, not known bugs.

---

## Optional round — JA4<->UA spoof "self-swap" (2026-06-19)

Closes the critic's third un-probed surface. `ngx_http_heavybag_ua_spoof_eval()` (`heavybag_ua_parse.c:717`) raises `is_spoofed` on either of two signals: **ja4_signal** — the observed TLS JA4's family contradicts the UA-claimed family (`fam_ja4 != fam_ua`, both must be != UNKNOWN; `:744`) — or **cidr_signal** — a UA in a verified-bot class whose client IP is outside that class's CIDR (`:756`). The protocol A10 stanza covered exactly one mismatch + one off-control; this round drives the full `{fam_ja4} x {fam_ua}` grid plus the cidr path.

**"self-swap":** the concern was whether swapping the two inputs (which side claims which family) could misfire. It cannot — `fam_ja4` is always the ja4.list lookup of the observed JA4, `fam_ua` always the UA-parse, two independent code paths with no conditional swap, compared by a symmetric `!=`. This round proves that symmetry empirically: tool-JA4+Chrome-UA **and** chromium-JA4+curl-UA both spoof; tool+curl **and** chromium+Chrome both pass.

**Surface:** new harness `tests/run-spoof-fuzz.sh` + `tests/heavybag-spoof-fuzz.conf` (4 vhosts, ports 288xx), registered as CTest `heavybag_spoof`. The host curl has one observed JA4; the runner maps it to a chosen family per `waf_ja4_list` reload (`chromium/firefox/safari/tool`, or absent -> UNKNOWN), so the whole fam_ja4 axis is reachable with a single client. **21/21 PASS** (no production defect). SKIPs (exit 2) if the live JA4 is unreadable.

| Vector | fam_ja4 / fam_ua | Result | Proves |
|---|---|---|---|
| match | tool / curl(TOOL); chromium / Chrome; firefox / Firefox; safari / Safari | 200, X-Spoof=0 | equal families never spoof |
| mismatch | tool / Chrome(CHROMIUM) | 403, X-Spoof=1 | the canonical "tool pretending to be a browser" |
| **self-swap** | chromium / curl(TOOL) | 403 | reverse of the above -> the compare is symmetric |
| cross | firefox / Chrome; safari / curl; chromium / Firefox | 403 | every distinct family pair contradicts |
| same-family | chromium / Edge(CHROMIUM) | 200 | Edge groups with Chrome -> NOT a spoof |
| UNKNOWN guard (ua) | tool / `MysteryBrowser`(UNKNOWN) | 200 | an unmapped UA suppresses the signal |
| UNKNOWN guard (ja4) | absent(UNKNOWN) / Chrome | 200 | a JA4 not in the list suppresses the signal |
| observe | tool / Chrome, `waf_spoof_block off` | 200, X-Spoof=1 | detected (observability) but not blocked |
| detect | tool / Chrome, `waf detect` | 200, X-Spoof=1 | would-block recorded, request allowed |
| cidr_signal | fake `Googlebot` UA, IP outside verified CIDR | 403 `spoof` | the second signal; spoof runs before fake-bot (`module.c:1163`<`:1213`) so the verdict is SPOOF |
| cidr control | `Googlebot` inside CIDR; non-crawler UA outside | 200 | needs both the crawler class AND an out-of-range IP |

**Verdict:** **no production defect.** The mismatch matrix is exact and symmetric, both UNKNOWN guards suppress false positives, observe/detect downgrade correctly, and the cidr_signal fires (and wins over fake-bot) as designed. Purely additive: **no `src/*.c`/`*.h` edited; deployed SSL `.so` md5 `03a216df17d1661854e8287045050eb8` unchanged**. New files: `tests/run-spoof-fuzz.sh`, `tests/heavybag-spoof-fuzz.conf`, +1 CTest registration (`heavybag_spoof`; CTest count 12 -> 13). (One test-harness bug was caught + fixed during the run: the error-log filter initially flagged benign `[notice] worker process ... exited with code 0` reload lines; narrowed to non-zero exits / signals only.)

**Still un-probed (optional):** only stat_cc table saturation remains (513+ distinct country codes exhaust the 512-slot open-addressed `cc[]` table -> the `cc_overflow` silent-drop path). Best exercised at the unit layer with a synthetic shm (needs a `heavybag_status` header-split), so deferred to its own round -- see below.

---

## Optional round — stat_cc table saturation (2026-06-19)

Closes the critic's fourth (and final) un-probed surface. `ngx_http_heavybag_stat_cc_bump()` is a lock-free, open-addressed, linear-probe table of `HEAVYBAG_STAT_CC_SLOTS` (512) `{cc16,total,blocked}` slots. With real geo data the distinct-CC count tops out at ~249 + a handful of libloc specials, so the slot-collision probe and the `cc_overflow` drop are **unreachable at the integration layer** (you cannot inject 513 distinct country codes from a real DB) -- they need a synthetic in-memory shm, i.e. the unit layer.

**This is the only round that touches production source** (the prior three were test-only). To unit-test the *real* function (not a tautological copy), `ngx_http_heavybag_stat_cc_bump` was **relocated from `ngx_http_heavybag_module.c` to `heavybag_status.c`** -- the status TU already owns the `cc[]` layout, so this is its correct home -- and `heavybag_status.h` was **header-split** into the 3-region shim pattern used by rate/geo/match (`-DHEAVYBAG_STAT_CC_UNIT_TEST` -> nginx-free type + atomic shim). The function body is byte-identical; only its TU moved. `module.c`'s 18 call sites + the stream head resolve it via the `heavybag_rep.h` prototype, now linking to `heavybag_status.o`.

**Coverage:** new `tests/unit/test-stat-cc.c` (suite `stat_cc`, 15 vectors), wired into `run-unit-tests.sh` (no extra libs; part of the existing `heavybag_unit` CTest). Unit suite 148 -> 163.

| # | Vector | Asserts |
|---|---|---|
| V1 | NULL shm | no-op, no crash |
| V2 | cc16==0 sentinel | never consumes a slot, cc_overflow stays 0 |
| V3-V4 | single allowed / blocked bump | total/blocked correct |
| V5 | repeated same CC | accumulates in ONE slot |
| V6 | two distinct CCs, no collision | independent slots + counts |
| V7 | **collision** (257 & 769, same %512) | first claims home slot 257, second linear-probes to 258, no cross-poisoning |
| V8 | **probe wraps** (511 & 1023) | high-slot collision wraps to slot 0 |
| V9 | 3-CC collision chain | three probes to three adjacent slots |
| V10 | **saturation** (fill 512, then 513th) | `cc_overflow`++, 513th NOT stored, table uncorrupted |
| V11 | full table + EXISTING CC | still found + counted (not an overflow) |
| V12 | overflow accumulates | 3 distinct over-capacity CCs -> cc_overflow==3 |
| V13 | blocked subset of total | mixed sequence accounting |
| V14 | max uint16 cc16=0xFFFF | slot 511, works |
| V15 | realistic packed ISO-2 codes | US/FR/DE/AU/JP/GB/CA/NL all land, no overflow |

**Verdict:** **no production defect.** The collision probe, wrap-around, saturation drop, and full-table-existing-CC paths all behave exactly as documented; the overflow is a clean drop (`cc_overflow`++), never a slot corruption. The relocation is binary-compatible and runtime-identical -- **the full 13-test CTest suite passes against the rebuilt `.so`** (including `heavybag_stat`, which exercises the live per-country cc_bump path). The deployed SSL `.so` md5 changed `03a216df17d1661854e8287045050eb8` -> `a889e9163dbe503b34596c033c79dddf` (a real functional rebuild from the TU move, behaviour-identical, verified by the suite). Files: `src/heavybag_status.{c,h}` (relocate + header-split), `src/ngx_http_heavybag_module.c` (cc_bump removed -> pointer comment), `tests/unit/test-stat-cc.c` (new), `tests/unit/run-unit-tests.sh` (+1 stanza). No new CTest registration (folds into `heavybag_unit`).

**ALL 4 of the critic's un-probed deep-fuzz surfaces are now closed** (authhttp SMTP, reputation verdict-precedence, JA4<->UA spoof self-swap, stat_cc saturation). Each found **no production defect** -- the campaign's Discovery verdict (zero attacker-triggerable memory-corruption / crash / security bypass) holds across the full deep-fuzz sweep.
