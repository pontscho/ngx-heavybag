---
name: qa-subunit-inventory
type: analysis
status: current
title: QA Subunit Inventory & Unit-Test Coverage
description: Per-translation-unit line counts, unit-test presence, risk classification, and the known landmines for the ngx_http_heavybag module.
sources:
  - modules/ngx_http_heavybag/src/heavybag_ua_parse.c
  - modules/ngx_http_heavybag/src/heavybag_match.c
  - modules/ngx_http_heavybag/src/heavybag_geo.c
  - modules/ngx_http_heavybag/src/heavybag_rate.c
  - modules/ngx_http_heavybag/src/heavybag_ja4.c
  - modules/ngx_http_heavybag/src/heavybag_reputation.c
  - modules/ngx_http_heavybag/src/heavybag_spoof.c
  - modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c
  - modules/ngx_http_heavybag/src/heavybag_status.c
  - modules/ngx_http_heavybag/src/heavybag_stream.c
  - modules/ngx_http_heavybag/src/heavybag_authhttp.c
verified:
  commit: 7a935b0
  date: 2026-06-21
links:
  - qa-findings
  - overview
  - threat-model
---
# QA Subunit Inventory & Unit-Test Coverage

> Recon snapshot of the `ngx_http_heavybag` translation units taken during the
> QA hardening campaign (2026-06-17): per-TU line counts, unit-test presence,
> and a risk classification, plus the cross-session "known landmines" notes.
> The severity-grouped findings these subunits produced — and their fix
> dispositions — live in [[qa-findings]]. See [[overview]] for the subsystem
> map and [[threat-model]] for the attack-surface analysis.

## Subunit inventory & unit-test coverage (recon, 2026-06-17)

### Shared analysis libs (unit-testable in isolation)
| Subunit | Lines | Unit test | Risk |
|---|---|---|---|
| `heavybag_ua_parse.c` | 769 | yes | medium |
| `heavybag_match.c` | 596 | **none** | high |
| `heavybag_geo.c` | 497 | **none** | high (nanolibloc layout) |
| `heavybag_rate.c` | 500 | **none** | high (shared mem) |
| `heavybag_ja4.c` | 424 | yes | medium |
| `heavybag_reputation.c` | 344 | **none** | high (shared mem) |
| `heavybag_spoof.c` | 315 | **none** | medium (UA↔JA4, r->ctx mine) |

### nginx integration glue (runtime-bound)
| Subunit | Lines | Unit test | Risk |
|---|---|---|---|
| `ngx_http_heavybag_module.c` | 2922 | **none** | critical (the giant) |
| `heavybag_status.c` | 796 | **none** | medium |
| `heavybag_stream.c` | 617 | **none** | high (L4) |
| `heavybag_authhttp.c` | 321 | **none** | medium |

**Headline gap:** 9 of 11 translation units have no unit tests — including the two highest-risk classes (geo memory-layout, shared-memory concurrency in rate/reputation/status).

## Known landmines (from prior work)

- nginx clears `r->ctx` on internal redirect → per-connection data used across HTTP phases must come from SSL ex-data, NOT request ctx.
- nanolibloc `location.db` network-leaf entry is 12 bytes; flags (anycast etc.) at byte offset 8 (not 2).
- nginx pool lifetime: `r->pool` freed at request end, `c->pool` at connection end; cross-request state needs the shared-memory slab.
