---
name: stress-campaign
type: analysis
status: current
title: Stress & Load Campaign Ledger
description: Cross-session ledger of the reproducible stress/load campaign — scenarios, S3 counter invariants, and result tables.
sources:
  - modules/ngx_http_heavybag/tests/run-stress-tests.sh
  - modules/ngx_http_heavybag/tests/stress/stress-lib.sh
  - modules/ngx_http_heavybag/tools/gen-stress-corpus.pl
verified:
  commit: 7a935b0
  date: 2026-06-21
links:
  - stress-testing
  - overview
---
# heavybag WAF — Stress & Load Campaign Ledger

> Master ledger for the reproducible stress / load-testing campaign of the
> `ngx_http_heavybag` module. Goal: a documented, bit-reproducible measurement
> layer over the (already mature) correctness suite — throughput/latency cost,
> rate-limiter accuracy, lock-free correctness under genuine concurrency, CPU
> under burst, and long-run stability. This document is the cross-session memory
> of the campaign; the per-run numbers come from the `summary.json` artifacts.
>
> **Naming:** `heavybag` = product identity (C symbols / .so / metrics / logs).
> `waf` = nginx config surface (directives, `$waf_*` vars, `X-WAF-*` headers, zone names).

## Campaign parameters (locked 2026-06-21)

- **Focus (partner decision):** correctness-under-load + rate-precision + perf-overhead
  + stability/soak + **CPU under burst** + **latency distribution**.
- **Tools:** h2load (nghttp2) + wrk2 (Gil Tene's constant-arrival fork) combo.
- **Scope:** all three heads — HTTP (L7), stream (L4), mail (auth_http).
- **Reproducibility contract:** nginx-side knobs are BAKED in the stress conf; only
  load-side params are env-tunable, and every one is recorded into each run's
  `params.env` + `summary.json`. The absolute req/s is machine-specific — the
  reproducible metric is the **enforce-vs-`waf off` RATIO**. The machine header
  (CPU / kernel / cores / worker_processes) is stamped into every `summary.json`.
- **Ground truth:** the status-endpoint counter delta (`/waf/stat/plain`, the
  `getcnt()` source lifted to before/after JSON snapshots), never the load tool's
  own status tally.
- **Commits:** partner commits on main and pushes himself. Phased commits
  (infra+HTTP / stream+mail / CPU-burst / soak), atomic style.

## Tooling layout

| Path | Role |
|---|---|
| `tools/stress/versions.env` | pinned h2load/wrk2 versions + H3-capability expectation |
| `modules/ngx_http_heavybag/tools/gen-stress-corpus.pl` | deterministic `replay-vectors.jsonl` → `stress-urls.txt` (top-N, fixed benign cadence, no randomness) |
| `tests/corpus/stress-urls.txt` | **committed** deterministic URL corpus (the load contract) |
| `tests/stress/heavybag-stress-test.conf` | dedicated stress conf, 283xx port band, `worker_processes >=2` baked |
| `tests/stress/stress-lib.sh` | counter snapshot/delta/invariants, CPU/RSS sampling, HDR parsing, tool/capability probes |
| `tests/run-stress-tests.sh` | orchestrator (S1–S5, `--quick` smoke = ctest, `--soak` opt-in) |
| `docs/stress-campaign.md` | this ledger |
| `cmake/Tests.cmake` | `heavybag_stress` (smoke gate) + `heavybag_soak` (opt-in) |

## Scenario inventory

| ID | Name | Tool | Heads | Metric | Gate? |
|---|---|---|---|---|---|
| **S1** | perf-overhead | h2load (H1/H2/H3) | HTTP | enforce-vs-off req/s ratio + latency p50/p99/p999 + full distribution | no (measure) |
| **S2** | rate-precision | wrk2 `-R` sweep | HTTP | measured 429-share vs theoretical `max(0,R−limit)/R` + HDR latency | no (measure) |
| **S3** | correctness-under-load | h2load + curl | HTTP + stream + mail | **per-head counter invariants** | **YES** |
| **S4** | cpu-burst | h2load | HTTP | warmup→burst→cooldown CPU%/RSS timeseries + burst-window HDR | no (measure) |
| **S5** | soak (opt-in) | h2load | HTTP | RSS/fd trend + reload cycling + least-squares leak gate | YES (leak) |

### S3 invariants (the hard correctness gate)

Measured on the counter delta around a concurrent mixed-load window:

- **HTTP:**  `Δhttp_requests_total == Δhttp_allowed + Σ Δhttp_blocked[reason]`
- **STREAM:** `Δstream_connections_total == Δstream_allowed + Σ Δstream_denied[reason]`
- **MAIL:** no status counter → **wire-only** (Auth-Status OK/deny), allow+deny mix.
- **Side assertions:** `Δhttp_allowlist_hits ≤ Δhttp_allowed` (subset, NOT an addend);
  no counter delta goes negative (monotonic).
- **Excluded by construction:** the `would_block[*]` overlay (detect requests count
  as `allowed`), the `http_scanner_path_{403,404,444}` / `http_resp_*` / `http_flag_*`
  / `http_ua*` breakdowns (overlays, not addends), and all `waf off` traffic
  (moves no counter). The 16 reason slots are the only block/deny addends:
  `allowlist blocklist geo geo_whitelist flag scanner_ua empty_ua scanner_path
  asn method args cookie referer fake_bot rate_limit spoof`.

The sharpest surface: the HTTP head and the stream head (port 28391) draw rate
budget from the **same** `waf_rate` shm zone (`heavybag_stream.c:449-454`); loading
both concurrently with `worker_processes >= 2` is the real lock-free race the
`concurrent_same_key` TSan micro-bench only approximates.

## Reproducibility — concretely

- `gen-stress-corpus.pl` is deterministic (top-N by `count` DESC then `uri` ASC,
  fixed benign cadence, **no randomness**); `stress-urls.txt` is committed, so every
  host replays the identical load. Regenerate + verify byte-identity:
  `perl modules/ngx_http_heavybag/tools/gen-stress-corpus.pl` (idempotent).
- Pinned tool versions in `tools/stress/versions.env`; the harness WARNs on drift
  and records expected+found in `summary.json` (never fails on version).
- H3 is a capability, not a version: the harness probes `h2load --help` for the
  HTTP/3 flag and SKIPs the H3 dimension when absent (most distro builds are H1/H2).
- wrk2 must support `-R`; Debian's `wrk` (Will Glozer) does NOT → the harness treats
  it as absent and SKIPs S2 with an actionable message.

## How to run

> Full operational guide (install, params, reading results, troubleshooting):
> [`docs/stress-testing.md`](stress-testing.md).

```sh
# smoke (the ctest gate): ~10s/scenario, pass/fail = S3 invariants
bash modules/ngx_http_heavybag/tests/run-stress-tests.sh --quick
#   or: ctest --test-dir build -R heavybag_stress

# full reference run (fills the tables below)
bash modules/ngx_http_heavybag/tests/run-stress-tests.sh

# opt-in soak
HB_STRESS_SOAK_OPT_IN=1 HB_SOAK_DUR=3600 ctest --test-dir build -R heavybag_soak
```

Artifacts land under `tests/corpus/.stress/<scenario>-<timestamp>/` (gitignored):
`params.env`, raw tool output, `counter-delta.json`, `cpu-rss.csv`, `summary.json`.

---

# Results ledger

> Populated from the `summary.json` of each reference run. Record the machine
> header with every table so cross-host numbers stay comparable.

## Pipeline verification (2026-06-21, dev host, curl fallback)

The load tools (h2load, wrk2) were **not installed** on the build host, so the
pipeline was verified tool-independently: config render + `nginx -t`, corpus
determinism (byte-identical, md5 stable), SKIP-on-absent gating, and the **S3
counter invariants driven with a curl fallback** (`HB_STRESS_CURL_FALLBACK=1`)
under `worker_processes=2` concurrent multi-head load.

**S3 correctness gate — PASS:**

| Head | Invariant | Observed |
|---|---|---|
| HTTP | `Δrequests_total == Δallowed + ΣΔblocked` | `6012 == 2558 + 3454` ✓ |
| STREAM | `Δconnections_total == Δallowed + ΣΔdenied` | `2000 == 116 + 1884` ✓ |
| HTTP | `Δallowlist_hits ≤ Δallowed` | `0 ≤ 2558` ✓ |
| — | monotonic (no negative delta) | ✓ |
| MAIL | wire-only Auth-Status | deny=`static blocklist`, allow=`OK` ✓ |

This already demonstrates the lock-free counters and the shared-shm rate buckets
stay consistent under real cross-worker, cross-head contention — the core
correctness claim. The throughput/latency/CPU tables below await a reference run
on a host with h2load + wrk2 installed.

## S1 — perf overhead (enforce vs `waf off`)

_Pending reference run (needs h2load). Machine header: —_

| Proto | baseline req/s | enforce req/s | overhead ratio | p50 | p99 | p999 |
|---|---|---|---|---|---|---|
| H1 | | | | | | |
| H2 | | | | | | |
| H3 | | | | | | |

## S2 — rate precision

_Pending reference run (needs wrk2). Rate vhost limit = 100 r/s._

| R (req/s) | requests | blocked 429 | measured share | theoretical `max(0,R−100)/R` |
|---|---|---|---|---|
| 50 | | | | 0.000 |
| 100 | | | | 0.000 |
| 200 | | | | 0.500 |
| 500 | | | | 0.800 |

## S4 — CPU under burst

_Pending reference run (needs h2load). See `cpu-rss.csv` + `burst.hdr` per run._

| Phase | worker CPU% (sum) | RSS (KiB) | burst req/s | burst p99 / p999 |
|---|---|---|---|---|
| warmup | | | | |
| burst | | | | |
| cooldown | | | | |

## S5 — soak

_Pending opt-in run. Leak gate: RSS least-squares slope ≤ 64 KiB/s._

| Duration | reloads | RSS slope (KiB/s) | fd trend | verdict |
|---|---|---|---|---|
| | | | | |
