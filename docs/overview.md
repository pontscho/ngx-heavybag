---
name: overview
type: overview
status: current
title: Project Overview — ngx_http_heavybag (edge firewall)
description: What heavybag is, its architecture, and the map to every wiki page.
sources:
  - README.md
  - modules/ngx_http_heavybag/config
verified:
  commit: 7a935b0
  date: 2026-06-21
links:
  - threat-model
  - threat-intel-sources
  - stress-testing
  - stress-campaign
  - qa-campaign
  - honeypot-B-plan
  - stats-implementation-plan
  - user-agent-plan
---

# Project Overview — heavybag

heavybag is a lean, fast **edge firewall** for vanilla nginx, shipped as a
dynamic C module (one `.so` carrying **two** nginx modules — HTTP + stream —
plus an `ngx_mail` `auth_http` content handler) over a single IP-reputation
core `README.md`. It is *not* a deep WAF: it does scanner-path blocking,
User-Agent classification (`$waf_type`), Apache fingerprint spoofing, embedded
nanolibloc geo/reputation filtering, and HTTP + SMTP + stream (L4) protection
driven by the same reputation engine. It replaces a legacy
`nginx-firewall.conf` of ~130 location-based scanner rules with compiled,
anchored, hot-reloadable rules `README.md`.

## Architecture in one breath

Three entry points ("heads") converge on the *same*
`modules/ngx_http_heavybag/src/heavybag_reputation.c:ngx_http_heavybag_reputation_check`:
the HTTP `PREACCESS` handler, the SMTP `auth_http` endpoint
`modules/ngx_http_heavybag/src/heavybag_authhttp.c:ngx_http_heavybag_authhttp_handler`,
and the stream `ACCESS` handler
`modules/ngx_http_heavybag/src/heavybag_stream.c:ngx_stream_heavybag_handler`.
The HTTP head adds the request-aware layers (UA classification + signatures in
`modules/ngx_http_heavybag/src/heavybag_match.c`, descriptive UA parse in
`modules/ngx_http_heavybag/src/heavybag_ua_parse.c`, JA4 + spoof in
`modules/ngx_http_heavybag/src/heavybag_ja4.c`). The only shared state is the
read-only mmap'd geo DB `modules/ngx_http_heavybag/src/heavybag_geo.c` and two
lock-free shm zones — the rate limiter
`modules/ngx_http_heavybag/src/heavybag_rate.c` and the statistics endpoint
`modules/ngx_http_heavybag/src/heavybag_status.c`. Full directive reference,
build instructions, and per-head behaviour live in `README.md`.

## Subsystems (by source directory)

- **HTTP module glue** — directives, phases, merge, `$waf_*` variables
  `modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c`.
- **Reputation core** — the shared allow/block/geo/asn/flag/country decision
  `modules/ngx_http_heavybag/src/heavybag_reputation.c`.
- **Geo / signature verify** — IPFire `location.db` reader + load-time ECDSA
  P-521 verify `modules/ngx_http_heavybag/src/heavybag_geo.c:ngx_http_heavybag_geo_verify`.
- **Signature matching** — scanner/args/cookie/referer buckets + UA classify
  `modules/ngx_http_heavybag/src/heavybag_match.c:ngx_http_heavybag_scanner_lookup`.
- **Rate limiting** — lock-free per-IP token bucket
  `modules/ngx_http_heavybag/src/heavybag_rate.c:ngx_http_heavybag_rate_check`.
- **Statistics** — lock-free counters, plain/json/prometheus
  `modules/ngx_http_heavybag/src/heavybag_status.c`.
- **Stream (L4) head** and **mail (SMTP) head** —
  `modules/ngx_http_heavybag/src/heavybag_stream.c`,
  `modules/ngx_http_heavybag/src/heavybag_authhttp.c`.

## Page map

- [[threat-model]] — empirical attack-surface analysis and the data-driven
  rule-tuning loop (A–D).
- [[threat-intel-sources]] — external feeds for the header-attack fixtures.
- [[honeypot-B-plan]] — detect-mode FP/TP replay harness (decision record).
- [[stats-implementation-plan]] — statistics / status subsystem design.
- [[user-agent-plan]] — descriptive UA parser + JA4/UA spoof design.
- [[stress-testing]] — operational stress/load testing guide.
- [[stress-campaign]] — stress campaign ledger and result tables.
- [[qa-campaign]] — QA hardening campaign findings ledger.

> Build, configuration, and the full directive reference are in the
> repo-root `README.md` (linked, not duplicated here).
