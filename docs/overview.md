---
name: overview
type: overview
status: active
title: Project Overview — ngx_http_heavybag (edge firewall)
description: What heavybag is, its architecture, and the map to every wiki page.
sources:
  - README.md
  - modules/ngx_http_heavybag/config
verified:
  commit: 10bc7ea
  date: 2026-09-24
links:
  - threat-model
  - mail-authhttp
  - build-matrix
  - threat-intel-sources
  - stress-testing
  - stress-campaign
  - qa-findings
  - qa-test-matrix
  - qa-subunit-inventory
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

The reputation *configuration* is shared too, not only the decision: the
merge, the fail-closed geo-dependency validation and the directive setters for
geo/ASN/flag/block/allow lists live once in `heavybag_reputation.c`
(`modules/ngx_http_heavybag/src/heavybag_reputation.c:ngx_http_heavybag_rep_conf_merge`,
`modules/ngx_http_heavybag/src/heavybag_reputation.c:ngx_http_heavybag_rep_conf_validate`),
and the HTTP and stream heads both call into them, so the two heads cannot
drift apart on inheritance or validation order.

## Behaviour worth knowing before reading the code

- **Unknown-geo sources pass by default.** A source the geo DB has no record
  for passes the reputation stage (the deny-list convention). Denying it is an
  explicit opt-in, the `unknown` token of `waf_flag_block`
  `modules/ngx_http_heavybag/src/heavybag_reputation.c:ngx_http_heavybag_flag_add`;
  the README warns that it also denies loopback/RFC1918 `README.md`.
- **Mail head trusts `Client-IP` only from an authenticated caller.** The
  forwarded address is honoured only when the peer is loopback/unix **and** the
  request carries an `X-WAF-Key` that constant-time-matches
  `waf_mail_trusted_secret`; every other case judges the real connection peer
  `modules/ngx_http_heavybag/src/heavybag_authhttp.c:ngx_http_heavybag_authhttp_caller_trusted`,
  `modules/ngx_http_heavybag/src/heavybag_authhttp.c:ngx_http_heavybag_authhttp_secret_eq`.
  `waf_mail_failopen` (default on) still allows an *authenticated* request whose
  `Client-IP` is missing or unparseable, by design `README.md`. Details in
  [[mail-authhttp]].
- **Subrequests are not re-inspected.** Only the main request runs the
  pipeline (`r != r->main` bail), so a stricter ruleset on a subrequest's target
  location never applies `README.md`.
- **PCRE2 is a build requirement.** The bounded regex helper
  `modules/ngx_http_heavybag/src/heavybag_match.c:ngx_http_heavybag_regex_exec`
  has a PCRE2 arm with match/depth limits; the PCRE1 arm is an `#error` outside
  the unit-test build.

## Subsystems (by source directory)

- **HTTP module glue** — directives, phases, merge, `$waf_*` variables
  `modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c`.
- **Reputation core** — the shared allow/block/geo/asn/flag/country decision
  plus the shared rep-conf merge/validate/setter layer
  `modules/ngx_http_heavybag/src/heavybag_reputation.c`.
- **Geo / signature verify** — IPFire `location.db` reader + load-time ECDSA
  P-521 verify `modules/ngx_http_heavybag/src/heavybag_geo.c:ngx_http_heavybag_geo_verify`;
  the IPv4-mapped root descent refuses a malformed tree at load time
  `modules/ngx_http_heavybag/src/heavybag_geo.c:ngx_http_heavybag_geo_ipv4root`.
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

- [[mail-authhttp]] — the mail (SMTP) `auth_http` head: caller trust model,
  `waf_mail_failopen`, counter accounting, `Auth-Status` outputs.
- [[build-matrix]] — runbook for the build-portability matrix
  (`heavybag_build_matrix`) and the `heavybag_module` self-heal.
- [[threat-model]] — empirical attack-surface analysis and the data-driven
  rule-tuning loop (A–D).
- [[threat-intel-sources]] — external feeds for the header-attack fixtures.
- [[honeypot-B-plan]] — detect-mode FP/TP replay harness (decision record).
- [[stats-implementation-plan]] — statistics / status subsystem design.
- [[user-agent-plan]] — descriptive UA parser + JA4/UA spoof design.
- [[stress-testing]] — operational stress/load testing guide.
- [[stress-campaign]] — stress campaign ledger and result tables.
- [[qa-findings]] — QA hardening campaign findings ledger and fix dispositions.
- [[qa-test-matrix]] — the permanent unit/integration/build regression net.
- [[qa-subunit-inventory]] — per-translation-unit risk and unit-test coverage.

> Build, configuration, and the full directive reference are in the
> repo-root `README.md` (linked, not duplicated here). The S6–S8 code and
> security review reports and the fix task list sit under `reviews/`
> as review artifacts, outside the wiki's page contract.
