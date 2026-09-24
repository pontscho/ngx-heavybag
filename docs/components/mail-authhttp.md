---
name: mail-authhttp
type: component
status: active
title: Mail (SMTP) auth_http head
description: The ngx_mail auth_http content handler — caller trust model, waf_mail_failopen, counter accounting, allowlist/rate interplay and Auth-Status outputs.
sources:
  - modules/ngx_http_heavybag/src/heavybag_authhttp.c
  - modules/ngx_http_heavybag/src/heavybag_authhttp.c:ngx_http_heavybag_authhttp_handler
  - modules/ngx_http_heavybag/src/heavybag_authhttp.c:ngx_http_heavybag_authhttp_caller_trusted
  - modules/ngx_http_heavybag/src/heavybag_authhttp.c:ngx_http_heavybag_authhttp_secret_eq
  - modules/ngx_http_heavybag/src/heavybag_authhttp.c:ngx_http_heavybag_authhttp_peer_trusted
  - modules/ngx_http_heavybag/src/heavybag_authhttp.h
  - modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c:ngx_http_heavybag_set_mail_auth
  - modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c:ngx_http_heavybag_set_mail_backend
  - modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c:ngx_http_heavybag_set_mail_secret
verified:
  commit: 10bc7ea
  date: 2026-09-24
links:
  - overview
  - qa-findings
---

# Mail (SMTP) auth_http head

The mail head is one of heavybag's three entry points ([[overview]]). It is a
content handler for an HTTP location that speaks the `ngx_mail` `auth_http`
protocol. Before proxying an SMTP/IMAP/POP3 session, `ngx_mail` issues a GET
carrying the real session peer in the `Client-IP` header. The handler runs the
shared reputation verdict (and the per-IP rate limit) on an address and
answers with `Auth-*` response headers
`modules/ngx_http_heavybag/src/heavybag_authhttp.h`,
`modules/ngx_http_heavybag/src/heavybag_authhttp.c:ngx_http_heavybag_authhttp_handler`.

## Directives

- `waf_mail_auth`: location-only, no arguments. It installs the content
  handler on the location. The reputation directives on that location, or
  inherited ones, drive the verdict
  `modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c:ngx_http_heavybag_set_mail_auth`.
- `waf_mail_backend <ip> <port>`: the MTA returned on allow. The address
  **must be numeric**, because the mail proxy parses it with `ngx_parse_addr`
  and cannot resolve hostnames. The port must be 1–65535, and a duplicate is
  rejected
  `modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c:ngx_http_heavybag_set_mail_backend`.
- `waf_mail_trusted_secret <token>`: the shared secret that authenticates the
  caller. An **empty token is rejected at config time**, because an operator
  who wrote the directive meant to enable the feature and it must not silently
  degrade to fail-closed. A duplicate is rejected
  `modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c:ngx_http_heavybag_set_mail_secret`.
- `waf_mail_failopen on|off`: default **on** (merged with default 1). See
  below `modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c`.

**Operator requirement: `waf off` on the auth_http location.** Without it, the
HTTP `PREACCESS` handler judges the *connection* peer (the loopback mail proxy)
and can 403 the auth request before the content handler runs `README.md`. It
would also count the request a second time on top of the mail head's own
accounting `modules/ngx_http_heavybag/src/heavybag_authhttp.c`. The directive
setter does not enforce this. It is a configuration contract
`modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c:ngx_http_heavybag_set_mail_auth`.
The mail side mirrors the secret with `auth_http_header X-WAF-Key "<token>";`
`modules/ngx_http_heavybag/src/heavybag_authhttp.h`.

## Trust model: whose address is judged

`Client-IP` is attacker-controlled input unless the *caller* is authenticated.
A loopback peer is only a topology filter, because any co-located process can
connect and forge `Client-IP`. The forwarded address is honoured only when
**both** of these hold
`modules/ngx_http_heavybag/src/heavybag_authhttp.c:ngx_http_heavybag_authhttp_caller_trusted`:

1. The peer is AF_UNIX, `127.0.0.0/8`, `::1`, or the v4-mapped loopback
   `::ffff:127.0.0.0/8` (dual-stack listener). This check is necessary but not
   sufficient
   `modules/ngx_http_heavybag/src/heavybag_authhttp.c:ngx_http_heavybag_authhttp_peer_trusted`.
2. The request carries `X-WAF-Key` and its value **constant-time** equals
   `waf_mail_trusted_secret`. The comparison folds every byte of an
   equal-length pair into one accumulator, so its timing depends only on the
   length. A length mismatch short-circuits, and an empty secret never matches
   `modules/ngx_http_heavybag/src/heavybag_authhttp.c:ngx_http_heavybag_authhttp_secret_eq`.

Every other case is **fail-closed**: `Client-IP` is ignored and the real
connection peer is judged. That covers no secret configured, a missing or
mismatched key, and a remote peer. Each path WARN-logs its own reason, so an
operator can tell a config gap from a spoof attempt
`modules/ngx_http_heavybag/src/heavybag_authhttp.c:ngx_http_heavybag_authhttp_caller_trusted`.
Header lookup is case-insensitive and the **first** occurrence wins, which
makes a duplicated `Client-IP` deterministic
`modules/ngx_http_heavybag/src/heavybag_authhttp.c`.

## `waf_mail_failopen`: fail-open by design

The flag governs exactly one edge: an **authenticated** caller whose
`Client-IP` is missing or unparseable. `ngx_mail` always sets `Client-IP`, so
this case means a malformed request
`modules/ngx_http_heavybag/src/heavybag_authhttp.c:ngx_http_heavybag_authhttp_handler`.

- **on (default, a partner decision):** the auth request is allowed
  **without any WAF judgement** (no reputation check, no rate limit), so a
  malformed header can never break mail delivery. The allow is WARN-logged.
- **off:** the request is denied with `Auth-Status: mail client-ip missing`.
  This is for operators who would rather drop an unattributable auth than let
  it through unjudged
  `modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c`.

The default is deliberate and low-stakes. The shared-secret trust model
already closes the evasion vector, because an unauthenticated process never
reaches this branch and is judged on its own peer address instead. The
remaining case is a genuinely authenticated proxy that omits `Client-IP`
`modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c`. Unauthenticated
callers are not covered by this flag at all.

## Verdict pipeline

1. **Reputation**: `ngx_http_heavybag_reputation_check` runs on the chosen
   address. A deny answers with the reputation reason
   `modules/ngx_http_heavybag/src/heavybag_authhttp.c:ngx_http_heavybag_authhttp_handler`.
2. **Allowlist skip**: a `waf_allowlist` hit under `waf_allowlist_scope full`
   (the default) skips every later stage, including the rate limit, so a
   trusted relay is never throttled by its own auth traffic. With scope
   `reputation` the rate bucket still applies. This matches the HTTP and stream
   heads (see `lifecycle-v01` in [[qa-findings]])
   `modules/ngx_http_heavybag/src/heavybag_authhttp.c:ngx_http_heavybag_authhttp_handler`.
3. **Per-IP rate limit**: uses the HTTP head's `waf_rate_zone` and the
   location's `waf_rate_limit` rules (selected via the verdict's geo data). It
   has **no detect mode**: this endpoint always enforces
   `modules/ngx_http_heavybag/src/heavybag_authhttp.c:ngx_http_heavybag_authhttp_handler`.

## Counter accounting

The mail head keeps the exported invariant
`requests_total == allowed + sum(blocked)`. It **reuses the `http_*`
counters**, with no separate `mail_*` fields and no shm layout change. Only the
globals move, because the mail head has no per-vhost slot
`modules/ngx_http_heavybag/src/heavybag_authhttp.c`:

- every request that reaches a verdict bumps `http_requests_total` once, then
  exactly one of `http_allowed` or `http_blocked[reason]`;
- a rate deny books `http_blocked[RATE_LIMIT]` plus `http_resp_429`;
- an allowlisted allow also bumps `http_allowlist_hits`;
- the **unjudged edges** (the missing or unparseable `Client-IP` branch under
  either `waf_mail_failopen` setting) are deliberately **not counted**. There
  is no reason slot for "not judged", and adding one would bump the shm
  layout. They are WARN-logged instead
  `modules/ngx_http_heavybag/src/heavybag_authhttp.c:ngx_http_heavybag_authhttp_handler`.

## Outputs

The response is always a header-only `200`. `ngx_mail` ignores the status line
and parses the `Auth-*` headers
`modules/ngx_http_heavybag/src/heavybag_authhttp.c`.

- **Allow**: `Auth-Status: OK`, `Auth-Server`, `Auth-Port` (from
  `waf_mail_backend`). If no backend is configured, the handler logs an
  error and sends `Auth-Status: OK` alone, and the mail proxy then rejects the
  session `modules/ngx_http_heavybag/src/heavybag_authhttp.c`.
- **Deny**: `Auth-Status: <reason>`, where the reason is a static reputation
  string (e.g. "static blocklist", "network flag", "geo country"), or
  `rate limit`, or `mail client-ip missing` (fail-open off). `ngx_mail` turns
  the deny into an SMTP error reply `modules/ngx_http_heavybag/src/heavybag_authhttp.c`,
  `modules/ngx_http_heavybag/src/heavybag_authhttp.h`.

The history of this trust model (the superseded loopback-only gate,
`authhttp-01`) is recorded in [[qa-findings]].
