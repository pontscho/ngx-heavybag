/*
 * ngx_http_heavybag_module - SMTP auth_http endpoint
 *
 * See heavybag_authhttp.h. The mail proxy forwards the real session peer in
 * the Client-IP header; we run the same verdict function the HTTP PREACCESS
 * phase uses and translate the result into the response headers
 * ngx_mail_auth_http_module expects. The response is a header-only 200;
 * ngx_mail ignores the status line and parses Auth-*.
 *
 * TRUST MODEL (SV11, CWE-290/348). Client-IP is attacker-controlled input
 * unless the CALLER is authenticated. The host may run other local processes,
 * so "the peer is loopback" is a topology filter, NOT an authenticator: any
 * co-located process can connect() and forge a Client-IP to pick its own
 * verdict, which is a WAF-evasion primitive. The forwarded address is
 * therefore honoured only when BOTH hold:
 *
 *   (1) the peer is loopback / AF_UNIX  -- the cheap first filter, and
 *   (2) the request carries X-WAF-Key whose value CONSTANT-TIME-equals the
 *       configured waf_mail_trusted_secret (the actual authenticator).
 *
 * Everything else -- no secret configured, header missing, value mismatched,
 * remote peer -- is fail-CLOSED: Client-IP is ignored and the real connection
 * peer is judged. The operator wires the mail side up with
 * `auth_http_header X-WAF-Key "<token>";` so ngx_mail attaches it to every
 * auth request.
 *
 * ACCOUNTING (observability-01). The mail head is a first-class citizen of the
 * exported invariant requests_total == allowed + sum(blocked), documented at
 * ngx_http_heavybag_module.c:747-752. It REUSES the http_* counters (no
 * segregated mail_* fields, no serializer change, no shm layout bump): every
 * auth request that reaches a verdict bumps http_requests_total once, then
 * exactly one of http_allowed / http_blocked[reason]. The two edges that
 * never reach a verdict -- a missing / unparseable Client-IP on an
 * authenticated channel, resolved by waf_mail_failopen -- are deliberately
 * OUTSIDE the accounting: there is no reason slot for "not judged" and adding
 * one would bump the shm layout. Those edges are WARN-logged instead. The
 * auth_http location runs with `waf off`, so the HTTP PREACCESS handler never
 * counts these requests a second time.
 */

#ifdef HEAVYBAG_AUTHHTTP_UNIT_TEST
/* Standalone unit build (tests/unit/test-authhttp.c): only the pure
 * secret_eq core is compiled; this shim stands in for the nginx types it uses. */
#include <stddef.h>
#include <stdint.h>
typedef unsigned char  u_char;
typedef uintptr_t      ngx_uint_t;
typedef struct {
    size_t   len;
    u_char  *data;
} ngx_str_t;
#else
#include "ngx_http_heavybag.h"
#include "heavybag_authhttp.h"
#include "heavybag_reputation.h"
#include "heavybag_status.h"
#include "heavybag_rate.h"
#endif


#ifndef HEAVYBAG_AUTHHTTP_UNIT_TEST
static ngx_table_elt_t *ngx_http_heavybag_add_header(ngx_http_request_t *r,
    const char *key, size_t klen, u_char *val, size_t vlen);
static ngx_str_t *ngx_http_heavybag_authhttp_header(ngx_http_request_t *r,
    const char *name, size_t nlen);
#endif
static ngx_uint_t ngx_http_heavybag_authhttp_secret_eq(ngx_str_t *a,
    ngx_str_t *b);
#ifndef HEAVYBAG_AUTHHTTP_UNIT_TEST
static ngx_uint_t ngx_http_heavybag_authhttp_peer_trusted(ngx_connection_t *c);
static ngx_uint_t ngx_http_heavybag_authhttp_caller_trusted(
    ngx_http_request_t *r, ngx_http_heavybag_loc_conf_t *wlcf);
static ngx_int_t ngx_http_heavybag_authhttp_finalize(ngx_http_request_t *r);
static ngx_int_t ngx_http_heavybag_authhttp_allow(ngx_http_request_t *r,
    ngx_http_heavybag_loc_conf_t *wlcf);
static ngx_int_t ngx_http_heavybag_authhttp_deny(ngx_http_request_t *r,
    ngx_str_t *reason);


static ngx_str_t  ngx_http_heavybag_auth_status = ngx_string("Auth-Status");
static ngx_str_t  ngx_http_heavybag_auth_server = ngx_string("Auth-Server");
static ngx_str_t  ngx_http_heavybag_auth_port = ngx_string("Auth-Port");
static ngx_str_t  ngx_http_heavybag_auth_ok = ngx_string("OK");


ngx_int_t
ngx_http_heavybag_authhttp_handler(ngx_http_request_t *r)
{
    ngx_int_t                  rc;
    ngx_str_t                  reason;
    ngx_str_t                 *client_ip = NULL;
    ngx_addr_t                 addr;
    struct sockaddr           *sa;
    ngx_http_heavybag_verdict_t     verdict;
    ngx_http_heavybag_loc_conf_t   *wlcf;
    ngx_http_heavybag_main_conf_t  *wmcf;
    ngx_http_heavybag_rate_rule_t  *rate_rule;
    ngx_http_heavybag_stat_shm_t   *sh;

    /* auth_http issues GET; discard any body and ignore the method. */
    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_heavybag_module);
    wmcf = ngx_http_get_module_main_conf(r, ngx_http_heavybag_module);
    sh = (wmcf->stat_zone != NULL) ? wmcf->stat_zone->data : NULL;

    /*
     * Whose address do we judge? Only an AUTHENTICATED caller (loopback/unix
     * peer AND a matching X-WAF-Key) may dictate it through Client-IP; every
     * other caller is judged on the connection peer it actually came from.
     * See the trust-model note at the top of this file. (The location should
     * also carry "waf off".)
     */
    if (ngx_http_heavybag_authhttp_caller_trusted(r, wlcf)) {

        client_ip = ngx_http_heavybag_authhttp_header(r, "Client-IP",
                                                      sizeof("Client-IP") - 1);

        if (client_ip == NULL
            || ngx_parse_addr(r->pool, &addr, client_ip->data, client_ip->len)
               != NGX_OK)
        {
            /*
             * ngx_mail always sets Client-IP from the real peer, so a missing
             * or unparseable value on an AUTHENTICATED channel means a
             * malformed request.
             *
             * waf_mail_failopen on -- THE DEFAULT (partner decision,
             * 2026-08-28): fail OPEN. Consequence, stated plainly: this auth
             * request is ALLOWED WITHOUT ANY WAF JUDGEMENT -- no reputation
             * check, no rate limit -- so that a malformed header can never
             * break mail delivery. It is WARN-logged, and (see the accounting
             * note at the top of this file) not counted. The evasion vector
             * this used to open is already closed by the shared-secret trust
             * model above: an unauthenticated local process cannot reach this
             * branch at all, it is judged on its own peer address instead.
             * off: fail CLOSED (deny) for an operator who would rather drop an
             * unattributable auth than risk letting it through unjudged.
             */
            if (wlcf->mail_failopen) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "heavybag: mail auth without parseable Client-IP, "
                              "allowing (waf_mail_failopen on)");
                return ngx_http_heavybag_authhttp_allow(r, wlcf);
            }

            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "heavybag: mail auth without parseable Client-IP, "
                          "denying (waf_mail_failopen off)");
            ngx_str_set(&reason, "mail client-ip missing");
            return ngx_http_heavybag_authhttp_deny(r, &reason);
        }

        sa = addr.sockaddr;

    } else {
        /* not authenticated: the helper already logged the specific reason */
        sa = r->connection->sockaddr;
    }

    /*
     * observability-01: from here on this auth request reaches exactly one
     * verdict (allow or deny), so count it once -- the mail head keeps the
     * exported invariant requests_total == allowed + sum(blocked) true, using
     * the existing http_* counters. There is no per-vhost slot for the mail
     * head, so only the globals move.
     */
    if (sh != NULL) {
        (void) ngx_atomic_fetch_add(&sh->http_requests_total, 1);
    }

    /*
     * The verdict side data drives the rate-limit rule selection (for_geo);
     * geo_valid stays 0 unless this location has a waf_geo_db, in which case
     * the default rule applies.
     */
    rc = ngx_http_heavybag_reputation_check(&wlcf->rep, sa, &reason, &verdict);

    if (rc != NGX_DECLINED) {
        /* book the deny under its reason so rep-blocks stop being invisible */
        if (sh != NULL) {
            (void) ngx_atomic_fetch_add(&sh->http_blocked[verdict.reason], 1);
        }

        if (client_ip != NULL) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "heavybag: mail reputation block %V (%V)",
                          client_ip, &reason);
        } else {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "heavybag: mail reputation block peer (%V)", &reason);
        }
        return ngx_http_heavybag_authhttp_deny(r, &reason);
    }

    /*
     * Allowlist full-scope bypass -- lifecycle-v01 parity with the HTTP head
     * (ngx_http_heavybag_module.c:1044-1048). A waf_allowlist CIDR hit returns
     * DECLINED with reason ALLOWLIST; with waf_allowlist_scope full (the
     * default) that trusted address skips EVERY later stage, so a trusted mail
     * relay is never throttled by its own auth traffic ("trusted == trusted")
     * and an allowlisted, geo-less IP stays out of the default rate bucket.
     * With scope reputation only the reputation stage is exempted and the rate
     * bucket still applies. (#3 / SV9, CWE-284)
     */
    if (verdict.reason == HEAVYBAG_REASON_ALLOWLIST
        && wlcf->allowlist_scope == HEAVYBAG_ALLOWLIST_FULL)
    {
        goto allowed;
    }

    /*
     * Reputation allowed: per-IP rate limit. No detect mode here (the auth
     * endpoint always enforces). The mail head has no per-vhost slot, so a
     * rate deny is booked on the global http_blocked[RATE_LIMIT] + http_resp_429
     * counters. The backing zone is the HTTP head's waf_rate_zone.
     */
    if (wlcf->rate_rules != NULL) {
        rate_rule = ngx_http_heavybag_rate_rule_select(wlcf->rate_rules, &verdict);

        if (rate_rule != NULL) {

            if (ngx_http_heavybag_rate_check(
                    (wmcf->rate_zone != NULL) ? wmcf->rate_zone->data : NULL,
                    sa, rate_rule->rate_num_fp, rate_rule->period_ms,
                    rate_rule->burst_fp)
                == NGX_BUSY)
            {
                ngx_str_t  rl = ngx_string("rate limit");

                if (sh != NULL) {
                    (void) ngx_atomic_fetch_add(
                        &sh->http_blocked[HEAVYBAG_REASON_RATE_LIMIT], 1);
                    (void) ngx_atomic_fetch_add(&sh->http_resp_429, 1);
                }

                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                              "heavybag: mail rate limit exceeded");

                return ngx_http_heavybag_authhttp_deny(r, &rl);
            }
        }
    }

allowed:

    /* the other half of the invariant: exactly one allowed per counted request */
    if (sh != NULL) {
        (void) ngx_atomic_fetch_add(&sh->http_allowed, 1);
        if (verdict.reason == HEAVYBAG_REASON_ALLOWLIST) {
            (void) ngx_atomic_fetch_add(&sh->http_allowlist_hits, 1);
        }
    }

    return ngx_http_heavybag_authhttp_allow(r, wlcf);
}

#endif /* !HEAVYBAG_AUTHHTTP_UNIT_TEST */


/*
 * Constant-time equality of two byte strings.
 *
 * DO NOT "optimize" this into memcmp / ngx_strcmp / ngx_strncmp / strcmp: it
 * compares a caller-supplied X-WAF-Key against the configured
 * waf_mail_trusted_secret, and every one of those primitives returns on the
 * first differing byte, which leaks the secret prefix-by-prefix through
 * response timing (CWE-208). The loop below always touches every byte of an
 * equal-length pair and folds the differences into one accumulator, so its
 * running time depends on the LENGTH only, never on the contents.
 *
 * A length mismatch short-circuits: the length of a secret is not itself a
 * secret, and comparing unequal lengths byte-wise is meaningless. An empty
 * secret never matches -- an unconfigured token must not authenticate anyone.
 */
static ngx_uint_t
ngx_http_heavybag_authhttp_secret_eq(ngx_str_t *a, ngx_str_t *b)
{
    size_t  i;
    u_char  diff;

    if (a->len == 0 || a->len != b->len) {
        return 0;
    }

    diff = 0;

    for (i = 0; i < a->len; i++) {
        diff |= (u_char) (a->data[i] ^ b->data[i]);
    }

    return (diff == 0) ? 1 : 0;
}

#ifndef HEAVYBAG_AUTHHTTP_UNIT_TEST  /* nginx-coupled remainder: out of the secret_eq unit TU */

/*
 * Is the CALLER authenticated to dictate the address we judge (Client-IP)?
 *
 * Two conjunctive conditions, cheapest first (see the trust-model note at the
 * top of this file): the peer must be loopback / AF_UNIX, AND the request must
 * carry an X-WAF-Key that constant-time-matches waf_mail_trusted_secret. The
 * secret -- not the peer class -- is the authenticator; the peer test alone is
 * passed by any co-located process (SV11).
 *
 * Fail-closed by construction: every failure path returns 0, and the caller
 * then judges the real connection peer. Each path logs its own specific reason
 * so an operator can tell a config gap from a spoof attempt.
 */
static ngx_uint_t
ngx_http_heavybag_authhttp_caller_trusted(ngx_http_request_t *r,
    ngx_http_heavybag_loc_conf_t *wlcf)
{
    ngx_str_t  *key;

    /*
     * No secret configured -> nobody can ever be authenticated -> Client-IP is
     * never honoured. Logged loudly because it is a config gap the operator
     * has to close (waf_mail_trusted_secret here + auth_http_header X-WAF-Key
     * on the mail side), not a transient condition.
     */
    if (wlcf->mail_trusted_secret.len == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "heavybag: mail auth Client-IP not trusted: "
                      "waf_mail_trusted_secret is not configured (fail-closed)");
        return 0;
    }

    if (!ngx_http_heavybag_authhttp_peer_trusted(r->connection)) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "heavybag: mail auth from untrusted peer, ignoring Client-IP "
                      "and judging the connection peer");
        return 0;
    }

    key = ngx_http_heavybag_authhttp_header(r, "X-WAF-Key",
                                            sizeof("X-WAF-Key") - 1);

    if (key == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "heavybag: mail auth X-WAF-Key missing, ignoring "
                      "Client-IP and judging the connection peer");
        return 0;
    }

    if (!ngx_http_heavybag_authhttp_secret_eq(key,
                                              &wlcf->mail_trusted_secret))
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "heavybag: mail auth X-WAF-Key mismatched, ignoring "
                      "Client-IP and judging the connection peer");
        return 0;
    }

    return 1;
}


/*
 * Is the request peer of the right class to be the mail proxy? In this
 * edge-firewall topology the mail proxy reaches auth_http over loopback (or a
 * unix socket), so a remote peer is disqualified outright. NECESSARY BUT NOT
 * SUFFICIENT: this only narrows the candidate set to local processes -- the
 * shared secret checked by _caller_trusted() above is what actually
 * authenticates the caller.
 */
static ngx_uint_t
ngx_http_heavybag_authhttp_peer_trusted(ngx_connection_t *c)
{
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    if (c->sockaddr == NULL) {
        return 0;
    }

    switch (c->sockaddr->sa_family) {

#if (NGX_HAVE_UNIX_DOMAIN)
    case AF_UNIX:
        return 1;
#endif

    case AF_INET:
        sin = (struct sockaddr_in *) c->sockaddr;
        /* 127.0.0.0/8, byte-order independent */
        return ((u_char *) &sin->sin_addr.s_addr)[0] == 127;

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) c->sockaddr;
        if (IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr)) {
            return 1;                       /* ::1 */
        }
        /* On a dual-stack (ipv6only=off) listener the loopback mail proxy
         * arrives as ::ffff:127.0.0.1, not ::1. Trust the v4-mapped loopback
         * /8 too, mirroring the rate keyer's v4-mapped handling (heavybag_rate
         * .c). Without this the loopback peer is judged untrusted and the
         * Client-IP it sets is dropped. */
        if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            return sin6->sin6_addr.s6_addr[12] == 127;   /* ::ffff:127.0.0.0/8 */
        }
        return 0;
#endif
    }

    return 0;
}


/*
 * Allow: "Auth-Status: OK" plus the backend MTA from waf_mail_backend.
 * ngx_mail rejects the session with an internal error if Auth-Server /
 * Auth-Port are missing, so a misconfigured backend is logged loudly.
 */
static ngx_int_t
ngx_http_heavybag_authhttp_allow(ngx_http_request_t *r,
    ngx_http_heavybag_loc_conf_t *wlcf)
{
    if (ngx_http_heavybag_add_header(r, (char *) ngx_http_heavybag_auth_status.data,
                                ngx_http_heavybag_auth_status.len,
                                ngx_http_heavybag_auth_ok.data,
                                ngx_http_heavybag_auth_ok.len)
        == NULL)
    {
        return NGX_ERROR;
    }

    if (wlcf->mail_backend_addr.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "heavybag: mail auth allowed but waf_mail_backend is not set; "
                      "the mail proxy will reject the session");
        return ngx_http_heavybag_authhttp_finalize(r);
    }

    if (ngx_http_heavybag_add_header(r, (char *) ngx_http_heavybag_auth_server.data,
                                ngx_http_heavybag_auth_server.len,
                                wlcf->mail_backend_addr.data,
                                wlcf->mail_backend_addr.len)
        == NULL)
    {
        return NGX_ERROR;
    }

    if (ngx_http_heavybag_add_header(r, (char *) ngx_http_heavybag_auth_port.data,
                                ngx_http_heavybag_auth_port.len,
                                wlcf->mail_backend_port.data,
                                wlcf->mail_backend_port.len)
        == NULL)
    {
        return NGX_ERROR;
    }

    return ngx_http_heavybag_authhttp_finalize(r);
}


/*
 * Deny: "Auth-Status: <reason>". reason points at a static string from the
 * reputation core ("static blocklist" / "network flag" / "geo country"),
 * never contains CRLF. ngx_mail prefixes the SMTP error code.
 */
static ngx_int_t
ngx_http_heavybag_authhttp_deny(ngx_http_request_t *r, ngx_str_t *reason)
{
    if (ngx_http_heavybag_add_header(r, (char *) ngx_http_heavybag_auth_status.data,
                                ngx_http_heavybag_auth_status.len,
                                reason->data, reason->len)
        == NULL)
    {
        return NGX_ERROR;
    }

    return ngx_http_heavybag_authhttp_finalize(r);
}


static ngx_int_t
ngx_http_heavybag_authhttp_finalize(ngx_http_request_t *r)
{
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;
    r->header_only = 1;

    return ngx_http_send_header(r);
}


static ngx_table_elt_t *
ngx_http_heavybag_add_header(ngx_http_request_t *r, const char *key, size_t klen,
    u_char *val, size_t vlen)
{
    ngx_table_elt_t  *h;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NULL;
    }

    h->hash = 1;
    h->key.len = klen;
    h->key.data = (u_char *) key;
    h->value.len = vlen;
    h->value.data = val;
    h->next = NULL;

    return h;
}


/*
 * Locate a non-standard request header by name (Client-IP / X-WAF-Key have no
 * dedicated headers_in slot, so the list has to be walked). Case-insensitive;
 * the FIRST occurrence wins, which is what makes a duplicated Client-IP
 * deterministic. Returns a pointer into the request's own header list --
 * borrowed, never copied, valid for the life of the request.
 */
static ngx_str_t *
ngx_http_heavybag_authhttp_header(ngx_http_request_t *r, const char *name,
    size_t nlen)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;

    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].key.len == nlen
            && ngx_strncasecmp(h[i].key.data, (u_char *) name, nlen) == 0)
        {
            return &h[i].value;
        }
    }

    return NULL;
}

#endif /* !HEAVYBAG_AUTHHTTP_UNIT_TEST */
