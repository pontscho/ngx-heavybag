/*
 * ngx_http_waf_module - shared reputation configuration + core
 *
 * One decision function feeds three heads: the HTTP PREACCESS phase, the
 * SMTP auth_http endpoint and the stream (L4) access phase. The reputation
 * inputs are gathered in ngx_waf_rep_conf_t, embedded in the HTTP location
 * conf and the stream server conf (the mail head reuses the HTTP one).
 *
 * This header is deliberately context-neutral (ngx_core only): it must be
 * includable from both the HTTP and the stream translation units without
 * pulling in ngx_http.h / ngx_stream.h.
 */

#ifndef _WAF_REP_H_INCLUDED_
#define _WAF_REP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/* full type lives in waf_geo.h; only the pointer is stored here */
struct ngx_http_waf_geo_db_s;


typedef struct {
    struct ngx_http_waf_geo_db_s  *geo_db;     /* waf_geo_db               */
    ngx_array_t                   *block_cc;   /* uint16 packed CC, block  */
    ngx_array_t                   *allow_cc;   /* uint16 packed CC, allow  */
    uint16_t                       flag_mask;  /* libloc flags to block    */
    ngx_array_t                   *blocklist;  /* ngx_cidr_t -> deny       */
    ngx_array_t                   *allowlist;  /* ngx_cidr_t -> allow      */
} ngx_waf_rep_conf_t;


/*
 * Verdict for *sa. Returns NGX_DECLINED to allow, or a forbidden status to
 * deny: NGX_HTTP_FORBIDDEN (403) for blocklist / network-flag / geo-block,
 * NGX_HTTP_NOT_FOUND (404) for a geo-whitelist miss. On deny *reason is set
 * to a static description for logging / Auth-Status. The numeric codes are
 * HTTP values; non-HTTP heads key off "!= NGX_DECLINED" and the reason.
 */
ngx_int_t ngx_http_waf_reputation_check(ngx_waf_rep_conf_t *rep,
    struct sockaddr *sa, ngx_str_t *reason);

/* Append a "addr/prefix" CIDR to *arr (created on first use). */
ngx_int_t ngx_http_waf_cidr_add(ngx_conf_t *cf, ngx_array_t **arr,
    ngx_str_t *text);

/* Append an ISO-3166 alpha-2 country code (packed uint16) to *arr. */
ngx_int_t ngx_http_waf_country_add(ngx_conf_t *cf, ngx_array_t **arr,
    ngx_str_t *cc);

/* Map a flag name (anonymous-proxy/satellite/anycast/drop/tor) into *rep. */
ngx_int_t ngx_http_waf_flag_add(ngx_conf_t *cf, ngx_waf_rep_conf_t *rep,
    ngx_str_t *tok);

/*
 * Open and mmap the libloc geo database at *path (config-time); NULL on
 * error (already logged). Defined in waf_geo.c. Re-declared here (the full
 * ngx_http_waf_geo_db_t type lives in waf_geo.h) so the stream head can wire
 * waf_geo_db without including the HTTP-flavoured waf_geo.h / ngx_http.h.
 */
struct ngx_http_waf_geo_db_s *ngx_http_waf_geo_open(ngx_conf_t *cf,
    ngx_str_t *path);


#endif /* _WAF_REP_H_INCLUDED_ */
