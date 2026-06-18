/*
 * ngx_http_heavybag_module - path scanner matching and User-Agent classification
 *
 * Scanner patterns live in a hot-reloadable list file (one pattern per
 * line, optional action token). Patterns are bucketed by action and each
 * bucket is compiled to a single anchored PCRE2 alternation, JIT-compiled
 * and freed via the configuration cycle pool (reload-safe). User-Agent
 * signature lists (scanner/ai-crawler/crawler/bot) use the same machinery,
 * one alternation per category, feeding the $waf_type classifier.
 */

#ifndef _HEAVYBAG_MATCH_H_INCLUDED_
#define _HEAVYBAG_MATCH_H_INCLUDED_


#ifndef HEAVYBAG_MATCH_UNIT_TEST

#include "ngx_http_heavybag.h"

#else

/*
 * Standalone unit-test type shim (-DHEAVYBAG_MATCH_UNIT_TEST): substitute
 * nginx for the config-time scanner-list parser + the PCRE2 bucket core, NO
 * nginx / SSL headers. Every typedef mirrors nginx byte-for-byte -- the shim
 * REPLACES nginx, it never redefines its semantics; the real -Werror SSL
 * module build stays the only correctness contract. ngx_regex_t is opaque
 * (cast to pcre2_code* in heavybag_match.c, exactly as production does); the
 * runtime-symbol shim (arena, ngx_array, ngx_regex_compile -> real
 * pcre2_compile, config-log capture) lives in heavybag_match.c. The nginx-glue
 * tail (ua_list/ja4/verified_bot/ua_classify) sits behind #ifndef both here
 * and in the .c -- it needs an ngx_http_request_t / cidr_add / the ja4 table.
 */
#include <stddef.h>
#include <stdint.h>

typedef unsigned char  u_char;
typedef intptr_t       ngx_int_t;
typedef uintptr_t      ngx_uint_t;
typedef struct { size_t len; u_char *data; } ngx_str_t;

typedef struct ngx_pool_s   ngx_pool_t;    /* opaque: the test arena mallocs */
typedef struct ngx_regex_s  ngx_regex_t;   /* opaque: cast to pcre2_code*     */

typedef struct {
    ngx_pool_t  *pool;
    ngx_pool_t  *temp_pool;
    void        *cycle;
} ngx_conf_t;

typedef struct {
    void        *elts;
    ngx_uint_t   nelts;
    size_t       size;
    ngx_uint_t   nalloc;
    ngx_pool_t  *pool;
} ngx_array_t;

typedef struct {
    ngx_str_t     pattern;
    ngx_pool_t   *pool;
    ngx_int_t     options;
    ngx_str_t     err;
    ngx_regex_t  *regex;
} ngx_regex_compile_t;

/* action bucket enum -- mirrors ngx_http_heavybag.h (the shim does not pull
 * the module header): 404=0, 403=1, 444=2, MAX=3. */
typedef enum {
    HEAVYBAG_ACTION_404 = 0,
    HEAVYBAG_ACTION_403,
    HEAVYBAG_ACTION_444,
    HEAVYBAG_ACTION_MAX
} ngx_http_heavybag_action_e;

#endif


/*
 * Read and compile the signature list referenced by *path into re_bucket,
 * a HEAVYBAG_ACTION_MAX-sized row of per-action regex slots (the caller owns the
 * row: scanner_re[] or one sig_re[cat][] row). Each non-comment line is
 * "<pattern>[ <action>]"; patterns sharing an action compile to one
 * alternation. Runs at configuration time (directive setter); the caller
 * sets its own duplicate-guard string. Reload-safe via cf->pool.
 */
ngx_int_t ngx_http_heavybag_scanner_compile(ngx_conf_t *cf, ngx_str_t *path,
    ngx_regex_t **re_bucket);

/*
 * Match subject against the compiled buckets in re_bucket in action order.
 * Returns the nginx status code to finalize with (NGX_HTTP_NOT_FOUND /
 * _FORBIDDEN / NGX_HTTP_CLOSE) on a hit, or NGX_DECLINED when nothing
 * matches. NULL bucket slots are skipped.
 */
ngx_int_t ngx_http_heavybag_scanner_lookup(ngx_regex_t **re_bucket,
    ngx_str_t *subject);

#ifndef HEAVYBAG_MATCH_UNIT_TEST   /* nginx-glue tail: ngx_http_request_t / ja4 table / cidr_add */

/*
 * Read and compile one config-file UA signature list into wlcf's ua_re[cat]
 * slot. Each non-comment, non-blank line is a single case-insensitive PCRE2
 * fragment (no action token); the whole list compiles to one alternation.
 * Runs at configuration time (directive setter); reload-safe via cf->pool.
 */
ngx_int_t ngx_http_heavybag_ua_list_compile(ngx_conf_t *cf,
    ngx_http_heavybag_loc_conf_t *wlcf, ngx_str_t *path, ngx_http_heavybag_ua_e cat);

/*
 * Read the verified-bot CIDR allowlist referenced by *path into *arr (a lazily
 * created ngx_cidr_t array; the signature is peer to ngx_http_heavybag_cidr_add, not
 * ua_list_compile). Each non-comment, non-blank line is one "addr/prefix" CIDR;
 * turning a published range (e.g. Google's googlebot.json) into this plain list
 * is the offline cron's job, not the WAF's. A missing/unreadable file is fatal
 * (NGX_ERROR -> reload aborts, old config stays live); a genuinely unparseable
 * CIDR line is fatal too. A file that exists but yields zero usable entries
 * leaves *arr NULL (the class stays unconfigured -> silently skipped) and only
 * warns. Runs at configuration time (directive setter); reload-safe via cf->pool.
 *
 * The lazy allocation is load-bearing: zero entries MUST leave *arr NULL (never
 * an allocated zero-element array), so the PREACCESS "!= NULL" guard can never
 * be fooled into treating an empty list as a block-all allowlist.
 */
ngx_int_t ngx_http_heavybag_verified_bot_compile(ngx_conf_t *cf, ngx_array_t **arr,
    ngx_str_t *path);

/*
 * Classify the request's User-Agent into ctx->ua and set ctx->classified.
 * Missing/empty UA -> HEAVYBAG_UA_EMPTY; otherwise the first matching ua_re[]
 * bucket in priority order (SCANNER..BOT); no match -> HEAVYBAG_UA_REGULAR.
 */
void ngx_http_heavybag_ua_classify(ngx_http_request_t *r,
    ngx_http_heavybag_loc_conf_t *wlcf, ngx_http_heavybag_ctx_t *ctx);

/*
 * Read the JA4 fingerprint -> coarse-TLS-family list referenced by *path into
 * wlcf->ja4_table. Each non-comment, non-blank line is "<ja4> <family>" where
 * <family> is chromium/firefox/safari/tool/bot/unknown. The table is copied
 * into cf->pool and sorted by the ja4 bytes so the per-request lookup
 * (ngx_http_heavybag_ja4_family, heavybag_ua_parse.c) can bsearch it. A missing/unreadable
 * file is fatal (reload aborts); malformed lines are skipped with a warning.
 * Runs at configuration time (directive setter); reload-safe via cf->pool.
 */
ngx_int_t ngx_http_heavybag_ja4_list_compile(ngx_conf_t *cf,
    ngx_http_heavybag_loc_conf_t *wlcf, ngx_str_t *path);

#endif /* HEAVYBAG_MATCH_UNIT_TEST -- nginx-glue tail */


#endif /* _HEAVYBAG_MATCH_H_INCLUDED_ */
