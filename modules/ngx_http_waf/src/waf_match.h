/*
 * ngx_http_waf_module - path scanner matching and User-Agent classification
 *
 * Scanner patterns live in a hot-reloadable list file (one pattern per
 * line, optional action token). Patterns are bucketed by action and each
 * bucket is compiled to a single anchored PCRE2 alternation, JIT-compiled
 * and freed via the configuration cycle pool (reload-safe). User-Agent
 * signature lists (scanner/ai-crawler/crawler/bot) use the same machinery,
 * one alternation per category, feeding the $waf_type classifier.
 */

#ifndef _WAF_MATCH_H_INCLUDED_
#define _WAF_MATCH_H_INCLUDED_


#include "ngx_http_waf.h"


/*
 * Read and compile the signature list referenced by *path into re_bucket,
 * a WAF_ACTION_MAX-sized row of per-action regex slots (the caller owns the
 * row: scanner_re[] or one sig_re[cat][] row). Each non-comment line is
 * "<pattern>[ <action>]"; patterns sharing an action compile to one
 * alternation. Runs at configuration time (directive setter); the caller
 * sets its own duplicate-guard string. Reload-safe via cf->pool.
 */
ngx_int_t ngx_http_waf_scanner_compile(ngx_conf_t *cf, ngx_str_t *path,
    ngx_regex_t **re_bucket);

/*
 * Match subject against the compiled buckets in re_bucket in action order.
 * Returns the nginx status code to finalize with (NGX_HTTP_NOT_FOUND /
 * _FORBIDDEN / NGX_HTTP_CLOSE) on a hit, or NGX_DECLINED when nothing
 * matches. NULL bucket slots are skipped.
 */
ngx_int_t ngx_http_waf_scanner_lookup(ngx_regex_t **re_bucket,
    ngx_str_t *subject);

/*
 * Read and compile one config-file UA signature list into wlcf's ua_re[cat]
 * slot. Each non-comment, non-blank line is a single case-insensitive PCRE2
 * fragment (no action token); the whole list compiles to one alternation.
 * Runs at configuration time (directive setter); reload-safe via cf->pool.
 */
ngx_int_t ngx_http_waf_ua_list_compile(ngx_conf_t *cf,
    ngx_http_waf_loc_conf_t *wlcf, ngx_str_t *path, ngx_http_waf_ua_e cat);

/*
 * Read the verified-bot CIDR allowlist referenced by *path into *arr (a lazily
 * created ngx_cidr_t array; the signature is peer to ngx_http_waf_cidr_add, not
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
ngx_int_t ngx_http_waf_verified_bot_compile(ngx_conf_t *cf, ngx_array_t **arr,
    ngx_str_t *path);

/*
 * Classify the request's User-Agent into ctx->ua and set ctx->classified.
 * Missing/empty UA -> WAF_UA_EMPTY; otherwise the first matching ua_re[]
 * bucket in priority order (SCANNER..BOT); no match -> WAF_UA_REGULAR.
 */
void ngx_http_waf_ua_classify(ngx_http_request_t *r,
    ngx_http_waf_loc_conf_t *wlcf, ngx_http_waf_ctx_t *ctx);


#endif /* _WAF_MATCH_H_INCLUDED_ */
