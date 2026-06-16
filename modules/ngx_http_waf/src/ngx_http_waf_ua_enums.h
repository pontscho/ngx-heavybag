/*
 * ngx_http_waf_module - descriptive User-Agent parser enums.
 *
 * Leaf header: plain enums only, NO nginx types and NO includes, so it can be
 * pulled into the standalone parser unit test (-DWAF_UA_PARSE_UNIT_TEST) which
 * runs without the nginx headers -- the same isolation model waf_ja4.c uses.
 * ngx_http_waf.h includes this so the request ctx can carry the enum fields;
 * this is the single source of truth for the five families (no drift between
 * the production build and the test build).
 *
 * All enums use UNKNOWN == 0 so an ngx_pcalloc'd ctx defaults to "unknown".
 */

#ifndef _NGX_HTTP_WAF_UA_ENUMS_H_INCLUDED_
#define _NGX_HTTP_WAF_UA_ENUMS_H_INCLUDED_


/* Descriptive browser family -- values are stable string-table indices. */
typedef enum {
    WAF_BROWSER_UNKNOWN = 0,
    WAF_BROWSER_MSIE, WAF_BROWSER_EDGE, WAF_BROWSER_FIREFOX, WAF_BROWSER_CHROME,
    WAF_BROWSER_YABROWSER, WAF_BROWSER_SAFARI, WAF_BROWSER_SAMSUNG,
    WAF_BROWSER_XIAOMIBROWSER, WAF_BROWSER_OPERA, WAF_BROWSER_SLEIPNIR,
    WAF_BROWSER_VIVALDI, WAF_BROWSER_ANDROIDBROWSER, WAF_BROWSER_SILK,
    WAF_BROWSER_CURL, WAF_BROWSER_WGET, WAF_BROWSER_FFMPEG,
    WAF_BROWSER_APPLECOREMEDIA, WAF_BROWSER_LIBMPV,
    /* 2026 additions */
    WAF_BROWSER_DUCKDUCKGO, WAF_BROWSER_WHALE, WAF_BROWSER_UCBROWSER,
    WAF_BROWSER_HUAWEIBROWSER, WAF_BROWSER_OPERAGX,
    WAF_BROWSER_HEADLESSCHROME, WAF_BROWSER_PYTHON, WAF_BROWSER_GOHTTP,
    WAF_BROWSER_JAVA, WAF_BROWSER_OKHTTP,
    WAF_BROWSER_MAX
} ngx_http_waf_ua_browser_e;


typedef enum {
    WAF_OS_UNKNOWN = 0,
    WAF_OS_WINDOWS, WAF_OS_IPHONE, WAF_OS_IPAD, WAF_OS_IPOD, WAF_OS_MACOS,
    WAF_OS_ANDROID, WAF_OS_LINUX, WAF_OS_BSD, WAF_OS_CROS,
    WAF_OS_XBOX360, WAF_OS_XBOXONE, WAF_OS_PSP, WAF_OS_PSVITA,
    WAF_OS_PS3, WAF_OS_PS4, WAF_OS_PS5,
    WAF_OS_NINTENDO3DS, WAF_OS_NINTENDODSI, WAF_OS_NINTENDOWII, WAF_OS_NINTENDOWIIU,
    WAF_OS_INETTV, WAF_OS_BLACKBERRY10, WAF_OS_BLACKBERRY,
    WAF_OS_WATCHOS, WAF_OS_WEBOS, WAF_OS_WPHONE,
    WAF_OS_HARMONYOS,  /* 2026 addition -- match BEFORE the android fallback */
    WAF_OS_MAX
} ngx_http_waf_ua_os_e;


/* Device class; the bot-class values mirror ngx_http_waf_ua_e and are taken
 * over from ctx->ua when it is a threat class. */
typedef enum {
    WAF_CAT_UNKNOWN = 0,
    WAF_CAT_MOBILE, WAF_CAT_TABLET, WAF_CAT_PC, WAF_CAT_TV, WAF_CAT_CONSOLE,
    WAF_CAT_SCANNER, WAF_CAT_AI_CRAWLER, WAF_CAT_CRAWLER, WAF_CAT_BOT,
    WAF_CAT_MAX
} ngx_http_waf_ua_category_e;


typedef enum {
    WAF_VENDOR_UNKNOWN = 0,
    WAF_VENDOR_APPLE, WAF_VENDOR_MOZILLA, WAF_VENDOR_GOOGLE, WAF_VENDOR_MS,
    WAF_VENDOR_OPERA, WAF_VENDOR_SAMSUNG, WAF_VENDOR_XIAOMI, WAF_VENDOR_MEGAINDEX,
    WAF_VENDOR_YAHOO, WAF_VENDOR_BAIDU, WAF_VENDOR_YANDEX, WAF_VENDOR_FACEBOOK,
    WAF_VENDOR_DUCKDUCKGO, WAF_VENDOR_PINTEREST, WAF_VENDOR_ALEXA, WAF_VENDOR_TWITTER,
    WAF_VENDOR_HUAWEI, WAF_VENDOR_NAVER,  /* additions */
    WAF_VENDOR_MAX
} ngx_http_waf_ua_vendor_e;


/* Coarse TLS client family for JA4<->UA comparison. JA4 cannot split
 * Chromium variants, so chromium is one family. */
typedef enum {
    WAF_TLSFAM_UNKNOWN = 0,
    WAF_TLSFAM_CHROMIUM, WAF_TLSFAM_FIREFOX, WAF_TLSFAM_SAFARI,
    WAF_TLSFAM_TOOL,   /* curl, go, python, java, okhttp, wget, ... */
    WAF_TLSFAM_BOT,    /* fingerprints attributed to crawlers/automation */
    WAF_TLSFAM_MAX
} ngx_http_waf_tls_family_e;


/*
 * One entry of the JA4-fingerprint -> coarse-TLS-family table loaded from
 * lists/ja4.list ("<ja4> <family>" per line). Built once at config time into
 * a cf->pool ngx_array_t, sorted by the ja4 bytes, looked up per request via
 * bsearch (O(log n)). Read-only at runtime.
 *
 * NOTE: this struct references ngx_str_t -- the includer MUST have ngx_str_t
 * defined first (ngx_http_waf.h gets it from ngx_core.h; the parser unit test
 * defines a minimal ngx_str_t in its shim before including this header).
 */
typedef struct {
    ngx_str_t                  ja4;     /* 36-char fingerprint (config pool) */
    ngx_http_waf_tls_family_e  family;  /* coarse family it maps to          */
} ngx_http_waf_ja4_entry_t;


#endif /* _NGX_HTTP_WAF_UA_ENUMS_H_INCLUDED_ */
