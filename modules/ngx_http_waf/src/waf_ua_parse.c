/*
 * ngx_http_waf_module - descriptive User-Agent parser + UA<->JA4 spoof eval.
 *
 * The deterministic core (browser / os / device-category / vendor / version
 * from the raw UA bytes, plus the JA4-family bsearch and the expected-family
 * map) is nginx-free and is pulled into the standalone unit test under
 * -DWAF_UA_PARSE_UNIT_TEST -- the same isolation model as waf_ja4.c. The
 * nginx-facing wrappers (request ctx population, CIDR spoof reinforcement,
 * loc-conf table lookup) sit behind #ifndef WAF_UA_PARSE_UNIT_TEST.
 *
 * Matching is case-insensitive and bounded (waf_ua_find never reads past the
 * UA value length), 1:1 with the fixed reference oracle user-agent.lua but
 * with the Chromium-derivative tokens (Edge/OPR/YaBrowser/Samsung/Vivaldi/
 * HeadlessChrome/...) tested BEFORE the bare Chrome/ token so they are not
 * swallowed by the generic match (the dead Lua order is deliberately NOT
 * mirrored). The version is a slice INTO the UA value (never copied),
 * terminated at the first byte outside [0-9A-Za-z._-]; that charset clamp is a
 * security control -- ua_version is the only one of the five variables that
 * carries raw attacker bytes, so clamping neutralizes CR/LF/quote/control-char
 * injection into any downstream log_format / add_header sink at the source.
 */

#ifdef WAF_UA_PARSE_UNIT_TEST

/* Standalone: minimal nginx shim, no nginx/SSL headers. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>   /* memcmp */
typedef unsigned char  u_char;
typedef intptr_t       ngx_int_t;
typedef uintptr_t      ngx_uint_t;
typedef struct { size_t len; u_char *data; } ngx_str_t;
#include "ngx_http_waf_ua_enums.h"

#else

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_waf.h"
#include "waf_ua_parse.h"
#include "waf_match.h"   /* ngx_http_waf_ua_classify */

#endif


/* ===================================================================== *
 *  Static string tables (immutable; shared read-only across workers)    *
 * ===================================================================== */

#define WAF_S(s)  { sizeof(s) - 1, (u_char *) (s) }

static ngx_str_t  waf_browser_str[] = {
    WAF_S("unknown"),        /* WAF_BROWSER_UNKNOWN        */
    WAF_S("msie"),           /* WAF_BROWSER_MSIE           */
    WAF_S("edge"),           /* WAF_BROWSER_EDGE           */
    WAF_S("firefox"),        /* WAF_BROWSER_FIREFOX        */
    WAF_S("chrome"),         /* WAF_BROWSER_CHROME         */
    WAF_S("yabrowser"),      /* WAF_BROWSER_YABROWSER      */
    WAF_S("safari"),         /* WAF_BROWSER_SAFARI         */
    WAF_S("samsung"),        /* WAF_BROWSER_SAMSUNG        */
    WAF_S("xiaomibrowser"),  /* WAF_BROWSER_XIAOMIBROWSER  */
    WAF_S("opera"),          /* WAF_BROWSER_OPERA          */
    WAF_S("sleipnir"),       /* WAF_BROWSER_SLEIPNIR       */
    WAF_S("vivaldi"),        /* WAF_BROWSER_VIVALDI        */
    WAF_S("androidbrowser"), /* WAF_BROWSER_ANDROIDBROWSER */
    WAF_S("silk"),           /* WAF_BROWSER_SILK           */
    WAF_S("curl"),           /* WAF_BROWSER_CURL           */
    WAF_S("wget"),           /* WAF_BROWSER_WGET           */
    WAF_S("ffmpeg"),         /* WAF_BROWSER_FFMPEG         */
    WAF_S("applecoremedia"), /* WAF_BROWSER_APPLECOREMEDIA */
    WAF_S("libmpv"),         /* WAF_BROWSER_LIBMPV         */
    WAF_S("duckduckgo"),     /* WAF_BROWSER_DUCKDUCKGO     */
    WAF_S("whale"),          /* WAF_BROWSER_WHALE          */
    WAF_S("ucbrowser"),      /* WAF_BROWSER_UCBROWSER      */
    WAF_S("huaweibrowser"),  /* WAF_BROWSER_HUAWEIBROWSER  */
    WAF_S("operagx"),        /* WAF_BROWSER_OPERAGX        */
    WAF_S("headlesschrome"), /* WAF_BROWSER_HEADLESSCHROME */
    WAF_S("python"),         /* WAF_BROWSER_PYTHON         */
    WAF_S("gohttp"),         /* WAF_BROWSER_GOHTTP         */
    WAF_S("java"),           /* WAF_BROWSER_JAVA           */
    WAF_S("okhttp"),         /* WAF_BROWSER_OKHTTP         */
};

static ngx_str_t  waf_category_str[] = {
    WAF_S("unknown"),     /* WAF_CAT_UNKNOWN    */
    WAF_S("mobile"),      /* WAF_CAT_MOBILE     */
    WAF_S("tablet"),      /* WAF_CAT_TABLET     */
    WAF_S("pc"),          /* WAF_CAT_PC         */
    WAF_S("tv"),          /* WAF_CAT_TV         */
    WAF_S("console"),     /* WAF_CAT_CONSOLE    */
    WAF_S("scanner"),     /* WAF_CAT_SCANNER    */
    WAF_S("ai-crawler"),  /* WAF_CAT_AI_CRAWLER */
    WAF_S("crawler"),     /* WAF_CAT_CRAWLER    */
    WAF_S("bot"),         /* WAF_CAT_BOT        */
};

static ngx_str_t  waf_vendor_str[] = {
    WAF_S("unknown"),     /* WAF_VENDOR_UNKNOWN    */
    WAF_S("apple"),       /* WAF_VENDOR_APPLE      */
    WAF_S("mozilla"),     /* WAF_VENDOR_MOZILLA    */
    WAF_S("google"),      /* WAF_VENDOR_GOOGLE     */
    WAF_S("microsoft"),   /* WAF_VENDOR_MS         */
    WAF_S("opera"),       /* WAF_VENDOR_OPERA      */
    WAF_S("samsung"),     /* WAF_VENDOR_SAMSUNG    */
    WAF_S("xiaomi"),      /* WAF_VENDOR_XIAOMI     */
    WAF_S("megaindex"),   /* WAF_VENDOR_MEGAINDEX  */
    WAF_S("yahoo"),       /* WAF_VENDOR_YAHOO      */
    WAF_S("baidu"),       /* WAF_VENDOR_BAIDU      */
    WAF_S("yandex"),      /* WAF_VENDOR_YANDEX     */
    WAF_S("facebook"),    /* WAF_VENDOR_FACEBOOK   */
    WAF_S("duckduckgo"),  /* WAF_VENDOR_DUCKDUCKGO */
    WAF_S("pinterest"),   /* WAF_VENDOR_PINTEREST  */
    WAF_S("alexa"),       /* WAF_VENDOR_ALEXA      */
    WAF_S("twitter"),     /* WAF_VENDOR_TWITTER    */
    WAF_S("huawei"),      /* WAF_VENDOR_HUAWEI     */
    WAF_S("naver"),       /* WAF_VENDOR_NAVER      */
};


/* ===================================================================== *
 *  Bounded, case-insensitive substring search (the only scan primitive) *
 * ===================================================================== */

/*
 * Find needle (nlen bytes) inside hay (hlen bytes), ASCII-case-insensitive.
 * Returns a pointer into hay at the match start, or NULL. Never reads past
 * hay + hlen -- safe on non-NUL-terminated buffers and on binary/oversized
 * UA values.
 */
static const u_char *
waf_ua_find(const u_char *hay, size_t hlen, const char *needle, size_t nlen)
{
    size_t  i, j, last;
    u_char  a, b;

    if (nlen == 0 || nlen > hlen) {
        return NULL;
    }

    last = hlen - nlen;

    for (i = 0; i <= last; i++) {
        for (j = 0; j < nlen; j++) {
            a = hay[i + j];
            b = (u_char) needle[j];
            if (a >= 'A' && a <= 'Z') { a = (u_char) (a | 0x20); }
            if (b >= 'A' && b <= 'Z') { b = (u_char) (b | 0x20); }
            if (a != b) { break; }
        }
        if (j == nlen) {
            return hay + i;
        }
    }

    return NULL;
}

#define WAF_HAS(h, hl, lit)  (waf_ua_find((h), (hl), (lit), sizeof(lit) - 1) != NULL)


/*
 * Slice the version token immediately following `token` in the UA. Sets
 * *vstart and *vlen to a slice INTO hay, bounded by hay+hlen and terminated at
 * the first byte outside the conservative version charset [0-9A-Za-z._-].
 * If the token is absent, or the byte right after it is out of charset,
 * *vlen is 0 (the getter then reports the version as not_found).
 */
static void
waf_ua_version(const u_char *hay, size_t hlen, const char *token, size_t tlen,
    const u_char **vstart, size_t *vlen)
{
    const u_char  *p, *s, *q, *end;
    u_char         c;

    *vstart = NULL;
    *vlen = 0;

    p = waf_ua_find(hay, hlen, token, tlen);
    if (p == NULL) {
        return;
    }

    s = p + tlen;
    end = hay + hlen;

    for (q = s; q < end; q++) {
        c = *q;
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')
              || (c >= 'A' && c <= 'Z') || c == '.' || c == '_' || c == '-'))
        {
            break;
        }
    }

    *vstart = s;
    *vlen = (size_t) (q - s);
}

#define WAF_VER(h, hl, lit, vs, vl) \
    waf_ua_version((h), (hl), (lit), sizeof(lit) - 1, (vs), (vl))


/* ===================================================================== *
 *  Operating system detection (try_os)                                  *
 * ===================================================================== */

static ngx_http_waf_ua_os_e
waf_ua_try_os(const u_char *ua, size_t n)
{
    /* 2026: HarmonyOS rides on a "Linux; Android"-shaped UA -- match first so
     * the Android fallback does not win. */
    if (WAF_HAS(ua, n, "HarmonyOS")) { return WAF_OS_HARMONYOS; }

    if (WAF_HAS(ua, n, "Windows")) {
        /* more-specific console string before the bare "Xbox" token */
        if (WAF_HAS(ua, n, "Xbox; Xbox One)")) { return WAF_OS_XBOXONE; }
        if (WAF_HAS(ua, n, "Xbox"))            { return WAF_OS_XBOX360; }
        return WAF_OS_WINDOWS;
    }

    if (WAF_HAS(ua, n, "Mac OS X") || WAF_HAS(ua, n, "Darwin")
        || WAF_HAS(ua, n, "-iOS/"))
    {
        if (WAF_HAS(ua, n, "like Mac OS X") || WAF_HAS(ua, n, "iPhone")) {
            return WAF_OS_IPHONE;
        }
        if (WAF_HAS(ua, n, "CFNetwork")) { return WAF_OS_IPHONE; }
        if (WAF_HAS(ua, n, "iPad;"))     { return WAF_OS_IPAD; }
        if (WAF_HAS(ua, n, "iPod"))      { return WAF_OS_IPOD; }
        return WAF_OS_MACOS;
    }

    if (WAF_HAS(ua, n, "Watch")) { return WAF_OS_WATCHOS; }

    if (WAF_HAS(ua, n, "Linux")) {
        if (WAF_HAS(ua, n, "Windows Phone")) { return WAF_OS_WPHONE; }
        if (WAF_HAS(ua, n, "Android"))       { return WAF_OS_ANDROID; }
        if (WAF_HAS(ua, n, "Web0S;") || WAF_HAS(ua, n, "webOS/")) {
            return WAF_OS_WEBOS;
        }
        return WAF_OS_LINUX;
    }

    if (WAF_HAS(ua, n, "X11; FreeBSD "))                 { return WAF_OS_BSD; }
    if (WAF_HAS(ua, n, "PSP (PlayStation Portable);"))   { return WAF_OS_PSP; }
    if (WAF_HAS(ua, n, "PlayStation Vita"))              { return WAF_OS_PSVITA; }
    if (WAF_HAS(ua, n, "PLAYSTATION 3 ")
        || WAF_HAS(ua, n, "PLAYSTATION 3;"))             { return WAF_OS_PS3; }
    if (WAF_HAS(ua, n, "PlayStation 4 "))                { return WAF_OS_PS4; }
    if (WAF_HAS(ua, n, "PlayStation 5 "))                { return WAF_OS_PS5; }
    if (WAF_HAS(ua, n, "Nintendo 3DS;"))                 { return WAF_OS_NINTENDO3DS; }
    if (WAF_HAS(ua, n, "Nintendo DSi;"))                 { return WAF_OS_NINTENDODSI; }
    if (WAF_HAS(ua, n, "Nintendo Wii;"))                 { return WAF_OS_NINTENDOWII; }
    if (WAF_HAS(ua, n, "(Nintendo WiiU)"))               { return WAF_OS_NINTENDOWIIU; }
    if (WAF_HAS(ua, n, "InettvBrowser/"))                { return WAF_OS_INETTV; }
    if (WAF_HAS(ua, n, "X11; CrOS "))                    { return WAF_OS_CROS; }
    if (WAF_HAS(ua, n, "(Win98;"))                       { return WAF_OS_WINDOWS; }
    if (WAF_HAS(ua, n, "Macintosh; U; PPC;"))            { return WAF_OS_MACOS; }
    if (WAF_HAS(ua, n, "Mac_PowerPC"))                   { return WAF_OS_MACOS; }
    if (WAF_HAS(ua, n, "BB10"))                          { return WAF_OS_BLACKBERRY10; }
    if (WAF_HAS(ua, n, "BlackBerry"))                    { return WAF_OS_BLACKBERRY; }

    return WAF_OS_UNKNOWN;
}


/* ===================================================================== *
 *  Browser detection (try_browser) + version slice                      *
 * ===================================================================== */

/*
 * Ordering note: every Chromium-derivative below carries the bare "Chrome/"
 * token, so each is tested BEFORE the generic Chrome/ branch. HeadlessChrome/
 * literally ends in "Chrome/", so it too is tested first. Brave and Arc ship a
 * Chrome-identical UA by design and are therefore reported as `chrome` -- do
 * NOT add a Brave/Arc matcher, it cannot fire from the UA alone.
 */
static ngx_http_waf_ua_browser_e
waf_ua_try_browser(const u_char *ua, size_t n, ngx_http_waf_ua_os_e os,
    const u_char **vs, size_t *vl)
{
    *vs = NULL;
    *vl = 0;

    /* --- Internet Explorer ------------------------------------------- */
    if (WAF_HAS(ua, n, "compatible; MSIE")) { return WAF_BROWSER_MSIE; }
    if (WAF_HAS(ua, n, "Trident/"))  { WAF_VER(ua, n, "Trident/", vs, vl);  return WAF_BROWSER_MSIE; }
    if (WAF_HAS(ua, n, "IEMobile/")) { WAF_VER(ua, n, "IEMobile/", vs, vl); return WAF_BROWSER_MSIE; }

    /* --- Edge (Chromium + legacy + mobile) --------------------------- */
    if (WAF_HAS(ua, n, "Edge/"))    { WAF_VER(ua, n, "Edge/", vs, vl);    return WAF_BROWSER_EDGE; }
    if (WAF_HAS(ua, n, "Edg/"))     { WAF_VER(ua, n, "Edg/", vs, vl);     return WAF_BROWSER_EDGE; }
    if (WAF_HAS(ua, n, "EdgA/"))    { WAF_VER(ua, n, "EdgA/", vs, vl);    return WAF_BROWSER_EDGE; }
    if (WAF_HAS(ua, n, "EdgiOS/"))  { WAF_VER(ua, n, "EdgiOS/", vs, vl);  return WAF_BROWSER_EDGE; }

    /* --- brand tokens that ride on Chrome/ / AppleWebKit ------------- */
    if (WAF_HAS(ua, n, "DuckDuckGo/")) { WAF_VER(ua, n, "DuckDuckGo/", vs, vl); return WAF_BROWSER_DUCKDUCKGO; }
    if (WAF_HAS(ua, n, "Ddg/"))        { WAF_VER(ua, n, "Ddg/", vs, vl);        return WAF_BROWSER_DUCKDUCKGO; }
    if (WAF_HAS(ua, n, "OPRGX/"))      { WAF_VER(ua, n, "OPRGX/", vs, vl);      return WAF_BROWSER_OPERAGX; }
    if (WAF_HAS(ua, n, "OPR/"))        { WAF_VER(ua, n, "OPR/", vs, vl);        return WAF_BROWSER_OPERA; }
    if (WAF_HAS(ua, n, "SamsungBrowser/"))     { WAF_VER(ua, n, "SamsungBrowser/", vs, vl);     return WAF_BROWSER_SAMSUNG; }
    if (WAF_HAS(ua, n, "YaBrowser/"))          { WAF_VER(ua, n, "YaBrowser/", vs, vl);          return WAF_BROWSER_YABROWSER; }
    if (WAF_HAS(ua, n, "XiaoMi/MiuiBrowser/")) { WAF_VER(ua, n, "XiaoMi/MiuiBrowser/", vs, vl); return WAF_BROWSER_XIAOMIBROWSER; }
    if (WAF_HAS(ua, n, "Vivaldi/"))            { WAF_VER(ua, n, "Vivaldi/", vs, vl);            return WAF_BROWSER_VIVALDI; }
    if (WAF_HAS(ua, n, "HuaweiBrowser/"))      { WAF_VER(ua, n, "HuaweiBrowser/", vs, vl);      return WAF_BROWSER_HUAWEIBROWSER; }
    if (WAF_HAS(ua, n, "UCBrowser/"))          { WAF_VER(ua, n, "UCBrowser/", vs, vl);          return WAF_BROWSER_UCBROWSER; }
    if (WAF_HAS(ua, n, "Whale/"))              { WAF_VER(ua, n, "Whale/", vs, vl);              return WAF_BROWSER_WHALE; }
    if (WAF_HAS(ua, n, "Sleipnir/"))           { WAF_VER(ua, n, "Sleipnir/", vs, vl);           return WAF_BROWSER_SLEIPNIR; }

    /* --- Firefox ----------------------------------------------------- */
    if (WAF_HAS(ua, n, "Firefox/")) { WAF_VER(ua, n, "Firefox/", vs, vl); return WAF_BROWSER_FIREFOX; }
    if (WAF_HAS(ua, n, "FxiOS/"))   { WAF_VER(ua, n, "FxiOS/", vs, vl);   return WAF_BROWSER_FIREFOX; }

    /* --- Chrome family (derivatives already excluded above) ---------- */
    if (WAF_HAS(ua, n, "Chrome") && WAF_HAS(ua, n, "wv")) { return WAF_BROWSER_CHROME; } /* webview */
    if (WAF_HAS(ua, n, "Silk/"))          { WAF_VER(ua, n, "Silk/", vs, vl);          return WAF_BROWSER_SILK; }
    if (WAF_HAS(ua, n, "HeadlessChrome/")) { WAF_VER(ua, n, "HeadlessChrome/", vs, vl); return WAF_BROWSER_HEADLESSCHROME; }
    if (WAF_HAS(ua, n, "CriOS/"))         { WAF_VER(ua, n, "CriOS/", vs, vl);         return WAF_BROWSER_CHROME; }
    if (WAF_HAS(ua, n, "Chrome/"))        { WAF_VER(ua, n, "Chrome/", vs, vl);        return WAF_BROWSER_CHROME; }

    /* --- WebKit / Safari (android variant -> androidbrowser) --------- */
    if (WAF_HAS(ua, n, "Outlook-iOS/")) {
        WAF_VER(ua, n, "Outlook-iOS/", vs, vl);
        return (os == WAF_OS_ANDROID) ? WAF_BROWSER_ANDROIDBROWSER : WAF_BROWSER_SAFARI;
    }
    if (WAF_HAS(ua, n, "AppleWebKit/")) {
        WAF_VER(ua, n, "Safari/", vs, vl);
        return (os == WAF_OS_ANDROID) ? WAF_BROWSER_ANDROIDBROWSER : WAF_BROWSER_SAFARI;
    }
    if (WAF_HAS(ua, n, "WeatherReport/")) {
        WAF_VER(ua, n, "WeatherReport/", vs, vl);
        return (os == WAF_OS_ANDROID) ? WAF_BROWSER_ANDROIDBROWSER : WAF_BROWSER_SAFARI;
    }
    if (WAF_HAS(ua, n, "Safari/")) {
        WAF_VER(ua, n, "Safari/", vs, vl);
        return (os == WAF_OS_ANDROID) ? WAF_BROWSER_ANDROIDBROWSER : WAF_BROWSER_SAFARI;
    }

    /* --- Opera (Presto-era + bare) ----------------------------------- */
    if (WAF_HAS(ua, n, "Presto/")) { WAF_VER(ua, n, "Presto/", vs, vl); return WAF_BROWSER_OPERA; }
    if (WAF_HAS(ua, n, "Opera/"))  { WAF_VER(ua, n, "Opera/", vs, vl);  return WAF_BROWSER_OPERA; }
    if (WAF_HAS(ua, n, "Opera"))   { return WAF_BROWSER_OPERA; }

    /* --- non-browser clients / tools --------------------------------- */
    if (WAF_HAS(ua, n, "curl/"))          { WAF_VER(ua, n, "curl/", vs, vl);          return WAF_BROWSER_CURL; }
    if (WAF_HAS(ua, n, "libmpv"))         { WAF_VER(ua, n, "libmpv", vs, vl);         return WAF_BROWSER_LIBMPV; }
    if (WAF_HAS(ua, n, "Wget/"))          { WAF_VER(ua, n, "Wget/", vs, vl);          return WAF_BROWSER_WGET; }
    if (WAF_HAS(ua, n, "Lavf/"))          { WAF_VER(ua, n, "Lavf/", vs, vl);          return WAF_BROWSER_FFMPEG; }
    if (WAF_HAS(ua, n, "AppleCoreMedia/")) { WAF_VER(ua, n, "AppleCoreMedia/", vs, vl); return WAF_BROWSER_APPLECOREMEDIA; }
    if (WAF_HAS(ua, n, "Dalvik/"))        { WAF_VER(ua, n, "Dalvik/", vs, vl);        return WAF_BROWSER_ANDROIDBROWSER; }

    /* --- 2026 HTTP libraries (also threat-classified; still ID'd) ---- */
    if (WAF_HAS(ua, n, "python-requests/")) { WAF_VER(ua, n, "python-requests/", vs, vl); return WAF_BROWSER_PYTHON; }
    if (WAF_HAS(ua, n, "python-httpx/"))    { WAF_VER(ua, n, "python-httpx/", vs, vl);    return WAF_BROWSER_PYTHON; }
    if (WAF_HAS(ua, n, "Python-urllib/"))   { WAF_VER(ua, n, "Python-urllib/", vs, vl);   return WAF_BROWSER_PYTHON; }
    if (WAF_HAS(ua, n, "aiohttp/"))         { WAF_VER(ua, n, "aiohttp/", vs, vl);         return WAF_BROWSER_PYTHON; }
    if (WAF_HAS(ua, n, "Go-http-client/"))  { WAF_VER(ua, n, "Go-http-client/", vs, vl);  return WAF_BROWSER_GOHTTP; }
    if (WAF_HAS(ua, n, "Java/"))            { WAF_VER(ua, n, "Java/", vs, vl);            return WAF_BROWSER_JAVA; }
    if (WAF_HAS(ua, n, "okhttp/"))          { WAF_VER(ua, n, "okhttp/", vs, vl);          return WAF_BROWSER_OKHTTP; }

    return WAF_BROWSER_UNKNOWN;
}


/* ===================================================================== *
 *  Device category (try_device) -- device classes only; threat classes  *
 *  are layered on top from ctx->ua by the nginx wrapper.                 *
 * ===================================================================== */

static ngx_http_waf_ua_category_e
waf_ua_try_device(const u_char *ua, size_t n, ngx_http_waf_ua_os_e os,
    ngx_http_waf_ua_browser_e browser)
{
    /* os-driven device class */
    switch (os) {
    case WAF_OS_IPHONE: case WAF_OS_IPOD: case WAF_OS_ANDROID:
    case WAF_OS_BLACKBERRY10: case WAF_OS_BLACKBERRY: case WAF_OS_WPHONE:
    case WAF_OS_WATCHOS: case WAF_OS_HARMONYOS:
        return WAF_CAT_MOBILE;
    case WAF_OS_IPAD:
        return WAF_CAT_TABLET;
    case WAF_OS_WEBOS:
        return WAF_CAT_TV;
    case WAF_OS_XBOX360: case WAF_OS_XBOXONE: case WAF_OS_PSP:
    case WAF_OS_PSVITA: case WAF_OS_PS3: case WAF_OS_PS4: case WAF_OS_PS5:
    case WAF_OS_NINTENDO3DS: case WAF_OS_NINTENDODSI: case WAF_OS_NINTENDOWII:
    case WAF_OS_NINTENDOWIIU: case WAF_OS_INETTV:
        return WAF_CAT_CONSOLE;
    case WAF_OS_WINDOWS: case WAF_OS_MACOS: case WAF_OS_LINUX:
    case WAF_OS_BSD: case WAF_OS_CROS:
        return WAF_CAT_PC;
    default:
        break;
    }

    /* browser-driven device class */
    if (browser == WAF_BROWSER_SILK) { return WAF_CAT_TABLET; }

    /* substring fallbacks (1:1 with the Lua oracle) */
    if (WAF_HAS(ua, n, "Table OS") || WAF_HAS(ua, n, "SAMSUNG SM-T")
        || WAF_HAS(ua, n, "; SM-T"))
    {
        return WAF_CAT_TABLET;
    }

    if (WAF_HAS(ua, n, "KDDI-") || WAF_HAS(ua, n, "WILLCOM")
        || WAF_HAS(ua, n, "DDIPOCKET") || WAF_HAS(ua, n, "SymbianOS")
        || WAF_HAS(ua, n, "Hatena-Mobile-Gateway/")
        || WAF_HAS(ua, n, "livedoor-Mobile-Gateway/")
        || WAF_HAS(ua, n, "Google Wireless Transcoder")
        || WAF_HAS(ua, n, "Naver Transcoder") || WAF_HAS(ua, n, "jig browser")
        || WAF_HAS(ua, n, "emobile/") || WAF_HAS(ua, n, "OpenBrowser")
        || WAF_HAS(ua, n, "Browser/Obigo-Browser") || WAF_HAS(ua, n, "SoftBank")
        || WAF_HAS(ua, n, "Vodafone") || WAF_HAS(ua, n, "Nokia")
        || WAF_HAS(ua, n, "J-PHONE") || WAF_HAS(ua, n, "DoCoMo")
        || WAF_HAS(ua, n, ";FOMA;"))
    {
        return WAF_CAT_MOBILE;
    }

    if (WAF_HAS(ua, n, "Nintendo DSi;") || WAF_HAS(ua, n, "Nintendo Wii;")) {
        return WAF_CAT_CONSOLE;
    }

    return WAF_CAT_UNKNOWN;
}


/* ===================================================================== *
 *  Vendor attribution (try_vendor)                                      *
 * ===================================================================== */

static ngx_http_waf_ua_vendor_e
waf_ua_try_vendor(const u_char *ua, size_t n, ngx_http_waf_ua_os_e os,
    ngx_http_waf_ua_browser_e browser)
{
    /* browser-driven vendor (ipad INCLUDED -- the fixed oracle bug) */
    if (browser == WAF_BROWSER_SAFARI
        && (os == WAF_OS_IPHONE || os == WAF_OS_IPAD || os == WAF_OS_IPOD
            || os == WAF_OS_MACOS))
    {
        if (WAF_HAS(ua, n, "FBNV/")) { return WAF_VENDOR_FACEBOOK; }
        return WAF_VENDOR_APPLE;
    }

    switch (browser) {
    case WAF_BROWSER_SAMSUNG:        return WAF_VENDOR_SAMSUNG;
    case WAF_BROWSER_YABROWSER:      return WAF_VENDOR_YANDEX;
    case WAF_BROWSER_XIAOMIBROWSER:  return WAF_VENDOR_XIAOMI;
    case WAF_BROWSER_OPERA:
    case WAF_BROWSER_OPERAGX:        return WAF_VENDOR_OPERA;
    case WAF_BROWSER_EDGE:           return WAF_VENDOR_MS;
    case WAF_BROWSER_FIREFOX:        return WAF_VENDOR_MOZILLA;
    case WAF_BROWSER_CHROME:
    case WAF_BROWSER_ANDROIDBROWSER:
    case WAF_BROWSER_HEADLESSCHROME: return WAF_VENDOR_GOOGLE;
    case WAF_BROWSER_MSIE:           return WAF_VENDOR_MS;
    case WAF_BROWSER_DUCKDUCKGO:     return WAF_VENDOR_DUCKDUCKGO;
    case WAF_BROWSER_WHALE:          return WAF_VENDOR_NAVER;
    case WAF_BROWSER_HUAWEIBROWSER:  return WAF_VENDOR_HUAWEI;
    default:                         break;
    }

    if (os == WAF_OS_HARMONYOS)                       { return WAF_VENDOR_HUAWEI; }
    if (os == WAF_OS_XBOXONE || os == WAF_OS_XBOX360) { return WAF_VENDOR_MS; }
    if (WAF_HAS(ua, n, "AppleCoreMedia"))             { return WAF_VENDOR_APPLE; }

    /* crawler-vendor attribution fallback (substrings are crawler-specific) */
    if (WAF_HAS(ua, n, "Google"))                { return WAF_VENDOR_GOOGLE; }
    if (WAF_HAS(ua, n, "Applebot/"))             { return WAF_VENDOR_APPLE; }
    if (WAF_HAS(ua, n, "bingbot/")
        || WAF_HAS(ua, n, "BingPreview/")
        || WAF_HAS(ua, n, "msnbot/"))            { return WAF_VENDOR_MS; }
    if (WAF_HAS(ua, n, "DuckDuckGo"))            { return WAF_VENDOR_DUCKDUCKGO; }
    if (WAF_HAS(ua, n, "Pinterestbot/"))         { return WAF_VENDOR_PINTEREST; }
    if (WAF_HAS(ua, n, "Alexabot/")
        || WAF_HAS(ua, n, "alexa.com"))          { return WAF_VENDOR_ALEXA; }
    if (WAF_HAS(ua, n, "facebookexternalhit/"))  { return WAF_VENDOR_FACEBOOK; }
    if (WAF_HAS(ua, n, "Yahoo"))                 { return WAF_VENDOR_YAHOO; }
    if (WAF_HAS(ua, n, "MegaIndex.ru/"))         { return WAF_VENDOR_MEGAINDEX; }
    if (WAF_HAS(ua, n, "Baiduspider"))           { return WAF_VENDOR_BAIDU; }
    if (WAF_HAS(ua, n, "Twitterbot/"))           { return WAF_VENDOR_TWITTER; }
    if (WAF_HAS(ua, n, "PanguBot"))              { return WAF_VENDOR_HUAWEI; }
    if (WAF_HAS(ua, n, "Yandex"))                { return WAF_VENDOR_YANDEX; }

    return WAF_VENDOR_UNKNOWN;
}


/* ===================================================================== *
 *  Deterministic core orchestrator (nginx-free, unit-tested directly)   *
 * ===================================================================== */

/*
 * Parse the raw UA bytes into the descriptive fields. device_cat is the pure
 * device class (mobile/tablet/pc/tv/console/unknown); the threat-class
 * override (scanner/ai-crawler/crawler/bot) is applied by the nginx wrapper
 * from ctx->ua. The *vstart and *vlen out-params slice INTO ua (never copied), vlen 0 when
 * no version is present.
 */
static void
waf_ua_parse_core(const u_char *ua, size_t n,
    ngx_http_waf_ua_browser_e *browser, ngx_http_waf_ua_os_e *os,
    ngx_http_waf_ua_category_e *device_cat, ngx_http_waf_ua_vendor_e *vendor,
    const u_char **vstart, size_t *vlen)
{
    ngx_http_waf_ua_os_e       o;
    ngx_http_waf_ua_browser_e  b;

    o = waf_ua_try_os(ua, n);
    b = waf_ua_try_browser(ua, n, o, vstart, vlen);

    *os = o;
    *browser = b;
    *device_cat = waf_ua_try_device(ua, n, o, b);
    *vendor = waf_ua_try_vendor(ua, n, o, b);
}


/* ===================================================================== *
 *  JA4 coarse-family helpers (core + table lookup)                      *
 * ===================================================================== */

/* Map a parsed UA browser to the coarse TLS family it should present. Only
 * browsers with a reliably-known TLS family are mapped; ambiguous / regional /
 * legacy clients return UNKNOWN so they can never produce a false-positive
 * spoof signal. */
ngx_http_waf_tls_family_e
ngx_http_waf_ua_expected_tls_family(ngx_http_waf_ua_browser_e b)
{
    switch (b) {
    case WAF_BROWSER_CHROME:
    case WAF_BROWSER_HEADLESSCHROME:
    case WAF_BROWSER_EDGE:
    case WAF_BROWSER_YABROWSER:
    case WAF_BROWSER_SAMSUNG:
    case WAF_BROWSER_OPERA:
    case WAF_BROWSER_OPERAGX:
    case WAF_BROWSER_VIVALDI:
        return WAF_TLSFAM_CHROMIUM;
    case WAF_BROWSER_FIREFOX:
        return WAF_TLSFAM_FIREFOX;
    case WAF_BROWSER_SAFARI:
        return WAF_TLSFAM_SAFARI;
    case WAF_BROWSER_CURL:
    case WAF_BROWSER_WGET:
    case WAF_BROWSER_FFMPEG:
    case WAF_BROWSER_LIBMPV:
    case WAF_BROWSER_APPLECOREMEDIA:
    case WAF_BROWSER_PYTHON:
    case WAF_BROWSER_GOHTTP:
    case WAF_BROWSER_JAVA:
    case WAF_BROWSER_OKHTTP:
        return WAF_TLSFAM_TOOL;
    default:
        return WAF_TLSFAM_UNKNOWN;
    }
}


/*
 * bsearch the sorted JA4 table (ascending by ja4 bytes) for `ja4`/`len`.
 * Returns the coarse family, or WAF_TLSFAM_UNKNOWN when absent. The table is
 * built + sorted at config time by ngx_http_waf_ja4_list_compile (waf_match.c).
 */
static ngx_http_waf_tls_family_e
waf_ja4_family_lookup(const ngx_http_waf_ja4_entry_t *entries, ngx_uint_t n,
    const u_char *ja4, size_t len)
{
    ngx_int_t  lo, hi, mid, cmp;
    size_t     m;

    if (entries == NULL || n == 0 || ja4 == NULL || len == 0) {
        return WAF_TLSFAM_UNKNOWN;
    }

    lo = 0;
    hi = (ngx_int_t) n - 1;

    while (lo <= hi) {
        mid = lo + (hi - lo) / 2;

        m = entries[mid].ja4.len < len ? entries[mid].ja4.len : len;
        cmp = (m == 0) ? 0
                       : (ngx_int_t) memcmp(entries[mid].ja4.data, ja4, m);
        if (cmp == 0) {
            if (entries[mid].ja4.len < len)      { cmp = -1; }
            else if (entries[mid].ja4.len > len) { cmp = 1; }
        }

        if (cmp == 0) {
            return entries[mid].family;
        }
        if (cmp < 0) {
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }

    return WAF_TLSFAM_UNKNOWN;
}


/* ===================================================================== *
 *  Static string-table accessors                                        *
 * ===================================================================== */

ngx_str_t *
ngx_http_waf_browser_str(ngx_http_waf_ua_browser_e b)
{
    if ((ngx_uint_t) b >= WAF_BROWSER_MAX) { b = WAF_BROWSER_UNKNOWN; }
    return &waf_browser_str[b];
}

ngx_str_t *
ngx_http_waf_category_str(ngx_http_waf_ua_category_e c)
{
    if ((ngx_uint_t) c >= WAF_CAT_MAX) { c = WAF_CAT_UNKNOWN; }
    return &waf_category_str[c];
}

ngx_str_t *
ngx_http_waf_vendor_str(ngx_http_waf_ua_vendor_e v)
{
    if ((ngx_uint_t) v >= WAF_VENDOR_MAX) { v = WAF_VENDOR_UNKNOWN; }
    return &waf_vendor_str[v];
}


#ifndef WAF_UA_PARSE_UNIT_TEST

/* ===================================================================== *
 *  nginx-facing wrappers                                                *
 * ===================================================================== */

/* Map the threat classification (ctx->ua) to the category-override label. */
static ngx_http_waf_ua_category_e
waf_ua_threat_category(ngx_http_waf_ua_e ua)
{
    switch (ua) {
    case WAF_UA_SCANNER:     return WAF_CAT_SCANNER;
    case WAF_UA_AI_CRAWLER:  return WAF_CAT_AI_CRAWLER;
    case WAF_UA_CRAWLER:     return WAF_CAT_CRAWLER;
    case WAF_UA_BOT:         return WAF_CAT_BOT;
    default:                 return WAF_CAT_UNKNOWN;
    }
}


void
ngx_http_waf_ua_parse(ngx_http_request_t *r, ngx_http_waf_loc_conf_t *wlcf,
    ngx_http_waf_ctx_t *ctx)
{
    const u_char                *vs;
    size_t                       vl, n;
    ngx_str_t                   *ua;
    ngx_http_waf_ua_category_e   threat;

    if (ctx->ua_parsed) {
        return;
    }

    /* category override needs the threat classification */
    if (!ctx->classified) {
        ngx_http_waf_ua_classify(r, wlcf, ctx);
    }

    ua = (r->headers_in.user_agent != NULL)
         ? &r->headers_in.user_agent->value : NULL;

    if (ua == NULL || ua->len == 0) {
        /* empty UA: all descriptive fields stay UNKNOWN (pcalloc default) */
        ctx->ua_browser = WAF_BROWSER_UNKNOWN;
        ctx->ua_os = WAF_OS_UNKNOWN;
        ctx->ua_vendor = WAF_VENDOR_UNKNOWN;
        ctx->ua_version.len = 0;
        ctx->ua_version.data = NULL;

        threat = waf_ua_threat_category(ctx->ua);
        ctx->ua_category = threat;   /* UNKNOWN for non-threat empty UA */
        ctx->ua_parsed = 1;
        return;
    }

    n = ua->len;
    waf_ua_parse_core(ua->data, n, &ctx->ua_browser, &ctx->ua_os,
                      &ctx->ua_category, &ctx->ua_vendor, &vs, &vl);

    ctx->ua_version.data = (u_char *) vs;
    ctx->ua_version.len = vl;

    /* threat class (if any) overrides the device class */
    threat = waf_ua_threat_category(ctx->ua);
    if (threat != WAF_CAT_UNKNOWN) {
        ctx->ua_category = threat;
    }

    ctx->ua_parsed = 1;
}


ngx_http_waf_tls_family_e
ngx_http_waf_ja4_family(ngx_http_waf_loc_conf_t *wlcf, ngx_str_t *ja4)
{
    if (wlcf->ja4_table == NULL || ja4 == NULL || ja4->len == 0) {
        return WAF_TLSFAM_UNKNOWN;
    }

    return waf_ja4_family_lookup(wlcf->ja4_table->elts, wlcf->ja4_table->nelts,
                                 ja4->data, ja4->len);
}


void
ngx_http_waf_ua_spoof_eval(ngx_http_request_t *r, ngx_http_waf_loc_conf_t *wlcf,
    ngx_http_waf_ctx_t *ctx)
{
    ngx_http_waf_tls_family_e  fam_ja4, fam_ua;
    struct sockaddr           *sa;
    ngx_uint_t                 ja4_signal, cidr_signal;

    if (ctx->spoof_evaluated) {
        return;
    }

    if (!ctx->ua_parsed) {
        ngx_http_waf_ua_parse(r, wlcf, ctx);
    }

    /* ja4_signal: TLS request whose JA4 family contradicts the UA family.
     * Both families must be known; an unknown JA4 (absent/ambiguous) or an
     * unmapped UA browser yields no signal (avoids false positives). */
    ja4_signal = 0;
    if (ctx->ja4.len > 0) {
        fam_ja4 = ngx_http_waf_ja4_family(wlcf, &ctx->ja4);
        fam_ua = ngx_http_waf_ua_expected_tls_family(ctx->ua_browser);
        if (fam_ja4 != WAF_TLSFAM_UNKNOWN && fam_ua != WAF_TLSFAM_UNKNOWN
            && fam_ja4 != fam_ua)
        {
            ja4_signal = 1;
        }
    }

    /* cidr_signal: UA claims a verified-bot class with a configured CIDR list
     * but the client IP is outside it. Same check + same XFF trust boundary
     * as the fake-bot block. NULL-fallback for client_sa: a getter on a
     * `waf off` path can run before POST_READ sets ctx->client_sa. */
    cidr_signal = 0;
    if ((ctx->ua == WAF_UA_CRAWLER || ctx->ua == WAF_UA_AI_CRAWLER)
        && wlcf->verified_bot_cidrs[ctx->ua] != NULL)
    {
        sa = (ctx->client_sa != NULL) ? ctx->client_sa : r->connection->sockaddr;
        if (ngx_cidr_match(sa, wlcf->verified_bot_cidrs[ctx->ua]) != NGX_OK) {
            cidr_signal = 1;
        }
    }

    ctx->is_spoofed = (ja4_signal || cidr_signal) ? 1 : 0;
    ctx->spoof_evaluated = 1;
}

#endif /* WAF_UA_PARSE_UNIT_TEST */
