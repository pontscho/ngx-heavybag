/*
 * Unit tests for the pure reputation verdict-precedence core
 * (ngx_http_heavybag_reputation_check, heavybag_reputation.c:16-190).
 *
 * Compiled standalone: includes heavybag_reputation.c under
 * -DHEAVYBAG_REPUTATION_UNIT_TEST so only the nginx-free decision function is
 * pulled in. The type shim in heavybag_rep.h substitutes nginx byte-for-byte
 * (NGX_* codes, ngx_str_set, an ngx_array_t mirroring struct ngx_array_s's
 * field order, an opaque ngx_cidr_t); the geo db/result structs + the base
 * scalar types come from the geo shim (heavybag_geo.h under
 * HEAVYBAG_GEO_UNIT_TEST, pulled in by the rep shim). The config-time *_add()
 * helpers in heavybag_reputation.c are gated out by the same guard -- they need
 * ngx_conf_t / mmap / ngx_ptocidr and are covered by the live nginx config
 * layer. The -Werror SSL module build stays the only correctness contract.
 *
 * The two external calls reputation_check makes -- ngx_cidr_match and
 * ngx_http_heavybag_geo_lookup -- are STUBBED here: the stub decides match /
 * geo-result per case, because this suite tests verdict PRECEDENCE, not CIDR
 * or radix-trie arithmetic (those are covered by test-geo.c + the live
 * reputation-precedence integration fuzz). Every case asserts BOTH the return
 * code AND the out->reason the verdict published.
 */

#ifndef HEAVYBAG_REPUTATION_UNIT_TEST
#define HEAVYBAG_REPUTATION_UNIT_TEST
#endif

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../../src/heavybag_reputation.c"

#define CTEST_MAIN
#include "ctest.h"


/* ---- scripted external dependencies (reputation_check's only calls) ----- */

/* geo_lookup just copies this scripted result into the caller's *res. */
static ngx_http_heavybag_geo_result_t  g_geo;

void
ngx_http_heavybag_geo_lookup(ngx_http_heavybag_geo_db_t *db,
    struct sockaddr *sa, ngx_http_heavybag_geo_result_t *res)
{
    (void) db;
    (void) sa;
    *res = g_geo;
}

/*
 * ngx_cidr_match returns NGX_OK only for the ONE cidr vector the test marked
 * as the matching list (keyed by pointer identity), so a case can make the
 * allowlist match without the blocklist matching and vice-versa.
 */
static ngx_array_t  *g_match;

ngx_int_t
ngx_cidr_match(struct sockaddr *sa, ngx_array_t *cidr)
{
    (void) sa;
    return (cidr != NULL && cidr == g_match) ? NGX_OK : NGX_DECLINED;
}


/* ---- fixtures ----------------------------------------------------------- */

#define CC16(a, b)  ((uint16_t) (((unsigned) (a) << 8) | (unsigned char) (b)))

static ngx_http_heavybag_geo_db_t  g_db;        /* dummy non-NULL geo handle  */
static ngx_array_t                 g_cidr_a;    /* stand-in allowlist vector  */
static ngx_array_t                 g_cidr_b;    /* stand-in blocklist vector  */

static void
reset(ngx_heavybag_rep_conf_t *rep, ngx_str_t *reason,
    ngx_http_heavybag_verdict_t *out)
{
    memset(rep, 0, sizeof *rep);
    memset(&g_geo, 0, sizeof g_geo);     /* found = 0 by default              */
    g_match = NULL;                      /* no CIDR matches unless armed      */
    reason->len = 0;
    reason->data = NULL;
    memset(out, 0xff, sizeof *out);      /* poison: every field must be set   */
}

static void
mk_v4(struct sockaddr_in *sin, const char *ip)
{
    memset(sin, 0, sizeof *sin);
    sin->sin_family = AF_INET;
    inet_pton(AF_INET, ip, &sin->sin_addr);
}

static void
mk_v6(struct sockaddr_in6 *s6, const char *ip)
{
    memset(s6, 0, sizeof *s6);
    s6->sin6_family = AF_INET6;
    inet_pton(AF_INET6, ip, &s6->sin6_addr);
}

/* reason->data is a NUL-terminated C literal (ngx_str_set), so compare both. */
static int
reason_is(ngx_str_t *r, const char *s)
{
    size_t  n = strlen(s);
    return r->len == n && r->data != NULL && memcmp(r->data, s, n) == 0;
}


/* ======================================================================= *
 *  B1  sa == NULL -> DECLINED, no lookup, reason NONE (heavybag_reputation.c:41) *
 * ======================================================================= */
CTEST(rep, null_sa_declined)
{
    ngx_heavybag_rep_conf_t       rep;
    ngx_str_t                     reason;
    ngx_http_heavybag_verdict_t   out;

    reset(&rep, &reason, &out);
    ASSERT_EQUAL(NGX_DECLINED,
        ngx_http_heavybag_reputation_check(&rep, NULL, &reason, &out));
    ASSERT_EQUAL(HEAVYBAG_REASON_NONE, out.reason);
    ASSERT_EQUAL_U(0, out.geo_valid);
}


/* ======================================================================= *
 *  B2  allowlist CIDR match short-circuits to allow (46-53).               *
 * ======================================================================= */
CTEST(rep, allowlist_declined)
{
    ngx_heavybag_rep_conf_t       rep;
    ngx_str_t                     reason;
    ngx_http_heavybag_verdict_t   out;
    struct sockaddr_in            sin;

    reset(&rep, &reason, &out);
    rep.allowlist = &g_cidr_a;
    g_match = &g_cidr_a;
    mk_v4(&sin, "10.0.0.1");

    ASSERT_EQUAL(NGX_DECLINED,
        ngx_http_heavybag_reputation_check(&rep, (struct sockaddr *) &sin,
                                           &reason, &out));
    ASSERT_EQUAL(HEAVYBAG_REASON_ALLOWLIST, out.reason);
    ASSERT_EQUAL_U(0, out.geo_valid);          /* short-circuit before geo */
}


/* ======================================================================= *
 *  B3  static blocklist CIDR match -> 403 (56-64).                          *
 * ======================================================================= */
CTEST(rep, blocklist_forbidden)
{
    ngx_heavybag_rep_conf_t       rep;
    ngx_str_t                     reason;
    ngx_http_heavybag_verdict_t   out;
    struct sockaddr_in            sin;

    reset(&rep, &reason, &out);
    rep.blocklist = &g_cidr_b;                 /* allowlist NULL -> not tried */
    g_match = &g_cidr_b;
    mk_v4(&sin, "203.0.113.7");

    ASSERT_EQUAL(NGX_HTTP_FORBIDDEN,
        ngx_http_heavybag_reputation_check(&rep, (struct sockaddr *) &sin,
                                           &reason, &out));
    ASSERT_EQUAL(HEAVYBAG_REASON_BLOCKLIST, out.reason);
    ASSERT_TRUE(reason_is(&reason, "static blocklist"));
}


/* ======================================================================= *
 *  B4  geo_db == NULL -> DECLINED, no lookup (67-69).                       *
 * ======================================================================= */
CTEST(rep, geo_db_null_declined)
{
    ngx_heavybag_rep_conf_t       rep;
    ngx_str_t                     reason;
    ngx_http_heavybag_verdict_t   out;
    struct sockaddr_in            sin;

    reset(&rep, &reason, &out);
    rep.geo_db = NULL;
    mk_v4(&sin, "8.8.8.8");

    ASSERT_EQUAL(NGX_DECLINED,
        ngx_http_heavybag_reputation_check(&rep, (struct sockaddr *) &sin,
                                           &reason, &out));
    ASSERT_EQUAL(HEAVYBAG_REASON_NONE, out.reason);
    ASSERT_EQUAL_U(0, out.geo_valid);          /* no lookup ran */
}


/* ======================================================================= *
 *  B5  geo miss + whitelist mode -> 404 hidden (89-101).                    *
 * ======================================================================= */
CTEST(rep, geo_miss_whitelist_not_found)
{
    ngx_heavybag_rep_conf_t       rep;
    ngx_str_t                     reason;
    ngx_http_heavybag_verdict_t   out;
    struct sockaddr_in            sin;
    uint16_t                      acc[1];
    ngx_array_t                   allow;

    reset(&rep, &reason, &out);
    rep.geo_db = &g_db;
    g_geo.found = 0;                           /* no geo record */
    acc[0] = CC16('U', 'S');
    allow.elts = acc; allow.nelts = 1;
    rep.allow_cc = &allow;
    mk_v4(&sin, "192.0.2.9");

    ASSERT_EQUAL(NGX_HTTP_NOT_FOUND,
        ngx_http_heavybag_reputation_check(&rep, (struct sockaddr *) &sin,
                                           &reason, &out));
    ASSERT_EQUAL(HEAVYBAG_REASON_GEO_WHITELIST, out.reason);
    ASSERT_EQUAL_U(1, out.geo_valid);          /* lookup ran, just missed */
    ASSERT_TRUE(reason_is(&reason, "geo not whitelisted"));
}


/* ======================================================================= *
 *  B6  geo miss + block mode (no allow_cc) -> DECLINED (102).               *
 * ======================================================================= */
CTEST(rep, geo_miss_block_declined)
{
    ngx_heavybag_rep_conf_t       rep;
    ngx_str_t                     reason;
    ngx_http_heavybag_verdict_t   out;
    struct sockaddr_in            sin;

    reset(&rep, &reason, &out);
    rep.geo_db = &g_db;
    g_geo.found = 0;
    rep.allow_cc = NULL;
    mk_v4(&sin, "192.0.2.10");

    ASSERT_EQUAL(NGX_DECLINED,
        ngx_http_heavybag_reputation_check(&rep, (struct sockaddr *) &sin,
                                           &reason, &out));
    ASSERT_EQUAL(HEAVYBAG_REASON_NONE, out.reason);
    ASSERT_EQUAL_U(1, out.geo_valid);
}


/* ======================================================================= *
 *  B7  network-flag block (flag_mask & res.flags) -> 403 (106-112), and    *
 *  the geo primitives are copied into the verdict (79-86).                 *
 * ======================================================================= */
CTEST(rep, flag_mask_forbidden)
{
    ngx_heavybag_rep_conf_t       rep;
    ngx_str_t                     reason;
    ngx_http_heavybag_verdict_t   out;
    struct sockaddr_in            sin;

    reset(&rep, &reason, &out);
    rep.geo_db = &g_db;
    g_geo.found = 1;
    g_geo.country[0] = 'U'; g_geo.country[1] = 'S';
    g_geo.flags = NGX_HTTP_HEAVYBAG_GEO_FLAG_ANYCAST;     /* 0x0004 */
    g_geo.asn = 13335;
    rep.flag_mask = NGX_HTTP_HEAVYBAG_GEO_FLAG_ANYCAST;
    mk_v4(&sin, "1.1.1.1");

    ASSERT_EQUAL(NGX_HTTP_FORBIDDEN,
        ngx_http_heavybag_reputation_check(&rep, (struct sockaddr *) &sin,
                                           &reason, &out));
    ASSERT_EQUAL(HEAVYBAG_REASON_FLAG, out.reason);
    ASSERT_TRUE(reason_is(&reason, "network flag"));
    /* write-only geo primitives published to the caller */
    ASSERT_EQUAL_U(1, out.geo_valid);
    ASSERT_EQUAL('U', out.country[0]);
    ASSERT_EQUAL('S', out.country[1]);
    ASSERT_EQUAL_U(NGX_HTTP_HEAVYBAG_GEO_FLAG_ANYCAST, out.flags);
    ASSERT_EQUAL_U(13335, out.asn);
}


/* ======================================================================= *
 *  B8  ASN block (asn != 0 and listed) -> 403 (119-131).                    *
 * ======================================================================= */
CTEST(rep, block_asn_forbidden)
{
    ngx_heavybag_rep_conf_t       rep;
    ngx_str_t                     reason;
    ngx_http_heavybag_verdict_t   out;
    struct sockaddr_in            sin;
    uint32_t                      asns[2];
    ngx_array_t                   ba;

    reset(&rep, &reason, &out);
    rep.geo_db = &g_db;
    g_geo.found = 1;
    g_geo.country[0] = 'D'; g_geo.country[1] = 'E';
    g_geo.asn = 64500;
    asns[0] = 64499; asns[1] = 64500;
    ba.elts = asns; ba.nelts = 2;
    rep.block_asn = &ba;
    mk_v4(&sin, "198.51.100.4");

    ASSERT_EQUAL(NGX_HTTP_FORBIDDEN,
        ngx_http_heavybag_reputation_check(&rep, (struct sockaddr *) &sin,
                                           &reason, &out));
    ASSERT_EQUAL(HEAVYBAG_REASON_ASN, out.reason);
    ASSERT_TRUE(reason_is(&reason, "asn"));
}


/* ======================================================================= *
 *  B8e  asn == 0 fails OPEN: block_asn set but res.asn == 0 must NOT match  *
 *  (the `res.asn != 0` guard at 119). Falls through to default DECLINED.    *
 * ======================================================================= */
CTEST(rep, block_asn_zero_fails_open)
{
    ngx_heavybag_rep_conf_t       rep;
    ngx_str_t                     reason;
    ngx_http_heavybag_verdict_t   out;
    struct sockaddr_in            sin;
    uint32_t                      asns[1];
    ngx_array_t                   ba;

    reset(&rep, &reason, &out);
    rep.geo_db = &g_db;
    g_geo.found = 1;
    g_geo.country[0] = 'D'; g_geo.country[1] = 'E';
    g_geo.asn = 0;                             /* unknown ASN */
    asns[0] = 0;                               /* even a literal 0 entry */
    ba.elts = asns; ba.nelts = 1;
    rep.block_asn = &ba;
    mk_v4(&sin, "198.51.100.5");

    ASSERT_EQUAL(NGX_DECLINED,
        ngx_http_heavybag_reputation_check(&rep, (struct sockaddr *) &sin,
                                           &reason, &out));
    ASSERT_EQUAL(HEAVYBAG_REASON_NONE, out.reason);
}


/* ======================================================================= *
 *  B9  special-CC flag list (Tor T1, no flag bit) -> 403 (141-153).         *
 * ======================================================================= */
CTEST(rep, flag_cc_forbidden)
{
    ngx_heavybag_rep_conf_t       rep;
    ngx_str_t                     reason;
    ngx_http_heavybag_verdict_t   out;
    struct sockaddr_in            sin;
    uint16_t                      fcc[1];
    ngx_array_t                   fc;

    reset(&rep, &reason, &out);
    rep.geo_db = &g_db;
    g_geo.found = 1;
    g_geo.country[0] = 'T'; g_geo.country[1] = '1';   /* Tor exit */
    g_geo.flags = 0;                                  /* no flag bit */
    fcc[0] = CC16('T', '1');
    fc.elts = fcc; fc.nelts = 1;
    rep.flag_cc = &fc;
    mk_v4(&sin, "185.220.101.1");

    ASSERT_EQUAL(NGX_HTTP_FORBIDDEN,
        ngx_http_heavybag_reputation_check(&rep, (struct sockaddr *) &sin,
                                           &reason, &out));
    ASSERT_EQUAL(HEAVYBAG_REASON_FLAG, out.reason);
    ASSERT_TRUE(reason_is(&reason, "network flag"));
}


/* ======================================================================= *
 *  B10  whitelist mode, country listed -> allow (159-166); reason stays     *
 *  NONE (the allow path returns DECLINED without touching *reason).        *
 * ======================================================================= */
CTEST(rep, allow_cc_match_declined)
{
    ngx_heavybag_rep_conf_t       rep;
    ngx_str_t                     reason;
    ngx_http_heavybag_verdict_t   out;
    struct sockaddr_in            sin;
    uint16_t                      acc[2];
    ngx_array_t                   allow;

    reset(&rep, &reason, &out);
    rep.geo_db = &g_db;
    g_geo.found = 1;
    g_geo.country[0] = 'U'; g_geo.country[1] = 'S';
    acc[0] = CC16('D', 'E'); acc[1] = CC16('U', 'S');
    allow.elts = acc; allow.nelts = 2;
    rep.allow_cc = &allow;
    mk_v4(&sin, "23.1.2.3");

    ASSERT_EQUAL(NGX_DECLINED,
        ngx_http_heavybag_reputation_check(&rep, (struct sockaddr *) &sin,
                                           &reason, &out));
    ASSERT_EQUAL(HEAVYBAG_REASON_NONE, out.reason);
}


/* ======================================================================= *
 *  B11  whitelist mode, country NOT listed -> 404 (168-172).               *
 * ======================================================================= */
CTEST(rep, allow_cc_miss_not_found)
{
    ngx_heavybag_rep_conf_t       rep;
    ngx_str_t                     reason;
    ngx_http_heavybag_verdict_t   out;
    struct sockaddr_in            sin;
    uint16_t                      acc[1];
    ngx_array_t                   allow;

    reset(&rep, &reason, &out);
    rep.geo_db = &g_db;
    g_geo.found = 1;
    g_geo.country[0] = 'D'; g_geo.country[1] = 'E';
    acc[0] = CC16('U', 'S');
    allow.elts = acc; allow.nelts = 1;
    rep.allow_cc = &allow;
    mk_v4(&sin, "5.6.7.8");

    ASSERT_EQUAL(NGX_HTTP_NOT_FOUND,
        ngx_http_heavybag_reputation_check(&rep, (struct sockaddr *) &sin,
                                           &reason, &out));
    ASSERT_EQUAL(HEAVYBAG_REASON_GEO_WHITELIST, out.reason);
    ASSERT_TRUE(reason_is(&reason, "geo not whitelisted"));
}


/* ======================================================================= *
 *  B12  block mode, country listed -> 403 (175-187).                       *
 * ======================================================================= */
CTEST(rep, block_cc_forbidden)
{
    ngx_heavybag_rep_conf_t       rep;
    ngx_str_t                     reason;
    ngx_http_heavybag_verdict_t   out;
    struct sockaddr_in            sin;
    uint16_t                      bcc[1];
    ngx_array_t                   blk;

    reset(&rep, &reason, &out);
    rep.geo_db = &g_db;
    g_geo.found = 1;
    g_geo.country[0] = 'C'; g_geo.country[1] = 'N';
    g_geo.flags = 0;
    bcc[0] = CC16('C', 'N');
    blk.elts = bcc; blk.nelts = 1;
    rep.block_cc = &blk;                       /* allow_cc NULL -> block mode */
    mk_v4(&sin, "1.2.4.8");

    ASSERT_EQUAL(NGX_HTTP_FORBIDDEN,
        ngx_http_heavybag_reputation_check(&rep, (struct sockaddr *) &sin,
                                           &reason, &out));
    ASSERT_EQUAL(HEAVYBAG_REASON_GEO, out.reason);
    ASSERT_TRUE(reason_is(&reason, "geo country"));
}


/* ======================================================================= *
 *  B13  geo hit but nothing matches -> default allow (189).                *
 * ======================================================================= */
CTEST(rep, geo_hit_default_declined)
{
    ngx_heavybag_rep_conf_t       rep;
    ngx_str_t                     reason;
    ngx_http_heavybag_verdict_t   out;
    struct sockaddr_in            sin;
    uint16_t                      bcc[1];
    ngx_array_t                   blk;

    reset(&rep, &reason, &out);
    rep.geo_db = &g_db;
    g_geo.found = 1;
    g_geo.country[0] = 'F'; g_geo.country[1] = 'R';
    bcc[0] = CC16('C', 'N');                   /* block list that does NOT hit */
    blk.elts = bcc; blk.nelts = 1;
    rep.block_cc = &blk;
    mk_v4(&sin, "212.27.48.10");

    ASSERT_EQUAL(NGX_DECLINED,
        ngx_http_heavybag_reputation_check(&rep, (struct sockaddr *) &sin,
                                           &reason, &out));
    ASSERT_EQUAL(HEAVYBAG_REASON_NONE, out.reason);
    ASSERT_EQUAL_U(1, out.geo_valid);
}


/* ======================================================================= *
 *  E1  IPv6 sockaddr flows through unchanged (blocklist match over v6).     *
 * ======================================================================= */
CTEST(rep, ipv6_blocklist_forbidden)
{
    ngx_heavybag_rep_conf_t       rep;
    ngx_str_t                     reason;
    ngx_http_heavybag_verdict_t   out;
    struct sockaddr_in6           s6;

    reset(&rep, &reason, &out);
    rep.blocklist = &g_cidr_b;
    g_match = &g_cidr_b;
    mk_v6(&s6, "2001:db8::dead");

    ASSERT_EQUAL(NGX_HTTP_FORBIDDEN,
        ngx_http_heavybag_reputation_check(&rep, (struct sockaddr *) &s6,
                                           &reason, &out));
    ASSERT_EQUAL(HEAVYBAG_REASON_BLOCKLIST, out.reason);
}


/* ======================================================================= *
 *  E2  IPv4-mapped IPv6 sockaddr flows through the geo path (flag block).   *
 * ======================================================================= */
CTEST(rep, v4mapped_flag_forbidden)
{
    ngx_heavybag_rep_conf_t       rep;
    ngx_str_t                     reason;
    ngx_http_heavybag_verdict_t   out;
    struct sockaddr_in6           s6;

    reset(&rep, &reason, &out);
    rep.geo_db = &g_db;
    g_geo.found = 1;
    g_geo.country[0] = 'X'; g_geo.country[1] = 'X';
    g_geo.flags = NGX_HTTP_HEAVYBAG_GEO_FLAG_DROP;        /* 0x0008 */
    rep.flag_mask = NGX_HTTP_HEAVYBAG_GEO_FLAG_DROP;
    mk_v6(&s6, "::ffff:203.0.113.9");

    ASSERT_EQUAL(NGX_HTTP_FORBIDDEN,
        ngx_http_heavybag_reputation_check(&rep, (struct sockaddr *) &s6,
                                           &reason, &out));
    ASSERT_EQUAL(HEAVYBAG_REASON_FLAG, out.reason);
}


/* ======================================================================= *
 *  P1  precedence: flag_mask wins over a co-matching ASN and block_cc.      *
 * ======================================================================= */
CTEST(rep, precedence_flag_beats_asn_and_cc)
{
    ngx_heavybag_rep_conf_t       rep;
    ngx_str_t                     reason;
    ngx_http_heavybag_verdict_t   out;
    struct sockaddr_in            sin;
    uint32_t                      asns[1];
    uint16_t                      bcc[1];
    ngx_array_t                   ba, blk;

    reset(&rep, &reason, &out);
    rep.geo_db = &g_db;
    g_geo.found = 1;
    g_geo.country[0] = 'C'; g_geo.country[1] = 'N';
    g_geo.flags = NGX_HTTP_HEAVYBAG_GEO_FLAG_ANON_PROXY;  /* 0x0001 */
    g_geo.asn = 64500;
    rep.flag_mask = NGX_HTTP_HEAVYBAG_GEO_FLAG_ANON_PROXY;
    asns[0] = 64500;  ba.elts = asns;  ba.nelts = 1;  rep.block_asn = &ba;
    bcc[0] = CC16('C', 'N'); blk.elts = bcc; blk.nelts = 1; rep.block_cc = &blk;
    mk_v4(&sin, "9.9.9.9");

    ASSERT_EQUAL(NGX_HTTP_FORBIDDEN,
        ngx_http_heavybag_reputation_check(&rep, (struct sockaddr *) &sin,
                                           &reason, &out));
    ASSERT_EQUAL(HEAVYBAG_REASON_FLAG, out.reason);     /* flag, not ASN/GEO */
}


/* ======================================================================= *
 *  P2  precedence: ASN wins over a co-matching flag_cc and block_cc.        *
 * ======================================================================= */
CTEST(rep, precedence_asn_beats_cc)
{
    ngx_heavybag_rep_conf_t       rep;
    ngx_str_t                     reason;
    ngx_http_heavybag_verdict_t   out;
    struct sockaddr_in            sin;
    uint32_t                      asns[1];
    uint16_t                      fcc[1], bcc[1];
    ngx_array_t                   ba, fc, blk;

    reset(&rep, &reason, &out);
    rep.geo_db = &g_db;
    g_geo.found = 1;
    g_geo.country[0] = 'C'; g_geo.country[1] = 'N';
    g_geo.flags = 0;                                  /* flag_mask must miss */
    g_geo.asn = 64500;
    asns[0] = 64500; ba.elts = asns; ba.nelts = 1; rep.block_asn = &ba;
    fcc[0] = CC16('C', 'N'); fc.elts = fcc; fc.nelts = 1; rep.flag_cc = &fc;
    bcc[0] = CC16('C', 'N'); blk.elts = bcc; blk.nelts = 1; rep.block_cc = &blk;
    mk_v4(&sin, "9.9.9.10");

    ASSERT_EQUAL(NGX_HTTP_FORBIDDEN,
        ngx_http_heavybag_reputation_check(&rep, (struct sockaddr *) &sin,
                                           &reason, &out));
    ASSERT_EQUAL(HEAVYBAG_REASON_ASN, out.reason);      /* ASN, before flag_cc */
}


/* ======================================================================= *
 *  P3  precedence: whitelist allow wins over a co-listed block_cc -- the    *
 *  block list is not consulted in whitelist mode (159 returns first).      *
 * ======================================================================= */
CTEST(rep, precedence_allow_beats_block)
{
    ngx_heavybag_rep_conf_t       rep;
    ngx_str_t                     reason;
    ngx_http_heavybag_verdict_t   out;
    struct sockaddr_in            sin;
    uint16_t                      acc[1], bcc[1];
    ngx_array_t                   allow, blk;

    reset(&rep, &reason, &out);
    rep.geo_db = &g_db;
    g_geo.found = 1;
    g_geo.country[0] = 'U'; g_geo.country[1] = 'S';
    acc[0] = CC16('U', 'S'); allow.elts = acc; allow.nelts = 1; rep.allow_cc = &allow;
    bcc[0] = CC16('U', 'S'); blk.elts = bcc; blk.nelts = 1;  rep.block_cc = &blk;
    mk_v4(&sin, "23.9.9.9");

    ASSERT_EQUAL(NGX_DECLINED,
        ngx_http_heavybag_reputation_check(&rep, (struct sockaddr *) &sin,
                                           &reason, &out));
    ASSERT_EQUAL(HEAVYBAG_REASON_NONE, out.reason);     /* allowed, not blocked */
}


/* ======================================================================= *
 *  P4  precedence: flag_cc (special-CC) wins over whitelist-miss 404 --     *
 *  the special-CC deny at 141 runs BEFORE the allow_cc policy at 159.      *
 * ======================================================================= */
CTEST(rep, precedence_flag_cc_beats_whitelist)
{
    ngx_heavybag_rep_conf_t       rep;
    ngx_str_t                     reason;
    ngx_http_heavybag_verdict_t   out;
    struct sockaddr_in            sin;
    uint16_t                      fcc[1], acc[1];
    ngx_array_t                   fc, allow;

    reset(&rep, &reason, &out);
    rep.geo_db = &g_db;
    g_geo.found = 1;
    g_geo.country[0] = 'T'; g_geo.country[1] = '1';   /* Tor */
    fcc[0] = CC16('T', '1'); fc.elts = fcc; fc.nelts = 1; rep.flag_cc = &fc;
    acc[0] = CC16('U', 'S'); allow.elts = acc; allow.nelts = 1; rep.allow_cc = &allow;
    mk_v4(&sin, "185.220.101.2");

    ASSERT_EQUAL(NGX_HTTP_FORBIDDEN,                    /* 403 flag, not 404 */
        ngx_http_heavybag_reputation_check(&rep, (struct sockaddr *) &sin,
                                           &reason, &out));
    ASSERT_EQUAL(HEAVYBAG_REASON_FLAG, out.reason);
}


int
main(int argc, const char *argv[])
{
    return ctest_main(argc, argv);
}
