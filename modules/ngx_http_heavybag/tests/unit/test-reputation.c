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


/* ======================================================================= *
 *  U1 (SV14/T5.d)  block mode + no geo record + a flag policy but NO       *
 *  `unknown` token -> ALLOW. This is the deny-list convention: a missing    *
 *  record is a data-freshness gap, not proof of Tor-ness (an attacker       *
 *  cannot delete itself from the database), so the platform does not decide *
 *  for the operator -- cf. AWS WAF's "XX" label matching no country list.  *
 * ======================================================================= */
CTEST(rep, no_record_flag_policy_without_token_allows)
{
    ngx_heavybag_rep_conf_t       rep;
    ngx_str_t                     reason;
    ngx_http_heavybag_verdict_t   out;
    struct sockaddr_in            sin;
    uint16_t                      fcc[1];
    ngx_array_t                   fc;

    reset(&rep, &reason, &out);
    rep.geo_db = &g_db;
    g_geo.found = 0;                           /* IP absent from the database */
    rep.allow_cc = NULL;                       /* block mode                  */
    rep.flag_mask = NGX_HTTP_HEAVYBAG_GEO_FLAG_DROP;
    fcc[0] = CC16('T', '1');                   /* "waf_flag_block tor drop"   */
    fc.elts = fcc; fc.nelts = 1;
    rep.flag_cc = &fc;
    rep.flag_block_set = 1;
    rep.flag_block_unknown = 0;                /* the `unknown` token is OFF  */
    mk_v4(&sin, "192.0.2.66");

    ASSERT_EQUAL(NGX_DECLINED,
        ngx_http_heavybag_reputation_check(&rep, (struct sockaddr *) &sin,
                                           &reason, &out));
    ASSERT_EQUAL(HEAVYBAG_REASON_NONE, out.reason);
    ASSERT_EQUAL_U(1, out.geo_valid);          /* a lookup ran, it just missed */
}


/* ======================================================================= *
 *  U2 (SV14/T5.d)  the opt-in: "waf_flag_block tor unknown" -> the same     *
 *  no-record source is DENIED. flag_mask stays 0 here (tor carries no bit   *
 *  and `unknown` carries neither bit nor code), so the bit is the only      *
 *  thing that can drive this verdict.                                      *
 * ======================================================================= */
CTEST(rep, no_record_unknown_token_denies)
{
    ngx_heavybag_rep_conf_t       rep;
    ngx_str_t                     reason;
    ngx_http_heavybag_verdict_t   out;
    struct sockaddr_in            sin;
    uint16_t                      fcc[1];
    ngx_array_t                   fc;

    reset(&rep, &reason, &out);
    rep.geo_db = &g_db;
    g_geo.found = 0;
    rep.allow_cc = NULL;
    rep.flag_mask = 0;
    fcc[0] = CC16('T', '1');
    fc.elts = fcc; fc.nelts = 1;
    rep.flag_cc = &fc;
    rep.flag_block_set = 1;
    rep.flag_block_unknown = 1;                /* "... unknown" */
    mk_v4(&sin, "192.0.2.67");

    ASSERT_EQUAL(NGX_HTTP_FORBIDDEN,
        ngx_http_heavybag_reputation_check(&rep, (struct sockaddr *) &sin,
                                           &reason, &out));
    ASSERT_EQUAL(HEAVYBAG_REASON_FLAG, out.reason);
    ASSERT_TRUE(reason_is(&reason, "network flag (no geo record)"));
    ASSERT_EQUAL_U(1, out.geo_valid);
    ASSERT_EQUAL_U(0, out.flags);              /* nothing to attribute a bit to */
}


/* ======================================================================= *
 *  U3 (SV14/T5.d)  whitelist mode is fail-closed on its own and ignores    *
 *  the token: the 404 hide wins even with `unknown` off.                   *
 * ======================================================================= */
CTEST(rep, no_record_whitelist_unchanged)
{
    ngx_heavybag_rep_conf_t       rep;
    ngx_str_t                     reason;
    ngx_http_heavybag_verdict_t   out;
    struct sockaddr_in            sin;
    uint16_t                      acc[1];
    ngx_array_t                   allow;

    reset(&rep, &reason, &out);
    rep.geo_db = &g_db;
    g_geo.found = 0;
    acc[0] = CC16('U', 'S');
    allow.elts = acc; allow.nelts = 1;
    rep.allow_cc = &allow;
    rep.flag_mask = NGX_HTTP_HEAVYBAG_GEO_FLAG_DROP;   /* both policies set */
    rep.flag_block_set = 1;
    rep.flag_block_unknown = 0;                        /* no opt-in needed  */
    mk_v4(&sin, "192.0.2.68");

    ASSERT_EQUAL(NGX_HTTP_NOT_FOUND,
        ngx_http_heavybag_reputation_check(&rep, (struct sockaddr *) &sin,
                                           &reason, &out));
    ASSERT_EQUAL(HEAVYBAG_REASON_GEO_WHITELIST, out.reason);
    ASSERT_TRUE(reason_is(&reason, "geo not whitelisted"));
}


/* ----------------------------------------------------------------------- *
 *  Shared conf-merge layer (rep-conf-01 / flag-unit-01).                    *
 *  ngx_http_heavybag_rep_conf_merge() + _needs_geo() are the SINGLE         *
 *  implementation behind both the HTTP location merge and the stream server *
 *  merge, so asserting them here asserts both heads at once -- that is the  *
 *  point of the consolidation (the two hand-written copies had drifted).    *
 * ----------------------------------------------------------------------- */

/* one fully-populated parent policy, reused by the merge cases */
static void
mk_parent(ngx_heavybag_rep_conf_t *prev, ngx_array_t *a)
{
    memset(prev, 0, sizeof *prev);
    prev->geo_db = &g_db;
    prev->block_cc = a;
    prev->block_asn = a;
    prev->allow_cc = a;
    prev->flag_cc = a;
    prev->flag_mask = NGX_HTTP_HEAVYBAG_GEO_FLAG_DROP;
    prev->flag_block_set = 1;
    prev->flag_block_unknown = 1;
    prev->blocklist = a;
    prev->allowlist = a;
}


/* ======================================================================= *
 *  M1  child that configured nothing inherits every field from the parent. *
 * ======================================================================= */
CTEST(rep, merge_child_empty_inherits_all)
{
    ngx_heavybag_rep_conf_t  prev, conf;
    ngx_array_t              a;

    mk_parent(&prev, &a);
    memset(&conf, 0, sizeof conf);

    ngx_http_heavybag_rep_conf_merge(&prev, &conf);

    ASSERT_TRUE(conf.geo_db == &g_db);
    ASSERT_TRUE(conf.block_cc == &a);
    ASSERT_TRUE(conf.block_asn == &a);
    ASSERT_TRUE(conf.allow_cc == &a);
    ASSERT_TRUE(conf.flag_cc == &a);
    ASSERT_EQUAL_U(NGX_HTTP_HEAVYBAG_GEO_FLAG_DROP, conf.flag_mask);
    ASSERT_EQUAL_U(1, conf.flag_block_unknown); /* all THREE parts travel */
    ASSERT_EQUAL_U(1, conf.flag_block_set);     /* marker travels with the unit */
    ASSERT_TRUE(conf.blocklist == &a);
    ASSERT_TRUE(conf.allowlist == &a);
}


/* ======================================================================= *
 *  M2  child that configured everything inherits nothing (clean override). *
 * ======================================================================= */
CTEST(rep, merge_child_full_inherits_nothing)
{
    ngx_heavybag_rep_conf_t   prev, conf;
    ngx_array_t               a, b;
    ngx_http_heavybag_geo_db_t  own_db;

    mk_parent(&prev, &a);

    memset(&conf, 0, sizeof conf);
    conf.geo_db = &own_db;
    conf.block_cc = &b;
    conf.block_asn = &b;
    conf.allow_cc = &b;
    conf.flag_cc = &b;
    conf.flag_mask = NGX_HTTP_HEAVYBAG_GEO_FLAG_ANYCAST;
    conf.flag_block_set = 1;
    conf.blocklist = &b;
    conf.allowlist = &b;

    ngx_http_heavybag_rep_conf_merge(&prev, &conf);

    ASSERT_TRUE(conf.geo_db == &own_db);
    ASSERT_TRUE(conf.block_cc == &b);
    ASSERT_TRUE(conf.block_asn == &b);
    ASSERT_TRUE(conf.allow_cc == &b);
    ASSERT_TRUE(conf.flag_cc == &b);
    ASSERT_EQUAL_U(NGX_HTTP_HEAVYBAG_GEO_FLAG_ANYCAST, conf.flag_mask);
    /* the parent's `unknown` opt-in must NOT leak into a child that spelled
     * out its own waf_flag_block -- the whole unit is overridden */
    ASSERT_EQUAL_U(0, conf.flag_block_unknown);
    ASSERT_TRUE(conf.blocklist == &b);
    ASSERT_TRUE(conf.allowlist == &b);
}


/* ======================================================================= *
 *  M3 (#2 / SV8)  waf_flag_block is ONE unit: a TOR-ONLY child overrides    *
 *  BOTH halves. Pre-fix the child's flag_mask was 0 (tor carries no bit),   *
 *  so the `flag_mask == 0` inherit rule silently re-imported the parent's   *
 *  DROP bit -- a policy the child never asked for (CWE-284).               *
 * ======================================================================= */
CTEST(rep, merge_flag_block_tor_child_overrides_both)
{
    ngx_heavybag_rep_conf_t       prev, conf;
    ngx_array_t                   pfc, cfc;
    uint16_t                      pcodes[2], ccodes[1];
    ngx_str_t                     reason;
    ngx_http_heavybag_verdict_t   out;
    struct sockaddr_in            sin;

    /* parent: waf_flag_block tor drop unknown -> mask=DROP, cc={T1,XD}, unk=1 */
    pcodes[0] = CC16('T', '1'); pcodes[1] = CC16('X', 'D');
    pfc.elts = pcodes; pfc.nelts = 2;
    memset(&prev, 0, sizeof prev);
    prev.geo_db = &g_db;
    prev.flag_mask = NGX_HTTP_HEAVYBAG_GEO_FLAG_DROP;
    prev.flag_cc = &pfc;
    prev.flag_block_set = 1;
    prev.flag_block_unknown = 1;

    /* child: waf_flag_block tor  ->  mask=0, flag_cc={T1}, unk=0 */
    ccodes[0] = CC16('T', '1');
    cfc.elts = ccodes; cfc.nelts = 1;
    memset(&conf, 0, sizeof conf);
    conf.flag_cc = &cfc;
    conf.flag_block_set = 1;

    ngx_http_heavybag_rep_conf_merge(&prev, &conf);

    ASSERT_EQUAL_U(0, conf.flag_mask);         /* parent's DROP bit NOT pulled in */
    ASSERT_EQUAL_U(0, conf.flag_block_unknown); /* nor the parent's `unknown` */
    ASSERT_TRUE(conf.flag_cc == &cfc);
    ASSERT_TRUE(conf.geo_db == &g_db);         /* unrelated fields still inherit */

    /* behavioural half: a DROP-flagged source is allowed at the child ... */
    memset(&g_geo, 0, sizeof g_geo);
    g_match = NULL;
    reason.len = 0; reason.data = NULL;
    memset(&out, 0xff, sizeof out);
    g_geo.found = 1;
    g_geo.country[0] = 'X'; g_geo.country[1] = 'X';
    g_geo.flags = NGX_HTTP_HEAVYBAG_GEO_FLAG_DROP;
    mk_v4(&sin, "198.51.100.77");

    ASSERT_EQUAL(NGX_DECLINED,
        ngx_http_heavybag_reputation_check(&conf, (struct sockaddr *) &sin,
                                           &reason, &out));

    /* ... while the parent level, which really did ask for drop, still blocks */
    memset(&out, 0xff, sizeof out);
    ASSERT_EQUAL(NGX_HTTP_FORBIDDEN,
        ngx_http_heavybag_reputation_check(&prev, (struct sockaddr *) &sin,
                                           &reason, &out));
    ASSERT_EQUAL(HEAVYBAG_REASON_FLAG, out.reason);
}


/* ======================================================================= *
 *  M4 (#2 / SV8)  parent "tor drop" + child "anonymous-proxy": the child    *
 *  blocks A1 ONLY -- neither the parent's DROP bit nor its T1/XD codes leak *
 *  in -- and the parent level keeps blocking T1 + XD.                      *
 * ======================================================================= */
CTEST(rep, merge_flag_block_child_anon_only)
{
    ngx_heavybag_rep_conf_t       prev, conf;
    ngx_array_t                   pfc, cfc;
    uint16_t                      pcodes[2], ccodes[1];
    ngx_str_t                     reason;
    ngx_http_heavybag_verdict_t   out;
    struct sockaddr_in            sin;

    pcodes[0] = CC16('T', '1'); pcodes[1] = CC16('X', 'D');
    pfc.elts = pcodes; pfc.nelts = 2;
    memset(&prev, 0, sizeof prev);
    prev.geo_db = &g_db;
    prev.flag_mask = NGX_HTTP_HEAVYBAG_GEO_FLAG_DROP;
    prev.flag_cc = &pfc;
    prev.flag_block_set = 1;

    ccodes[0] = CC16('A', '1');
    cfc.elts = ccodes; cfc.nelts = 1;
    memset(&conf, 0, sizeof conf);
    conf.flag_mask = NGX_HTTP_HEAVYBAG_GEO_FLAG_ANON_PROXY;
    conf.flag_cc = &cfc;
    conf.flag_block_set = 1;

    ngx_http_heavybag_rep_conf_merge(&prev, &conf);

    ASSERT_EQUAL_U(NGX_HTTP_HEAVYBAG_GEO_FLAG_ANON_PROXY, conf.flag_mask);
    ASSERT_TRUE(conf.flag_cc == &cfc);

    /* child: an A1 anonymous-proxy source is blocked */
    memset(&g_geo, 0, sizeof g_geo);
    g_match = NULL;
    reason.len = 0; reason.data = NULL;
    memset(&out, 0xff, sizeof out);
    g_geo.found = 1;
    g_geo.country[0] = 'A'; g_geo.country[1] = '1';
    g_geo.flags = NGX_HTTP_HEAVYBAG_GEO_FLAG_ANON_PROXY;
    mk_v4(&sin, "203.0.113.55");
    ASSERT_EQUAL(NGX_HTTP_FORBIDDEN,
        ngx_http_heavybag_reputation_check(&conf, (struct sockaddr *) &sin,
                                           &reason, &out));
    ASSERT_EQUAL(HEAVYBAG_REASON_FLAG, out.reason);

    /* child: a Tor exit is NOT blocked -- the child overrode the whole unit */
    memset(&g_geo, 0, sizeof g_geo);
    memset(&out, 0xff, sizeof out);
    g_geo.found = 1;
    g_geo.country[0] = 'T'; g_geo.country[1] = '1';
    ASSERT_EQUAL(NGX_DECLINED,
        ngx_http_heavybag_reputation_check(&conf, (struct sockaddr *) &sin,
                                           &reason, &out));

    /* parent: the same Tor exit still blocks, and so does an XD source */
    memset(&out, 0xff, sizeof out);
    ASSERT_EQUAL(NGX_HTTP_FORBIDDEN,
        ngx_http_heavybag_reputation_check(&prev, (struct sockaddr *) &sin,
                                           &reason, &out));
    memset(&g_geo, 0, sizeof g_geo);
    memset(&out, 0xff, sizeof out);
    g_geo.found = 1;
    g_geo.country[0] = 'X'; g_geo.country[1] = 'D';
    ASSERT_EQUAL(NGX_HTTP_FORBIDDEN,
        ngx_http_heavybag_reputation_check(&prev, (struct sockaddr *) &sin,
                                           &reason, &out));
}


/* ======================================================================= *
 *  M5 (#2 / SV8)  a child that never used waf_flag_block inherits BOTH      *
 *  halves -- the marker, not flag_mask/flag_cc, decides.                   *
 * ======================================================================= */
CTEST(rep, merge_no_flag_block_inherits_both)
{
    ngx_heavybag_rep_conf_t  prev, conf;
    ngx_array_t              pfc;
    uint16_t                 pcodes[1];

    pcodes[0] = CC16('T', '1');
    pfc.elts = pcodes; pfc.nelts = 1;
    memset(&prev, 0, sizeof prev);
    prev.geo_db = &g_db;
    prev.flag_mask = NGX_HTTP_HEAVYBAG_GEO_FLAG_DROP;
    prev.flag_cc = &pfc;
    prev.flag_block_set = 1;
    prev.flag_block_unknown = 1;

    memset(&conf, 0, sizeof conf);             /* no waf_flag_block here */

    ngx_http_heavybag_rep_conf_merge(&prev, &conf);

    ASSERT_EQUAL_U(NGX_HTTP_HEAVYBAG_GEO_FLAG_DROP, conf.flag_mask);
    ASSERT_TRUE(conf.flag_cc == &pfc);
    ASSERT_EQUAL_U(1, conf.flag_block_unknown);   /* the third part too */
    ASSERT_EQUAL_U(1, conf.flag_block_set);
}


/* ======================================================================= *
 *  M6 (#12/T5.a)  merge-then-validate ORDER contract. Both heads now run    *
 *  the identical pair, and validation MUST see the fully inherited config:  *
 *  a child that only sets a policy is legal because the parent supplies the *
 *  database; validating before the merge would wrongly reject it.          *
 * ======================================================================= */
CTEST(rep, merge_then_validate_order)
{
    ngx_heavybag_rep_conf_t   prev, conf;
    ngx_array_t               a;
    ngx_http_heavybag_geo_db_t  own_db;

    /* parent owns the database, child owns the policy */
    memset(&prev, 0, sizeof prev);
    prev.geo_db = &g_db;
    memset(&conf, 0, sizeof conf);
    conf.block_cc = &a;

    /* validating BEFORE the merge would reject this legal config */
    ASSERT_EQUAL_U(1, ngx_http_heavybag_rep_conf_needs_geo(&conf));

    ngx_http_heavybag_rep_conf_merge(&prev, &conf);

    ASSERT_EQUAL_U(0, ngx_http_heavybag_rep_conf_needs_geo(&conf));

    /* a child with its OWN database + its own policy is legal either way --
     * identical on both heads, which is what the consolidation guarantees */
    memset(&prev, 0, sizeof prev);
    memset(&conf, 0, sizeof conf);
    conf.geo_db = &own_db;
    conf.flag_mask = NGX_HTTP_HEAVYBAG_GEO_FLAG_ANYCAST;
    conf.flag_block_set = 1;
    ASSERT_EQUAL_U(0, ngx_http_heavybag_rep_conf_needs_geo(&conf));
    ngx_http_heavybag_rep_conf_merge(&prev, &conf);
    ASSERT_EQUAL_U(0, ngx_http_heavybag_rep_conf_needs_geo(&conf));
}


/* ======================================================================= *
 *  M7 (#12/T5.a)  the fail-closed predicate itself: EVERY geo-dependent     *
 *  policy trips it on its own, and a database-less config with only plain   *
 *  CIDR lists (or nothing) is accepted.                                    *
 * ======================================================================= */
CTEST(rep, needs_geo_predicate)
{
    ngx_heavybag_rep_conf_t  rep;
    ngx_array_t              a;

    /* nothing geo-dependent configured -> accepted (all arms evaluated) */
    memset(&rep, 0, sizeof rep);
    rep.blocklist = &a;
    rep.allowlist = &a;
    ASSERT_EQUAL_U(0, ngx_http_heavybag_rep_conf_needs_geo(&rep));

    memset(&rep, 0, sizeof rep); rep.block_cc = &a;
    ASSERT_EQUAL_U(1, ngx_http_heavybag_rep_conf_needs_geo(&rep));

    memset(&rep, 0, sizeof rep); rep.allow_cc = &a;
    ASSERT_EQUAL_U(1, ngx_http_heavybag_rep_conf_needs_geo(&rep));

    memset(&rep, 0, sizeof rep); rep.block_asn = &a;
    ASSERT_EQUAL_U(1, ngx_http_heavybag_rep_conf_needs_geo(&rep));

    memset(&rep, 0, sizeof rep); rep.flag_cc = &a;
    ASSERT_EQUAL_U(1, ngx_http_heavybag_rep_conf_needs_geo(&rep));

    memset(&rep, 0, sizeof rep);
    rep.flag_mask = NGX_HTTP_HEAVYBAG_GEO_FLAG_SATELLITE;
    ASSERT_EQUAL_U(1, ngx_http_heavybag_rep_conf_needs_geo(&rep));

    /* `waf_flag_block unknown` alone contributes neither a bit nor a code,
     * but it still needs a database: without one the reputation core returns
     * at the geo_db == NULL gate and the token would be silently inert */
    memset(&rep, 0, sizeof rep);
    rep.flag_block_set = 1;
    rep.flag_block_unknown = 1;
    ASSERT_EQUAL_U(1, ngx_http_heavybag_rep_conf_needs_geo(&rep));

    /* a database present short-circuits the whole predicate */
    memset(&rep, 0, sizeof rep);
    rep.geo_db = &g_db;
    rep.block_cc = &a;
    ASSERT_EQUAL_U(0, ngx_http_heavybag_rep_conf_needs_geo(&rep));
}


int
main(int argc, const char *argv[])
{
    return ctest_main(argc, argv);
}
