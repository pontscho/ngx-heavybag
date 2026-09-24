/*
 * Unit tests for the pure geo radix-trie walk + leaf decode (heavybag_geo.c).
 *
 * Compiled standalone: includes heavybag_geo.c under -DHEAVYBAG_GEO_UNIT_TEST so
 * only the nginx-free core is pulled in (no nginx / mmap / OpenSSL headers).
 * The type shim in heavybag_geo.h substitutes nginx byte-for-byte; the real
 * -Werror SSL module build stays the correctness contract. Built + run by
 * run-unit-tests.sh with `cc -DHEAVYBAG_GEO_UNIT_TEST`.
 *
 * The DB layout the walk depends on (12-byte tree nodes, 12-byte network
 * leaves, the SHARED block-index/flag macros in heavybag_geo.h) is exercised
 * against hand-built in-memory blocks. Both ngx_http_heavybag_geo_walk (static)
 * and ngx_http_heavybag_geo_lookup are reachable because this TU includes the
 * .c directly. The on-disk layout constants live in the production code and
 * are tested, never re-declared here.
 *
 * NODE (12 bytes, big-endian): [0,4) child for bit==0 | [4,8) child for
 *   bit==1 | [8,12) net. net with the high bit (0x80000000) set marks an
 *   internal node (no leaf here); otherwise net is a leaf index. A child
 *   pointer of 0 is the terminal sentinel (node 0 is the root, nothing points
 *   back to it). LEAF (12 bytes): [0,2) country | [2,4) reserved | [4,8) ASN |
 *   [8,10) flags | [10,12) reserved.
 *
 * PURE LOADER PREDICATES (in scope): the decisions the config-time loader
 * makes over untrusted header/tree bytes are extracted as ungated helpers in
 * heavybag_geo.c -- ngx_http_heavybag_geo_block_oob (block-table bounds),
 * ngx_http_heavybag_geo_entry_oob (12-byte node/leaf index bounds, shared
 * with the runtime walker and the leaf decode) and
 * ngx_http_heavybag_geo_ipv4root (the 96-step descent to the IPv4-mapped
 * root). V21-V26 drive them directly; only the logging around them lives in
 * the #ifndef'd geo_open.
 *
 * OUT OF UNIT SCOPE (honest limits, NOT faked here) -- the rest of the
 * config-time open() path (ngx_http_heavybag_geo_open / _verify) is behind
 * #ifndef and needs ngx_conf_t + mmap + an ECDSA-P521/SHA-512-signed
 * location.db + OpenSSL:
 *   - magic check, mandatory signature verify, size < DATA_OFF / > MAX_SIZE
 *     rejection, all-zero FILE fail-closed (magic mismatch), and the
 *     post-mmap load-time re-stat (a real file-truncation race -- any unit
 *     test of it would be flaky, so none is written).
 * These are covered by the Fix-round-3 LIVE nginx test (real FR/AU/US
 * ground-truth lookups against the project's signed geodb/location.db, oracle
 * reference/geolookup.c) and the config-build layer -- they cannot be unit
 * tested without nginx+OpenSSL, so they are deliberately absent here.
 */

#ifndef HEAVYBAG_GEO_UNIT_TEST
#define HEAVYBAG_GEO_UNIT_TEST
#endif
#include "../../src/heavybag_geo.c"

#define CTEST_MAIN
#include "ctest.h"

#include <string.h>
#include <arpa/inet.h>


/* ---- synthetic DB builders --------------------------------------------- */

#define NT    NGX_HTTP_HEAVYBAG_GEO_NT
#define ND    NGX_HTTP_HEAVYBAG_GEO_ND
#define SENT  0x80000000U          /* internal node: no leaf at this node */

static void
put_u32(u_char *p, uint32_t v)
{
    p[0] = (u_char) (v >> 24);
    p[1] = (u_char) (v >> 16);
    p[2] = (u_char) (v >> 8);
    p[3] = (u_char) v;
}

/* node idx: child for bit0 (left), child for bit1 (right), net/leaf-or-SENT */
static void
node_set(u_char *nt, uint32_t idx, uint32_t left, uint32_t right, uint32_t net)
{
    u_char  *n = nt + (size_t) idx * 12;
    put_u32(n,     left);
    put_u32(n + 4, right);
    put_u32(n + 8, net);
}

/* leaf idx: 2-byte country, reserved, 4-byte ASN, 2-byte flags, reserved.
 * rsv2/rsv10 fill the [2,4) and [10,12) reserved bytes so a reader that
 * mistakenly took flags from offset 2 (the historic nanolibloc bug) would
 * read the poison instead of the real flags at offset 8. */
static void
leaf_set(u_char *nd, uint32_t idx, const char *cc, uint16_t rsv2,
    uint32_t asn, uint16_t flags, uint16_t rsv10)
{
    u_char  *e = nd + (size_t) idx * 12;
    e[0] = (u_char) cc[0];
    e[1] = (u_char) cc[1];
    e[2] = (u_char) (rsv2 >> 8);  e[3] = (u_char) rsv2;
    put_u32(e + 4, asn);
    e[8] = (u_char) (flags >> 8); e[9] = (u_char) flags;
    e[10] = (u_char) (rsv10 >> 8); e[11] = (u_char) rsv10;
}

static void
db_init(ngx_http_heavybag_geo_db_t *db, u_char *nt, uint32_t nnodes,
    u_char *nd, uint32_t nleaves, uint32_t v4root)
{
    memset(db, 0, sizeof *db);
    db->block[NT] = nt;  db->block_len[NT] = nnodes * 12;
    db->block[ND] = nd;  db->block_len[ND] = nleaves * 12;
    db->ipv4root = v4root;
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

/* lookup helper: prime res with 0xff so a stale-found bug cannot pass as 0 */
static ngx_http_heavybag_geo_result_t
look_v4(ngx_http_heavybag_geo_db_t *db, const char *ip)
{
    struct sockaddr_in               sin;
    ngx_http_heavybag_geo_result_t   res;
    memset(&res, 0xff, sizeof res);
    mk_v4(&sin, ip);
    ngx_http_heavybag_geo_lookup(db, (struct sockaddr *) &sin, &res);
    return res;
}

static ngx_http_heavybag_geo_result_t
look_v6(ngx_http_heavybag_geo_db_t *db, const char *ip)
{
    struct sockaddr_in6              s6;
    ngx_http_heavybag_geo_result_t   res;
    memset(&res, 0xff, sizeof res);
    mk_v6(&s6, ip);
    ngx_http_heavybag_geo_lookup(db, (struct sockaddr *) &s6, &res);
    return res;
}


/* ======================================================================= *
 *  V1  basic v4 leaf decode: country + ASN read from a matched leaf.       *
 * ======================================================================= */
CTEST(geo, v4_basic_decode)
{
    u_char  nt[12], nd[12];
    ngx_http_heavybag_geo_db_t  db;
    ngx_http_heavybag_geo_result_t  r;

    node_set(nt, 0, 0, 0, 0);                 /* root carries leaf 0 */
    leaf_set(nd, 0, "HU", 0, 12345U, 0x0004, 0);
    db_init(&db, nt, 1, nd, 1, 0);

    r = look_v4(&db, "1.2.3.4");
    ASSERT_EQUAL_U(1, r.found);
    ASSERT_EQUAL('H', r.country[0]);
    ASSERT_EQUAL('U', r.country[1]);
    ASSERT_EQUAL_U(12345U, r.asn);
}


/* ======================================================================= *
 *  V2  flags read from ND offset 8 (libloc landmine), NOT offset 2.        *
 *  Poison bytes at [2,4) and [10,12); the real flags sit at [8,10).        *
 * ======================================================================= */
CTEST(geo, flags_at_offset_8)
{
    u_char  nt[12], nd[12];
    ngx_http_heavybag_geo_db_t  db;
    ngx_http_heavybag_geo_result_t  r;

    node_set(nt, 0, 0, 0, 0);
    /* rsv2=0xDEAD, asn=0x11223344, flags=DROP(0x0008), rsv10=0xBEEF */
    leaf_set(nd, 0, "US", 0xDEAD, 0x11223344U, 0x0008, 0xBEEF);
    db_init(&db, nt, 1, nd, 1, 0);

    r = look_v4(&db, "8.8.8.8");
    ASSERT_EQUAL_U(1, r.found);
    ASSERT_EQUAL_U(0x0008U, r.flags);          /* DROP, from offset 8 */
    ASSERT_NOT_EQUAL_U(0xDEADU, r.flags);      /* not the [2,4) poison */
    ASSERT_NOT_EQUAL_U(0xBEEFU, r.flags);      /* not the [10,12) poison */
    ASSERT_EQUAL_U(0x11223344U, r.asn);
}


/* ======================================================================= *
 *  V3  ::ffff:1.2.3.4 (IPv4-mapped) keys through ipv4root and resolves to   *
 *  the SAME leaf as native 1.2.3.4. ipv4root != 0 so the v4 tree is a       *
 *  distinct subtree, genuinely walked.                                     *
 *                                                                          *
 *  Shared DB for V3+V4:                                                     *
 *    node0 = v6 root  -> leaf 6 "XX"                                        *
 *    node1 = ipv4root -> (bit0) node2 ; node2 -> leaf 5 "FR"                *
 * ======================================================================= */
static void
build_mapped_db(ngx_http_heavybag_geo_db_t *db, u_char *nt, u_char *nd)
{
    node_set(nt, 0, 0, 0, 6);                 /* v6 root: leaf 6 */
    node_set(nt, 1, 2, 0, SENT);              /* ipv4root: bit0 -> node2 */
    node_set(nt, 2, 0, 0, 5);                 /* leaf 5 */
    leaf_set(nd, 5, "FR", 0, 3215U, 0, 0);
    leaf_set(nd, 6, "XX", 0, 0U, 0, 0);
    db_init(db, nt, 3, nd, 7, 1 /* ipv4root */);
}

CTEST(geo, v4mapped_equals_native_v4)
{
    u_char  nt[3 * 12], nd[7 * 12];
    ngx_http_heavybag_geo_db_t  db;
    ngx_http_heavybag_geo_result_t  rn, rm;

    build_mapped_db(&db, nt, nd);

    rn = look_v4(&db, "1.2.3.4");
    rm = look_v6(&db, "::ffff:1.2.3.4");

    ASSERT_EQUAL_U(1, rn.found);
    ASSERT_EQUAL_U(1, rm.found);
    ASSERT_EQUAL('F', rn.country[0]);  ASSERT_EQUAL('R', rn.country[1]);
    ASSERT_EQUAL('F', rm.country[0]);  ASSERT_EQUAL('R', rm.country[1]);
}


/* ======================================================================= *
 *  V4  ::1.2.3.4 (IPv4-COMPATIBLE, NOT v4-mapped) is walked as a full v6    *
 *  address from node 0, NOT through ipv4root -> it must NOT see the v4      *
 *  tree's "FR" leaf; it lands on the v6 root leaf "XX".                     *
 * ======================================================================= */
CTEST(geo, v4compat_uses_full_v6_path)
{
    u_char  nt[3 * 12], nd[7 * 12];
    ngx_http_heavybag_geo_db_t  db;
    ngx_http_heavybag_geo_result_t  r;

    build_mapped_db(&db, nt, nd);

    r = look_v6(&db, "::1.2.3.4");
    ASSERT_EQUAL_U(1, r.found);
    ASSERT_EQUAL('X', r.country[0]);           /* v6 root leaf, not "FR" */
    ASSERT_EQUAL('X', r.country[1]);
}


/* ======================================================================= *
 *  V5  a genuine (non-mapped, non-compat) AF_INET6 address is walked over   *
 *  the 16-byte path: 8000:: takes bit0==1 (right child) at the v6 root.     *
 * ======================================================================= */
CTEST(geo, v6_full_path_branch)
{
    u_char  nt[2 * 12], nd[4 * 12];
    ngx_http_heavybag_geo_db_t  db;
    ngx_http_heavybag_geo_result_t  r;

    node_set(nt, 0, 0, 1, SENT);              /* v6 root: bit0==1 -> node1 */
    node_set(nt, 1, 0, 0, 3);                 /* leaf 3 */
    leaf_set(nd, 3, "V6", 0, 0U, 0, 0);
    db_init(&db, nt, 2, nd, 4, 0);

    r = look_v6(&db, "8000::");               /* byte0=0x80 -> bit0=1 */
    ASSERT_EQUAL_U(1, r.found);
    ASSERT_EQUAL('V', r.country[0]);  ASSERT_EQUAL('6', r.country[1]);

    /* :: takes bit0==0 -> node0.left==0 -> terminates with no leaf */
    r = look_v6(&db, "::");
    ASSERT_EQUAL_U(0, r.found);
}


/* ======================================================================= *
 *  V6  all-zero address matches a root leaf at depth 0 (:: and 0.0.0.0).    *
 * ======================================================================= */
CTEST(geo, all_zero_root_leaf)
{
    u_char  nt[12], nd[12];
    ngx_http_heavybag_geo_db_t  db;
    ngx_http_heavybag_geo_result_t  r4, r6;

    node_set(nt, 0, 0, 0, 0);                 /* root leaf 0, no children */
    leaf_set(nd, 0, "RT", 0, 0U, 0, 0);
    db_init(&db, nt, 1, nd, 1, 0);

    r4 = look_v4(&db, "0.0.0.0");
    r6 = look_v6(&db, "::");
    ASSERT_EQUAL_U(1, r4.found);
    ASSERT_EQUAL_U(1, r6.found);
    ASSERT_EQUAL('R', r4.country[0]);  ASSERT_EQUAL('T', r4.country[1]);
    ASSERT_EQUAL('R', r6.country[0]);  ASSERT_EQUAL('T', r6.country[1]);
}


/* ======================================================================= *
 *  V7  /0 default: a non-zero address falls back to the root leaf when no   *
 *  deeper node exists on its path.                                         *
 * ======================================================================= */
CTEST(geo, default_route_fallback)
{
    u_char  nt[12], nd[12];
    ngx_http_heavybag_geo_db_t  db;
    ngx_http_heavybag_geo_result_t  r;

    node_set(nt, 0, 0, 0, 0);                 /* root leaf, no children */
    leaf_set(nd, 0, "DF", 0, 0U, 0, 0);
    db_init(&db, nt, 1, nd, 1, 0);

    r = look_v4(&db, "203.0.113.55");
    ASSERT_EQUAL_U(1, r.found);
    ASSERT_EQUAL('D', r.country[0]);  ASSERT_EQUAL('F', r.country[1]);
}


/* ======================================================================= *
 *  V8  longest-prefix: a deeper leaf supersedes a shorter (/0) one.        *
 *    node0: leaf0 "DF" (/0), bit0 -> node1                                 *
 *    node1: leaf1 "SP" (more specific)                                     *
 * ======================================================================= */
CTEST(geo, longest_prefix_override)
{
    u_char  nt[2 * 12], nd[2 * 12];
    ngx_http_heavybag_geo_db_t  db;
    ngx_http_heavybag_geo_result_t  r0, r1;

    node_set(nt, 0, 1, 0, 0);                 /* leaf0, bit0 -> node1 */
    node_set(nt, 1, 0, 0, 1);                 /* leaf1 */
    leaf_set(nd, 0, "DF", 0, 0U, 0, 0);
    leaf_set(nd, 1, "SP", 0, 0U, 0, 0);
    db_init(&db, nt, 2, nd, 2, 0);

    r0 = look_v4(&db, "0.0.0.0");             /* bit0=0 -> node1 -> "SP" */
    r1 = look_v4(&db, "128.0.0.0");           /* bit0=1 -> no child -> "DF" */
    ASSERT_EQUAL('S', r0.country[0]);  ASSERT_EQUAL('P', r0.country[1]);
    ASSERT_EQUAL('D', r1.country[0]);  ASSERT_EQUAL('F', r1.country[1]);
}


/* ======================================================================= *
 *  V9  an internal node (net high-bit set) is NOT recorded as a leaf; a     *
 *  path of only-internal nodes yields no match.                            *
 * ======================================================================= */
CTEST(geo, internal_sentinel_not_a_leaf)
{
    u_char  nt[2 * 12], nd[12];
    ngx_http_heavybag_geo_db_t  db;
    ngx_http_heavybag_geo_result_t  r;

    node_set(nt, 0, 1, 0, SENT);              /* internal */
    node_set(nt, 1, 0, 0, SENT);              /* internal, terminal */
    leaf_set(nd, 0, "NO", 0, 0U, 0, 0);       /* present but never indexed */
    db_init(&db, nt, 2, nd, 1, 0);

    r = look_v4(&db, "0.0.0.0");
    ASSERT_EQUAL_U(0, r.found);
}


/* ======================================================================= *
 *  V10  /32 host leaf: the leaf is only reachable after all 32 v4 bits are  *
 *  consumed. A 33-node right-spine for 255.255.255.255; flipping the last   *
 *  bit (…254) must NOT match.                                              *
 * ======================================================================= */
CTEST(geo, v4_host_route_full_depth)
{
    u_char  nt[33 * 12], nd[12];
    ngx_http_heavybag_geo_db_t  db;
    ngx_http_heavybag_geo_result_t  r;
    uint32_t  i;

    memset(nt, 0, sizeof nt);
    for (i = 0; i < 32; i++) {
        node_set(nt, i, 0, i + 1, SENT);      /* bit1 -> next, internal */
    }
    node_set(nt, 32, 0, 0, 0);                /* depth-32 leaf 0 */
    leaf_set(nd, 0, "HX", 0, 0U, 0, 0);
    db_init(&db, nt, 33, nd, 1, 0);

    r = look_v4(&db, "255.255.255.255");
    ASSERT_EQUAL_U(1, r.found);
    ASSERT_EQUAL('H', r.country[0]);  ASSERT_EQUAL('X', r.country[1]);

    r = look_v4(&db, "255.255.255.254");      /* last bit 0 -> falls off */
    ASSERT_EQUAL_U(0, r.found);
}


/* ======================================================================= *
 *  V11  /128 host leaf: analogous to V10 over the full 128-bit v6 depth.    *
 * ======================================================================= */
CTEST(geo, v6_host_route_full_depth)
{
    u_char  nt[129 * 12], nd[12];
    ngx_http_heavybag_geo_db_t  db;
    ngx_http_heavybag_geo_result_t  r;
    uint32_t  i;

    memset(nt, 0, sizeof nt);
    for (i = 0; i < 128; i++) {
        node_set(nt, i, 0, i + 1, SENT);
    }
    node_set(nt, 128, 0, 0, 0);               /* depth-128 leaf 0 */
    leaf_set(nd, 0, "H6", 0, 0U, 0, 0);
    db_init(&db, nt, 129, nd, 1, 0);

    r = look_v6(&db, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    ASSERT_EQUAL_U(1, r.found);
    ASSERT_EQUAL('H', r.country[0]);  ASSERT_EQUAL('6', r.country[1]);

    r = look_v6(&db, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe");
    ASSERT_EQUAL_U(0, r.found);
}


/* ======================================================================= *
 *  V12  ND-leaf bound off-by-one: the last in-range leaf (idx M-1, whose    *
 *  end == block_len) is accepted; leaf idx M (one past) is rejected.       *
 *  block_len[ND] = 2*12 = 24; leaf 1 ends at 24 (OK), leaf 2 ends at 36.   *
 * ======================================================================= */
CTEST(geo, nd_leaf_bound_off_by_one)
{
    u_char  nt[2 * 12], nd[2 * 12];
    ngx_http_heavybag_geo_db_t  db;
    ngx_http_heavybag_geo_result_t  r0, r1;

    node_set(nt, 0, 1, 0, 1);                 /* bit0=1 path: net=leaf 1 (OK) */
    node_set(nt, 1, 0, 0, 2);                 /* bit0=0 path: net=leaf 2 (oob) */
    leaf_set(nd, 0, "L0", 0, 0U, 0, 0);
    leaf_set(nd, 1, "L1", 0, 0U, 0, 0);
    db_init(&db, nt, 2, nd, 2 /* block_len = 24 */, 0);

    /* 128.0.0.0: bit0=1 -> stays at node0, net=leaf1 -> last valid leaf */
    r1 = look_v4(&db, "128.0.0.0");
    ASSERT_EQUAL_U(1, r1.found);
    ASSERT_EQUAL('L', r1.country[0]);  ASSERT_EQUAL('1', r1.country[1]);

    /* 0.0.0.0: bit0=0 -> node1, net=leaf2 -> one past block_len -> rejected */
    r0 = look_v4(&db, "0.0.0.0");
    ASSERT_EQUAL_U(0, r0.found);
}


/* ======================================================================= *
 *  V13  NT-node bound off-by-one: a node sitting exactly at block_len is    *
 *  walkable; a child index one node past block_len makes the walk return   *
 *  no-match (the whole 12-byte node must fit, never an over-read).         *
 *  block_len[NT] = 2*12 = 24: node1 ends at 24 (OK), node2 would end at 36. *
 * ======================================================================= */
CTEST(geo, nt_node_bound_off_by_one)
{
    u_char  nt[2 * 12], nd[12];
    ngx_http_heavybag_geo_db_t  db;
    ngx_http_heavybag_geo_result_t  r1, r2;

    /* In-bounds path: node0 bit0=1 -> node1 (last node, exact boundary). */
    node_set(nt, 0, 2 /*oob*/, 1 /*node1*/, SENT);
    node_set(nt, 1, 0, 0, 0);                 /* node1 carries leaf 0 */
    leaf_set(nd, 0, "OK", 0, 0U, 0, 0);
    db_init(&db, nt, 2, nd, 1 /* nt block_len = 24 */, 0);

    r1 = look_v4(&db, "128.0.0.0");           /* bit0=1 -> node1 (exact bound) */
    ASSERT_EQUAL_U(1, r1.found);
    ASSERT_EQUAL('O', r1.country[0]);  ASSERT_EQUAL('K', r1.country[1]);

    /* 0.0.0.0 -> bit0=0 -> node0.left==2 -> off=24, off+12=36 > 24 -> -1 */
    r2 = look_v4(&db, "0.0.0.0");
    ASSERT_EQUAL_U(0, r2.found);
}


/* ======================================================================= *
 *  V14  leaf index near UINT32_MAX: net=0x7FFFFFFF (high bit clear, so it   *
 *  is a leaf index, not the internal sentinel). The lookup bound            *
 *  (size_t)net*12+12 must reject it WITHOUT a 32-bit multiply wrap.         *
 * ======================================================================= */
CTEST(geo, leaf_index_near_uint32_max_no_wrap)
{
    u_char  nt[12], nd[12];
    ngx_http_heavybag_geo_db_t  db;
    ngx_http_heavybag_geo_result_t  r;

    node_set(nt, 0, 0, 0, 0x7FFFFFFFU);       /* huge leaf index */
    leaf_set(nd, 0, "ZZ", 0, 0U, 0, 0);
    db_init(&db, nt, 1, nd, 1 /* block_len = 12 */, 0);

    r = look_v4(&db, "1.2.3.4");
    ASSERT_EQUAL_U(0, r.found);               /* rejected, no wrap, no crash */
}


/* ======================================================================= *
 *  V15  child index near UINT32_MAX: a child pointer of 0xFFFFFFFE makes    *
 *  off=(size_t)nxt*12 huge; off+12 > ntlen must reject in size_t (no 32-bit *
 *  wrap, no over-read).                                                    *
 * ======================================================================= */
CTEST(geo, node_index_near_uint32_max_no_wrap)
{
    u_char  nt[12], nd[12];
    ngx_http_heavybag_geo_db_t  db;
    ngx_http_heavybag_geo_result_t  r;

    node_set(nt, 0, 0xFFFFFFFEU, 0, SENT);    /* bit0 -> huge child */
    leaf_set(nd, 0, "ZZ", 0, 0U, 0, 0);
    db_init(&db, nt, 1, nd, 1, 0);

    r = look_v4(&db, "0.0.0.0");              /* bit0=0 -> huge child -> -1 */
    ASSERT_EQUAL_U(0, r.found);
}


/* ======================================================================= *
 *  V16  self-referential child cannot hang: node0.left -> node0. The walk   *
 *  is bounded by the address length (mask>>3 >= addrlen breaks), so it      *
 *  terminates after at most 32 (v4) iterations and returns the recorded     *
 *  leaf. If this looped forever the test process would never exit.         *
 * ======================================================================= */
CTEST(geo, self_loop_terminates)
{
    u_char  nt[2 * 12], nd[12];
    ngx_http_heavybag_geo_db_t  db;
    ngx_http_heavybag_geo_result_t  r;

    /*
     * Index 0 is the terminal sentinel (a child of 0 stops the walk), so a
     * genuine self-loop needs a non-zero node that points at itself. Root the
     * v4 walk at node 1 and make its bit0 child == node 1.
     */
    node_set(nt, 0, 0, 0, SENT);              /* unused placeholder */
    node_set(nt, 1, 1, 0, 0);                 /* node1: bit0 -> self, leaf 0 */
    leaf_set(nd, 0, "LP", 0, 0U, 0, 0);
    db_init(&db, nt, 2, nd, 1, 1 /* ipv4root = node1 */);

    /* 0.0.0.0: bit0 always 0 -> node1 -> node1 -> ... bounded by 32 bits */
    r = look_v4(&db, "0.0.0.0");
    ASSERT_EQUAL_U(1, r.found);               /* terminated, recorded leaf 0 */
    ASSERT_EQUAL('L', r.country[0]);  ASSERT_EQUAL('P', r.country[1]);
}


/* ======================================================================= *
 *  V17  single-node tree (block_len[NT] == 12): root only. Both a leaf      *
 *  root and an internal-only root behave cleanly (no over-read at the       *
 *  one-node boundary).                                                     *
 * ======================================================================= */
CTEST(geo, single_node_tree)
{
    u_char  nt[12], nd[12];
    ngx_http_heavybag_geo_db_t  db;
    ngx_http_heavybag_geo_result_t  r;

    /* leaf root */
    node_set(nt, 0, 0, 0, 0);
    leaf_set(nd, 0, "S1", 0, 0U, 0, 0);
    db_init(&db, nt, 1, nd, 1, 0);
    r = look_v4(&db, "9.9.9.9");
    ASSERT_EQUAL_U(1, r.found);
    ASSERT_EQUAL('S', r.country[0]);  ASSERT_EQUAL('1', r.country[1]);

    /* internal-only root -> no leaf anywhere */
    node_set(nt, 0, 0, 0, SENT);
    db_init(&db, nt, 1, nd, 1, 0);
    r = look_v4(&db, "9.9.9.9");
    ASSERT_EQUAL_U(0, r.found);
}


/* ======================================================================= *
 *  V18  unsupported address family (AF_UNIX) -> clean no-match, no walk.    *
 * ======================================================================= */
CTEST(geo, unknown_family_no_match)
{
    u_char  nt[12], nd[12];
    ngx_http_heavybag_geo_db_t  db;
    struct sockaddr                 sa;
    ngx_http_heavybag_geo_result_t  r;

    node_set(nt, 0, 0, 0, 0);
    leaf_set(nd, 0, "NO", 0, 0U, 0, 0);
    db_init(&db, nt, 1, nd, 1, 0);

    memset(&sa, 0, sizeof sa);
    sa.sa_family = AF_UNIX;
    memset(&r, 0xff, sizeof r);
    ngx_http_heavybag_geo_lookup(&db, &sa, &r);
    ASSERT_EQUAL_U(0, r.found);
}


/* ======================================================================= *
 *  V19  NULL db and NULL sockaddr -> clean no-match, no crash.             *
 * ======================================================================= */
CTEST(geo, null_db_and_null_sockaddr)
{
    u_char  nt[12], nd[12];
    ngx_http_heavybag_geo_db_t  db;
    struct sockaddr_in              sin;
    ngx_http_heavybag_geo_result_t  r;

    node_set(nt, 0, 0, 0, 0);
    leaf_set(nd, 0, "NO", 0, 0U, 0, 0);
    db_init(&db, nt, 1, nd, 1, 0);
    mk_v4(&sin, "1.2.3.4");

    /* NULL db */
    memset(&r, 0xff, sizeof r);
    ngx_http_heavybag_geo_lookup(NULL, (struct sockaddr *) &sin, &r);
    ASSERT_EQUAL_U(0, r.found);

    /* NULL sockaddr */
    memset(&r, 0xff, sizeof r);
    ngx_http_heavybag_geo_lookup(&db, NULL, &r);
    ASSERT_EQUAL_U(0, r.found);
}


/* ======================================================================= *
 *  V20  MSB-first bit extraction: bit 0 is the most-significant bit of      *
 *  byte 0, so 0.0.0.0 routes left (bit0=0) and 128.0.0.0 routes right       *
 *  (bit0=1) to distinct leaves.                                            *
 * ======================================================================= */
CTEST(geo, msb_first_bit_direction)
{
    u_char  nt[3 * 12], nd[2 * 12];
    ngx_http_heavybag_geo_db_t  db;
    ngx_http_heavybag_geo_result_t  rl, rr;

    node_set(nt, 0, 1, 2, SENT);              /* bit0=0 -> node1, bit0=1 -> node2 */
    node_set(nt, 1, 0, 0, 0);                 /* left leaf 0 */
    node_set(nt, 2, 0, 0, 1);                 /* right leaf 1 */
    leaf_set(nd, 0, "LL", 0, 0U, 0, 0);
    leaf_set(nd, 1, "RR", 0, 0U, 0, 0);
    db_init(&db, nt, 3, nd, 2, 0);

    rl = look_v4(&db, "0.0.0.0");             /* MSB 0 */
    rr = look_v4(&db, "128.0.0.0");           /* MSB 1 (0x80) */
    ASSERT_EQUAL('L', rl.country[0]);  ASSERT_EQUAL('L', rl.country[1]);
    ASSERT_EQUAL('R', rr.country[0]);  ASSERT_EQUAL('R', rr.country[1]);
}


/* ======================================================================= *
 *  Config-time loader predicates (T2 fix round). geo_open() itself stays    *
 *  behind #ifndef (ngx_conf_t + mmap + OpenSSL), but the two decisions it    *
 *  makes over untrusted bytes are pure helpers and ARE reachable here.       *
 * ======================================================================= */

#define V4ROOT_NODES  97          /* nodes 0..95 walked + node 96 = the root */

/*
 * A well-formed ::ffff:0:0/96 spine: node i -> node i+1, through the bit0
 * child for the first 80 steps (the leading zeroes) and the bit1 child for
 * the last 16 (the 0xffff marker), so the descent ends on node 96.
 */
static void
build_v4root_spine(u_char *nt)
{
    uint32_t  i;

    memset(nt, 0, (size_t) V4ROOT_NODES * 12);

    for (i = 0; i < 80; i++) {
        node_set(nt, i, i + 1, 0, SENT);      /* bit0 child -> next node */
    }
    for (i = 80; i < 96; i++) {
        node_set(nt, i, 0, i + 1, SENT);      /* bit1 child -> next node */
    }
    node_set(nt, 96, 0, 0, 0);                /* the IPv4-mapped root itself */
}


/* ======================================================================= *
 *  V21  a complete /96 chain descends to the IPv4-mapped root (no false     *
 *  rejection introduced by the terminator check).                          *
 * ======================================================================= */
CTEST(geo, ipv4root_descent_ok)
{
    u_char    nt[V4ROOT_NODES * 12];
    uint32_t  root = 0xDEADBEEFU;

    build_v4root_spine(nt);

    ASSERT_EQUAL(NGX_HTTP_HEAVYBAG_GEO_V4ROOT_OK,
        (int) ngx_http_heavybag_geo_ipv4root(nt, (uint32_t) sizeof nt, &root));
    ASSERT_EQUAL_U(96U, root);
}


/* ======================================================================= *
 *  V22  (#8 / SV3) a zero child ANYWHERE above depth 96 is the trie's      *
 *  terminal sentinel, so the /96 chain is short: the load must FAIL.       *
 *  Pre-fix the descent ignored it, re-read node 0 (always in bounds, so    *
 *  the bounds check never fired) and kept going, silently adopting a bogus *
 *  ipv4root -- every IPv4 lookup then walked the wrong subtree. Break at 0 *
 *  is the all-zero-tree case; 79/80 straddle the bit0 -> bit1 switch.      *
 * ======================================================================= */
CTEST(geo, ipv4root_zero_child_before_96_fails)
{
    static const uint32_t  breaks[] = { 0, 1, 40, 79, 80, 90, 94 };

    u_char      nt[V4ROOT_NODES * 12];
    uint32_t    root;
    ngx_uint_t  k;

    for (k = 0; k < sizeof breaks / sizeof breaks[0]; k++) {
        build_v4root_spine(nt);
        node_set(nt, breaks[k], 0, 0, SENT);   /* both children terminal */

        root = 0xDEADBEEFU;
        ASSERT_EQUAL(NGX_HTTP_HEAVYBAG_GEO_V4ROOT_DEADEND,
            (int) ngx_http_heavybag_geo_ipv4root(nt, (uint32_t) sizeof nt,
                                                 &root));
        ASSERT_EQUAL_U(0xDEADBEEFU, root);     /* untouched on failure */
    }
}


/* ======================================================================= *
 *  V23  boundary: a zero produced by the LAST (96th) step is a dead end     *
 *  TOO. The chain is walked in full, but it names node 0 -- the depth-0 v6  *
 *  root -- as the IPv4 root, which is the same broken state V22 catches:    *
 *  a bogus ipv4root, so every IPv4 lookup walks the wrong subtree. In an    *
 *  intact DB index 0 is depth 0 and is never a valid IPv4 root, so this is  *
 *  rejected fail-closed rather than adopted. (Pre-fix the descent exempted  *
 *  the 96th step via `i + 1 < 96` and returned root == 0.)                  *
 * ======================================================================= */
CTEST(geo, ipv4root_zero_child_at_last_step_fails)
{
    u_char    nt[V4ROOT_NODES * 12];
    uint32_t  root = 0xDEADBEEFU;

    build_v4root_spine(nt);
    node_set(nt, 95, 0, 0, SENT);   /* step 95 reads node 95's bit1 child: 0 */

    ASSERT_EQUAL(NGX_HTTP_HEAVYBAG_GEO_V4ROOT_DEADEND,
        (int) ngx_http_heavybag_geo_ipv4root(nt, (uint32_t) sizeof nt, &root));
    ASSERT_EQUAL_U(0xDEADBEEFU, root);     /* untouched on failure */
}


/* ======================================================================= *
 *  V24  a node that does not fit inside the network-tree block aborts the   *
 *  descent (whole 12-byte node required, never a partial over-read). The    *
 *  descent reads nodes 0..95, so 96 nodes are exactly enough and 95 are    *
 *  one short.                                                              *
 * ======================================================================= */
CTEST(geo, ipv4root_truncated_tree_fails)
{
    u_char    nt[V4ROOT_NODES * 12];
    uint32_t  root;

    build_v4root_spine(nt);

    root = 0xDEADBEEFU;
    ASSERT_EQUAL(NGX_HTTP_HEAVYBAG_GEO_V4ROOT_TRUNC,
        (int) ngx_http_heavybag_geo_ipv4root(nt, 40 * 12, &root));
    ASSERT_EQUAL_U(0xDEADBEEFU, root);

    /* exact fit: node 95 ends at 96*12 == block_len */
    root = 0xDEADBEEFU;
    ASSERT_EQUAL(NGX_HTTP_HEAVYBAG_GEO_V4ROOT_OK,
        (int) ngx_http_heavybag_geo_ipv4root(nt, 96 * 12, &root));
    ASSERT_EQUAL_U(96U, root);

    /* one node short: the last step no longer fits */
    root = 0xDEADBEEFU;
    ASSERT_EQUAL(NGX_HTTP_HEAVYBAG_GEO_V4ROOT_TRUNC,
        (int) ngx_http_heavybag_geo_ipv4root(nt, 95 * 12, &root));
    ASSERT_EQUAL_U(0xDEADBEEFU, root);
}


/* ======================================================================= *
 *  V25  (SV4, CWE-190 -> 125) block-table bounds are width-independent:     *
 *  off+len must not be able to wrap a 32-bit size_t into a "fits" verdict.  *
 * ======================================================================= */
CTEST(geo, block_bounds_width_independent)
{
    const size_t  size = 4200;                 /* a minimum-size DB */

    /* in bounds, including the exact end-of-file fit */
    ASSERT_FALSE(ngx_http_heavybag_geo_block_oob(0, 0, size) != 0);
    ASSERT_FALSE(ngx_http_heavybag_geo_block_oob(0, 4200, size) != 0);
    ASSERT_FALSE(ngx_http_heavybag_geo_block_oob(4200, 0, size) != 0);
    ASSERT_FALSE(ngx_http_heavybag_geo_block_oob(4000, 200, size) != 0);

    /* one byte past the end; and an offset past the end on its own */
    ASSERT_TRUE(ngx_http_heavybag_geo_block_oob(4000, 201, size) != 0);
    ASSERT_TRUE(ngx_http_heavybag_geo_block_oob(4201, 0, size) != 0);

    /* a length that alone exceeds the file, from an in-range offset */
    ASSERT_TRUE(ngx_http_heavybag_geo_block_oob(8, 0xFFFFFFFFU, size) != 0);

    /*
     * The pre-fix predicate was `(size_t) off + len > size`. On an ILP32
     * build size_t IS 32 bits, so off=0xfffffff0 + len=0x20 wraps to 0x10 and
     * the block was accepted -- db->block[i] would then be base + 0xfffffff0,
     * far outside the mapping. The wrapped arithmetic is spelled out at fixed
     * 32-bit width so this reproduces on an LP64 host too (where the pre-fix
     * form happened to be safe); the shipped predicate must disagree with it.
     */
    ASSERT_EQUAL_U(0x10U, (uint32_t) (0xFFFFFFF0U + 0x20U));
    ASSERT_FALSE((uint32_t) (0xFFFFFFF0U + 0x20U) > (uint32_t) size);
    ASSERT_TRUE(ngx_http_heavybag_geo_block_oob(0xFFFFFFF0U, 0x20U, size) != 0);
}


/* ======================================================================= *
 *  V26  (SV4, CWE-190 -> 125) the SAME width-independence requirement for   *
 *  the 12-byte ENTRY index -- the node/leaf counterpart of V25. One helper, *
 *  ngx_http_heavybag_geo_entry_oob, now backs all three index sites: the    *
 *  /96 descent, the runtime walker, and the leaf decode in _lookup.         *
 *                                                                          *
 *  Exact-arithmetic half: `idx*12 + 12 <= len` must equal `idx < len/12`,   *
 *  including a trailing PARTIAL entry (len not a multiple of 12), which     *
 *  must not be walkable.                                                   *
 *                                                                          *
 *  Wrap half: the pre-fix bound was `(size_t) idx * 12 + 12 > len`. On an   *
 *  ILP32 build size_t IS 32 bits, so the product folds over. The arithmetic *
 *  is spelled out at fixed 32-bit width below, which is why it reproduces   *
 *  on an LP64 host too -- where the pre-fix form happened to be safe. So    *
 *  this test would NOT have failed before the fix on this host; the         *
 *  written-out fold IS the evidence, and what is required of the shipped    *
 *  predicate is that it disagree with it. (Same construction and same       *
 *  honesty caveat as V25.)                                                  *
 * ======================================================================= */
CTEST(geo, entry_bounds_width_independent)
{
    /* 100 whole entries */
    ASSERT_FALSE(ngx_http_heavybag_geo_entry_oob(0, 100 * 12) != 0);
    ASSERT_FALSE(ngx_http_heavybag_geo_entry_oob(99, 100 * 12) != 0);
    ASSERT_TRUE(ngx_http_heavybag_geo_entry_oob(100, 100 * 12) != 0);

    /* single-entry and empty blocks */
    ASSERT_FALSE(ngx_http_heavybag_geo_entry_oob(0, 12) != 0);
    ASSERT_TRUE(ngx_http_heavybag_geo_entry_oob(1, 12) != 0);
    ASSERT_TRUE(ngx_http_heavybag_geo_entry_oob(0, 0) != 0);

    /* trailing partial entry: 20 bytes hold entry 0 only, never entry 1 */
    ASSERT_FALSE(ngx_http_heavybag_geo_entry_oob(0, 20) != 0);
    ASSERT_TRUE(ngx_http_heavybag_geo_entry_oob(1, 20) != 0);
    ASSERT_TRUE(ngx_http_heavybag_geo_entry_oob(1, 23) != 0);
    ASSERT_FALSE(ngx_http_heavybag_geo_entry_oob(1, 24) != 0);

    /*
     * Vector A -- idx = 0x7fffffff, the LARGEST index the leaf path can
     * carry (0x80000000 is the internal-node marker, so a leaf index is at
     * most 0x7fffffff; V14 feeds exactly this value through _lookup). At
     * 32-bit width idx*12 folds to 0xfffffff4 and idx*12+12 folds to
     * EXACTLY 0 -- so the pre-fix bound read "0 > len", false, i.e. IN
     * BOUNDS for every block length there is, and the decode then indexed
     * block + 0xfffffff4.
     */
    ASSERT_EQUAL_U(0xFFFFFFF4U, (uint32_t) (0x7FFFFFFFU * 12U));
    ASSERT_EQUAL_U(0U, (uint32_t) (0x7FFFFFFFU * 12U + 12U));
    ASSERT_FALSE((uint32_t) (0x7FFFFFFFU * 12U + 12U) > (uint32_t) (100 * 12));
    ASSERT_TRUE(ngx_http_heavybag_geo_entry_oob(0x7FFFFFFFU, 100 * 12) != 0);
    ASSERT_TRUE(ngx_http_heavybag_geo_entry_oob(0x7FFFFFFFU, 0xFFFFFFF0U) != 0);

    /*
     * Vector B -- idx = 357913941 (0x15555555): idx*12 folds to 0xfffffffc
     * and idx*12+12 to 8, likewise "in bounds" pre-fix. A node index is not
     * masked at all, so the walker could carry this straight from the DB.
     */
    ASSERT_EQUAL_U(0xFFFFFFFCU, (uint32_t) (357913941U * 12U));
    ASSERT_EQUAL_U(8U, (uint32_t) (357913941U * 12U + 12U));
    ASSERT_FALSE((uint32_t) (357913941U * 12U + 12U) > (uint32_t) (100 * 12));
    ASSERT_TRUE(ngx_http_heavybag_geo_entry_oob(357913941U, 100 * 12) != 0);

    /* 0xffffffff, for completeness: folds to 0xfffffff4 + 12 == 0 as well */
    ASSERT_TRUE(ngx_http_heavybag_geo_entry_oob(0xFFFFFFFFU, 100 * 12) != 0);
}


int
main(int argc, const char *argv[])
{
    return ctest_main(argc, argv);
}
