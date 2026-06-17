/*
 * Unit tests for the pure JA4 core (ngx_http_heavybag_ja4_build).
 *
 * Compiled standalone: includes heavybag_ja4.c under -DHEAVYBAG_JA4_UNIT_TEST so only the
 * nginx-free core is pulled in (no nginx / SSL headers). Built + run by
 * run-unit-tests.sh with `cc -DHEAVYBAG_JA4_UNIT_TEST -lcrypto`.
 */

#ifndef HEAVYBAG_JA4_UNIT_TEST
#define HEAVYBAG_JA4_UNIT_TEST
#endif
#include "../../src/heavybag_ja4.c"

#define CTEST_MAIN
#include "ctest.h"

#include <string.h>


/*
 * The FoxIO canonical example. Cipher / extension order here is deliberately
 * the raw ClientHello order (GREASE included): the core filters GREASE, sorts
 * ciphers and extensions, and keeps signature algorithms in original order.
 * The expected fingerprint is the published FoxIO value.
 */
static const uint16_t  canon_ciphers[] = {
    0x5a5a,                         /* GREASE -> dropped               */
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9,
    0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035
};

static const uint16_t  canon_exts[] = {
    0xfafa, 0x1a1a,                 /* GREASE -> dropped               */
    0x0000,                         /* SNI    -> counted, not in _c    */
    0x0010,                         /* ALPN   -> counted, not in _c    */
    0x0005, 0x000a, 0x000b, 0x000d, 0x0012, 0x0015, 0x0017, 0x001b,
    0x0023, 0x002b, 0x002d, 0x0033, 0x4469, 0xff01
};

/* signature_algorithms (ext 0x000d) values, ORIGINAL order -> feeds _c */
static const uint16_t  canon_sigalgs[] = {
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601
};

static const uint8_t   canon_alpn[] = { 'h', '2' };


CTEST(ja4, foxio_canonical_vector)
{
    char  out[HEAVYBAG_JA4_LEN];
    int   rc;

    rc = ngx_http_heavybag_ja4_build(
        canon_ciphers, sizeof(canon_ciphers) / sizeof(canon_ciphers[0]),
        canon_exts,    sizeof(canon_exts)    / sizeof(canon_exts[0]),
        canon_sigalgs, sizeof(canon_sigalgs) / sizeof(canon_sigalgs[0]),
        canon_alpn,    sizeof(canon_alpn),
        0x0304 /* TLS 1.3 */, 0 /* not QUIC */, out);

    ASSERT_EQUAL(0, rc);
    ASSERT_STR("t13d1516h2_8daaf6152771_e5627efa2ab1", out);
}


/* GREASE values must be dropped from BOTH the counts and the hashes: the
 * fingerprint of a hello with extra GREASE must equal the one without. */
CTEST(ja4, grease_is_filtered)
{
    static const uint16_t  with_grease[]  = { 0x0a0a, 0x1301, 0x1a1a, 0x1302,
                                              0xfafa };
    static const uint16_t  without[]      = { 0x1301, 0x1302 };
    static const uint16_t  exts[]         = { 0x0000, 0x000d };
    char  a[HEAVYBAG_JA4_LEN];
    char  b[HEAVYBAG_JA4_LEN];

    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(with_grease, 5, exts, 2,
                     NULL, 0, NULL, 0, 0x0303, 0, a));
    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(without, 2, exts, 2,
                     NULL, 0, NULL, 0, 0x0303, 0, b));

    /* identical non-GREASE input -> identical fingerprint (cipher count "02") */
    ASSERT_STR(a, b);
    ASSERT_EQUAL('0', a[4]);
    ASSERT_EQUAL('2', a[5]);
}


/* A non-alphanumeric ALPN end byte is hex-escaped, never emitted raw. */
CTEST(ja4, alpn_hex_fallback)
{
    static const uint16_t  ciphers[] = { 0x1301 };
    static const uint16_t  exts[]    = { 0x0000 };
    static const uint8_t   alpn[]    = { 0x01, 0xff };   /* both non-alnum */
    char  out[HEAVYBAG_JA4_LEN];

    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(ciphers, 1, exts, 1, NULL, 0,
                     alpn, sizeof(alpn), 0x0304, 0, out));

    /* bytes 8-9 = high nibble of 0x01 ('0'), low nibble of 0xff ('f') */
    ASSERT_EQUAL('0', out[8]);
    ASSERT_EQUAL('f', out[9]);
}


/* No ALPN -> "00"; protocol char 'q' for QUIC. */
CTEST(ja4, no_alpn_and_quic)
{
    static const uint16_t  ciphers[] = { 0x1301 };
    static const uint16_t  exts[]    = { 0x0000 };
    char  out[HEAVYBAG_JA4_LEN];

    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(ciphers, 1, exts, 1, NULL, 0,
                     NULL, 0, 0x0304, 1 /* QUIC */, out));

    ASSERT_EQUAL('q', out[0]);
    ASSERT_EQUAL('0', out[8]);
    ASSERT_EQUAL('0', out[9]);
}


/*
 * ja4-01: with every extension excluded (SNI + ALPN + GREASE only) AND no
 * sigalgs, the JA4_c input is empty. FoxIO renders an empty list as the literal
 * "000000000000", NOT sha256("")[:12] (e3b0c44298fc) -- otherwise a spoof /
 * blocklist lookup keyed on the canonical JA4 misses a degenerate, fully
 * attacker-controlled ClientHello. This pins the corrected canonical behavior.
 */
CTEST(ja4, empty_sigalgs_and_exts)
{
    static const uint16_t  ciphers[] = { 0x1301 };
    static const uint16_t  exts[]    = { 0x0000, 0x0010, 0x0a0a };
    char  out[HEAVYBAG_JA4_LEN];

    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(ciphers, 1, exts, 3, NULL, 0,
                     NULL, 0, 0x0304, 0, out));

    /* out = "t13d0100_<jb>_000000000000" ; check the trailing _c segment */
    ASSERT_STR("000000000000", out + HEAVYBAG_JA4_LEN - 1 - 12);
}


/*
 * ja4-01 (cipher side): an empty cipher list (only GREASE / no ciphers) must
 * render JA4_b as the literal "000000000000", not sha256("")[:12]. JA4_b
 * occupies out[11..22] -- after the 10-char _a segment and its '_'. A real
 * extension is supplied so only the cipher field is exercised.
 */
CTEST(ja4, empty_ciphers_canonical_zeros)
{
    static const uint16_t  ciphers[] = { 0x0a0a, 0x1a1a };  /* all GREASE */
    static const uint16_t  exts[]    = { 0x000d };          /* one real ext */
    char  out[HEAVYBAG_JA4_LEN];

    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(ciphers, 2, exts, 1, NULL, 0,
                     NULL, 0, 0x0304, 0, out));

    /* cipher count field (bytes 4-5) is "00" */
    ASSERT_EQUAL('0', out[4]);
    ASSERT_EQUAL('0', out[5]);
    /* JA4_b (out[11..22]) is the canonical literal zeros */
    ASSERT_EQUAL(0, memcmp(out + 11, "000000000000", 12));
}


/* Oversized cipher list: the 2-digit count clamps to 99 and nothing overflows. */
CTEST(ja4, count_clamp_no_overflow)
{
    uint16_t  ciphers[300];
    static const uint16_t  exts[] = { 0x0000 };
    char      out[HEAVYBAG_JA4_LEN];
    int       i;

    for (i = 0; i < 300; i++) {
        ciphers[i] = (uint16_t) (0x0100 + i);   /* none match GREASE */
    }

    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(ciphers, 300, exts, 1, NULL, 0,
                     NULL, 0, 0x0304, 0, out));

    /* cipher count field (bytes 4-5) clamps to "99" */
    ASSERT_EQUAL('9', out[4]);
    ASSERT_EQUAL('9', out[5]);
}


/* ====================================================================== *
 * Phase 4 (QA test-matrix) -- ja4-fuzz backlog, PURE-CORE subset.
 *
 * Every vector below drives ngx_http_heavybag_ja4_build() directly: count
 * clamps, GREASE filtering, sort-vs-original-order semantics, the ALPN byte
 * sink, and the version-code table. Assertions are STRUCTURAL/RELATIVE
 * (two builds compared, or fixed byte offsets in the JA4 string) so no
 * hand-computed SHA256 literal is needed (mirrors `grease_is_filtered`).
 *
 * JA4 string layout (HEAVYBAG_JA4_LEN = 37):
 *   [0]      protocol  't'|'q'
 *   [1..2]   version    "13"
 *   [3]      SNI        'd'|'i'
 *   [4..5]   cipher cnt  "NN"
 *   [6..7]   ext cnt     "NN"
 *   [8..9]   ALPN        two chars
 *   [10]     '_'
 *   [11..22] JA4_b       12 hex (cipher hash)
 *   [23]     '_'
 *   [24..35] JA4_c       12 hex (ext+sigalg hash)
 *
 * HONEST out-of-unit-scope (the live SSL extractor, Phase 6b wire-walk):
 * the inner-length-lying-past-body clamps for supported_versions / sigalgs /
 * ALPN, the odd-trailing-byte / dangling-half-entry drops, and the
 * 2-byte-per-cipher wire parse all live in ngx_http_heavybag_ja4_compute()
 * behind `#if (NGX_HTTP_SSL)` -- they parse raw SSL_client_hello getters into
 * the arrays this core consumes, and need a live SSL*. The core's contract
 * (it trusts the parsed arrays + their counts) is what these vectors pin.
 * ====================================================================== */

/* The extension count field (bytes 6-7) clamps to "99", like the cipher field. */
CTEST(ja4, ext_count_clamp_99)
{
    uint16_t  exts[150];
    static const uint16_t  ciphers[] = { 0x1301 };
    char      out[HEAVYBAG_JA4_LEN];
    int       i;

    for (i = 0; i < 150; i++) {
        exts[i] = (uint16_t) (0x0100 + i);   /* high byte 0x01/0x02: never GREASE/SNI/ALPN */
    }

    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(ciphers, 1, exts, 150, NULL, 0,
                     NULL, 0, 0x0304, 0, out));

    ASSERT_EQUAL('9', out[6]);
    ASSERT_EQUAL('9', out[7]);
}


/* HEAVYBAG_JA4_MAX_ELEMS (256) hash clamp: a 257-entry cipher list keeps only
 * the first 256 (input order) before the sort, so it hashes identically to its
 * 256-prefix -- no over-read, deterministic JA4_b. */
CTEST(ja4, max_elems_hash_clamp)
{
    uint16_t  c256[256];
    uint16_t  c257[257];
    static const uint16_t  exts[] = { 0x0000 };
    char      a[HEAVYBAG_JA4_LEN];
    char      b[HEAVYBAG_JA4_LEN];
    int       i;

    for (i = 0; i < 257; i++) {
        c257[i] = (uint16_t) (0x0100 + i);   /* ascending; 257th is the largest */
        if (i < 256) {
            c256[i] = (uint16_t) (0x0100 + i);
        }
    }

    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(c256, 256, exts, 1, NULL, 0,
                     NULL, 0, 0x0304, 0, a));
    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(c257, 257, exts, 1, NULL, 0,
                     NULL, 0, 0x0304, 0, b));

    ASSERT_EQUAL(0, memcmp(a + 11, b + 11, 12));   /* JA4_b identical: 257th dropped at cap */
}


/* Ciphers are sorted before hashing -> the fingerprint is input-order invariant. */
CTEST(ja4, cipher_order_independent)
{
    static const uint16_t  fwd[]  = { 0x1301, 0x1302, 0xc02b };
    static const uint16_t  rev[]  = { 0xc02b, 0x1302, 0x1301 };
    static const uint16_t  exts[] = { 0x0000 };
    char  a[HEAVYBAG_JA4_LEN];
    char  b[HEAVYBAG_JA4_LEN];

    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(fwd, 3, exts, 1, NULL, 0,
                     NULL, 0, 0x0304, 0, a));
    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(rev, 3, exts, 1, NULL, 0,
                     NULL, 0, 0x0304, 0, b));

    ASSERT_STR(a, b);
}


/* Extensions are sorted before hashing -> JA4_c is input-order invariant. */
CTEST(ja4, ext_order_independent)
{
    static const uint16_t  ciphers[] = { 0x1301 };
    static const uint16_t  fwd[]     = { 0x0005, 0x000a, 0x0017 };
    static const uint16_t  rev[]     = { 0x0017, 0x000a, 0x0005 };
    char  a[HEAVYBAG_JA4_LEN];
    char  b[HEAVYBAG_JA4_LEN];

    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(ciphers, 1, fwd, 3, NULL, 0,
                     NULL, 0, 0x0304, 0, a));
    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(ciphers, 1, rev, 3, NULL, 0,
                     NULL, 0, 0x0304, 0, b));

    ASSERT_STR(a, b);
}


/* Signature algorithms are kept in ORIGINAL ClientHello order (never sorted):
 * reversing them changes JA4_c while JA4_a + JA4_b stay byte-identical. This is
 * the one field whose order is significant -- the behavioral pin. */
CTEST(ja4, sigalg_order_preserved)
{
    static const uint16_t  ciphers[] = { 0x1301 };
    static const uint16_t  exts[]    = { 0x000d };
    static const uint16_t  fwd[]     = { 0x0403, 0x0804, 0x0401 };
    static const uint16_t  rev[]     = { 0x0401, 0x0804, 0x0403 };
    char  a[HEAVYBAG_JA4_LEN];
    char  b[HEAVYBAG_JA4_LEN];

    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(ciphers, 1, exts, 1, fwd, 3,
                     NULL, 0, 0x0304, 0, a));
    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(ciphers, 1, exts, 1, rev, 3,
                     NULL, 0, 0x0304, 0, b));

    ASSERT_EQUAL(0, memcmp(a, b, 23));               /* JA4_a + '_' + JA4_b same */
    ASSERT_NOT_EQUAL(0, memcmp(a + 24, b + 24, 12));  /* JA4_c differs (order kept) */
}


/* JA4 does not de-duplicate extensions: a repeated type is counted twice and
 * appears twice in the JA4_c list. */
CTEST(ja4, duplicate_ext_types_kept)
{
    static const uint16_t  ciphers[] = { 0x1301 };
    static const uint16_t  one[]     = { 0x0005 };
    static const uint16_t  two[]     = { 0x0005, 0x0005 };
    char  a[HEAVYBAG_JA4_LEN];
    char  b[HEAVYBAG_JA4_LEN];

    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(ciphers, 1, one, 1, NULL, 0,
                     NULL, 0, 0x0304, 0, a));
    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(ciphers, 1, two, 2, NULL, 0,
                     NULL, 0, 0x0304, 0, b));

    ASSERT_EQUAL('0', a[6]); ASSERT_EQUAL('1', a[7]);
    ASSERT_EQUAL('0', b[6]); ASSERT_EQUAL('2', b[7]);
    ASSERT_NOT_EQUAL(0, memcmp(a + 24, b + 24, 12));
}


/* Same for ciphers: a repeated suite is counted and hashed twice. */
CTEST(ja4, duplicate_ciphers_kept)
{
    static const uint16_t  one[]  = { 0x1301 };
    static const uint16_t  two[]  = { 0x1301, 0x1301 };
    static const uint16_t  exts[] = { 0x0000 };
    char  a[HEAVYBAG_JA4_LEN];
    char  b[HEAVYBAG_JA4_LEN];

    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(one, 1, exts, 1, NULL, 0,
                     NULL, 0, 0x0304, 0, a));
    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(two, 2, exts, 1, NULL, 0,
                     NULL, 0, 0x0304, 0, b));

    ASSERT_EQUAL('0', a[4]); ASSERT_EQUAL('1', a[5]);
    ASSERT_EQUAL('0', b[4]); ASSERT_EQUAL('2', b[5]);
    ASSERT_NOT_EQUAL(0, memcmp(a + 11, b + 11, 12));
}


/* All-GREASE ciphers AND all-GREASE extensions: both counts "00", both hash
 * fields the canonical literal zeros, SNI absent ('i'). A fully degenerate,
 * attacker-controlled hello canonicalizes deterministically. */
CTEST(ja4, all_grease_cipher_and_ext)
{
    static const uint16_t  ciphers[] = { 0x0a0a, 0x1a1a };
    static const uint16_t  exts[]    = { 0x2a2a, 0xeaea };
    char  out[HEAVYBAG_JA4_LEN];

    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(ciphers, 2, exts, 2, NULL, 0,
                     NULL, 0, 0x0304, 0, out));

    ASSERT_EQUAL('i', out[3]);
    ASSERT_EQUAL('0', out[4]); ASSERT_EQUAL('0', out[5]);
    ASSERT_EQUAL('0', out[6]); ASSERT_EQUAL('0', out[7]);
    ASSERT_EQUAL(0, memcmp(out + 11, "000000000000", 12));
    ASSERT_EQUAL(0, memcmp(out + 24, "000000000000", 12));
}


/* A non-NULL ALPN pointer with length 0 still renders the field as "00". */
CTEST(ja4, alpn_zero_len_is_00)
{
    static const uint16_t  ciphers[] = { 0x1301 };
    static const uint16_t  exts[]    = { 0x0000 };
    static const uint8_t   alpn[]    = { 'h', '2' };
    char  out[HEAVYBAG_JA4_LEN];

    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(ciphers, 1, exts, 1, NULL, 0,
                     alpn, 0, 0x0304, 0, out));

    ASSERT_EQUAL('0', out[8]);
    ASSERT_EQUAL('0', out[9]);
}


/* A leading NUL ALPN byte is non-alphanumeric -> hex-escaped, not emitted raw. */
CTEST(ja4, alpn_leading_nul_hex_escaped)
{
    static const uint16_t  ciphers[] = { 0x1301 };
    static const uint16_t  exts[]    = { 0x0000 };
    static const uint8_t   alpn[]    = { 0x00, 'h' };
    char  out[HEAVYBAG_JA4_LEN];

    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(ciphers, 1, exts, 1, NULL, 0,
                     alpn, sizeof(alpn), 0x0304, 0, out));

    /* high nibble of first byte 0x00 -> '0'; low nibble of last byte 'h'(0x68) -> '8' */
    ASSERT_EQUAL('0', out[8]);
    ASSERT_EQUAL('8', out[9]);
}


/* Only the first and last ALPN bytes drive the field; an interior NUL is
 * transparent (length-driven, not C-string). */
CTEST(ja4, alpn_interior_nul_transparent)
{
    static const uint16_t  ciphers[] = { 0x1301 };
    static const uint16_t  exts[]    = { 0x0000 };
    static const uint8_t   alpn[]    = { 'h', 0x00, '2' };
    char  out[HEAVYBAG_JA4_LEN];

    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(ciphers, 1, exts, 1, NULL, 0,
                     alpn, sizeof(alpn), 0x0304, 0, out));

    ASSERT_EQUAL('h', out[8]);
    ASSERT_EQUAL('2', out[9]);
}


/* Single-byte ALPN: alpn[0] == alpn[len-1], both ends the same char. */
CTEST(ja4, alpn_single_byte)
{
    static const uint16_t  ciphers[] = { 0x1301 };
    static const uint16_t  exts[]    = { 0x0000 };
    static const uint8_t   alpn[]    = { 'x' };
    char  out[HEAVYBAG_JA4_LEN];

    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(ciphers, 1, exts, 1, NULL, 0,
                     alpn, 1, 0x0304, 0, out));

    ASSERT_EQUAL('x', out[8]);
    ASSERT_EQUAL('x', out[9]);
}


/* Version-code table (bytes 1-2): legacy TLS + SSL 3.0. */
CTEST(ja4, version_codes_legacy)
{
    static const uint16_t  ciphers[] = { 0x1301 };
    static const uint16_t  exts[]    = { 0x0000 };
    char  out[HEAVYBAG_JA4_LEN];

    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(ciphers, 1, exts, 1, NULL, 0,
                     NULL, 0, 0x0302, 0, out));
    ASSERT_EQUAL('1', out[1]); ASSERT_EQUAL('1', out[2]);   /* TLS 1.1 */

    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(ciphers, 1, exts, 1, NULL, 0,
                     NULL, 0, 0x0301, 0, out));
    ASSERT_EQUAL('1', out[1]); ASSERT_EQUAL('0', out[2]);   /* TLS 1.0 */

    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(ciphers, 1, exts, 1, NULL, 0,
                     NULL, 0, 0x0300, 0, out));
    ASSERT_EQUAL('s', out[1]); ASSERT_EQUAL('3', out[2]);   /* SSL 3.0 */
}


/* Version-code table: DTLS variants + the unknown-version fallback "00". */
CTEST(ja4, version_codes_dtls_and_unknown)
{
    static const uint16_t  ciphers[] = { 0x1301 };
    static const uint16_t  exts[]    = { 0x0000 };
    char  out[HEAVYBAG_JA4_LEN];

    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(ciphers, 1, exts, 1, NULL, 0,
                     NULL, 0, 0xfeff, 0, out));
    ASSERT_EQUAL('d', out[1]); ASSERT_EQUAL('1', out[2]);   /* DTLS 1.0 */

    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(ciphers, 1, exts, 1, NULL, 0,
                     NULL, 0, 0xfefd, 0, out));
    ASSERT_EQUAL('d', out[1]); ASSERT_EQUAL('2', out[2]);   /* DTLS 1.2 */

    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(ciphers, 1, exts, 1, NULL, 0,
                     NULL, 0, 0xfefc, 0, out));
    ASSERT_EQUAL('d', out[1]); ASSERT_EQUAL('3', out[2]);   /* DTLS 1.3 */

    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(ciphers, 1, exts, 1, NULL, 0,
                     NULL, 0, 0x9999, 0, out));
    ASSERT_EQUAL('0', out[1]); ASSERT_EQUAL('0', out[2]);   /* unrecognised -> 00 */
}


/* SNI presence byte (out[3]): 'd' when ext 0x0000 is present, 'i' otherwise. */
CTEST(ja4, sni_presence_byte)
{
    static const uint16_t  ciphers[]  = { 0x1301 };
    static const uint16_t  with_sni[] = { 0x0000, 0x000d };
    static const uint16_t  no_sni[]   = { 0x000d };
    char  a[HEAVYBAG_JA4_LEN];
    char  b[HEAVYBAG_JA4_LEN];

    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(ciphers, 1, with_sni, 2, NULL, 0,
                     NULL, 0, 0x0304, 0, a));
    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(ciphers, 1, no_sni, 1, NULL, 0,
                     NULL, 0, 0x0304, 0, b));

    ASSERT_EQUAL('d', a[3]);
    ASSERT_EQUAL('i', b[3]);
}


/* SNI (0x0000) and ALPN (0x0010) are COUNTED in byte 6-7 but EXCLUDED from the
 * JA4_c hash: adding them bumps the count yet leaves the hash identical to the
 * bare ext-only build. */
CTEST(ja4, sni_alpn_counted_excluded_from_hash)
{
    static const uint16_t  ciphers[] = { 0x1301 };
    static const uint16_t  full[]    = { 0x0000, 0x0010, 0x000d };
    static const uint16_t  bare[]    = { 0x000d };
    char  a[HEAVYBAG_JA4_LEN];
    char  b[HEAVYBAG_JA4_LEN];

    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(ciphers, 1, full, 3, NULL, 0,
                     NULL, 0, 0x0304, 0, a));
    ASSERT_EQUAL(0, ngx_http_heavybag_ja4_build(ciphers, 1, bare, 1, NULL, 0,
                     NULL, 0, 0x0304, 0, b));

    ASSERT_EQUAL('0', a[6]); ASSERT_EQUAL('3', a[7]);   /* SNI+ALPN+sigalg-ext counted */
    ASSERT_EQUAL('0', b[6]); ASSERT_EQUAL('1', b[7]);
    ASSERT_EQUAL(0, memcmp(a + 24, b + 24, 12));         /* JA4_c identical */
}


/* A NULL out pointer is the one hard error the core returns (-1), never a write. */
CTEST(ja4, null_out_returns_error)
{
    static const uint16_t  ciphers[] = { 0x1301 };
    static const uint16_t  exts[]    = { 0x0000 };

    ASSERT_EQUAL(-1, ngx_http_heavybag_ja4_build(ciphers, 1, exts, 1, NULL, 0,
                     NULL, 0, 0x0304, 0, NULL));
}


int
main(int argc, const char *argv[])
{
    return ctest_main(argc, argv);
}
