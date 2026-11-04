/*
 * Unit tests for the constant-time secret compare of the mail auth_http trust
 * gate (ngx_http_heavybag_authhttp_secret_eq, heavybag_authhttp.c), the
 * authenticator behind caller_trusted (SV11, CWE-208).
 *
 * Compiled standalone: includes heavybag_authhttp.c under
 * -DHEAVYBAG_AUTHHTTP_UNIT_TEST, which swaps the nginx headers for a 3-type shim
 * (u_char, ngx_uint_t, ngx_str_t) and compiles out the nginx-coupled handler /
 * caller_trusted / header helpers. Only the pure compare is exercised here; the
 * wiring (peer class + X-WAF-Key header) is covered by the live mailauth fuzz.
 *
 * Signature: ngx_uint_t secret_eq(ngx_str_t *a, ngx_str_t *b). a is the
 * configured secret, b the caller-supplied key. Both pointers are dereferenced
 * unconditionally (callers always pass valid ngx_str_t), so a NULL ngx_str_t*
 * is NOT part of the contract and is not tested; the edge handling that IS
 * contractual is len == 0 (empty secret never authenticates, even vs empty).
 *
 * Timing (constant-time-ness) is not observable in a unit test; what is pinned
 * is the verdict across every position a short-circuiting compare would differ.
 */

#ifndef HEAVYBAG_AUTHHTTP_UNIT_TEST
#define HEAVYBAG_AUTHHTTP_UNIT_TEST
#endif

#include <string.h>

#include "../../src/heavybag_authhttp.c"

#define CTEST_MAIN
#include "ctest.h"


static ngx_str_t
mk(const char *s)
{
    ngx_str_t  r;

    r.len = strlen(s);
    r.data = (u_char *) s;
    return r;
}


CTEST(authhttp_secret_eq, equal)
{
    ngx_str_t  a = mk("hbtest-secret-0123456789");
    ngx_str_t  b = mk("hbtest-secret-0123456789");

    ASSERT_EQUAL(1, (int) ngx_http_heavybag_authhttp_secret_eq(&a, &b));
}

CTEST(authhttp_secret_eq, same_pointer_equal)
{
    ngx_str_t  a = mk("s3cret");

    ASSERT_EQUAL(1, (int) ngx_http_heavybag_authhttp_secret_eq(&a, &a));
}

CTEST(authhttp_secret_eq, single_byte_equal)
{
    ngx_str_t  a = mk("x");
    ngx_str_t  b = mk("x");
    ngx_str_t  c = mk("y");

    ASSERT_EQUAL(1, (int) ngx_http_heavybag_authhttp_secret_eq(&a, &b));
    ASSERT_EQUAL(0, (int) ngx_http_heavybag_authhttp_secret_eq(&a, &c));
}

CTEST(authhttp_secret_eq, differs_last_byte)
{
    ngx_str_t  a = mk("hbtest-secret-A");
    ngx_str_t  b = mk("hbtest-secret-B");

    ASSERT_EQUAL(0, (int) ngx_http_heavybag_authhttp_secret_eq(&a, &b));
}

CTEST(authhttp_secret_eq, differs_first_byte)
{
    ngx_str_t  a = mk("Abtest-secret-x");
    ngx_str_t  b = mk("Bbtest-secret-x");

    ASSERT_EQUAL(0, (int) ngx_http_heavybag_authhttp_secret_eq(&a, &b));
}

CTEST(authhttp_secret_eq, differs_middle_byte)
{
    ngx_str_t  a = mk("hbtest-secret-x");
    ngx_str_t  b = mk("hbtest-seCret-x");

    ASSERT_EQUAL(0, (int) ngx_http_heavybag_authhttp_secret_eq(&a, &b));
}

CTEST(authhttp_secret_eq, differs_only_high_bit)
{
    /* a 0x80 xor must not be lost to a narrowing/sign accumulator bug */
    u_char     da[] = { 'k', 'e', 'y', 0x41 };
    u_char     db[] = { 'k', 'e', 'y', 0xc1 };
    ngx_str_t  a = { sizeof da, da };
    ngx_str_t  b = { sizeof db, db };

    ASSERT_EQUAL(0, (int) ngx_http_heavybag_authhttp_secret_eq(&a, &b));
}

CTEST(authhttp_secret_eq, shorter_candidate_prefix)
{
    ngx_str_t  a = mk("hbtest-secret");
    ngx_str_t  b = mk("hbtest-secre");

    ASSERT_EQUAL(0, (int) ngx_http_heavybag_authhttp_secret_eq(&a, &b));
}

CTEST(authhttp_secret_eq, longer_candidate_extends_secret)
{
    ngx_str_t  a = mk("hbtest-secret");
    ngx_str_t  b = mk("hbtest-secret!");

    ASSERT_EQUAL(0, (int) ngx_http_heavybag_authhttp_secret_eq(&a, &b));
}

CTEST(authhttp_secret_eq, empty_candidate_vs_nonempty_secret)
{
    ngx_str_t  a = mk("hbtest-secret");
    ngx_str_t  b = mk("");

    ASSERT_EQUAL(0, (int) ngx_http_heavybag_authhttp_secret_eq(&a, &b));
}

CTEST(authhttp_secret_eq, empty_secret_vs_nonempty_candidate)
{
    ngx_str_t  a = mk("");
    ngx_str_t  b = mk("hbtest-secret");

    ASSERT_EQUAL(0, (int) ngx_http_heavybag_authhttp_secret_eq(&a, &b));
}

CTEST(authhttp_secret_eq, empty_vs_empty_never_matches)
{
    /* an unconfigured token must not authenticate anyone, even an empty key */
    ngx_str_t  a = mk("");
    ngx_str_t  b = mk("");

    ASSERT_EQUAL(0, (int) ngx_http_heavybag_authhttp_secret_eq(&a, &b));
}

CTEST(authhttp_secret_eq, zero_len_null_data)
{
    ngx_str_t  a = { 0, NULL };
    ngx_str_t  b = { 0, NULL };
    ngx_str_t  c = mk("hbtest-secret");

    ASSERT_EQUAL(0, (int) ngx_http_heavybag_authhttp_secret_eq(&a, &b));
    ASSERT_EQUAL(0, (int) ngx_http_heavybag_authhttp_secret_eq(&a, &c));
    ASSERT_EQUAL(0, (int) ngx_http_heavybag_authhttp_secret_eq(&c, &a));
}

CTEST(authhttp_secret_eq, embedded_nul_is_data)
{
    /* length-delimited, not C-string: bytes after a NUL still count */
    u_char     da[] = { 'a', 0, 'b' };
    u_char     db[] = { 'a', 0, 'c' };
    ngx_str_t  a = { sizeof da, da };
    ngx_str_t  b = { sizeof db, db };

    ASSERT_EQUAL(0, (int) ngx_http_heavybag_authhttp_secret_eq(&a, &b));
    ASSERT_EQUAL(1, (int) ngx_http_heavybag_authhttp_secret_eq(&a, &a));
}


int
main(int argc, const char *argv[])
{
    return ctest_main(argc, argv);
}
