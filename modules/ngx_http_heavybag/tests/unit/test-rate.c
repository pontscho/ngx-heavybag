/*
 * Unit tests for the pure token-bucket rate-limit core (heavybag_rate.c).
 *
 * Compiled standalone: includes heavybag_rate.c under -DHEAVYBAG_RATE_UNIT_TEST so
 * only the nginx-free core is pulled in (no nginx / SSL headers). The shim in
 * heavybag_rate.{h,c} substitutes nginx byte-for-byte; the real -Werror SSL
 * module build remains the correctness contract. Built + run by
 * run-unit-tests.sh with `cc -DHEAVYBAG_RATE_UNIT_TEST`.
 *
 * The slot/header structs and the static key/check core are reachable because
 * this TU includes the .c directly. The table is a flat malloc buffer
 * [hdr][slot x nslots]; time is driven through the writable ngx_current_msec
 * shim global.
 *
 * OUT OF UNIT SCOPE (honest limits, not faked here):
 *   - CAS starvation fail-open: the bounded state-CAS only loses single-shot
 *     under genuine multi-worker contention; single-threaded __sync always wins
 *     iteration 0. Covered by the CAS_MAX bound + the integration/stress layer.
 *   - waf_rate zone MIN_SLOTS back-off: lives in ngx_http_heavybag_rate_init_zone
 *     (slab/ngx_shm_zone_t coupled, behind #ifndef) -> config/integration layer.
 *   - hash==0 -> sentinel 1 remap: an IP whose 64-bit FNV is exactly 0 is not
 *     brute-forceable (2^-64); the always-nonzero invariant is asserted instead
 *     (fnv_key_never_zero).
 */

#ifndef HEAVYBAG_RATE_UNIT_TEST
#define HEAVYBAG_RATE_UNIT_TEST
#endif
#include "../../src/heavybag_rate.c"

#define CTEST_MAIN
#include "ctest.h"

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>


/* ---- table + sockaddr helpers ------------------------------------------ */

static ngx_http_heavybag_rate_hdr_t *
mk_table(ngx_uint_t n)
{
    size_t  sz = sizeof(ngx_http_heavybag_rate_hdr_t)
                 + (size_t) n * sizeof(ngx_http_heavybag_rate_slot_t);
    ngx_http_heavybag_rate_hdr_t  *hdr = calloc(1, sz);
    hdr->nslots = n;
    return hdr;
}

static ngx_http_heavybag_rate_slot_t *
slots_of(ngx_http_heavybag_rate_hdr_t *hdr)
{
    return (ngx_http_heavybag_rate_slot_t *) (hdr + 1);
}

/* locate the slot that ended up owning key h (open-addressing aware) */
static ngx_http_heavybag_rate_slot_t *
find_slot(ngx_http_heavybag_rate_hdr_t *hdr, uint64_t h)
{
    ngx_uint_t  n = hdr->nslots, p, idx = (ngx_uint_t) (h % n);
    ngx_http_heavybag_rate_slot_t  *slots = slots_of(hdr);

    for (p = 0; p < HEAVYBAG_RATE_PROBE_MAX; p++) {
        ngx_http_heavybag_rate_slot_t  *s = &slots[(idx + p) % n];
        if (s->key == h) {
            return s;
        }
    }
    return NULL;
}

static uint32_t tok_of(ngx_http_heavybag_rate_slot_t *s) { return (uint32_t) (s->state & 0xffffffff); }
static uint32_t ts_of(ngx_http_heavybag_rate_slot_t *s)  { return (uint32_t) (s->state >> 32); }

static void
mk_v4(struct sockaddr_in *sin, const char *ip)
{
    memset(sin, 0, sizeof(*sin));
    sin->sin_family = AF_INET;
    inet_pton(AF_INET, ip, &sin->sin_addr);
}

static void
mk_v6(struct sockaddr_in6 *s6, const char *ip)
{
    memset(s6, 0, sizeof(*s6));
    s6->sin6_family = AF_INET6;
    inet_pton(AF_INET6, ip, &s6->sin6_addr);
}

/* a fast rule: 10 r/s, burst 5 tokens (in SCALE fixed-point units) */
#define R_NUM   (10ULL * HEAVYBAG_RATE_SCALE)   /* 10/s numerator */
#define R_PER   1000U                            /* /s period      */
#define R_BURST (5U * HEAVYBAG_RATE_SCALE)       /* 5-token bucket */


/* ======================================================================= *
 *  V1  burst_fp==0 -> fail-open + one-shot ALERT (round-2 guard).          *
 *  Placed first: the ALERT is a process-static one-shot. We assert only    *
 *  the NGX_OK return (the no-op log shim is unobservable), so ordering is   *
 *  not load-bearing for the assertion -- but the contract is documented.   *
 * ======================================================================= */
CTEST(rate, burst_zero_failopen)
{
    ngx_http_heavybag_rate_hdr_t  *hdr = mk_table(64);
    struct sockaddr_in             sin;

    ngx_current_msec = 1000000;
    mk_v4(&sin, "10.0.0.1");

    ASSERT_EQUAL(NGX_OK,
        ngx_http_heavybag_rate_check(hdr, (struct sockaddr *) &sin,
                                     R_NUM, R_PER, 0 /* burst==0 */));
    free(hdr);
}


/* V2  period_ms==0 -> fail-open, no SIGFPE (round-2 div-by-zero guard) */
CTEST(rate, period_zero_failopen)
{
    ngx_http_heavybag_rate_hdr_t  *hdr = mk_table(64);
    struct sockaddr_in             sin;

    ngx_current_msec = 1000000;
    mk_v4(&sin, "10.0.0.2");

    ASSERT_EQUAL(NGX_OK,
        ngx_http_heavybag_rate_check(hdr, (struct sockaddr *) &sin,
                                     R_NUM, 0 /* period==0 */, R_BURST));
    free(hdr);
}


/* V3  NULL shm -> fail-open */
CTEST(rate, null_shm_failopen)
{
    struct sockaddr_in  sin;
    ngx_current_msec = 1000000;
    mk_v4(&sin, "10.0.0.3");
    ASSERT_EQUAL(NGX_OK,
        ngx_http_heavybag_rate_check(NULL, (struct sockaddr *) &sin,
                                     R_NUM, R_PER, R_BURST));
}


/* V4  nslots==0 -> fail-open */
CTEST(rate, zero_slots_failopen)
{
    ngx_http_heavybag_rate_hdr_t  *hdr = mk_table(0);
    struct sockaddr_in             sin;
    ngx_current_msec = 1000000;
    mk_v4(&sin, "10.0.0.4");
    ASSERT_EQUAL(NGX_OK,
        ngx_http_heavybag_rate_check(hdr, (struct sockaddr *) &sin,
                                     R_NUM, R_PER, R_BURST));
    free(hdr);
}


/* V5  unsupported family (AF_UNIX) -> key()==0 -> fail-open */
CTEST(rate, unknown_family_failopen)
{
    ngx_http_heavybag_rate_hdr_t  *hdr = mk_table(64);
    struct sockaddr                sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_family = AF_UNIX;
    ngx_current_msec = 1000000;
    ASSERT_EQUAL(NGX_OK,
        ngx_http_heavybag_rate_check(hdr, &sa, R_NUM, R_PER, R_BURST));
    free(hdr);
}


/* V6  NULL sockaddr -> key(NULL)==0 -> fail-open */
CTEST(rate, null_sockaddr_failopen)
{
    ngx_http_heavybag_rate_hdr_t  *hdr = mk_table(64);
    ngx_current_msec = 1000000;
    ASSERT_EQUAL(NGX_OK,
        ngx_http_heavybag_rate_check(hdr, NULL, R_NUM, R_PER, R_BURST));
    free(hdr);
}


/* ======================================================================= *
 *  V7  exact burst boundary: first touch fills to burst, the Nth request   *
 *  is allowed and the (N+1)th is denied with == NGX_BUSY (-3).             *
 * ======================================================================= */
CTEST(rate, exact_burst_boundary)
{
    ngx_http_heavybag_rate_hdr_t  *hdr = mk_table(64);
    struct sockaddr_in             sin;
    int                            i;

    ngx_current_msec = 1000000;            /* large enough -> first touch fills */
    mk_v4(&sin, "203.0.113.7");

    /* 5-token bucket: 5 allows, frozen clock so no refill between calls */
    for (i = 0; i < 5; i++) {
        ASSERT_EQUAL(NGX_OK,
            ngx_http_heavybag_rate_check(hdr, (struct sockaddr *) &sin,
                                         R_NUM, R_PER, R_BURST));
    }
    ASSERT_EQUAL(NGX_BUSY,
        ngx_http_heavybag_rate_check(hdr, (struct sockaddr *) &sin,
                                     R_NUM, R_PER, R_BURST));
    free(hdr);
}


/* ======================================================================= *
 *  V8  sub-ms refill rounds to 0 AND keeps the old stamp (anti-drift): a    *
 *  1 ms tick at 1 r/h yields added==0, so tokens are unchanged and the      *
 *  refill timestamp must NOT advance (else small rates drift downward).     *
 * ======================================================================= */
CTEST(rate, subms_refill_keeps_stamp)
{
    ngx_http_heavybag_rate_hdr_t  *hdr = mk_table(64);
    struct sockaddr_in             sin;
    uint64_t                       h;
    ngx_http_heavybag_rate_slot_t *s;
    uint32_t                       tok_after_first;
    const uint64_t                 num = 1ULL * HEAVYBAG_RATE_SCALE;   /* 1/h */
    const ngx_uint_t               per = 3600000U;
    const ngx_uint_t               burst = 10U * HEAVYBAG_RATE_SCALE;  /* 10 tok */
    const uint64_t                 base = 40000000ULL; /* >=36e6 -> first touch fills */

    mk_v4(&sin, "198.51.100.8");
    h = ngx_http_heavybag_rate_key((struct sockaddr *) &sin);

    ngx_current_msec = base;
    ASSERT_EQUAL(NGX_OK,
        ngx_http_heavybag_rate_check(hdr, (struct sockaddr *) &sin, num, per, burst));
    s = find_slot(hdr, h);
    ASSERT_NOT_NULL(s);
    tok_after_first = tok_of(s);
    ASSERT_EQUAL_U((uint32_t) base, ts_of(s));     /* stamp == first touch */

    ngx_current_msec = base + 1;                   /* +1 ms: added rounds to 0 */
    ASSERT_EQUAL(NGX_OK,
        ngx_http_heavybag_rate_check(hdr, (struct sockaddr *) &sin, num, per, burst));
    s = find_slot(hdr, h);
    /* one token consumed by the 2nd allow, none refilled */
    ASSERT_EQUAL_U(tok_after_first - HEAVYBAG_RATE_SCALE, tok_of(s));
    /* stamp preserved at base, NOT bumped to base+1 */
    ASSERT_EQUAL_U((uint32_t) base, ts_of(s));
    free(hdr);
}


/* ======================================================================= *
 *  V9  49-day uint32 msec wrap mid-bucket: o_ts near 0xffffffff, now32      *
 *  wrapped to a small value -> the uint32 elapsed diff stays a small        *
 *  positive (wrap-safe), so the bucket gets a small refill, not a 2^32 one. *
 * ======================================================================= */
CTEST(rate, msec_wrap_midbucket)
{
    ngx_http_heavybag_rate_hdr_t  *hdr = mk_table(64);
    struct sockaddr_in             sin;
    uint64_t                       h;
    ngx_http_heavybag_rate_slot_t *s;
    const uint64_t                 num = 10ULL * HEAVYBAG_RATE_SCALE; /* 10/s */
    const ngx_uint_t               per = 1000U;
    const ngx_uint_t               burst = 10U * HEAVYBAG_RATE_SCALE;

    mk_v4(&sin, "192.0.2.9");
    h = ngx_http_heavybag_rate_key((struct sockaddr *) &sin);

    /* seed the slot by hand: ts=0xfffffff0, tok=5000 (5 tokens) */
    s = &slots_of(hdr)[h % hdr->nslots];
    s->key = h;
    s->state = ((uint64_t) 0xfffffff0U << 32) | 5000U;

    ngx_current_msec = 0x10;                 /* now32=0x10 -> elapsed=0x20=32 ms */
    ASSERT_EQUAL(NGX_OK,
        ngx_http_heavybag_rate_check(hdr, (struct sockaddr *) &sin, num, per, burst));

    s = find_slot(hdr, h);
    ASSERT_NOT_NULL(s);
    /* 32 ms * 10/s = 320 fp refilled: 5000 + 320 = 5320, minus 1000 spent */
    ASSERT_EQUAL_U(5320U - HEAVYBAG_RATE_SCALE, tok_of(s));
    ASSERT_EQUAL_U(0x10U, ts_of(s));
    free(hdr);
}


/* ======================================================================= *
 *  V10  clock skewed backwards: o_ts > now32 with no real wrap -> the       *
 *  uint32 elapsed underflows to a huge positive, refilling to burst. The    *
 *  limiter must NOT get stuck denying (fail-open behaviour), never UB.      *
 * ======================================================================= */
CTEST(rate, clock_backwards_refills)
{
    ngx_http_heavybag_rate_hdr_t  *hdr = mk_table(64);
    struct sockaddr_in             sin;
    uint64_t                       h;
    ngx_http_heavybag_rate_slot_t *s;

    mk_v4(&sin, "192.0.2.10");
    h = ngx_http_heavybag_rate_key((struct sockaddr *) &sin);

    /* seed: ts=1000000, tok=0 (empty bucket) */
    s = &slots_of(hdr)[h % hdr->nslots];
    s->key = h;
    s->state = ((uint64_t) 1000000U << 32) | 0U;

    ngx_current_msec = 999000;               /* 1000 ms backwards */
    ASSERT_EQUAL(NGX_OK,
        ngx_http_heavybag_rate_check(hdr, (struct sockaddr *) &sin,
                                     R_NUM, R_PER, R_BURST));
    s = find_slot(hdr, h);
    /* refilled to burst then one spent */
    ASSERT_EQUAL_U(R_BURST - HEAVYBAG_RATE_SCALE, tok_of(s));
    free(hdr);
}


/* ======================================================================= *
 *  V11  FNV key-equality gating: a probe that lands on an occupied slot     *
 *  whose key differs must NOT mutate that victim's bucket -- it walks on    *
 *  and claims the next free slot. (A hash collision cannot poison a victim.) *
 * ======================================================================= */
CTEST(rate, key_equality_gates_victim)
{
    ngx_http_heavybag_rate_hdr_t  *hdr = mk_table(64);
    struct sockaddr_in             sin;
    uint64_t                       hb;
    ngx_uint_t                     idx;
    ngx_http_heavybag_rate_slot_t *slots, *victim, *got;
    uint64_t                       victim_key, victim_state;

    mk_v4(&sin, "192.0.2.11");
    hb = ngx_http_heavybag_rate_key((struct sockaddr *) &sin);
    idx = (ngx_uint_t) (hb % hdr->nslots);
    slots = slots_of(hdr);

    /* occupy the home slot with a DIFFERENT key (a synthetic collision) */
    victim = &slots[idx];
    victim_key = hb ^ 0xdeadbeefULL;         /* guaranteed != hb, nonzero */
    victim_state = ((uint64_t) 12345U << 32) | 4242U;
    victim->key = victim_key;
    victim->state = victim_state;
    /* idx+1 left empty (key 0) */

    ngx_current_msec = 1000000;
    ASSERT_EQUAL(NGX_OK,
        ngx_http_heavybag_rate_check(hdr, (struct sockaddr *) &sin,
                                     R_NUM, R_PER, R_BURST));

    /* victim untouched */
    ASSERT_EQUAL_U(victim_key, victim->key);
    ASSERT_EQUAL_U(victim_state, victim->state);
    /* our key claimed a different slot */
    got = find_slot(hdr, hb);
    ASSERT_NOT_NULL(got);
    ASSERT_TRUE(got != victim);
    free(hdr);
}


/* V12  v4-mapped IPv6 (::ffff:a.b.c.d) keys identically to native IPv4 */
CTEST(rate, v4mapped_equals_native_v4)
{
    struct sockaddr_in   sin;
    struct sockaddr_in6  s6;
    mk_v4(&sin, "1.2.3.4");
    mk_v6(&s6, "::ffff:1.2.3.4");
    ASSERT_EQUAL_U(ngx_http_heavybag_rate_key((struct sockaddr *) &sin),
                   ngx_http_heavybag_rate_key((struct sockaddr *) &s6));
}


/* V13  native IPv6 is keyed on the /64 prefix only: same /64 -> same key, */
/*      different /64 -> different key (host part is attacker-rotatable).   */
CTEST(rate, v6_keyed_on_64_prefix)
{
    struct sockaddr_in6  a, b, c;
    mk_v6(&a, "2001:db8::1");
    mk_v6(&b, "2001:db8:0:0:dead:beef:9999:ffff");   /* same /64 */
    mk_v6(&c, "2001:db9::1");                         /* different /64 */
    ASSERT_EQUAL_U(ngx_http_heavybag_rate_key((struct sockaddr *) &a),
                   ngx_http_heavybag_rate_key((struct sockaddr *) &b));
    ASSERT_NOT_EQUAL_U(ngx_http_heavybag_rate_key((struct sockaddr *) &a),
                       ngx_http_heavybag_rate_key((struct sockaddr *) &c));
}


/* V14  FNV key is never 0 (0 is the empty-slot sentinel) across a sweep */
CTEST(rate, fnv_key_never_zero)
{
    struct sockaddr_in  sin;
    uint32_t            i;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    for (i = 1; i < 200000U; i++) {
        sin.sin_addr.s_addr = htonl(i);
        ASSERT_NOT_EQUAL_U(0,
            ngx_http_heavybag_rate_key((struct sockaddr *) &sin));
    }
}


/* ======================================================================= *
 *  V15  probe window full (32 occupied) -> evict the OLDEST slot, never a   *
 *  silent drop. The saturating newcomer takes the oldest slot and starts    *
 *  from a full bucket; rate_overflow stays 0 (eviction succeeded).         *
 * ======================================================================= */
CTEST(rate, window_full_evicts_oldest)
{
    ngx_http_heavybag_rate_hdr_t  *hdr = mk_table(64);
    struct sockaddr_in             sin;
    uint64_t                       h;
    ngx_uint_t                     idx, p;
    ngx_http_heavybag_rate_slot_t *slots, *oldest;
    uint32_t                       now32;
    const uint64_t                 base = 10000000ULL;

    mk_v4(&sin, "192.0.2.123");
    h = ngx_http_heavybag_rate_key((struct sockaddr *) &sin);
    idx = (ngx_uint_t) (h % hdr->nslots);
    slots = slots_of(hdr);
    now32 = (uint32_t) base;

    /* fill the whole 32-slot probe window with distinct foreign keys */
    for (p = 0; p < HEAVYBAG_RATE_PROBE_MAX; p++) {
        ngx_http_heavybag_rate_slot_t  *s = &slots[(idx + p) % hdr->nslots];
        s->key = (uint64_t) (0xA000U + p);              /* nonzero, != h */
        s->state = ((uint64_t) (now32 - 100U) << 32);   /* all recent... */
    }
    /* ...except slot p==15, made clearly the oldest -> the eviction target */
    oldest = &slots[(idx + 15) % hdr->nslots];
    oldest->state = ((uint64_t) (now32 - 5000000U) << 32);

    ngx_current_msec = base;
    ASSERT_EQUAL(NGX_OK,
        ngx_http_heavybag_rate_check(hdr, (struct sockaddr *) &sin,
                                     R_NUM, R_PER, R_BURST));

    /* the oldest slot was repurposed for our key */
    ASSERT_EQUAL_U(h, oldest->key);
    /* a fresh full bucket: burst minus one spent token */
    ASSERT_EQUAL_U(R_BURST - HEAVYBAG_RATE_SCALE, tok_of(oldest));
    /* eviction succeeded -> no overflow counted */
    ASSERT_EQUAL_U(0, ngx_http_heavybag_rate_overflow(hdr));
    free(hdr);
}


/* ======================================================================= *
 *  V16  max rate/burst: the P6 bound (num <= UINT32_MAX/SCALE) makes the    *
 *  64-bit refill product non-overflowing, and the (uint32) token downcast   *
 *  after the burst clamp is lossless even at the maximum elapsed (0xffffffff)*
 * ======================================================================= */
CTEST(rate, max_rate_no_overflow_lossless_downcast)
{
    ngx_http_heavybag_rate_hdr_t  *hdr = mk_table(64);
    struct sockaddr_in             sin;
    uint64_t                       h;
    ngx_http_heavybag_rate_slot_t *s;
    /* the largest values rule_add accepts: num <= 0xffffffff/SCALE */
    const uint64_t                 num = (0xffffffffULL / HEAVYBAG_RATE_SCALE)
                                         * HEAVYBAG_RATE_SCALE;
    const ngx_uint_t               per = 1000U;
    const ngx_uint_t               burst = (ngx_uint_t) num;   /* <= UINT32_MAX */

    mk_v4(&sin, "192.0.2.200");
    h = ngx_http_heavybag_rate_key((struct sockaddr *) &sin);

    /* seed: ts=0, tok=0 -> first touch sees elapsed=0xffffffff (max) */
    s = &slots_of(hdr)[h % hdr->nslots];
    s->key = h;
    s->state = 0;

    ngx_current_msec = 0xffffffffULL;
    ASSERT_EQUAL(NGX_OK,
        ngx_http_heavybag_rate_check(hdr, (struct sockaddr *) &sin, num, per, burst));

    s = find_slot(hdr, h);
    ASSERT_NOT_NULL(s);
    /* clamped to burst (lossless 32-bit), one token spent */
    ASSERT_EQUAL_U(burst - HEAVYBAG_RATE_SCALE, tok_of(s));
    ASSERT_EQUAL_U(0xffffffffU, ts_of(s));
    free(hdr);
}


int
main(int argc, const char *argv[])
{
    return ctest_main(argc, argv);
}
