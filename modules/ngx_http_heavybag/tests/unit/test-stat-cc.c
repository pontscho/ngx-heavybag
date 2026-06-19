/*
 * Unit tests for the pure per-country stat-table core
 * (ngx_http_heavybag_stat_cc_bump, heavybag_status.c).
 *
 * The QA-campaign critic's "un-probed stat_cc table saturation" surface. The
 * function is a lock-free, open-addressed, linear-probe table of
 * HEAVYBAG_STAT_CC_SLOTS (512) {cc16,total,blocked} slots. With real geo data the
 * distinct-CC count tops out at ~249 + a handful of libloc specials, well under
 * 512, so the slot-collision probe and the cc_overflow drop are UNREACHABLE at
 * the integration layer (you cannot inject 513 distinct country codes from a
 * real DB). They are therefore exercised here with a synthetic in-memory shm.
 *
 * Compiled standalone: includes heavybag_status.c under
 * -DHEAVYBAG_STAT_CC_UNIT_TEST so only the cc core is pulled in (the serializers
 * + content handler are nginx-coupled and compiled out). The shim in
 * heavybag_status.{h,c} substitutes nginx byte-for-byte (ngx_atomic_t = uint64,
 * atomic ops = __sync builtins); the real -Werror SSL module build remains the
 * correctness contract. Built + run by run-unit-tests.sh with
 * `cc -DHEAVYBAG_STAT_CC_UNIT_TEST` (no extra libs).
 *
 * OUT OF UNIT SCOPE (honest limits, not faked here):
 *   - genuine multi-worker CAS races on slot claim: single-threaded __sync
 *     always wins iteration 0; the lost-race re-read branch is covered by
 *     reasoning + the cmp_set semantics, not a fabricated race.
 *   - the live geo->cc16 packing + the stat_cc_bump call sites: integration
 *     (run-stat-tests.sh per-country counters, Fix-round-3 lifecycle-02).
 */

#ifndef HEAVYBAG_STAT_CC_UNIT_TEST
#define HEAVYBAG_STAT_CC_UNIT_TEST
#endif
#include "../../src/heavybag_status.c"

#define CTEST_MAIN
#include "ctest.h"

#include <string.h>
#include <stdlib.h>


/* ---- synthetic shm helpers --------------------------------------------- */

static ngx_http_heavybag_stat_shm_t *
mk_shm(void)
{
    /* zeroed: every cc16 slot starts empty (sentinel 0), cc_overflow 0 */
    return calloc(1, sizeof(ngx_http_heavybag_stat_shm_t));
}

/* index of the slot that ended up owning cc16, or -1 if absent (probe-aware:
 * just scan the whole table, the test does not assume a placement). */
static int
find_slot(ngx_http_heavybag_stat_shm_t *sh, uint16_t cc16)
{
    int  i;
    for (i = 0; i < HEAVYBAG_STAT_CC_SLOTS; i++) {
        if (sh->cc[i].cc16 == cc16) {
            return i;
        }
    }
    return -1;
}

/* count occupied (non-empty) slots */
static int
occupied(ngx_http_heavybag_stat_shm_t *sh)
{
    int  i, n = 0;
    for (i = 0; i < HEAVYBAG_STAT_CC_SLOTS; i++) {
        if (sh->cc[i].cc16 != 0) {
            n++;
        }
    }
    return n;
}


/* ---- V1: NULL shm is a no-op (no crash) -------------------------------- */
CTEST(stat_cc, null_shm_noop)
{
    ngx_http_heavybag_stat_cc_bump(NULL, 0x5553 /* "US" */, 1);   /* must not crash */
    ASSERT_TRUE(1);
}

/* ---- V2: cc16 == 0 sentinel never consumes a slot ---------------------- */
CTEST(stat_cc, zero_cc_sentinel_noop)
{
    ngx_http_heavybag_stat_shm_t *sh = mk_shm();
    int i;
    for (i = 0; i < 10; i++) {
        ngx_http_heavybag_stat_cc_bump(sh, 0, 1);
    }
    ASSERT_EQUAL(0, occupied(sh));
    ASSERT_EQUAL(0, (int) sh->cc_overflow);
    free(sh);
}

/* ---- V3: single allowed bump -> total=1, blocked=0 --------------------- */
CTEST(stat_cc, single_allowed)
{
    ngx_http_heavybag_stat_shm_t *sh = mk_shm();
    int s;
    ngx_http_heavybag_stat_cc_bump(sh, 0x5553, 0);   /* "US", allowed */
    s = find_slot(sh, 0x5553);
    ASSERT_NOT_EQUAL(-1, s);
    ASSERT_EQUAL(1, (int) sh->cc[s].total);
    ASSERT_EQUAL(0, (int) sh->cc[s].blocked);
    ASSERT_EQUAL(1, occupied(sh));
    free(sh);
}

/* ---- V4: blocked bump -> total++ AND blocked++ ------------------------- */
CTEST(stat_cc, single_blocked)
{
    ngx_http_heavybag_stat_shm_t *sh = mk_shm();
    int s;
    ngx_http_heavybag_stat_cc_bump(sh, 0x4652 /* "FR" */, 1);
    s = find_slot(sh, 0x4652);
    ASSERT_EQUAL(1, (int) sh->cc[s].total);
    ASSERT_EQUAL(1, (int) sh->cc[s].blocked);
    free(sh);
}

/* ---- V5: repeated same CC accumulates in ONE slot ---------------------- */
CTEST(stat_cc, repeat_same_cc_accumulates)
{
    ngx_http_heavybag_stat_shm_t *sh = mk_shm();
    int s, i;
    for (i = 0; i < 5; i++) ngx_http_heavybag_stat_cc_bump(sh, 0x5553, 0);
    for (i = 0; i < 2; i++) ngx_http_heavybag_stat_cc_bump(sh, 0x5553, 1);
    s = find_slot(sh, 0x5553);
    ASSERT_EQUAL(7, (int) sh->cc[s].total);     /* 5 allowed + 2 blocked */
    ASSERT_EQUAL(2, (int) sh->cc[s].blocked);
    ASSERT_EQUAL(1, occupied(sh));              /* still one slot */
    free(sh);
}

/* ---- V6: two distinct CCs, no collision -> two independent slots -------- */
CTEST(stat_cc, two_distinct_independent)
{
    ngx_http_heavybag_stat_shm_t *sh = mk_shm();
    int a, b;
    ngx_http_heavybag_stat_cc_bump(sh, 0x5553, 0);   /* slot 0x5553 % 512 */
    ngx_http_heavybag_stat_cc_bump(sh, 0x4652, 1);
    ngx_http_heavybag_stat_cc_bump(sh, 0x4652, 1);
    a = find_slot(sh, 0x5553);
    b = find_slot(sh, 0x4652);
    ASSERT_NOT_EQUAL(a, b);
    ASSERT_EQUAL(1, (int) sh->cc[a].total);
    ASSERT_EQUAL(2, (int) sh->cc[b].total);
    ASSERT_EQUAL(2, (int) sh->cc[b].blocked);
    ASSERT_EQUAL(0, (int) sh->cc_overflow);
    free(sh);
}

/* ---- V7: collision (same %512 slot) -> linear probe to the next slot ---- */
CTEST(stat_cc, collision_linear_probe)
{
    ngx_http_heavybag_stat_shm_t *sh = mk_shm();
    /* 257 and 257+512=769 both hash to slot 257 */
    int a, b;
    ngx_http_heavybag_stat_cc_bump(sh, 257, 0);
    ngx_http_heavybag_stat_cc_bump(sh, 769, 1);
    a = find_slot(sh, 257);
    b = find_slot(sh, 769);
    ASSERT_EQUAL(257, a);                     /* first claims its home slot */
    ASSERT_EQUAL(258, b);                     /* second probes to the next  */
    ASSERT_EQUAL(1, (int) sh->cc[a].total);   /* no cross-poisoning         */
    ASSERT_EQUAL(1, (int) sh->cc[b].total);
    ASSERT_EQUAL(1, (int) sh->cc[b].blocked);
    ASSERT_EQUAL(0, (int) sh->cc_overflow);
    free(sh);
}

/* ---- V8: probe wraps past the end of the table (slot 511 -> 0) --------- */
CTEST(stat_cc, probe_wraps_around)
{
    ngx_http_heavybag_stat_shm_t *sh = mk_shm();
    /* 511 -> slot 511; 1023 = 511+512 -> slot 511 occupied -> wrap to slot 0 */
    int a, b;
    ngx_http_heavybag_stat_cc_bump(sh, 511, 0);
    ngx_http_heavybag_stat_cc_bump(sh, 1023, 0);
    a = find_slot(sh, 511);
    b = find_slot(sh, 1023);
    ASSERT_EQUAL(511, a);
    ASSERT_EQUAL(0, b);                        /* wrapped to slot 0 */
    free(sh);
}

/* ---- V9: 3-CC collision chain on one home slot ------------------------- */
CTEST(stat_cc, collision_chain_three)
{
    ngx_http_heavybag_stat_shm_t *sh = mk_shm();
    int a, b, c;
    ngx_http_heavybag_stat_cc_bump(sh, 100, 0);          /* slot 100 */
    ngx_http_heavybag_stat_cc_bump(sh, 100 + 512, 0);    /* -> 101   */
    ngx_http_heavybag_stat_cc_bump(sh, 100 + 1024, 0);   /* -> 102   */
    a = find_slot(sh, 100);
    b = find_slot(sh, 612);
    c = find_slot(sh, 1124);
    ASSERT_EQUAL(100, a);
    ASSERT_EQUAL(101, b);
    ASSERT_EQUAL(102, c);
    ASSERT_EQUAL(3, occupied(sh));
    free(sh);
}

/* ---- V10: saturation -> 513th distinct CC drops, cc_overflow++ --------- */
CTEST(stat_cc, saturation_overflow_drop)
{
    ngx_http_heavybag_stat_shm_t *sh = mk_shm();
    int i;
    /* cc16 = 1..512 are all distinct and map to all 512 slots (512%512==0) */
    for (i = 1; i <= HEAVYBAG_STAT_CC_SLOTS; i++) {
        ngx_http_heavybag_stat_cc_bump(sh, (uint16_t) i, 0);
    }
    ASSERT_EQUAL(HEAVYBAG_STAT_CC_SLOTS, occupied(sh));   /* table full */
    ASSERT_EQUAL(0, (int) sh->cc_overflow);

    /* a 513th distinct CC has nowhere to go -> dropped, not stored */
    ngx_http_heavybag_stat_cc_bump(sh, 60000, 1);
    ASSERT_EQUAL(1, (int) sh->cc_overflow);
    ASSERT_EQUAL(-1, find_slot(sh, 60000));              /* never stored */
    ASSERT_EQUAL(HEAVYBAG_STAT_CC_SLOTS, occupied(sh));   /* still full, no corruption */
    free(sh);
}

/* ---- V11: a FULL table still accounts an EXISTING CC correctly --------- */
CTEST(stat_cc, full_table_existing_cc_still_bumps)
{
    ngx_http_heavybag_stat_shm_t *sh = mk_shm();
    int i, s;
    for (i = 1; i <= HEAVYBAG_STAT_CC_SLOTS; i++) {
        ngx_http_heavybag_stat_cc_bump(sh, (uint16_t) i, 0);
    }
    /* cc16=1 is already in the table; bumping it again must find + count it */
    ngx_http_heavybag_stat_cc_bump(sh, 1, 1);
    s = find_slot(sh, 1);
    ASSERT_NOT_EQUAL(-1, s);
    ASSERT_EQUAL(2, (int) sh->cc[s].total);
    ASSERT_EQUAL(1, (int) sh->cc[s].blocked);
    ASSERT_EQUAL(0, (int) sh->cc_overflow);     /* found, not an overflow */
    free(sh);
}

/* ---- V12: overflow accumulates across multiple dropped CCs ------------- */
CTEST(stat_cc, overflow_accumulates)
{
    ngx_http_heavybag_stat_shm_t *sh = mk_shm();
    int i;
    for (i = 1; i <= HEAVYBAG_STAT_CC_SLOTS; i++) {
        ngx_http_heavybag_stat_cc_bump(sh, (uint16_t) i, 0);
    }
    ngx_http_heavybag_stat_cc_bump(sh, 60000, 0);
    ngx_http_heavybag_stat_cc_bump(sh, 60001, 1);
    ngx_http_heavybag_stat_cc_bump(sh, 60002, 0);
    ASSERT_EQUAL(3, (int) sh->cc_overflow);
    free(sh);
}

/* ---- V13: blocked is a subset of total over a mixed sequence ----------- */
CTEST(stat_cc, blocked_subset_of_total)
{
    ngx_http_heavybag_stat_shm_t *sh = mk_shm();
    int s, i;
    for (i = 0; i < 10; i++) ngx_http_heavybag_stat_cc_bump(sh, 0x4445 /* "DE" */, 0);
    for (i = 0; i < 3; i++)  ngx_http_heavybag_stat_cc_bump(sh, 0x4445, 1);
    s = find_slot(sh, 0x4445);
    ASSERT_EQUAL(13, (int) sh->cc[s].total);
    ASSERT_EQUAL(3, (int) sh->cc[s].blocked);
    free(sh);
}

/* ---- V14: max uint16 cc16 = 0xFFFF works ------------------------------- */
CTEST(stat_cc, max_uint16_cc)
{
    ngx_http_heavybag_stat_shm_t *sh = mk_shm();
    int s;
    ngx_http_heavybag_stat_cc_bump(sh, 0xFFFF, 1);
    s = find_slot(sh, 0xFFFF);
    ASSERT_EQUAL((int) (0xFFFF % HEAVYBAG_STAT_CC_SLOTS), s);   /* 65535 % 512 == 511 */
    ASSERT_EQUAL(1, (int) sh->cc[s].total);
    free(sh);
}

/* ---- V15: realistic ISO-2 packed codes land in distinct slots ---------- */
CTEST(stat_cc, realistic_iso2_codes)
{
    ngx_http_heavybag_stat_shm_t *sh = mk_shm();
    /* a spread of real packed ISO-2 codes (c0<<8 | c1) */
    uint16_t ccs[] = { 0x5553/*US*/, 0x4652/*FR*/, 0x4445/*DE*/, 0x4155/*AU*/,
                       0x4A50/*JP*/, 0x4742/*GB*/, 0x4341/*CA*/, 0x4E4C/*NL*/ };
    int i, n = (int) (sizeof(ccs) / sizeof(ccs[0]));
    for (i = 0; i < n; i++) ngx_http_heavybag_stat_cc_bump(sh, ccs[i], 0);
    for (i = 0; i < n; i++) ASSERT_NOT_EQUAL(-1, find_slot(sh, ccs[i]));
    ASSERT_EQUAL(0, (int) sh->cc_overflow);
    free(sh);
}

int
main(int argc, const char *argv[])
{
    return ctest_main(argc, argv);
}
