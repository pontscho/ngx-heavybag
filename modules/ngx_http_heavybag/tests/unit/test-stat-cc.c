/*
 * Unit tests for the pure (nginx-free) cores of heavybag_status.c:
 *   - ngx_http_heavybag_stat_cc_bump      per-country lock-free stat table
 *   - ngx_http_heavybag_status_nvhosts    /status per-vhost render clamp
 *   - ngx_http_heavybag_stat_snapshot     field-wise counter snapshot
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
 *   - the CONCURRENCY property of ngx_http_heavybag_stat_snapshot (each counter
 *     read indivisibly while workers bump it) is a per-platform aligned-load
 *     guarantee, not something a single-threaded test can observe; what IS
 *     asserted here is the copy's completeness and field identity, which is
 *     the regression a hand-written field-wise copy actually invites.
 *   - the render-side effect of ngx_http_heavybag_status_nvhosts (no read past
 *     the per-vhost array after a reload that adds server{} blocks): needs the
 *     nginx runtime -- the reload e2e owns it.
 */

#ifndef HEAVYBAG_STAT_CC_UNIT_TEST
#define HEAVYBAG_STAT_CC_UNIT_TEST
#endif
#include "../../src/heavybag_status.c"

#define CTEST_MAIN
#include "ctest.h"

#include <stddef.h>      /* offsetof, for the snapshot padding accounting */
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

/* ======================================================================= *
 *  /status render-side vhost clamp (ngx_http_heavybag_status_nvhosts)       *
 *                                                                          *
 *  Pure min-of-three over the configured vhost count, the core server       *
 *  array length and the shm segment's OWN nvhosts. The third bound is the   *
 *  one that matters: nginx re-attaches the EXISTING stat segment across a   *
 *  reload, so a cycle that gained server{} blocks reports more vhosts than  *
 *  the trailing per-vhost array was allocated for -- rendering conf-many    *
 *  rows would read past the end of the mapped slab.                         *
 * ======================================================================= */

/* ---- C1: no bound engaged -> the configured count passes through ------- */
CTEST(status_nvhosts, all_equal_passthrough)
{
    ASSERT_EQUAL(4, (int) ngx_http_heavybag_status_nvhosts(4, 4, 4));
}

/* ---- C2: fewer servers in the core array than configured --------------- */
CTEST(status_nvhosts, clamped_by_server_array)
{
    ASSERT_EQUAL(2, (int) ngx_http_heavybag_status_nvhosts(5, 2, 9));
}

/* ---- C3: THE reload case -- segment shorter than this cycle's config ---- */
CTEST(status_nvhosts, clamped_by_shm_after_reload_growth)
{
    /* started with 3 server{} blocks, reloaded with 5: conf and the core
     * array both say 5, the re-attached segment still holds 3 rows */
    ASSERT_EQUAL(3, (int) ngx_http_heavybag_status_nvhosts(5, 5, 3));
}

/* ---- C4: shm is the smallest of three distinct bounds ------------------ */
CTEST(status_nvhosts, shm_is_the_smallest)
{
    ASSERT_EQUAL(1, (int) ngx_http_heavybag_status_nvhosts(7, 4, 1));
}

/* ---- C5: a LARGER segment (reload shrank the config) does not widen ---- */
CTEST(status_nvhosts, larger_shm_never_widens)
{
    ASSERT_EQUAL(2, (int) ngx_http_heavybag_status_nvhosts(2, 2, 8));
}

/* ---- C6: an empty segment renders no vhost rows at all ---------------- */
CTEST(status_nvhosts, zero_shm_renders_nothing)
{
    ASSERT_EQUAL(0, (int) ngx_http_heavybag_status_nvhosts(6, 6, 0));
}

/* ---- C7: every bound at zero stays zero (no underflow) ---------------- */
CTEST(status_nvhosts, all_zero)
{
    ASSERT_EQUAL(0, (int) ngx_http_heavybag_status_nvhosts(0, 0, 0));
}


/* ======================================================================= *
 *  Field-wise counter snapshot (ngx_http_heavybag_stat_snapshot)            *
 *                                                                          *
 *  Replaces a bulk `*dst = *sh` struct copy. The regression a hand-written  *
 *  field-wise copy invites is a FORGOTTEN field -- which would silently     *
 *  render as a frozen/garbage counter -- so the first test is byte-exact    *
 *  and generic (it catches fields added later too), and the second pins     *
 *  that fields are not cross-wired to each other.                           *
 * ======================================================================= */

/* ---- S1: no field left behind (byte-pattern sweep) --------------------- */
CTEST(stat_snapshot, copies_every_byte_but_padding)
{
    ngx_http_heavybag_stat_shm_t  *src = malloc(sizeof(*src));
    ngx_http_heavybag_stat_shm_t  *dst = malloc(sizeof(*dst));
    const unsigned char           *b;
    size_t                         i, untouched = 0, pad;

    /* source uniformly 0xA5, destination uniformly 0x5A: after the snapshot
     * every byte the copy is responsible for MUST read 0xA5. Anything still
     * 0x5A was never written -- i.e. a field the copy forgot. */
    memset(src, 0xA5, sizeof(*src));
    memset(dst, 0x5A, sizeof(*dst));

    ngx_http_heavybag_stat_snapshot(dst, src);

    /* the only bytes legitimately left behind are the alignment padding
     * between the 32-bit `layout` word and the first time_t */
    pad = offsetof(ngx_http_heavybag_stat_shm_t, start_time)
          - (offsetof(ngx_http_heavybag_stat_shm_t, layout) + sizeof(uint32_t));

    b = (const unsigned char *) dst;
    for (i = 0; i < sizeof(*dst); i++) {
        if (b[i] != 0xA5) {
            untouched++;
        }
    }

    ASSERT_EQUAL((int) pad, (int) untouched);

    free(src);
    free(dst);
}

/* ---- S2: fields are not cross-wired (distinct values survive) ---------- */
CTEST(stat_snapshot, distinct_values_land_in_their_own_field)
{
    ngx_http_heavybag_stat_shm_t  *src = mk_shm();
    ngx_http_heavybag_stat_shm_t  *dst = mk_shm();

    src->layout = 0xDEADBEEFu;
    src->start_time = 1000;
    src->last_reload_time = 2000;
    src->nvhosts = 3;
    src->http_requests_total = 11;
    src->http_allowed = 12;
    src->http_allowlist_hits = 13;
    src->http_blocked[1] = 14;
    src->http_would_block[2] = 15;
    src->http_scanner_path[0] = 16;
    src->http_resp_403 = 17;
    src->http_resp_404 = 18;
    src->http_resp_444 = 19;
    src->http_resp_429 = 20;
    src->http_ua[3] = 21;
    src->http_ua_cat[4] = 22;
    src->http_ua_spoofed = 23;
    src->flag_blocked[2] = 24;
    src->stream_connections_total = 25;
    src->stream_allowed = 26;
    src->stream_denied[5] = 27;
    src->stream_would_block[6] = 28;
    src->cc_overflow = 29;
    src->cc[7].cc16 = 0x4445;   /* "DE" */
    src->cc[7].total = 30;
    src->cc[7].blocked = 31;

    ngx_http_heavybag_stat_snapshot(dst, src);

    ASSERT_EQUAL((int) 0xDEADBEEFu, (int) dst->layout);
    ASSERT_EQUAL(1000, (int) dst->start_time);
    ASSERT_EQUAL(2000, (int) dst->last_reload_time);
    ASSERT_EQUAL(3, (int) dst->nvhosts);
    ASSERT_EQUAL(11, (int) dst->http_requests_total);
    ASSERT_EQUAL(12, (int) dst->http_allowed);
    ASSERT_EQUAL(13, (int) dst->http_allowlist_hits);
    ASSERT_EQUAL(14, (int) dst->http_blocked[1]);
    ASSERT_EQUAL(15, (int) dst->http_would_block[2]);
    ASSERT_EQUAL(16, (int) dst->http_scanner_path[0]);
    ASSERT_EQUAL(17, (int) dst->http_resp_403);
    ASSERT_EQUAL(18, (int) dst->http_resp_404);
    ASSERT_EQUAL(19, (int) dst->http_resp_444);
    ASSERT_EQUAL(20, (int) dst->http_resp_429);
    ASSERT_EQUAL(21, (int) dst->http_ua[3]);
    ASSERT_EQUAL(22, (int) dst->http_ua_cat[4]);
    ASSERT_EQUAL(23, (int) dst->http_ua_spoofed);
    ASSERT_EQUAL(24, (int) dst->flag_blocked[2]);
    ASSERT_EQUAL(25, (int) dst->stream_connections_total);
    ASSERT_EQUAL(26, (int) dst->stream_allowed);
    ASSERT_EQUAL(27, (int) dst->stream_denied[5]);
    ASSERT_EQUAL(28, (int) dst->stream_would_block[6]);
    ASSERT_EQUAL(29, (int) dst->cc_overflow);
    ASSERT_EQUAL(0x4445, (int) dst->cc[7].cc16);
    ASSERT_EQUAL(30, (int) dst->cc[7].total);
    ASSERT_EQUAL(31, (int) dst->cc[7].blocked);

    /* neighbours the source never set must stay zero -- a copy that smeared
     * one field across an array would show up here */
    ASSERT_EQUAL(0, (int) dst->http_blocked[0]);
    ASSERT_EQUAL(0, (int) dst->http_ua[4]);
    ASSERT_EQUAL(0, (int) dst->cc[6].cc16);

    free(src);
    free(dst);
}


int
main(int argc, const char *argv[])
{
    return ctest_main(argc, argv);
}
