/*
 * ngx_http_heavybag_module - lock-free per-IP token-bucket rate limiter (core)
 *
 * Fixed-size, open-addressed per-IP table in one shared zone, modelled on the
 * cc[512] country table's lock-free claim (ngx_http_heavybag_stat_cc_bump) rather
 * than nginx limit_req's rbtree+mutex. No locks, no slab churn on the hot path:
 * a slot is claimed once with ngx_atomic_cmp_set and its packed token-bucket
 * state is then mutated with a bounded CAS loop.
 *
 * SLOT (16 bytes):
 *   key   = 64-bit FNV-1a over (family tag + raw IP bytes); 0 = empty sentinel
 *           (a hash of 0 is remapped to 1). KEY equality -- not hash equality --
 *           gates the state mutation, so an attacker cannot poison a victim's
 *           bucket by finding a hash collision.
 *   state = (last_refill_ms32 << 32) | tokens_fp32. memzero -> ts 0 -> first
 *           touch sees a huge elapsed -> bucket fills to burst (no first-touch
 *           flag needed).
 *
 * The packed CAS requires a >= 64-bit atomic word; see the guards below.
 */

#ifndef HEAVYBAG_RATE_UNIT_TEST

#include <ngx_config.h>
#include <ngx_core.h>

#include "heavybag_rate.h"

#else

/* ===================================================================== *
 *  Standalone unit-test shim (-DHEAVYBAG_RATE_UNIT_TEST)                  *
 *                                                                        *
 *  Substitutes nginx for the pure token-bucket core. Every macro/typedef *
 *  mirrors nginx byte-for-byte (build/.../src/core/ngx_core.h): the shim *
 *  REPLACES nginx, it never redefines its semantics -- the real -Werror  *
 *  SSL module build is the only correctness contract. test-rate.c        *
 *  includes this .c directly, so the static slot/header structs and the  *
 *  static key/check core are reachable; rule_select/rule_add/init_zone   *
 *  (ngx_conf_t / ngx_array_t / slab coupled) stay behind #ifndef.        *
 * ===================================================================== */
#include <netinet/in.h>      /* sockaddr_in/in6, IN6_IS_ADDR_V4MAPPED */
#include "heavybag_rate.h"   /* type shim: u_char/ngx_*_t/ngx_atomic_t/ngx_msec_t */

#define NGX_PTR_SIZE    8
#define NGX_HAVE_INET6  1

#define NGX_OK          0
#define NGX_ERROR     (-1)
#define NGX_AGAIN     (-2)
#define NGX_BUSY      (-3)
#define NGX_DECLINED  (-5)

/* nginx atomics -> gcc/clang __sync builtins (identical return semantics) */
#define ngx_atomic_cmp_set(lock, old, set)  __sync_bool_compare_and_swap(lock, old, set)
#define ngx_atomic_fetch_add(value, add)    __sync_fetch_and_add(value, add)
#define ngx_cpu_pause()

/* the clock the vectors drive (nginx: volatile ngx_msec_t ngx_current_msec) */
ngx_msec_t  ngx_current_msec;

/* no-op log + zeroed cycle stub for the burst_fp==0 ALERT path (the macro
 * discards the variadic format args; ngx_cycle->log stays a valid pointer) */
#define NGX_LOG_ALERT  1
typedef struct ngx_log_s   { ngx_uint_t log_level; } ngx_log_t;
typedef struct ngx_cycle_s { ngx_log_t *log; }       ngx_cycle_t;
static ngx_log_t    heavybag_ut_log;
static ngx_cycle_t  heavybag_ut_cycle = { &heavybag_ut_log };
static ngx_cycle_t *ngx_cycle = &heavybag_ut_cycle;
#define ngx_log_error(level, log, err, ...)  ((void) (log))

#endif


#if (NGX_PTR_SIZE < 8)
#error "waf_rate requires a 64-bit platform (packed atomic token-bucket state)"
#endif

/* load-bearing guard: NGX_PTR_SIZE is the pointer width, NOT proof that the
 * atomic word is 64-bit, so assert the atomic width directly. */
#if (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L)
_Static_assert(sizeof(ngx_atomic_t) >= 8,
    "waf_rate: ngx_atomic_t must be >= 64-bit for the packed bucket state");
#endif


#define HEAVYBAG_RATE_PROBE_MAX   32      /* open-addressing probe window  */
#define HEAVYBAG_RATE_CAS_MAX     16      /* bounded state-CAS retries     */
#define HEAVYBAG_RATE_MIN_SLOTS   64      /* a smaller zone is a misconfig */

#define HEAVYBAG_RATE_FNV_OFFSET  14695981039346656037ULL
#define HEAVYBAG_RATE_FNV_PRIME   1099511628211ULL


typedef struct {
    ngx_atomic_t  key;     /* FNV-1a hash; 0 = empty                       */
    ngx_atomic_t  state;   /* (last_refill_ms32 << 32) | tokens_fp32       */
} ngx_http_heavybag_rate_slot_t;


typedef struct {
    ngx_atomic_t  rate_overflow;   /* eviction-CAS failures (saturation)   */
    ngx_uint_t    nslots;          /* length of the trailing slot array     */
    /* ngx_http_heavybag_rate_slot_t slots[nslots] follow, contiguous */
} ngx_http_heavybag_rate_hdr_t;


/*
 * Hash the rate-limit key for *sa: a family tag byte mixed with the raw
 * address bytes. AF_INET and an AF_INET6 v4-mapped address hash identically
 * (same client). A native IPv6 address is keyed on its /64 prefix only -- the
 * lower 64 bits are an attacker-rotatable host part, so per-/128 keying would
 * be trivially evaded; intra-/64 collateral throttling is the intended
 * anti-evasion default. Returns 0 (caller fail-opens) for any other family.
 */
static uint64_t
ngx_http_heavybag_rate_key(struct sockaddr *sa)
{
    u_char               *bytes;
    size_t                len, i;
    uint64_t              h;
    u_char                tag;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    if (sa == NULL) {
        return 0;
    }

    switch (sa->sa_family) {

    case AF_INET:
        sin = (struct sockaddr_in *) sa;
        bytes = (u_char *) &sin->sin_addr.s_addr;
        len = 4;
        tag = AF_INET;
        break;

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) sa;
        if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            bytes = sin6->sin6_addr.s6_addr + 12;   /* embedded IPv4 */
            len = 4;
            tag = AF_INET;                          /* same key as native v4 */
        } else {
            bytes = sin6->sin6_addr.s6_addr;        /* /64 prefix only */
            len = 8;
            tag = AF_INET6;
        }
        break;
#endif

    default:
        return 0;
    }

    h = HEAVYBAG_RATE_FNV_OFFSET;
    h ^= tag;
    h *= HEAVYBAG_RATE_FNV_PRIME;

    for (i = 0; i < len; i++) {
        h ^= bytes[i];
        h *= HEAVYBAG_RATE_FNV_PRIME;
    }

    return (h == 0) ? 1 : h;
}


ngx_int_t
ngx_http_heavybag_rate_check(void *shm, struct sockaddr *sa,
    uint64_t rate_num_fp, ngx_uint_t period_ms, ngx_uint_t burst_fp)
{
    int                        allow;
    uint64_t                   h, k, old, neu, added, newtok, oldest_key, sstate;
    uint32_t                   now32, o_ts, o_tok, tok, new_ts, elapsed;
    uint32_t                   age, best_age;
    ngx_uint_t                 i, p, idx, n;
    ngx_http_heavybag_rate_slot_t  *slots, *s, *oldest, *cand;
    ngx_http_heavybag_rate_hdr_t   *hdr = shm;

    if (hdr == NULL) {
        return NGX_OK;                       /* no zone -> fail-open */
    }

    h = ngx_http_heavybag_rate_key(sa);
    if (h == 0) {
        return NGX_OK;                       /* unsupported family -> fail-open */
    }

    n = hdr->nslots;
    if (n == 0) {
        return NGX_OK;
    }

    if (period_ms == 0) {
        return NGX_OK;                       /* exported API: avoid div-by-zero -> fail-open */
    }
    if (burst_fp == 0) {                     /* exported API: 0 burst would fail closed -> fail-open */
        static ngx_uint_t  warned;           /* one-time: a zeroed param is a CALLER bug, surface it */
        if (!warned) {
            warned = 1;
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                "heavybag: rate_check called with burst_fp==0 "
                "(rate limiting disabled for this caller)");
        }
        return NGX_OK;
    }

    slots = (ngx_http_heavybag_rate_slot_t *) (hdr + 1);
    idx = (ngx_uint_t) (h % n);
    s = NULL;
    oldest = NULL;
    oldest_key = 0;
    /*
     * Staleness floor: only a slot OLDER than a full period is an eviction
     * candidate. Such a bucket would have refilled to a full burst regardless,
     * so evicting it loses no token deficit -- whereas evicting a fresh slot
     * would let an established abuser reset its own throttle by hammering. We
     * start best_age at period_ms and require age STRICTLY greater (see below).
     */
    best_age = (uint32_t) period_ms;
    now32 = (uint32_t) (ngx_current_msec & 0xffffffff);

    /*
     * Probe the open-addressing window: claim an empty slot, find ours, or
     * track the oldest STALE (age > period_ms) slot for eviction. A fresh or
     * active slot is never an eviction victim. The candidate's key is
     * SNAPSHOTTED so the single-shot evict-CAS below can detect a concurrent
     * change and fail safely.
     */
    for (p = 0; p < HEAVYBAG_RATE_PROBE_MAX; p++) {
        cand = &slots[(idx + p) % n];

        k = cand->key;
        if (k == 0) {
            if (ngx_atomic_cmp_set(&cand->key, 0, h)) {
                s = cand;                    /* claimed a fresh empty slot */
                break;
            }
            k = cand->key;                   /* lost the race; read the winner */
        }
        if (k == h) {
            s = cand;                        /* our slot */
            break;
        }

        /* eviction-candidate tracking -- never evict a fresh/active slot */
        sstate = cand->state;
        if (sstate == 0) {
            continue;                        /* just-claimed/just-reset (key!=0,
                                              * state==0): not yet a limiter */
        }

        age = now32 - (uint32_t) (sstate >> 32);   /* wrap-safe age */
        if ((int32_t) age <= 0) {
            /* age <= 0 as signed: either a concurrent writer stamped this slot
             * at/after now32, or it is > ~24.8 days idle (past the 0x7FFFFFFF
             * ms int32 sign flip). Skipping a 24-day-idle slot is harmless;
             * the clamp's real job is to stop a future-stamped slot from
             * underflowing to a giant age and being picked as "oldest". */
            continue;
        }
        if (age > best_age) {                /* STRICTLY older than the floor */
            best_age = age;
            oldest = cand;
            oldest_key = k;
        }
    }

    if (s == NULL) {
        /*
         * No slot of ours and the window is full. If nothing crossed the
         * staleness floor (oldest == NULL: every probed slot is fresh/active),
         * we do NOT evict a live limiter -- the new IP fails open and the
         * saturation is COUNTED. An established abuser therefore cannot reset
         * its own bucket by saturating the window; the only cost is that an
         * extreme table-saturation attack lets new IPs through, observable via
         * rate_overflow (wired to metrics/alerts) and mitigated by sizing the
         * zone (see the waf_rate directive doc).
         */
        if (oldest == NULL) {
            (void) ngx_atomic_fetch_add(&hdr->rate_overflow, 1);
            return NGX_OK;       /* no stale victim -> new IP fails open */
        }

        /*
         * Evict the oldest STALE slot (age > period_ms, so it would have
         * refilled to a full burst anyway). SINGLE-SHOT CAS, no retry: if the
         * snapshotted key changed underneath us the CAS fails and we fail-open
         * -- one missed eviction is not a hole.
         */
        if (ngx_atomic_cmp_set(&oldest->key, oldest_key, h)) {
            oldest->state = 0;   /* plain store: the new owner starts from a
                                  * full bucket (state 0 -> huge elapsed). The
                                  * race with the CAS loop below costs at worst
                                  * one lost token decrement, fail-open. */
            s = oldest;

        } else {
            (void) ngx_atomic_fetch_add(&hdr->rate_overflow, 1);
            return NGX_OK;       /* eviction lost -> fail-open */
        }
    }

    /* INVARIANT: every path reaching here has s != NULL. The s == NULL block
     * above either returned (oldest == NULL, or the evict-CAS lost) or set
     * s = oldest; the probe loop sets s on claim/match. So the token-bucket
     * CAS loop below never dereferences a NULL slot. */

    /* token-bucket CAS on the packed state, bounded to guard against livelock */
    for (i = 0; i < HEAVYBAG_RATE_CAS_MAX; i++) {
        old   = s->state;
        o_ts  = (uint32_t) (old >> 32);
        o_tok = (uint32_t) (old & 0xffffffff);

        now32   = (uint32_t) (ngx_current_msec & 0xffffffff);
        elapsed = now32 - o_ts;          /* uint32 diff: real ~49-day wrap */
        added   = (uint64_t) elapsed * rate_num_fp / period_ms;

        newtok = (uint64_t) o_tok + added;
        if (newtok > burst_fp) {
            newtok = burst_fp;
        }
        tok = (uint32_t) newtok;

        allow = (tok >= HEAVYBAG_RATE_SCALE);
        if (allow) {
            tok -= HEAVYBAG_RATE_SCALE;
        }

        /* added==0: keep the old stamp so sub-(period/SCALE) elapsed is not
         * lost (otherwise small rates, e.g. 1r/h, drift downward) */
        new_ts = (added > 0) ? now32 : o_ts;
        neu = ((uint64_t) new_ts << 32) | tok;

        if (ngx_atomic_cmp_set(&s->state, old, neu)) {
            return allow ? NGX_OK : NGX_BUSY;
        }
        ngx_cpu_pause();
    }

    return NGX_OK;                        /* CAS starvation -> fail-open */
}


#ifndef HEAVYBAG_RATE_UNIT_TEST

ngx_http_heavybag_rate_rule_t *
ngx_http_heavybag_rate_rule_select(ngx_array_t *rules, ngx_http_heavybag_verdict_t *verdict)
{
    uint16_t                   cc16, *ccs;
    ngx_uint_t                 i, j;
    ngx_http_heavybag_rate_rule_t  *rule, *deflt;

    if (rules == NULL) {
        return NULL;
    }

    rule = rules->elts;
    deflt = NULL;

    /* H2: never `&& verdict->country` (an array decays to a non-NULL ptr,
     * always true); gate strictly on geo_valid and a non-zero packed code. */
    cc16 = (verdict->geo_valid)
           ? (uint16_t) ((verdict->country[0] << 8) | verdict->country[1])
           : 0;

    for (i = 0; i < rules->nelts; i++) {
        if (rule[i].geo_cc == NULL) {
            deflt = &rule[i];                 /* the (single) default rule */
            continue;
        }

        if (cc16 != 0) {
            ccs = rule[i].geo_cc->elts;
            for (j = 0; j < rule[i].geo_cc->nelts; j++) {
                if (ccs[j] == cc16) {
                    return &rule[i];          /* first for_geo match wins */
                }
            }
        }
    }

    return deflt;                             /* NULL when no rule applies */
}


char *
ngx_http_heavybag_rate_rule_add(ngx_conf_t *cf, ngx_array_t **rules)
{
    u_char                    *p, *last, *ds, unit;
    ngx_str_t                 *value, *a, cc;
    ngx_int_t                  num;
    ngx_uint_t                 i, k, period_ms;
    uint64_t                   rate_num_fp, burst_fp;
    ngx_array_t               *geo_cc;
    ngx_http_heavybag_rate_rule_t  *rule, *r;

    value = cf->args->elts;

    rate_num_fp = 0;
    burst_fp = 0;
    period_ms = 0;
    geo_cc = NULL;

    for (i = 1; i < cf->args->nelts; i++) {
        a = &value[i];

        if (a->len > 5 && ngx_strncmp(a->data, "rate=", 5) == 0) {
            p = a->data + 5;
            last = a->data + a->len;
            ds = p;
            while (p < last && *p >= '0' && *p <= '9') {
                p++;
            }
            if (p == ds || last - p != 3 || p[0] != 'r' || p[1] != '/') {
                return "has an invalid rate (expected Nr/s, Nr/m or Nr/h)";
            }
            num = ngx_atoi(ds, p - ds);
            if (num == NGX_ERROR || num <= 0) {
                return "has an invalid rate count";
            }
            unit = p[2];
            switch (unit) {
            case 's': period_ms = 1000; break;
            case 'm': period_ms = 60000; break;
            case 'h': period_ms = 3600000; break;
            default:
                return "has an invalid rate unit (expected s, m or h)";
            }
            /* P6: rate_num_fp <= UINT32_MAX makes the 64-bit refill product
             * (elapsed_u32 * rate_num_fp) provably non-overflowing */
            if ((uint64_t) num > (0xffffffffULL / HEAVYBAG_RATE_SCALE)) {
                return "rate is too large";
            }
            rate_num_fp = (uint64_t) num * HEAVYBAG_RATE_SCALE;
            continue;
        }

        if (a->len > 6 && ngx_strncmp(a->data, "burst=", 6) == 0) {
            num = ngx_atoi(a->data + 6, a->len - 6);
            if (num == NGX_ERROR || num <= 0) {
                return "has an invalid burst";
            }
            /* P6: burst_fp <= UINT32_MAX is the bucket's 32-bit token capacity */
            if ((uint64_t) num > (0xffffffffULL / HEAVYBAG_RATE_SCALE)) {
                return "burst is too large";
            }
            burst_fp = (uint64_t) num * HEAVYBAG_RATE_SCALE;
            continue;
        }

        if (a->len > 8 && ngx_strncmp(a->data, "for_geo=", 8) == 0) {
            p = a->data + 8;
            last = a->data + a->len;
            while (p < last) {
                ds = p;
                while (p < last && *p != ',') {
                    p++;
                }
                cc.data = ds;
                cc.len = p - ds;
                if (ngx_http_heavybag_country_add(cf, &geo_cc, &cc) != NGX_OK) {
                    return NGX_CONF_ERROR;
                }
                if (p < last) {
                    p++;            /* skip the comma */
                }
            }
            continue;
        }

        return "has an unknown parameter";
    }

    if (rate_num_fp == 0) {
        return "requires a rate=Nr/s (or /m, /h) parameter";
    }
    if (burst_fp == 0) {
        burst_fp = rate_num_fp;          /* default: one period worth */
    }

    if (*rules == NULL) {
        *rules = ngx_array_create(cf->pool, 2,
                                  sizeof(ngx_http_heavybag_rate_rule_t));
        if (*rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    if (geo_cc == NULL) {
        /* at most one default rule per rule set */
        r = (*rules)->elts;
        for (k = 0; k < (*rules)->nelts; k++) {
            if (r[k].geo_cc == NULL) {
                return "has more than one default rule (only one without "
                       "for_geo is allowed)";
            }
        }
    }

    rule = ngx_array_push(*rules);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }

    rule->rate_num_fp = rate_num_fp;
    rule->period_ms = period_ms;
    rule->burst_fp = (ngx_uint_t) burst_fp;
    rule->geo_cc = geo_cc;

    return NGX_CONF_OK;
}


ngx_int_t
ngx_http_heavybag_rate_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    size_t                    alloc, margin;
    ngx_uint_t                n, pages;
    ngx_slab_pool_t          *shpool;
    ngx_http_heavybag_rate_hdr_t  *hdr;
    ngx_http_heavybag_rate_hdr_t  *ohdr = data;

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    /* reload: reuse the previous cycle's table verbatim. The token state stays
     * in the slab, so live limits are NOT reset across a reload (desirable). */
    if (ohdr != NULL) {
        shm_zone->data = ohdr;
        return NGX_OK;
    }

    /* worker re-attach to an existing segment */
    if (shm_zone->shm.exists) {
        shm_zone->data = shpool->data;
        return NGX_OK;
    }

    /*
     * Fresh segment: size the slot table to fill the zone. Reserve a generous
     * margin for the slab pool header + per-page bookkeeping (~56 B/page; 128
     * is >2x), then back off if the slab still declines, so the first
     * ngx_slab_alloc succeeds without an alarming "no memory" log line.
     */
    pages = (ngx_uint_t) (shm_zone->shm.size / ngx_pagesize);
    margin = sizeof(ngx_slab_pool_t) + (size_t) pages * 128 + 2 * ngx_pagesize;

    if (shm_zone->shm.size <= margin
        || (shm_zone->shm.size - margin) / sizeof(ngx_http_heavybag_rate_slot_t)
           < HEAVYBAG_RATE_MIN_SLOTS)
    {
        ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                      "heavybag: waf_rate zone is too small");
        return NGX_ERROR;
    }

    n = (ngx_uint_t)
        ((shm_zone->shm.size - margin) / sizeof(ngx_http_heavybag_rate_slot_t));

    for ( ;; ) {
        if (n < HEAVYBAG_RATE_MIN_SLOTS) {
            ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                          "heavybag: waf_rate zone is too small");
            return NGX_ERROR;
        }

        alloc = sizeof(ngx_http_heavybag_rate_hdr_t)
                + (size_t) n * sizeof(ngx_http_heavybag_rate_slot_t);

        hdr = ngx_slab_alloc(shpool, alloc);
        if (hdr != NULL) {
            break;
        }

        n -= n / 8 + 1;                  /* back off ~12% and retry */
    }

    ngx_memzero(hdr, alloc);
    hdr->nslots = n;

    shpool->data = hdr;
    shm_zone->data = hdr;

    return NGX_OK;
}

#endif /* HEAVYBAG_RATE_UNIT_TEST */


ngx_atomic_uint_t
ngx_http_heavybag_rate_overflow(void *shm)
{
    ngx_http_heavybag_rate_hdr_t  *hdr = shm;

    if (hdr == NULL) {
        return 0;
    }

    return hdr->rate_overflow;
}
