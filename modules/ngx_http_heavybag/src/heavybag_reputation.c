/*
 * ngx_http_heavybag_module - shared reputation core
 *
 * See heavybag_reputation.h. The special IPFire source codes from waf_flag_block
 * (A1 anonymous proxy, A2 satellite, A3 anycast, T1 Tor exit, XD drop) deny
 * in BOTH block and whitelist modes: via the libloc uint16 network-flags
 * field (flag_mask) and, for codes that carry no flag bit such as Tor's T1,
 * via the separate flag_cc packed-CC list. The plain ISO block_cc/allow_cc
 * lists are the mutually exclusive country policy. Any signal denies.
 *
 * waf_flag_block also takes a non-libloc token, `unknown`, which denies a
 * source the database has no record for at all. It is OFF by default: in
 * deny-list semantics an unresolvable source passes (the industry convention
 * -- AWS WAF's "XX" label matches no country list, Cloudflare exposes "XX"
 * for the operator to name next to "T1"), so denying it is the operator's
 * explicit choice. Whitelist mode (allow_cc) is fail-closed regardless.
 */

#include "heavybag_reputation.h"
#include "heavybag_geo.h"


ngx_int_t
ngx_http_heavybag_reputation_check(ngx_heavybag_rep_conf_t *rep,
    struct sockaddr *sa, ngx_str_t *reason, ngx_http_heavybag_verdict_t *out)
{
    uint16_t                    cc16, *codes;
    uint32_t                   *asns;
    ngx_uint_t                  i;
    ngx_http_heavybag_geo_result_t   res;

    /*
     * Fully define the write-only verdict up front so callers never read an
     * uninitialised field: reason defaults to NONE, no geo lookup ran, no
     * country. Each return below only overrides reason; the geo branch fills
     * country/flags/geo_valid. Every write stays NULL-guarded (SMTP passes
     * NULL). The control flow / verdict is byte-identical to before.
     */
    if (out != NULL) {
        out->reason = HEAVYBAG_REASON_NONE;
        out->country[0] = 0;
        out->country[1] = 0;
        out->flags = 0;
        out->asn = 0;
        out->geo_valid = 0;
    }

    if (sa == NULL) {
        return NGX_DECLINED;
    }

    /* 1. allowlist short-circuits to allow */
    if (rep->allowlist
        && ngx_cidr_match(sa, rep->allowlist) == NGX_OK)
    {
        if (out != NULL) {
            out->reason = HEAVYBAG_REASON_ALLOWLIST;
        }
        return NGX_DECLINED;
    }

    /* 2. static blocklist */
    if (rep->blocklist
        && ngx_cidr_match(sa, rep->blocklist) == NGX_OK)
    {
        ngx_str_set(reason, "static blocklist");
        if (out != NULL) {
            out->reason = HEAVYBAG_REASON_BLOCKLIST;
        }
        return NGX_HTTP_FORBIDDEN;
    }

    /* 3. geo / network-flag reputation */
    if (rep->geo_db == NULL) {
        return NGX_DECLINED;
    }

    ngx_http_heavybag_geo_lookup(rep->geo_db, sa, &res);

    /*
     * A geo lookup ran: publish the primitive geo fields to the caller's
     * verdict (write-only, never consulted for the decision below). On a
     * miss res.country/flags are undefined, so only copy them when found;
     * geo_valid still records that the lookup happened.
     */
    if (out != NULL) {
        out->geo_valid = 1;
        if (res.found) {
            out->country[0] = res.country[0];
            out->country[1] = res.country[1];
            out->flags = res.flags;
            out->asn = res.asn;
        }
    }

    if (!res.found) {
        /*
         * No geo record. In whitelist mode the country cannot be proven to
         * be on the allow list, so the resource is hidden (404).
         */
        if (rep->allow_cc) {
            ngx_str_set(reason, "geo not whitelisted");
            if (out != NULL) {
                out->reason = HEAVYBAG_REASON_GEO_WHITELIST;
            }
            return NGX_HTTP_NOT_FOUND;
        }

        /*
         * Block mode. A missing record is NOT evidence that the source is a
         * Tor exit / anonymiser: an attacker cannot remove itself from the
         * database, so this is a data-freshness gap, not an evasion primitive.
         * Deny-list semantics therefore let the unknown source through by
         * default -- the same convention the industry settled on: AWS WAF
         * labels an unresolvable IP "XX" (not a real ISO code, so it matches
         * no country list), Cloudflare exposes it as the "XX" value the
         * operator may name explicitly alongside Tor's "T1"
         * (ip.src.country in {"T1" "XX"}), and nginx's geoip2 leaves the
         * choice to the map default, which is fail-open for a block list.
         *
         * The operator can opt in to the strict reading with the `unknown`
         * token of waf_flag_block (our equivalent of naming "XX"), which sets
         * flag_block_unknown. Then a source with no record is a network-flag
         * deny -- out->flags stays 0, so the per-flag breakdown attributes it
         * to no specific bit. Whitelist mode above needs no token: it is
         * fail-closed by construction, as it should be.
         */
        if (rep->flag_block_unknown) {
            ngx_str_set(reason, "network flag (no geo record)");
            if (out != NULL) {
                out->reason = HEAVYBAG_REASON_FLAG;
            }
            return NGX_HTTP_FORBIDDEN;
        }

        return NGX_DECLINED;
    }

    /* network-flag blocks apply first, in both block and whitelist modes */
    if (rep->flag_mask && (res.flags & rep->flag_mask)) {
        ngx_str_set(reason, "network flag");
        if (out != NULL) {
            out->reason = HEAVYBAG_REASON_FLAG;
        }
        return NGX_HTTP_FORBIDDEN;
    }

    /*
     * ASN block: an explicit deny list of autonomous systems, applied in
     * both block and whitelist modes (like the network-flag block above).
     * asn==0 (unknown / no record) fails open.
     */
    if (rep->block_asn && res.asn != 0) {
        asns = rep->block_asn->elts;

        for (i = 0; i < rep->block_asn->nelts; i++) {
            if (asns[i] == res.asn) {
                ngx_str_set(reason, "asn");
                if (out != NULL) {
                    out->reason = HEAVYBAG_REASON_ASN;
                }
                return NGX_HTTP_FORBIDDEN;
            }
        }
    }

    cc16 = (uint16_t) ((res.country[0] << 8) | res.country[1]);

    /*
     * Special source codes from waf_flag_block (A1/A2/A3/T1/XD) deny in both
     * modes, like flag_mask above: they mark the source itself (Tor / anon /
     * satellite / drop), independent of the country allow/deny policy. Tor
     * carries the T1 code but no flag bit, so flag_mask alone would miss it.
     */
    if (rep->flag_cc) {
        codes = rep->flag_cc->elts;

        for (i = 0; i < rep->flag_cc->nelts; i++) {
            if (codes[i] == cc16) {
                ngx_str_set(reason, "network flag");
                if (out != NULL) {
                    out->reason = HEAVYBAG_REASON_FLAG;
                }
                return NGX_HTTP_FORBIDDEN;
            }
        }
    }

    /*
     * Whitelist mode wins when set: the country must be listed or the
     * request is hidden (404). block_cc is not consulted in this mode.
     */
    if (rep->allow_cc) {
        codes = rep->allow_cc->elts;

        for (i = 0; i < rep->allow_cc->nelts; i++) {
            if (codes[i] == cc16) {
                return NGX_DECLINED;
            }
        }

        ngx_str_set(reason, "geo not whitelisted");
        if (out != NULL) {
            out->reason = HEAVYBAG_REASON_GEO_WHITELIST;
        }
        return NGX_HTTP_NOT_FOUND;
    }

    if (rep->block_cc) {
        codes = rep->block_cc->elts;

        for (i = 0; i < rep->block_cc->nelts; i++) {
            if (codes[i] == cc16) {
                ngx_str_set(reason, "geo country");
                if (out != NULL) {
                    out->reason = HEAVYBAG_REASON_GEO;
                }
                return NGX_HTTP_FORBIDDEN;
            }
        }
    }

    return NGX_DECLINED;
}


/*
 * Inherit every reputation field this level left unset (rep-conf-01). Shared
 * verbatim by the HTTP location merge and the stream server merge -- the two
 * hand-written copies were byte-identical by intent and had already drifted.
 * Pure struct work, so the standalone unit TU exercises the real thing.
 *
 * Sentinels: a NULL pointer means "not configured at this level" for every
 * list, because the *_add() helpers only ever create an array when they push
 * an element. flag_mask/flag_cc are the exception -- see below.
 */
void
ngx_http_heavybag_rep_conf_merge(ngx_heavybag_rep_conf_t *prev,
    ngx_heavybag_rep_conf_t *conf)
{
    if (conf->geo_db == NULL) {
        conf->geo_db = prev->geo_db;
    }
    if (conf->block_cc == NULL) {
        conf->block_cc = prev->block_cc;
    }
    if (conf->block_asn == NULL) {
        conf->block_asn = prev->block_asn;
    }
    if (conf->allow_cc == NULL) {
        conf->allow_cc = prev->allow_cc;
    }

    /*
     * waf_flag_block is ONE policy unit, inherited or overridden as a whole
     * (flag-unit-01). flag_mask (bit-carrying flags), flag_cc (special source
     * codes that carry no bit, e.g. Tor's T1) and flag_block_unknown (the
     * `unknown` token) are three parts of the same directive, so inheriting
     * them independently was incoherent: a child saying "waf_flag_block tor"
     * leaves flag_mask == 0, and the old `if (flag_mask == 0) inherit` rule
     * then silently re-imported the parent's bit policy on top of the child's
     * override -- while a child saying "waf_flag_block anonymous-proxy"
     * dropped the parent's Tor entry. With the explicit set-marker the rule is
     * symmetric: a child that never used the directive inherits ALL THREE; a
     * child that used it overrides all three (clean override, nothing leaks in
     * from the parent -- in particular the parent's `unknown` never applies to
     * a child that spelled out its own flag policy).
     */
    if (!conf->flag_block_set) {
        conf->flag_mask = prev->flag_mask;
        conf->flag_cc = prev->flag_cc;
        conf->flag_block_unknown = prev->flag_block_unknown;
        conf->flag_block_set = prev->flag_block_set;
    }

    if (conf->blocklist == NULL) {
        conf->blocklist = prev->blocklist;
    }
    if (conf->allowlist == NULL) {
        conf->allowlist = prev->allowlist;
    }
}


/*
 * Fail-closed predicate: a geo-dependent deny policy needs a geo database to
 * work at all. Without one the reputation check silently fails open (allows
 * everyone), so the protection would be configured yet inert. Split out of
 * *_rep_conf_validate() so the pure decision is unit-testable without nginx.
 * waf_blocklist / waf_allowlist are plain CIDR and need no database, so they
 * are deliberately excluded.
 */
ngx_uint_t
ngx_http_heavybag_rep_conf_needs_geo(ngx_heavybag_rep_conf_t *rep)
{
    return (rep->geo_db == NULL
            && (rep->block_cc != NULL
                || rep->allow_cc != NULL
                || rep->block_asn != NULL
                || rep->flag_cc != NULL
                || rep->flag_mask != 0
                || rep->flag_block_unknown));
}


#ifndef HEAVYBAG_REPUTATION_UNIT_TEST  /* config-time helpers need nginx; out of the pure-core unit TU */

ngx_int_t
ngx_http_heavybag_cidr_add(ngx_conf_t *cf, ngx_array_t **arr, ngx_str_t *text)
{
    ngx_int_t    rc;
    ngx_cidr_t  *cidr;

    if (*arr == NULL) {
        *arr = ngx_array_create(cf->pool, 4, sizeof(ngx_cidr_t));
        if (*arr == NULL) {
            return NGX_ERROR;
        }
    }

    cidr = ngx_array_push(*arr);
    if (cidr == NULL) {
        return NGX_ERROR;
    }

    rc = ngx_ptocidr(text, cidr);

    if (rc == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid network address \"%V\"", text);
        return NGX_ERROR;
    }

    if (rc == NGX_DONE) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "low address bits of \"%V\" are meaningless", text);
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_heavybag_country_add(ngx_conf_t *cf, ngx_array_t **arr, ngx_str_t *cc)
{
    uint16_t  *code;
    u_char     c0, c1;

    if (cc->len != 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "country code \"%V\" must be two letters", cc);
        return NGX_ERROR;
    }

    if (*arr == NULL) {
        *arr = ngx_array_create(cf->pool, 8, sizeof(uint16_t));
        if (*arr == NULL) {
            return NGX_ERROR;
        }
    }

    code = ngx_array_push(*arr);
    if (code == NULL) {
        return NGX_ERROR;
    }

    /* libloc stores codes uppercase */
    c0 = ngx_toupper(cc->data[0]);
    c1 = ngx_toupper(cc->data[1]);

    *code = (uint16_t) ((c0 << 8) | c1);

    return NGX_OK;
}


ngx_int_t
ngx_http_heavybag_asn_add(ngx_conf_t *cf, ngx_array_t **arr, ngx_str_t *val)
{
    off_t       n;
    uint32_t   *asn;

    /*
     * Parse into a 64-bit off_t, NOT ngx_int_t: on a 32-bit (ILP32) build
     * ngx_atoi overflows at 2^31-1 and would reject legitimate 4-byte ASNs
     * above ~2.15B (e.g. AS4200000000) before the range check runs. ngx_atoof
     * is width-independent, so the advertised 1..4294967295 range holds on
     * every build. (M2)
     */
    n = ngx_atoof(val->data, val->len);

    /* 4-byte ASN range 1..4294967295; 0 is reserved and fails open anyway */
    if (n == NGX_ERROR || n <= 0 || (uint64_t) n > 0xffffffffULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_asn_block value \"%V\" is not a valid ASN "
                           "(expected a decimal number 1..4294967295)", val);
        return NGX_ERROR;
    }

    if (*arr == NULL) {
        *arr = ngx_array_create(cf->pool, 8, sizeof(uint32_t));
        if (*arr == NULL) {
            return NGX_ERROR;
        }
    }

    asn = ngx_array_push(*arr);
    if (asn == NULL) {
        return NGX_ERROR;
    }

    *asn = (uint32_t) n;

    return NGX_OK;
}


ngx_int_t
ngx_http_heavybag_flag_add(ngx_conf_t *cf, ngx_heavybag_rep_conf_t *rep,
    ngx_str_t *tok)
{
    uint16_t   flag;
    ngx_str_t  cc;

    flag = 0;
    ngx_str_null(&cc);

    if ((tok->len == 15 && ngx_strncmp(tok->data, "anonymous-proxy", 15) == 0)
        || (tok->len == 4 && ngx_strncmp(tok->data, "anon", 4) == 0))
    {
        flag = NGX_HTTP_HEAVYBAG_GEO_FLAG_ANON_PROXY;
        ngx_str_set(&cc, "A1");

    } else if (tok->len == 9 && ngx_strncmp(tok->data, "satellite", 9) == 0) {
        flag = NGX_HTTP_HEAVYBAG_GEO_FLAG_SATELLITE;
        ngx_str_set(&cc, "A2");

    } else if (tok->len == 7 && ngx_strncmp(tok->data, "anycast", 7) == 0) {
        flag = NGX_HTTP_HEAVYBAG_GEO_FLAG_ANYCAST;
        ngx_str_set(&cc, "A3");

    } else if (tok->len == 4 && ngx_strncmp(tok->data, "drop", 4) == 0) {
        flag = NGX_HTTP_HEAVYBAG_GEO_FLAG_DROP;
        ngx_str_set(&cc, "XD");

    } else if (tok->len == 3 && ngx_strncmp(tok->data, "tor", 3) == 0) {
        /* Tor exits carry the special country code T1; no flag bit */
        ngx_str_set(&cc, "T1");

    } else if (tok->len == 7 && ngx_strncmp(tok->data, "unknown", 7) == 0) {
        /*
         * Not a libloc signal at all: the deliberate opt-in to denying a
         * source the database has NO record for. It contributes neither a bit
         * nor a country code -- the reputation core reads the bit directly on
         * the !res.found path. Our equivalent of naming AWS WAF's /
         * Cloudflare's "XX" pseudo-country in a rule.
         */
        rep->flag_block_unknown = 1;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "unknown waf_flag_block value \"%V\" (expected one of: "
            "anonymous-proxy, satellite, anycast, tor, drop, unknown)", tok);
        return NGX_ERROR;
    }

    /*
     * Mark the whole waf_flag_block unit as set at this level. Every accepted
     * token raises it, including the two that contribute no bit -- "tor"
     * (flag == 0, code T1 only) and "unknown" (neither bit nor code) -- so
     * flag_mask alone can never tell "unset" from "set to a bitless policy".
     * The merge keys off this marker, not off flag_mask / flag_cc /
     * flag_block_unknown (flag-unit-01).
     */
    rep->flag_block_set = 1;

    rep->flag_mask |= flag;

    if (cc.len) {
        if (ngx_http_heavybag_country_add(cf, &rep->flag_cc, &cc) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


/*
 * Config-time half of the fail-closed geo-dependency rule: refuse the config
 * at "nginx -t" rather than let a configured-but-inert policy bypass silently.
 * MUST be called AFTER ngx_http_heavybag_rep_conf_merge() so it judges the
 * full effective config -- the HTTP head used to validate half-way through its
 * inherit sequence, the stream head after it, and only one of those orders can
 * be right.
 */
char *
ngx_http_heavybag_rep_conf_validate(ngx_conf_t *cf, ngx_heavybag_rep_conf_t *rep)
{
    if (ngx_http_heavybag_rep_conf_needs_geo(rep)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "waf_geo_block / waf_geo_whitelist / waf_asn_block / waf_flag_block "
            "require waf_geo_db, but no geo database is configured");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/*
 * waf_geo_db <path>: open and attach the geo database for this level.
 * Rejects a duplicate directive; geo_open does the open and validation.
 */
char *
ngx_http_heavybag_rep_set_geo_db(ngx_conf_t *cf, ngx_heavybag_rep_conf_t *rep)
{
    ngx_str_t  *value;

    if (rep->geo_db != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    rep->geo_db = ngx_http_heavybag_geo_open(cf, &value[1]);
    if (rep->geo_db == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/*
 * waf_geo_block <CC>...: deny the listed countries. Each ISO-2 country-code
 * argument is appended to rep->block_cc.
 */
char *
ngx_http_heavybag_rep_set_geo_block(ngx_conf_t *cf, ngx_heavybag_rep_conf_t *rep)
{
    ngx_str_t   *value = cf->args->elts;
    ngx_uint_t   i;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_http_heavybag_country_add(cf, &rep->block_cc, &value[i])
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


/*
 * waf_geo_whitelist <CC>...: allow only the listed countries; everyone else
 * -- and any IP with no geo record -- is hidden (404). Coexists with
 * waf_geo_block but wins over it: when a whitelist is set the block list is
 * not consulted for the country decision.
 */
char *
ngx_http_heavybag_rep_set_geo_whitelist(ngx_conf_t *cf,
    ngx_heavybag_rep_conf_t *rep)
{
    ngx_str_t   *value = cf->args->elts;
    ngx_uint_t   i;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_http_heavybag_country_add(cf, &rep->allow_cc, &value[i])
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


/*
 * waf_asn_block <ASN>...: deny any source that resolves (via the geo
 * database) to one of the listed autonomous systems. Decimal ASNs only;
 * asn==0 (no record) is never matched.
 */
char *
ngx_http_heavybag_rep_set_asn_block(ngx_conf_t *cf, ngx_heavybag_rep_conf_t *rep)
{
    ngx_str_t   *value = cf->args->elts;
    ngx_uint_t   i;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_http_heavybag_asn_add(cf, &rep->block_asn, &value[i])
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


/*
 * waf_flag_block <flag>...: deny sources whose geo record carries one of the
 * named flags (anycast, satellite, ...) or the matching special source code;
 * the extra `unknown` token denies sources with no record at all. flag_add
 * also raises the flag_block_set marker the merge keys off.
 */
char *
ngx_http_heavybag_rep_set_flag_block(ngx_conf_t *cf, ngx_heavybag_rep_conf_t *rep)
{
    ngx_str_t   *value = cf->args->elts;
    ngx_uint_t   i;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_http_heavybag_flag_add(cf, rep, &value[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


/*
 * waf_blocklist <CIDR>: append a network to the reputation blocklist whose
 * sources are always denied.
 */
char *
ngx_http_heavybag_rep_set_blocklist(ngx_conf_t *cf, ngx_heavybag_rep_conf_t *rep)
{
    ngx_str_t  *value = cf->args->elts;

    if (ngx_http_heavybag_cidr_add(cf, &rep->blocklist, &value[1]) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/*
 * waf_allowlist <CIDR>: append a network to the reputation allowlist whose
 * sources bypass the reputation checks.
 */
char *
ngx_http_heavybag_rep_set_allowlist(ngx_conf_t *cf, ngx_heavybag_rep_conf_t *rep)
{
    ngx_str_t  *value = cf->args->elts;

    if (ngx_http_heavybag_cidr_add(cf, &rep->allowlist, &value[1]) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

#endif /* !HEAVYBAG_REPUTATION_UNIT_TEST */
