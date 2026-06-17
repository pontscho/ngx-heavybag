/*
 * ngx_http_heavybag_module - geo / reputation database (libloc reader)
 *
 * Adapted from arpi's nanolibloc.c (gereoffy/ipstat46) as a starting
 * point, rewritten for nginx:
 *   - no global state: everything lives in ngx_http_heavybag_geo_db_t;
 *   - the IPFire "location.db" is mmap'd read-only (shared across workers
 *     by fork copy-on-write, never dirtied) instead of malloc+read;
 *   - the per-network flags field (anonymous proxy / satellite / anycast /
 *     drop) is parsed -- nanolibloc skips it;
 *   - the mmap is released by an ngx_pool_cleanup_t bound to the
 *     configuration cycle pool, so a reload re-maps and frees cleanly.
 *
 * The on-disk format is big-endian. Five blocks: AS numbers, network
 * data (leaves), network tree (radix trie), countries, and a string pool.
 */

#ifndef _HEAVYBAG_GEO_H_INCLUDED_
#define _HEAVYBAG_GEO_H_INCLUDED_


#ifndef HEAVYBAG_GEO_UNIT_TEST

#include "ngx_http_heavybag.h"

#else

/*
 * Standalone unit-test shim (-DHEAVYBAG_GEO_UNIT_TEST): substitute nginx for
 * the pure radix-trie walk + 12-byte leaf-decode core, NO nginx / SSL
 * headers. Every typedef mirrors nginx byte-for-byte -- the shim REPLACES
 * nginx, it never redefines its semantics; the real -Werror SSL module build
 * stays the only correctness contract. Only the geo db/result structs and
 * the trie walk are exercised here; the config-time open()/verify path
 * (ngx_conf_t / mmap / OpenSSL) sits behind #ifndef in heavybag_geo.c.
 * test-geo.c includes that .c directly, so the static walk + the u32/u16
 * big-endian readers are reachable.
 */
#include <stddef.h>
#include <stdint.h>
typedef unsigned char  u_char;
typedef intptr_t       ngx_int_t;
typedef uintptr_t      ngx_uint_t;
typedef struct { size_t len; u_char *data; } ngx_str_t;
#define ngx_inline inline

#endif


/*
 * On-disk block indices and per-network flags. SHARED by the production build
 * and the unit-test shim -- NEVER duplicated into the shim: a divergent copy
 * would silently drift from the real layout the trie walk depends on.
 */
#define NGX_HTTP_HEAVYBAG_GEO_AS   0     /* AS number table   */
#define NGX_HTTP_HEAVYBAG_GEO_ND   1     /* network leaf data */
#define NGX_HTTP_HEAVYBAG_GEO_NT   2     /* network tree      */
#define NGX_HTTP_HEAVYBAG_GEO_CO   3     /* country table     */
#define NGX_HTTP_HEAVYBAG_GEO_PO   4     /* string pool       */
#define NGX_HTTP_HEAVYBAG_GEO_BLOCKS 5

/* libloc per-network flags (uint16, big-endian, at ND entry offset 8) */
#define NGX_HTTP_HEAVYBAG_GEO_FLAG_ANON_PROXY  0x0001
#define NGX_HTTP_HEAVYBAG_GEO_FLAG_SATELLITE   0x0002
#define NGX_HTTP_HEAVYBAG_GEO_FLAG_ANYCAST     0x0004
#define NGX_HTTP_HEAVYBAG_GEO_FLAG_DROP        0x0008


/*
 * geo db + result structs. SHARED: they reference only shimmable types
 * (u_char / size_t / uintXX / ngx_uint_t / ngx_str_t), so the unit test can
 * build a synthetic in-memory db and read a decoded result without nginx.
 */
typedef struct ngx_http_heavybag_geo_db_s {
    u_char      *map;                            /* mmap base address  */
    size_t       map_size;                       /* mmap length        */

    u_char      *block[NGX_HTTP_HEAVYBAG_GEO_BLOCKS]; /* pointers into map  */
    uint32_t     block_len[NGX_HTTP_HEAVYBAG_GEO_BLOCKS];

    uint32_t     ipv4root;                       /* IPv4 trie root node*/

    ngx_str_t    path;
} ngx_http_heavybag_geo_db_t;


typedef struct {
    ngx_uint_t   found;          /* 1 if a network matched the address */
    u_char       country[2];     /* ISO-2, or special A1/A2/A3/T1/XD   */
    uint16_t     flags;          /* NGX_HTTP_HEAVYBAG_GEO_FLAG_*            */
    uint32_t     asn;
} ngx_http_heavybag_geo_result_t;


#ifndef HEAVYBAG_GEO_UNIT_TEST

/*
 * mmap and validate the database at *path (config-time). The mapping is
 * released through a cleanup handler on cf->pool. Returns NULL on error
 * (already logged).
 */
ngx_http_heavybag_geo_db_t *ngx_http_heavybag_geo_open(ngx_conf_t *cf, ngx_str_t *path);

/* Look up an address (AF_INET / AF_INET6). Fills res (res->found=0 if none). */
void ngx_http_heavybag_geo_lookup(ngx_http_heavybag_geo_db_t *db, struct sockaddr *sa,
    ngx_http_heavybag_geo_result_t *res);

#endif /* HEAVYBAG_GEO_UNIT_TEST */


#endif /* _HEAVYBAG_GEO_H_INCLUDED_ */
