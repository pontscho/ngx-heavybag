/*
 * ngx_http_heavybag_module - geo / reputation database (libloc reader)
 *
 * See heavybag_geo.h. The radix-trie walk is taken 1:1 from nanolibloc (it is
 * the proven part); everything around it -- mmap lifetime, bounds checks,
 * context struct, flags parsing -- is rewritten for nginx.
 */

#include "heavybag_geo.h"

#ifndef HEAVYBAG_GEO_UNIT_TEST

#include <sys/mman.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#else

#include <netinet/in.h>   /* sockaddr_in/in6, IN6_IS_ADDR_V4MAPPED, AF_INET[6] */

#endif


/*
 * libloc signed-header layout (libloc 0.9.18, byte-exact). ONE coordinate
 * frame: the live mmap is read file-absolute as base+N; the stack header COPY
 * is indexed copy-local 0..4192, where copy-local N maps to file-absolute
 * base + 8 + N. The two buffers (mmap base vs stack copy) are never conflated.
 */
#define NGX_HTTP_HEAVYBAG_GEO_HDR_SIZE   4192   /* on-disk header size after magic  */
#define NGX_HTTP_HEAVYBAG_GEO_DATA_OFF   (8 + NGX_HTTP_HEAVYBAG_GEO_HDR_SIZE)  /* 4200    */
#define NGX_HTTP_HEAVYBAG_GEO_SIG_MAX    2048   /* per-slot signature blob capacity */
#define NGX_HTTP_HEAVYBAG_GEO_ZERO_BEG   60     /* copy-local: first u16 length     */
#define NGX_HTTP_HEAVYBAG_GEO_ZERO_END   4160   /* copy-local: end of sig2 blob     */
/* file-absolute signature offsets (base + 8 + copy-local): */
#define NGX_HTTP_HEAVYBAG_GEO_SIG1_LEN   (8 + 60)    /* 68   */
#define NGX_HTTP_HEAVYBAG_GEO_SIG2_LEN   (8 + 62)    /* 70   */
#define NGX_HTTP_HEAVYBAG_GEO_SIG1_OFF   (8 + 64)    /* 72   */
#define NGX_HTTP_HEAVYBAG_GEO_SIG2_OFF   (8 + 2112)  /* 2120 */

/*
 * Maximum accepted DB size. The real geodb/location.db measured 63,517,012
 * bytes (about 60.6 MiB) on 2026-06-12; this 512 MiB cap is roughly 8.5x that,
 * so an organically growing DB stays well under it, while a runaway or hostile
 * oversized file cannot stall a reload by being SHA-512'd first.
 */
#define NGX_HTTP_HEAVYBAG_GEO_MAX_SIZE   (512UL * 1024 * 1024)

/*
 * Pinned IPFire location database signing key (ECDSA P-521 / secp521r1,
 * created 2019-12-10 by Michael Tremer; stable since). Cross-sourced
 * byte-identical from git.ipfire.org and sources.debian.org; embedded PEM
 * block SHA-256:
 *   7d927e19042d9cf12ef4644d2d4fd3095e26e9b5815ebd9e82d973219497430e
 * A key rotation (multi-year horizon) requires rebuilding this module. The
 * key is a NUL-terminated string literal, loaded via BIO_new_mem_buf(key,-1).
 */
#ifndef HEAVYBAG_GEO_UNIT_TEST
static const char  ngx_http_heavybag_geo_signing_key[] =
"-----BEGIN PUBLIC KEY-----\n"
"MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB1PzZdV9DE59LVCdXy/9cRgvTy9lx\n"
"L5tV10awZDilwQ9GR8x/irJE8ctGSnZ5HgbOk+gilurmC5JlJmTjZrW7tt8Awiu8\n"
"ir3y2n7XXyiVGIzTHrA6Tw7SG+H9LzuIl0wCg6s6svnXVDyho7b0tSZPUGKMI28q\n"
"CUXef0jvZ9+ncTiJh1w=\n"
"-----END PUBLIC KEY-----\n";
#endif


/* big-endian 32-bit read */
static ngx_inline uint32_t
ngx_http_heavybag_geo_u32(const u_char *p)
{
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16)
           | ((uint32_t) p[2] << 8) | (uint32_t) p[3];
}


#ifndef HEAVYBAG_GEO_UNIT_TEST
static void
ngx_http_heavybag_geo_cleanup(void *data)
{
    ngx_http_heavybag_geo_db_t  *db = data;

    if (db->map != NULL && db->map != MAP_FAILED) {
        munmap(db->map, db->map_size);
        db->map = NULL;
    }
}
#endif


/*
 * Dedicated big-endian 16-bit read. MUST NOT reuse the 32-bit reader, which
 * would swallow the adjacent length field (sig1_len and sig2_len are packed
 * back-to-back).
 */
static ngx_inline uint16_t
ngx_http_heavybag_geo_u16(const u_char *p)
{
    return (uint16_t) (((uint16_t) p[0] << 8) | (uint16_t) p[1]);
}


/*
 * Width-independent block-table bounds test: is [off, off+len) outside a file
 * of `size` bytes? The natural `(size_t) off + len > size` WRAPS on an ILP32
 * build -- there size_t is 32-bit, and off/len are untrusted 32-bit header
 * fields, so e.g. off=0xfffffff0 + len=0x20 folds to 0x10 and passes, after
 * which db->block[i] points far outside the mapping. Subtracting instead of
 * adding cannot overflow at any width: the first test guarantees `size - off`
 * does not underflow. Same ILP32 hardening rationale as the ASN parser in
 * heavybag_reputation.c (M2); LP64 was already safe. (SV4, CWE-190 -> 125)
 */
static ngx_inline ngx_uint_t
ngx_http_heavybag_geo_block_oob(uint32_t off, uint32_t len, size_t size)
{
    return (off > size || len > size - off);
}


/*
 * Width-independent entry-index bounds test, the node/leaf counterpart of
 * geo_block_oob above: is 12-byte entry `idx` outside a block of `len` bytes?
 *
 * The natural `(size_t) idx * 12 + 12 > len` WRAPS on an ILP32 build -- there
 * size_t is 32-bit and idx is an untrusted 32-bit index straight out of the
 * DB, so the product alone folds over. The two live vectors:
 *   idx = 0x7fffffff (the largest value the leaf path can carry, since the
 *     0x80000000 bit is the internal-node marker): 0x7fffffff*12 + 12 folds to
 *     EXACTLY 0, so the pre-fix bound accepted it for ANY len, then indexed
 *     block + 0xfffffff4;
 *   idx = 357913941: folds to 8, likewise accepted.
 * Dividing instead of multiplying cannot overflow at any width: len/12 is the
 * number of whole entries that fit, and `12*idx + 12 <= len` is exactly
 * `idx < len/12` for integer division (0 <= len%12 < 12 leaves no room for a
 * partial entry). Callers MUST test before forming the offset -- a passing idx
 * satisfies idx*12 < len <= UINT32_MAX, which makes the subsequent multiply
 * unwrappable at any width.
 *
 * Same hardening class the block table already got, now closed for the three
 * node/leaf index sites (descent, walker, leaf decode). LP64 was already safe.
 * (SV4, CWE-190 -> 125)
 */
#define NGX_HTTP_HEAVYBAG_GEO_ENTRY  12   /* tree node AND network leaf size */

static ngx_inline ngx_uint_t
ngx_http_heavybag_geo_entry_oob(uint32_t idx, uint32_t len)
{
    return (idx >= len / NGX_HTTP_HEAVYBAG_GEO_ENTRY);
}


/*
 * Result of the IPv4-mapped-root descent. Dedicated codes rather than
 * NGX_OK/NGX_ERROR: those are nginx-only, and this descent is compiled into
 * the nginx-free unit-test build too. The caller owns the log wording.
 */
#define NGX_HTTP_HEAVYBAG_GEO_V4ROOT_OK       0
#define NGX_HTTP_HEAVYBAG_GEO_V4ROOT_TRUNC    1  /* node outside the NT block */
#define NGX_HTTP_HEAVYBAG_GEO_V4ROOT_DEADEND  2  /* zero child in the /96 chain */


/*
 * Descend the network tree to the IPv4-mapped root (::ffff:0:0/96): 96 steps,
 * the first 80 following the bit==0 child (the leading zeroes), the last 16
 * the bit==1 child (the 0xffff marker). Kept pure over the tree block so the
 * unit harness can drive it without nginx; *root is written only on OK.
 *
 * A fetched child of 0 is the trie's terminal sentinel -- node 0 is the root
 * and nothing points back to it, which is exactly why the runtime walker ends
 * on it (`} while (nxt)`, see _walk below). ANY zero along the chain, the 96th
 * step included, is therefore a hard load failure:
 *
 *   - a zero BEFORE the last step means the /96 chain is absent or short:
 *     `nxt` re-reads node 0 (always in bounds, so the bounds check never
 *     fires) and the descent silently keeps going from the v6 root;
 *   - a zero AT the last step walks the chain in full but names node 0 -- the
 *     v6 root, which by construction sits at depth 0 -- as the IPv4 root.
 *
 * Both land in the same wrong place: db->ipv4root then points at a node that
 * is not the ::ffff:0:0/96 subtree, so every IPv4 lookup walks the v6 trie
 * from the top and silently returns another network's country/ASN. In a
 * well-formed DB index 0 is depth 0 and can never legitimately be the IPv4
 * root, so rejecting it costs an intact database nothing. The ECDSA gate
 * proves the file's integrity, not its trie structure, so this fails closed
 * at config time, never a silent fallback. (#8 / SV3)
 */
static ngx_int_t
ngx_http_heavybag_geo_ipv4root(const u_char *nt, uint32_t ntlen, uint32_t *root)
{
    uint32_t    nxt;
    size_t      off;
    ngx_uint_t  i;

    nxt = 0;

    for (i = 0; i < 96; i++) {
        /* bounds BEFORE the multiply, so the offset cannot wrap on ILP32 */
        if (ngx_http_heavybag_geo_entry_oob(nxt, ntlen)) {
            return NGX_HTTP_HEAVYBAG_GEO_V4ROOT_TRUNC;
        }

        off = (size_t) nxt * NGX_HTTP_HEAVYBAG_GEO_ENTRY;

        nxt = ngx_http_heavybag_geo_u32(nt + off + (i < 80 ? 0 : 4));

        if (nxt == 0) {
            return NGX_HTTP_HEAVYBAG_GEO_V4ROOT_DEADEND;
        }
    }

    *root = nxt;

    return NGX_HTTP_HEAVYBAG_GEO_V4ROOT_OK;
}


/*
 * Verify the database's embedded ECDSA P-521 / SHA-512 signature against the
 * pinned IPFire public key -- libloc loc_database_verify() reproduced with
 * OpenSSL (libcrypto is already linked, see heavybag_ja4.c; no libloc dependency).
 *
 * Mandatory and fail-closed: an unsigned (both slots absent), tampered, or
 * corrupted DB, or ANY OpenSSL error, returns NGX_ERROR. The hashed message
 * is magic(8) ++ header(4192, copy-local bytes [60,4160) zeroed) ++ the rest
 * of the file (base + DATA_OFF .. EOF). Dual signature for key rotation:
 * verify sig1, then sig2; accept if EITHER yields EVP_DigestVerifyFinal == 1
 * (neither signature is forgeable without the private key, so EITHER-valid is
 * rotation tolerance, not a weakness).
 *
 * The caller guarantees size >= NGX_HTTP_HEAVYBAG_GEO_DATA_OFF (pre-mmap guard).
 */
#ifndef HEAVYBAG_GEO_UNIT_TEST
static ngx_int_t
ngx_http_heavybag_geo_verify(ngx_conf_t *cf, ngx_str_t *full,
    const u_char *base, size_t size)
{
    BIO            *bio = NULL;
    EVP_PKEY       *pkey = NULL;
    EVP_MD_CTX     *bctx = NULL;
    EVP_MD_CTX     *snap = NULL;
    ngx_int_t       rc = NGX_ERROR;
    int             valid = 0;
    ngx_uint_t      sig1_len, sig2_len, have1, have2;
    unsigned long   e;
    u_char          hdr[NGX_HTTP_HEAVYBAG_GEO_HDR_SIZE];
    char            errbuf[256];

    sig1_len = ngx_http_heavybag_geo_u16(base + NGX_HTTP_HEAVYBAG_GEO_SIG1_LEN);
    sig2_len = ngx_http_heavybag_geo_u16(base + NGX_HTTP_HEAVYBAG_GEO_SIG2_LEN);

    /* a slot is present iff 1 <= len <= SIG_MAX; never Final an empty slot */
    have1 = (sig1_len >= 1 && sig1_len <= NGX_HTTP_HEAVYBAG_GEO_SIG_MAX);
    have2 = (sig2_len >= 1 && sig2_len <= NGX_HTTP_HEAVYBAG_GEO_SIG_MAX);

    if (!have1 && !have2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "geo database \"%V\" is not signed", full);
        return NGX_ERROR;
    }

    /*
     * Drain any stale OpenSSL error left by earlier config-parse work, so the
     * error reported on a reject is guaranteed to be from this verification.
     */
    ERR_clear_error();

    bio = BIO_new_mem_buf(ngx_http_heavybag_geo_signing_key, -1);
    if (bio == NULL) {
        goto failed;
    }

    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (pkey == NULL) {
        goto failed;
    }

    bctx = EVP_MD_CTX_new();
    if (bctx == NULL) {
        goto failed;
    }

    /* NULL digest: OpenSSL selects SHA-512 for a P-521 key, matching libloc */
    if (EVP_DigestVerifyInit(bctx, NULL, NULL, NULL, pkey) != 1) {
        goto failed;
    }

    /*
     * Header copy: zero copy-local [60,4160) -- both u16 length fields and
     * both signature blobs -- leaving padding [4160,4192) intact, exactly as
     * libloc hashes it.
     */
    ngx_memcpy(hdr, base + 8, NGX_HTTP_HEAVYBAG_GEO_HDR_SIZE);
    ngx_memzero(hdr + NGX_HTTP_HEAVYBAG_GEO_ZERO_BEG,
                NGX_HTTP_HEAVYBAG_GEO_ZERO_END - NGX_HTTP_HEAVYBAG_GEO_ZERO_BEG);

    if (EVP_DigestVerifyUpdate(bctx, base, 8) != 1
        || EVP_DigestVerifyUpdate(bctx, hdr, NGX_HTTP_HEAVYBAG_GEO_HDR_SIZE) != 1
        || EVP_DigestVerifyUpdate(bctx, base + NGX_HTTP_HEAVYBAG_GEO_DATA_OFF,
                                  size - NGX_HTTP_HEAVYBAG_GEO_DATA_OFF) != 1)
    {
        goto failed;
    }

    /*
     * Exactly one live snapshot at a time: copy the un-finalized base ctx,
     * Final, then free-and-NULL before testing the next slot. copy_ex is
     * always from bctx (never from an already-finalized snapshot), so the
     * epilogue cannot double-free. valid is set ONLY on an exact == 1
     * (0 = bad signature, <0 = error -- both must reject).
     */
    if (have1) {
        snap = EVP_MD_CTX_new();
        if (snap == NULL || EVP_MD_CTX_copy_ex(snap, bctx) != 1) {
            goto failed;
        }
        if (EVP_DigestVerifyFinal(snap, base + NGX_HTTP_HEAVYBAG_GEO_SIG1_OFF,
                                  sig1_len) == 1)
        {
            valid = 1;
        }
        EVP_MD_CTX_free(snap);
        snap = NULL;
    }

    if (!valid && have2) {
        snap = EVP_MD_CTX_new();
        if (snap == NULL || EVP_MD_CTX_copy_ex(snap, bctx) != 1) {
            goto failed;
        }
        if (EVP_DigestVerifyFinal(snap, base + NGX_HTTP_HEAVYBAG_GEO_SIG2_OFF,
                                  sig2_len) == 1)
        {
            valid = 1;
        }
        EVP_MD_CTX_free(snap);
        snap = NULL;
    }

    if (valid) {
        rc = NGX_OK;
        goto cleanup;
    }

failed:

    e = ERR_get_error();
    if (e != 0) {
        ERR_error_string_n(e, errbuf, sizeof(errbuf));
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "geo database \"%V\" signature verification failed: %s",
            full, errbuf);
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "geo database \"%V\" signature verification failed", full);
    }

cleanup:

    if (snap != NULL) {
        EVP_MD_CTX_free(snap);
    }
    if (bctx != NULL) {
        EVP_MD_CTX_free(bctx);
    }
    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }
    if (bio != NULL) {
        BIO_free(bio);
    }

    return rc;
}


ngx_http_heavybag_geo_db_t *
ngx_http_heavybag_geo_open(ngx_conf_t *cf, ngx_str_t *path)
{
    u_char                  *base, *hdr;
    size_t                   size, nsize;
    uint32_t                 off, len;
    ngx_fd_t                 fd;
    ngx_str_t                full;
    ngx_uint_t               i;
    ngx_file_info_t          fi;
    ngx_pool_cleanup_t      *cln;
    ngx_http_heavybag_geo_db_t   *db;

    full = *path;

    if (ngx_conf_full_name(cf->cycle, &full, 1) != NGX_OK) {
        return NULL;
    }

    fd = ngx_open_file(full.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_open_file_n " \"%V\" failed", &full);
        return NULL;
    }

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_fd_info_n " \"%V\" failed", &full);
        ngx_close_file(fd);
        return NULL;
    }

    size = (size_t) ngx_file_size(&fi);

    /*
     * Strict: the signed header plus its trailing data offset is 4200 bytes,
     * so the verify pass can read magic ++ header ++ rest without underflow
     * (size is unsigned; size - DATA_OFF must not wrap). Reject before mmap.
     */
    if (size < NGX_HTTP_HEAVYBAG_GEO_DATA_OFF) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "geo database \"%V\" is too small", &full);
        ngx_close_file(fd);
        return NULL;
    }

    /* cap before mmap so a giant file cannot stall a reload by hashing first */
    if (size > NGX_HTTP_HEAVYBAG_GEO_MAX_SIZE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "geo database \"%V\" is too large (%uz bytes)",
                           &full, size);
        ngx_close_file(fd);
        return NULL;
    }

    /*
     * OPERATIONAL CONTRACT -- location.db MUST be replaced with write-new +
     * rename(2), NEVER truncated or rewritten in place.
     *
     * mmap does not pin the file's length: it maps pages of the inode, and if
     * that inode is shortened while the mapping is live, every touch past the
     * new EOF raises SIGBUS -- in a worker, mid-request, on a read that looks
     * like a plain pointer dereference (_walk/_lookup below). rename(2) does
     * not have that problem: it only swaps the directory entry, the old inode
     * stays alive and fully sized for as long as this mapping references it,
     * so live workers keep serving the old DB until the next reload re-maps.
     * Forbidden update patterns: `> location.db`, `curl -o` / `wget -O` onto
     * the live path, `cp` over it, rsync without --inplace being avoided.
     *
     * The re-stat below closes ONLY the load-time race (the file changing
     * between the ngx_fd_info above and this mmap). Truncation AFTER a
     * successful load stays fatal BY DESIGN -- the same trade-off nginx makes
     * for its own mmap'd output/cache files. A SIGBUS handler is deliberately
     * not installed: it could not make a half-mapped DB coherent, only hide
     * the operator error behind an unrecoverable-in-practice signal. (#10/SV5)
     */
    base = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);

    if (base == MAP_FAILED) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "mmap(\"%V\", %uz) failed", &full, size);
        ngx_close_file(fd);
        return NULL;
    }

    /*
     * Load-time belt: if the size moved under us, `size` describes a file that
     * no longer exists and the tail of the mapping is already SIGBUS-live.
     * Reject now, while we can still fail the configuration cleanly.
     */
    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_fd_info_n " \"%V\" failed after mmap", &full);
        munmap(base, size);
        ngx_close_file(fd);
        return NULL;
    }

    nsize = (size_t) ngx_file_size(&fi);

    if (nsize != size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "geo database \"%V\" changed size while loading (%uz -> %uz "
            "bytes); it must be replaced with write-new + rename(2), never "
            "truncated or rewritten in place", &full, size, nsize);
        munmap(base, size);
        ngx_close_file(fd);
        return NULL;
    }

    ngx_close_file(fd);

    db = ngx_pcalloc(cf->pool, sizeof(ngx_http_heavybag_geo_db_t));
    if (db == NULL) {
        munmap(base, size);
        return NULL;
    }

    db->map = base;
    db->map_size = size;
    db->path = *path;

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        munmap(base, size);
        return NULL;
    }
    cln->handler = ngx_http_heavybag_geo_cleanup;
    cln->data = db;

    /* Magic: "LOCD" "BXX\x01"  ==  4C4F4344 42585801 */
    if (ngx_http_heavybag_geo_u32(base) != 0x4C4F4344
        || ngx_http_heavybag_geo_u32(base + 4) != 0x42585801)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "geo database \"%V\" has a bad magic", &full);
        return NULL;
    }

    /*
     * Cryptographic gate, before any block offset is trusted: verify reads
     * the file linearly (magic ++ header ++ rest) and the pre-mmap guard
     * already ensures size >= DATA_OFF, so this is the correct first check.
     * On failure the pool cleanup (registered above) munmaps the mapping.
     */
    if (ngx_http_heavybag_geo_verify(cf, &full, base, size) != NGX_OK) {
        return NULL;
    }

    hdr = base + 8;

    for (i = 0; i < NGX_HTTP_HEAVYBAG_GEO_BLOCKS; i++) {
        off = ngx_http_heavybag_geo_u32(hdr + 20 + i * 8);
        len = ngx_http_heavybag_geo_u32(hdr + 24 + i * 8);

        if (ngx_http_heavybag_geo_block_oob(off, len, size)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "geo database \"%V\" block %ui out of bounds", &full, i);
            return NULL;
        }

        db->block[i] = base + off;
        db->block_len[i] = len;
    }

    /* Descend the v6 trie to the IPv4-mapped root (::ffff:0:0/96). */
    switch (ngx_http_heavybag_geo_ipv4root(
                db->block[NGX_HTTP_HEAVYBAG_GEO_NT],
                db->block_len[NGX_HTTP_HEAVYBAG_GEO_NT],
                &db->ipv4root))
    {
    case NGX_HTTP_HEAVYBAG_GEO_V4ROOT_OK:
        break;

    case NGX_HTTP_HEAVYBAG_GEO_V4ROOT_DEADEND:
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "geo database \"%V\" network tree does not reach the IPv4-mapped "
            "root: the ::ffff:0:0/96 chain has a zero child (node 0 is the "
            "depth-0 v6 root and is never a valid IPv4 root)", &full);
        return NULL;

    default:
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "geo database \"%V\" truncated network tree", &full);
        return NULL;
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "heavybag: geo database \"%V\" loaded (%uz bytes, %ui networks)",
        &full, size, db->block_len[NGX_HTTP_HEAVYBAG_GEO_ND]
                     / NGX_HTTP_HEAVYBAG_GEO_ENTRY);

    return db;
}
#endif /* HEAVYBAG_GEO_UNIT_TEST */


/* address -> network leaf index, or -1. IPv6 / generic bit walk. */
static ngx_int_t
ngx_http_heavybag_geo_walk(ngx_http_heavybag_geo_db_t *db, const u_char *addr,
    ngx_uint_t addrlen, uint32_t nxt)
{
    u_char     *nt = db->block[NGX_HTTP_HEAVYBAG_GEO_NT];
    uint32_t    ntlen = db->block_len[NGX_HTTP_HEAVYBAG_GEO_NT];
    uint32_t    net;
    ngx_int_t   ret = -1;
    ngx_uint_t  mask = 0;
    ngx_uint_t  bit;
    size_t      off;

    do {
        /*
         * Require the WHOLE 12-byte node to fit -- guarding only its first
         * byte over-reads a trailing node -- and test the index before it is
         * multiplied out, since nxt is an untrusted 32-bit value from the DB
         * and `(size_t) nxt * 12` wraps on an ILP32 size_t.
         */
        if (ngx_http_heavybag_geo_entry_oob(nxt, ntlen)) {
            return -1;
        }

        off = (size_t) nxt * NGX_HTTP_HEAVYBAG_GEO_ENTRY;

        net = ngx_http_heavybag_geo_u32(nt + off + 8);
        if (!(net & 0x80000000)) {
            ret = (ngx_int_t) net;
        }

        if (mask >> 3 >= addrlen) {
            break;
        }

        bit = (addr[mask >> 3] >> (7 - (mask & 7))) & 1;
        mask++;
        nxt = ngx_http_heavybag_geo_u32(nt + off + bit * 4);

    } while (nxt);

    return ret;
}


void
ngx_http_heavybag_geo_lookup(ngx_http_heavybag_geo_db_t *db, struct sockaddr *sa,
    ngx_http_heavybag_geo_result_t *res)
{
    u_char               *p;
    ngx_int_t             net;
    struct sockaddr_in   *sin;
    struct sockaddr_in6  *sin6;

    res->found = 0;

    if (db == NULL || sa == NULL) {
        return;
    }

    switch (sa->sa_family) {

    case AF_INET:
        sin = (struct sockaddr_in *) sa;
        net = ngx_http_heavybag_geo_walk(db, (u_char *) &sin->sin_addr.s_addr, 4,
                                    db->ipv4root);
        break;

    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) sa;

        if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            net = ngx_http_heavybag_geo_walk(db, sin6->sin6_addr.s6_addr + 12, 4,
                                        db->ipv4root);
        } else {
            net = ngx_http_heavybag_geo_walk(db, sin6->sin6_addr.s6_addr, 16, 0);
        }
        break;

    default:
        return;
    }

    /*
     * net < 0 is the walker's no-match; past that the walker guarantees the
     * 0x80000000 marker bit is clear, so net <= 0x7fffffff and the cast to
     * uint32_t is exact. The bound is taken on the INDEX (see
     * geo_entry_oob) -- 0x7fffffff * 12 + 12 folds to exactly 0 on an ILP32
     * size_t, which the old additive form accepted for any block length.
     */
    if (net < 0
        || ngx_http_heavybag_geo_entry_oob((uint32_t) net,
               db->block_len[NGX_HTTP_HEAVYBAG_GEO_ND]))
    {
        return;
    }

    /*
     * 12-byte network leaf (libloc database format v1):
     *   [0,2)  country code        [2,4)  reserved
     *   [4,8)  ASN (uint32 BE)     [8,10) flags (uint16 BE)
     *   [10,12) reserved
     * nanolibloc reads cc and asn but skips flags; the flags are at
     * offset 8, NOT right after the country code.
     */
    p = db->block[NGX_HTTP_HEAVYBAG_GEO_ND]
        + (size_t) net * NGX_HTTP_HEAVYBAG_GEO_ENTRY;

    res->country[0] = p[0];
    res->country[1] = p[1];
    res->asn = ngx_http_heavybag_geo_u32(p + 4);
    res->flags = (uint16_t) ((p[8] << 8) | p[9]);
    res->found = 1;
}
