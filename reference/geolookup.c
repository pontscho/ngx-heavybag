/*
 * geolookup.c -- standalone IP -> CC / ASN / flags resolver (dev tool).
 *
 * Honeypot work-stream D (docs/threat-model.md §6.D): offline ASN/geo tuning
 * from attacker IPs. Reads the IPFire location.db once, then for each IP on
 * stdin prints one TSV line on stdout:
 *
 *     <ip>\t<CC>\t<ASN>\t<flags_hex>
 *
 * A faithful, libc-only port of the bounds-guarded radix-trie reader in
 * modules/ngx_http_waf/src/waf_geo.c -- the *fixed* walk/lookup, NOT the
 * pre-fix reference/loctest.c, whose main() reads the ND leaf with no
 * `net*12+12 <= len[ND]` guard and whose `nxt *= 12` can wrap before its
 * bounds check. Both size_t guards from waf_geo.c are preserved here.
 *
 * The libloc signature verification (waf_geo.c ngx_http_waf_geo_verify) is
 * deliberately SKIPPED: this is offline analysis of the local, already-trusted
 * DB (same stance as loctest.c), which keeps the tool libc-only -- no -lcrypto.
 *
 * Build (manual; NOT part of the module build, like loctest.c / locverify.c):
 *     cc -O2 -Wall -Wextra -o /tmp/geolookup reference/geolookup.c
 *
 * Usage:
 *     printf '185.177.72.1\n8.8.8.8\n' | /tmp/geolookup geodb/location.db
 *
 * ASN is emitted as a decimal number only (the waf_asn_block directive takes a
 * decimal ASN); AS-name resolution (the AS table + string pool blocks) is out
 * of scope -- a possible future extension.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* block indices / flag bits, inlined from waf_geo.h:25-36 */
#define GEO_AS      0       /* AS number table   */
#define GEO_ND      1       /* network leaf data */
#define GEO_NT      2       /* network tree      */
#define GEO_CO      3       /* country table     */
#define GEO_PO      4       /* string pool       */
#define GEO_BLOCKS  5

#define GEO_FLAG_ANON_PROXY  0x0001
#define GEO_FLAG_SATELLITE   0x0002
#define GEO_FLAG_ANYCAST     0x0004
#define GEO_FLAG_DROP        0x0008

/* signed-header layout (waf_geo.c:25-26) */
#define GEO_HDR_SIZE   4192
#define GEO_DATA_OFF   (8 + GEO_HDR_SIZE)          /* 4200 */
#define GEO_MAX_SIZE   (512UL * 1024 * 1024)

typedef struct {
    unsigned char  *map;
    size_t          map_size;
    unsigned char  *block[GEO_BLOCKS];
    uint32_t        block_len[GEO_BLOCKS];
    uint32_t        ipv4root;
} geo_db_t;


/* big-endian readers (waf_geo.c:63-92) */
static uint32_t
geo_u32(const unsigned char *p)
{
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16)
         | ((uint32_t) p[2] << 8)  | (uint32_t) p[3];
}

static uint16_t
geo_u16(const unsigned char *p)
{
    return (uint16_t) (((uint16_t) p[0] << 8) | (uint16_t) p[1]);
}


/*
 * mmap and validate the database. Mirrors ngx_http_waf_geo_open
 * (waf_geo.c:253-392) minus the signature gate. Returns 0 on success, -1 on
 * any error (already reported to stderr); on failure nothing stays mapped.
 */
static int
geo_open(geo_db_t *db, const char *path)
{
    struct stat     st;
    unsigned char  *base, *hdr;
    size_t          size;
    uint32_t        nxt;
    int             fd, i;

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "geolookup: open \"%s\" failed\n", path);
        return -1;
    }
    if (fstat(fd, &st) != 0) {
        fprintf(stderr, "geolookup: fstat \"%s\" failed\n", path);
        close(fd);
        return -1;
    }
    size = (size_t) st.st_size;

    /* size >= DATA_OFF so the header read cannot underflow (waf_geo.c:293) */
    if (size < GEO_DATA_OFF) {
        fprintf(stderr, "geolookup: database \"%s\" is too small\n", path);
        close(fd);
        return -1;
    }
    if (size > GEO_MAX_SIZE) {
        fprintf(stderr, "geolookup: database \"%s\" is too large (%zu bytes)\n",
                path, size);
        close(fd);
        return -1;
    }

    base = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) {
        fprintf(stderr, "geolookup: mmap \"%s\" failed\n", path);
        return -1;
    }

    db->map = base;
    db->map_size = size;

    /* Magic: "LOCD" "BXX\x01"  ==  4C4F4344 42585801 (waf_geo.c:338) */
    if (geo_u32(base) != 0x4C4F4344 || geo_u32(base + 4) != 0x42585801) {
        fprintf(stderr, "geolookup: database \"%s\" has a bad magic\n", path);
        munmap(base, size);
        return -1;
    }

    /* signature verification intentionally skipped (offline, trusted DB) */

    hdr = base + 8;

    for (i = 0; i < GEO_BLOCKS; i++) {
        uint32_t off = geo_u32(hdr + 20 + i * 8);
        uint32_t len = geo_u32(hdr + 24 + i * 8);

        /* size_t arithmetic so off+len cannot wrap (waf_geo.c:362) */
        if ((size_t) off + len > size) {
            fprintf(stderr, "geolookup: database \"%s\" block %d out of bounds\n",
                    path, i);
            munmap(base, size);
            return -1;
        }
        db->block[i] = base + off;
        db->block_len[i] = len;
    }

    /* Descend the v6 trie to the IPv4-mapped root (::ffff:0:0/96). */
    nxt = 0;
    for (i = 0; i < 96; i++) {
        size_t off = (size_t) nxt * 12;

        if (off + 12 > db->block_len[GEO_NT]) {
            fprintf(stderr, "geolookup: database \"%s\" truncated network tree\n",
                    path);
            munmap(base, size);
            return -1;
        }
        nxt = geo_u32(db->block[GEO_NT] + off + (i < 80 ? 0 : 4));
    }
    db->ipv4root = nxt;

    return 0;
}


/*
 * address -> network leaf index, or -1. Ported verbatim from
 * ngx_http_waf_geo_walk (waf_geo.c:396-435), including the size_t off guard
 * that requires the whole 12-byte node to fit.
 */
static long
geo_walk(geo_db_t *db, const unsigned char *addr, unsigned addrlen, uint32_t nxt)
{
    unsigned char  *nt = db->block[GEO_NT];
    uint32_t        ntlen = db->block_len[GEO_NT];
    uint32_t        net;
    long            ret = -1;
    unsigned        mask = 0, bit;
    size_t          off;

    do {
        off = (size_t) nxt * 12;
        if (off + 12 > ntlen) {
            return -1;
        }

        net = geo_u32(nt + off + 8);
        if (!(net & 0x80000000)) {
            ret = (long) net;
        }

        if (mask >> 3 >= addrlen) {
            break;
        }

        bit = (addr[mask >> 3] >> (7 - (mask & 7))) & 1;
        mask++;
        nxt = geo_u32(nt + off + bit * 4);

    } while (nxt);

    return ret;
}


/*
 * Resolve an IP string. Mirrors ngx_http_waf_geo_lookup (waf_geo.c:438-497):
 * AF_INET / v4-mapped / AF_INET6 dispatch, the ND-leaf guard, and the
 * CC[0:2] / ASN(u32 @ +4) / flags(u16 @ +8) extraction. Returns 1 on a hit
 * (cc/asn/flags filled), 0 otherwise.
 */
static int
geo_lookup(geo_db_t *db, const char *ip, unsigned char cc[2],
    uint32_t *asn, uint16_t *flags)
{
    struct in_addr        a4;
    struct in6_addr       a6;
    const unsigned char  *p;
    long                  net;

    if (inet_pton(AF_INET, ip, &a4) == 1) {
        net = geo_walk(db, (const unsigned char *) &a4.s_addr, 4, db->ipv4root);

    } else if (inet_pton(AF_INET6, ip, &a6) == 1) {
        if (IN6_IS_ADDR_V4MAPPED(&a6)) {
            net = geo_walk(db, a6.s6_addr + 12, 4, db->ipv4root);
        } else {
            net = geo_walk(db, a6.s6_addr, 16, 0);
        }

    } else {
        return 0;
    }

    if (net < 0 || (size_t) net * 12 + 12 > db->block_len[GEO_ND]) {
        return 0;
    }

    p = db->block[GEO_ND] + (size_t) net * 12;

    cc[0] = p[0];
    cc[1] = p[1];
    *asn = geo_u32(p + 4);
    *flags = geo_u16(p + 8);   /* flags live at ND offset 8, NOT after the CC */
    return 1;
}


int
main(int argc, char *argv[])
{
    geo_db_t  db;
    char      line[256];

    if (argc != 2) {
        fprintf(stderr, "usage: %s <location.db>   (IPs on stdin)\n", argv[0]);
        return 1;
    }

    memset(&db, 0, sizeof db);
    if (geo_open(&db, argv[1]) != 0) {
        return 1;
    }

    while (fgets(line, sizeof line, stdin) != NULL) {
        unsigned char  cc[2];
        uint32_t       asn = 0;
        uint16_t       flags = 0;
        size_t         n = strlen(line);

        /* trim trailing CR/LF and surrounding blanks */
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'
                         || line[n - 1] == ' ' || line[n - 1] == '\t'))
        {
            line[--n] = '\0';
        }
        if (n == 0) {
            continue;
        }

        if (geo_lookup(&db, line, cc, &asn, &flags)) {
            unsigned char c0 = cc[0] ? cc[0] : '?';
            unsigned char c1 = cc[1] ? cc[1] : '?';
            printf("%s\t%c%c\t%u\t0x%04x\n", line, c0, c1, asn, flags);
        } else {
            /* no record -> CC=??, ASN=0 (fails open in waf_asn_block) */
            printf("%s\t??\t0\t0x0000\n", line);
        }
    }

    munmap(db.map, db.map_size);
    return 0;
}
