/*
 * Standalone dev-oracle for libloc database signature verification.
 * Usage: ./locverify <database.db> <public-key.pem>
 * Prints "VALID (sig1|sig2)" / "INVALID" / an error, exit 0 on VALID only.
 *
 * Reproduces libloc 0.9.18 loc_database_verify() byte-for-byte with OpenSSL
 * (ECDSA P-521 / SHA-512), WITHOUT linking libloc -- this is the oracle that
 * proves the pinned key + hash-order embedded into waf_geo.c are exact, in
 * BOTH directions (good DB verifies, tampered/truncated DB rejects).
 *
 * Mirrors the loctest.c dev-oracle pattern; NOT built by the module build.
 * Build: cc -O2 -Wall -o /tmp/locverify reference/locverify.c -lcrypto
 *
 * On-disk layout (after the 8-byte magic, header sizeof == 4192):
 *   created_at(8) vendor(4) description(4) license(4)  [header-rel 0..20)
 *   5 block off/len pairs                               [header-rel 20..60)
 *   signature1_length u16 BE                            [header-rel 60]
 *   signature2_length u16 BE                            [header-rel 62]
 *   signature1[2048]                                    [header-rel 64]
 *   signature2[2048]                                    [header-rel 2112]
 *   padding[32]                                         [header-rel 4160]
 * Hashed message: magic(8) ++ header(4192, header-rel [60,4160) ZEROED)
 *   ++ rest-of-file (file offset 4200 .. EOF). Padding [4160,4192) NOT zeroed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#define HDR_SIZE     4192
#define DATA_OFF     (8 + HDR_SIZE)        /* 4200 */
#define SIG_MAX      2048
#define ZERO_BEG     60                    /* header-rel: first u16 length */
#define ZERO_END     4160                  /* header-rel: end of sig2 blob */
#define SIG1_LEN_OFF (8 + 60)              /* file-abs 68 */
#define SIG2_LEN_OFF (8 + 62)              /* file-abs 70 */
#define SIG1_OFF     (8 + 64)              /* file-abs 72 */
#define SIG2_OFF     (8 + 2112)            /* file-abs 2120 */

/* dedicated big-endian 16-bit read (NOT a 32-bit read -- would swallow the
 * adjacent length field) */
static unsigned u16be(const unsigned char *p)
{
    return ((unsigned) p[0] << 8) | (unsigned) p[1];
}

static unsigned u32be(const unsigned char *p)
{
    return ((unsigned) p[0] << 24) | ((unsigned) p[1] << 16)
           | ((unsigned) p[2] << 8) | (unsigned) p[3];
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <database.db> <public-key.pem>\n", argv[0]);
        return 2;
    }

    /* --- mmap the DB --- */
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) { perror("open db"); return 2; }

    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat"); close(fd); return 2; }
    size_t size = (size_t) st.st_size;

    if (size < DATA_OFF) {
        fprintf(stderr, "error: file too small (%zu < %d)\n", size, DATA_OFF);
        close(fd);
        return 2;
    }

    unsigned char *base = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) { perror("mmap"); return 2; }

    if (u32be(base) != 0x4C4F4344 || u32be(base + 4) != 0x42585801) {
        fprintf(stderr, "error: bad magic\n");
        munmap(base, size);
        return 2;
    }

    /* --- load the public key --- */
    FILE *kf = fopen(argv[2], "r");
    if (!kf) { perror("open key"); munmap(base, size); return 2; }
    EVP_PKEY *pkey = PEM_read_PUBKEY(kf, NULL, NULL, NULL);
    fclose(kf);
    if (!pkey) {
        char errbuf[256];
        ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
        fprintf(stderr, "error: cannot read public key: %s\n", errbuf);
        munmap(base, size);
        return 2;
    }

    /* --- signature length/presence (present slot <=> 1 <= len <= 2048) --- */
    unsigned sig1_len = u16be(base + SIG1_LEN_OFF);
    unsigned sig2_len = u16be(base + SIG2_LEN_OFF);
    int have1 = (sig1_len >= 1 && sig1_len <= SIG_MAX);
    int have2 = (sig2_len >= 1 && sig2_len <= SIG_MAX);

    if (!have1 && !have2) {
        fprintf(stderr, "error: database is not signed (both sig lengths 0)\n");
        EVP_PKEY_free(pkey);
        munmap(base, size);
        return 2;
    }

    /* --- build the base digest ctx over magic ++ zeroed-header ++ rest --- */
    unsigned char hdr[HDR_SIZE];
    memcpy(hdr, base + 8, HDR_SIZE);
    memset(hdr + ZERO_BEG, 0, ZERO_END - ZERO_BEG);

    EVP_MD_CTX *bctx = EVP_MD_CTX_new();
    int valid = 0;
    int which = 0;

    if (!bctx) { goto done; }
    if (EVP_DigestVerifyInit(bctx, NULL, NULL, NULL, pkey) != 1) { goto done; }
    if (EVP_DigestVerifyUpdate(bctx, base, 8) != 1) { goto done; }
    if (EVP_DigestVerifyUpdate(bctx, hdr, HDR_SIZE) != 1) { goto done; }
    if (EVP_DigestVerifyUpdate(bctx, base + DATA_OFF, size - DATA_OFF) != 1) {
        goto done;
    }

    /* --- per-slot: snapshot the un-finalized base ctx, Final, free-and-NULL,
     *     accept ONLY on == 1 --- */
    if (have1) {
        EVP_MD_CTX *snap = EVP_MD_CTX_new();
        if (snap && EVP_MD_CTX_copy_ex(snap, bctx) == 1) {
            if (EVP_DigestVerifyFinal(snap, base + SIG1_OFF, sig1_len) == 1) {
                valid = 1; which = 1;
            }
        }
        if (snap) { EVP_MD_CTX_free(snap); snap = NULL; }
    }

    if (!valid && have2) {
        EVP_MD_CTX *snap = EVP_MD_CTX_new();
        if (snap && EVP_MD_CTX_copy_ex(snap, bctx) == 1) {
            if (EVP_DigestVerifyFinal(snap, base + SIG2_OFF, sig2_len) == 1) {
                valid = 1; which = 2;
            }
        }
        if (snap) { EVP_MD_CTX_free(snap); snap = NULL; }
    }

done:
    if (bctx) { EVP_MD_CTX_free(bctx); }
    EVP_PKEY_free(pkey);
    munmap(base, size);

    if (valid) {
        printf("VALID (sig%d)\n", which);
        return 0;
    }
    printf("INVALID\n");
    return 1;
}
