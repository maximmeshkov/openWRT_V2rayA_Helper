#include "node_key.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* SHA-256, FIPS 180-4. The public key is the first 128 bits of the digest. */
struct digest {
    uint32_t h[8];
    uint64_t bytes;
    unsigned char block[64];
};

static const struct digest initial = {{0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                                       0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}, 0, {0}};

static uint32_t rotate(uint32_t n, unsigned bits)
{
    return (n >> bits) | (n << (32 - bits));
}

static void digest_block(struct digest *d)
{
    static const uint32_t k[] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };
    uint32_t w[64];
    for (size_t i = 0; i < 16; i++) {
        const unsigned char *b = d->block + 4 * i;
        w[i] = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
    }
    for (size_t i = 16; i < 64; i++) {
        uint32_t a = w[i-15], b = w[i-2];
        uint32_t s0 = rotate(a, 7) ^ rotate(a, 18) ^ (a >> 3);
        uint32_t s1 = rotate(b, 17) ^ rotate(b, 19) ^ (b >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=d->h[0], b=d->h[1], c=d->h[2], t=d->h[3];
    uint32_t e=d->h[4], f=d->h[5], g=d->h[6], h=d->h[7];
    for (size_t i = 0; i < 64; i++) {
        uint32_t s1 = rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25);
        uint32_t choose = (e & f) ^ (~e & g);
        uint32_t t1 = h + s1 + choose + k[i] + w[i];
        uint32_t s0 = rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        h=g; g=f; f=e; e=t+t1;
        t=c; c=b; b=a; a=t1+s0+majority;
    }
    d->h[0]+=a; d->h[1]+=b; d->h[2]+=c; d->h[3]+=t;
    d->h[4]+=e; d->h[5]+=f; d->h[6]+=g; d->h[7]+=h;
}

static void digest_update(struct digest *d, const void *bytes, size_t len)
{
    const unsigned char *p = bytes;
    while (len) {
        size_t i = d->bytes % sizeof(d->block);
        size_t n = sizeof(d->block) - i;
        if (n > len) n = len;
        memcpy(d->block + i, p, n);
        d->bytes += n;
        if (i + n == sizeof(d->block)) digest_block(d);
        p += n;
        len -= n;
    }
}

static void finish(struct digest *d, char key[33])
{
    uint64_t bits = d->bytes * 8;
    unsigned char padding[64] = {0x80};
    size_t len = 1 + (119 - d->bytes % 64) % 64;
    digest_update(d, padding, len);
    unsigned char trailer[8];
    for (size_t i = 0; i < 8; i++) trailer[i] = (unsigned char)(bits >> (56 - 8 * i));
    digest_update(d, trailer, sizeof(trailer));
    for (size_t i = 0; i < 4; i++) snprintf(key + 8 * i, 9, "%08x", (unsigned int)d->h[i]);
}

void node_key(char key[33], const char *type, const char *source,
              const char *name, const char *address, const char *net)
{
    struct digest d = initial;
    const char *fields[] = {type, source, name, address, net};
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++)
        digest_update(&d, fields[i], strlen(fields[i]) + 1);
    finish(&d, key);
}

void text_fingerprint(char key[33], const char *text)
{
    struct digest d = initial;
    digest_update(&d, text, strlen(text));
    finish(&d, key);
}
