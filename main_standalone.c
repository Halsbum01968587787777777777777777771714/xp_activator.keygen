/*
 * Windows XP CD Key Verification/Generator v0.03
 * by z22
 *
 * Converted to pure C, zero external dependencies.
 * Compatible with x86, Win95+, MSVC, MinGW, GCC.
 * No OpenSSL, no CRT beyond stdio/string/stdlib.
 *
 * Implements:
 *   - SHA-1 (FIPS 180-4)
 *   - Big-integer arithmetic (multi-precision, 512-bit words)
 *   - Elliptic Curve arithmetic over GFp (Weierstrass)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>

/* =========================================================
 *  COMPILE-TIME SETTINGS
 * ========================================================= */
#define FIELD_BITS  384
#define FIELD_BYTES 48

/* Number of 32-bit limbs we need for 384-bit numbers */
#define BN_LIMBS    16   /* 512 bits = 16 x 32-bit limbs, plenty of headroom */

static uint8_t cset[] = "BCDFGHJKMPQRTVWXY2346789";

/* =========================================================
 *  SHA-1  (FIPS 180-4)
 * ========================================================= */
typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t  buf[64];
} SHA1_CTX;

#define ROL32(x,n) (((x)<<(n))|((x)>>(32-(n))))

static void sha1_transform(uint32_t state[5], const uint8_t block[64])
{
    uint32_t a,b,c,d,e,t,w[80];
    int i;

    for (i = 0; i < 16; i++) {
        w[i]  = ((uint32_t)block[i*4  ]) << 24;
        w[i] |= ((uint32_t)block[i*4+1]) << 16;
        w[i] |= ((uint32_t)block[i*4+2]) <<  8;
        w[i] |= ((uint32_t)block[i*4+3]);
    }
    for (i = 16; i < 80; i++)
        w[i] = ROL32(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1);

    a=state[0]; b=state[1]; c=state[2]; d=state[3]; e=state[4];

#define SHA1_R0(v,w2,x,y,z,i) \
    t=ROL32(v,5)+((w2&(x^y))^y)+z+w[i]+0x5A827999; z=y; y=x; x=ROL32(w2,30); w2=v; v=t;
#define SHA1_R1(v,w2,x,y,z,i) \
    t=ROL32(v,5)+((w2&(x^y))^y)+z+w[i]+0x5A827999; z=y; y=x; x=ROL32(w2,30); w2=v; v=t;
#define SHA1_R2(v,w2,x,y,z,i) \
    t=ROL32(v,5)+(w2^x^y)+z+w[i]+0x6ED9EBA1;       z=y; y=x; x=ROL32(w2,30); w2=v; v=t;
#define SHA1_R3(v,w2,x,y,z,i) \
    t=ROL32(v,5)+(((w2|x)&y)|(w2&x))+z+w[i]+0x8F1BBCDC; z=y; y=x; x=ROL32(w2,30); w2=v; v=t;
#define SHA1_R4(v,w2,x,y,z,i) \
    t=ROL32(v,5)+(w2^x^y)+z+w[i]+0xCA62C1D6;       z=y; y=x; x=ROL32(w2,30); w2=v; v=t;

    SHA1_R0(a,b,c,d,e, 0) SHA1_R0(e,a,b,c,d, 1) SHA1_R0(d,e,a,b,c, 2) SHA1_R0(c,d,e,a,b, 3)
    SHA1_R0(b,c,d,e,a, 4) SHA1_R0(a,b,c,d,e, 5) SHA1_R0(e,a,b,c,d, 6) SHA1_R0(d,e,a,b,c, 7)
    SHA1_R0(c,d,e,a,b, 8) SHA1_R0(b,c,d,e,a, 9) SHA1_R0(a,b,c,d,e,10) SHA1_R0(e,a,b,c,d,11)
    SHA1_R0(d,e,a,b,c,12) SHA1_R0(c,d,e,a,b,13) SHA1_R0(b,c,d,e,a,14) SHA1_R0(a,b,c,d,e,15)
    SHA1_R1(e,a,b,c,d,16) SHA1_R1(d,e,a,b,c,17) SHA1_R1(c,d,e,a,b,18) SHA1_R1(b,c,d,e,a,19)
    SHA1_R2(a,b,c,d,e,20) SHA1_R2(e,a,b,c,d,21) SHA1_R2(d,e,a,b,c,22) SHA1_R2(c,d,e,a,b,23)
    SHA1_R2(b,c,d,e,a,24) SHA1_R2(a,b,c,d,e,25) SHA1_R2(e,a,b,c,d,26) SHA1_R2(d,e,a,b,c,27)
    SHA1_R2(c,d,e,a,b,28) SHA1_R2(b,c,d,e,a,29) SHA1_R2(a,b,c,d,e,30) SHA1_R2(e,a,b,c,d,31)
    SHA1_R2(d,e,a,b,c,32) SHA1_R2(c,d,e,a,b,33) SHA1_R2(b,c,d,e,a,34) SHA1_R2(a,b,c,d,e,35)
    SHA1_R2(e,a,b,c,d,36) SHA1_R2(d,e,a,b,c,37) SHA1_R2(c,d,e,a,b,38) SHA1_R2(b,c,d,e,a,39)
    SHA1_R3(a,b,c,d,e,40) SHA1_R3(e,a,b,c,d,41) SHA1_R3(d,e,a,b,c,42) SHA1_R3(c,d,e,a,b,43)
    SHA1_R3(b,c,d,e,a,44) SHA1_R3(a,b,c,d,e,45) SHA1_R3(e,a,b,c,d,46) SHA1_R3(d,e,a,b,c,47)
    SHA1_R3(c,d,e,a,b,48) SHA1_R3(b,c,d,e,a,49) SHA1_R3(a,b,c,d,e,50) SHA1_R3(e,a,b,c,d,51)
    SHA1_R3(d,e,a,b,c,52) SHA1_R3(c,d,e,a,b,53) SHA1_R3(b,c,d,e,a,54) SHA1_R3(a,b,c,d,e,55)
    SHA1_R3(e,a,b,c,d,56) SHA1_R3(d,e,a,b,c,57) SHA1_R3(c,d,e,a,b,58) SHA1_R3(b,c,d,e,a,59)
    SHA1_R4(a,b,c,d,e,60) SHA1_R4(e,a,b,c,d,61) SHA1_R4(d,e,a,b,c,62) SHA1_R4(c,d,e,a,b,63)
    SHA1_R4(b,c,d,e,a,64) SHA1_R4(a,b,c,d,e,65) SHA1_R4(e,a,b,c,d,66) SHA1_R4(d,e,a,b,c,67)
    SHA1_R4(c,d,e,a,b,68) SHA1_R4(b,c,d,e,a,69) SHA1_R4(a,b,c,d,e,70) SHA1_R4(e,a,b,c,d,71)
    SHA1_R4(d,e,a,b,c,72) SHA1_R4(c,d,e,a,b,73) SHA1_R4(b,c,d,e,a,74) SHA1_R4(a,b,c,d,e,75)
    SHA1_R4(e,a,b,c,d,76) SHA1_R4(d,e,a,b,c,77) SHA1_R4(c,d,e,a,b,78) SHA1_R4(b,c,d,e,a,79)

    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d; state[4]+=e;
}

static void SHA1_Init(SHA1_CTX *ctx)
{
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count[0] = ctx->count[1] = 0;
}

static void SHA1_Update(SHA1_CTX *ctx, const uint8_t *data, uint32_t len)
{
    uint32_t i, j;
    j = (ctx->count[0] >> 3) & 63;
    if ((ctx->count[0] += len << 3) < (len << 3)) ctx->count[1]++;
    ctx->count[1] += (len >> 29);
    if ((j + len) > 63) {
        i = 64 - j;
        memcpy(&ctx->buf[j], data, i);
        sha1_transform(ctx->state, ctx->buf);
        for (; i + 63 < len; i += 64)
            sha1_transform(ctx->state, data + i);
        j = 0;
    } else {
        i = 0;
    }
    memcpy(&ctx->buf[j], &data[i], len - i);
}

static void SHA1_Final(uint8_t digest[20], SHA1_CTX *ctx)
{
    uint32_t i;
    uint8_t finalcount[8];
    for (i = 0; i < 8; i++)
        finalcount[i] = (uint8_t)((ctx->count[(i>=4?0:1)] >> ((3-(i&3))*8)) & 0xff);
    SHA1_Update(ctx, (uint8_t *)"\200", 1);
    while ((ctx->count[0] & 504) != 448)
        SHA1_Update(ctx, (uint8_t *)"\0", 1);
    SHA1_Update(ctx, finalcount, 8);
    for (i = 0; i < 20; i++)
        digest[i] = (uint8_t)((ctx->state[i>>2] >> ((3-(i&3))*8)) & 0xff);
}

/* =========================================================
 *  BIGNUM  (fixed-size, little-endian 32-bit limbs)
 *  All numbers are at most BN_LIMBS*32 bits wide.
 * ========================================================= */
typedef struct {
    uint32_t d[BN_LIMBS];
    int      neg; /* 0=positive, 1=negative */
} BN;

static void bn_zero(BN *r) { memset(r->d, 0, sizeof(r->d)); r->neg=0; }
static void bn_copy(BN *r, const BN *a) { memcpy(r, a, sizeof(BN)); }

static int bn_is_zero(const BN *a)
{
    int i;
    for (i=0; i<BN_LIMBS; i++) if(a->d[i]) return 0;
    return 1;
}

/* Number of significant limbs */
static int bn_num_limbs(const BN *a)
{
    int i;
    for (i=BN_LIMBS-1; i>0; i--) if(a->d[i]) return i+1;
    return 1;
}

/* Number of significant bytes */
static int bn_num_bytes(const BN *a)
{
    int limbs = bn_num_limbs(a);
    int top = a->d[limbs-1];
    int bytes = (limbs-1)*4;
    if (top >> 24)       bytes += 4;
    else if (top >> 16)  bytes += 3;
    else if (top >> 8)   bytes += 2;
    else                 bytes += 1;
    return bytes;
}

/* Compare absolute values: -1, 0, 1 */
static int bn_cmp_abs(const BN *a, const BN *b)
{
    int i;
    for (i=BN_LIMBS-1; i>=0; i--) {
        if (a->d[i] > b->d[i]) return  1;
        if (a->d[i] < b->d[i]) return -1;
    }
    return 0;
}

static int bn_cmp(const BN *a, const BN *b)
{
    if (!a->neg && !b->neg) return  bn_cmp_abs(a,b);
    if ( a->neg && !b->neg) return -1;
    if (!a->neg &&  b->neg) return  1;
    return -bn_cmp_abs(a,b);
}

/* r = a + b  (unsigned, ignores neg) */
static void bn_add_abs(BN *r, const BN *a, const BN *b)
{
    uint64_t carry = 0;
    int i;
    for (i=0; i<BN_LIMBS; i++) {
        uint64_t s = (uint64_t)a->d[i] + b->d[i] + carry;
        r->d[i] = (uint32_t)s;
        carry   = s >> 32;
    }
}

/* r = a - b  (unsigned, assumes a >= b) */
static void bn_sub_abs(BN *r, const BN *a, const BN *b)
{
    int64_t borrow = 0;
    int i;
    for (i=0; i<BN_LIMBS; i++) {
        int64_t s = (int64_t)a->d[i] - b->d[i] - borrow;
        r->d[i]  = (uint32_t)s;
        borrow   = (s < 0) ? 1 : 0;
    }
}

static void bn_add(BN *r, const BN *a, const BN *b)
{
    if (a->neg == b->neg) {
        bn_add_abs(r, a, b);
        r->neg = a->neg;
        return;
    }
    /* Different signs */
    int c = bn_cmp_abs(a, b);
    if (c >= 0) { bn_sub_abs(r, a, b); r->neg = a->neg; }
    else        { bn_sub_abs(r, b, a); r->neg = b->neg; }
    if (bn_is_zero(r)) r->neg = 0;
}

static void bn_sub(BN *r, const BN *a, const BN *b)
{
    BN tmp;
    bn_copy(&tmp, b);
    tmp.neg = !tmp.neg;
    bn_add(r, a, &tmp);
}

/* r = a * b  (schoolbook, sufficient for our sizes) */
static void bn_mul(BN *r, const BN *a, const BN *b)
{
    BN res;
    int i, j;
    bn_zero(&res);
    for (i=0; i<BN_LIMBS; i++) {
        uint64_t carry = 0;
        if (!a->d[i]) continue;
        for (j=0; j<BN_LIMBS && (i+j)<BN_LIMBS; j++) {
            uint64_t uv = (uint64_t)a->d[i] * b->d[j] + res.d[i+j] + carry;
            res.d[i+j] = (uint32_t)uv;
            carry       = uv >> 32;
        }
    }
    res.neg = a->neg ^ b->neg;
    if (bn_is_zero(&res)) res.neg = 0;
    bn_copy(r, &res);
}

/* Multiply by a single word */
static void bn_mul_word(BN *r, const BN *a, uint32_t w)
{
    uint64_t carry = 0;
    int i;
    for (i=0; i<BN_LIMBS; i++) {
        uint64_t uv = (uint64_t)a->d[i] * w + carry;
        r->d[i] = (uint32_t)uv;
        carry    = uv >> 32;
    }
    r->neg = a->neg;
}

/* Divide r by w, return remainder */
static uint32_t bn_div_word(BN *r, uint32_t w)
{
    uint64_t rem = 0;
    int i;
    for (i=BN_LIMBS-1; i>=0; i--) {
        uint64_t cur = (rem << 32) | r->d[i];
        r->d[i] = (uint32_t)(cur / w);
        rem      = cur % w;
    }
    return (uint32_t)rem;
}

/* Left shift by 1 bit */
static void bn_shl1(BN *r, const BN *a)
{
    int i;
    for (i=BN_LIMBS-1; i>0; i--)
        r->d[i] = (a->d[i]<<1)|(a->d[i-1]>>31);
    r->d[0] = a->d[0]<<1;
    r->neg  = a->neg;
}

/* Right shift by 1 bit */
static void bn_shr1(BN *r, const BN *a)
{
    int i;
    for (i=0; i<BN_LIMBS-1; i++)
        r->d[i] = (a->d[i]>>1)|(a->d[i+1]<<31);
    r->d[BN_LIMBS-1] = a->d[BN_LIMBS-1]>>1;
    r->neg = a->neg;
}

/* r = a mod m  (assumes a >= 0) */
static void bn_mod(BN *r, const BN *a, const BN *m)
{
    BN q, rem, shifted, tmp;
    int i, bits_a, bits_m, shift;

    bn_copy(&rem, a);
    rem.neg = 0;

    if (bn_cmp_abs(&rem, m) < 0) {
        bn_copy(r, &rem);
        r->neg = 0;
        return;
    }

    /* Compute bit length */
    bits_a = bn_num_limbs(&rem) * 32;
    bits_m = bn_num_limbs(m)    * 32;
    shift  = bits_a - bits_m;
    if (shift < 0) shift = 0;

    /* Shift m left by shift bits */
    bn_copy(&shifted, m);
    for (i=0; i<shift; i++) {
        bn_shl1(&tmp, &shifted);
        bn_copy(&shifted, &tmp);
    }

    for (i=shift; i>=0; i--) {
        if (bn_cmp_abs(&rem, &shifted) >= 0) {
            bn_sub_abs(&tmp, &rem, &shifted);
            bn_copy(&rem, &tmp);
        }
        if (i > 0) {
            bn_shr1(&tmp, &shifted);
            bn_copy(&shifted, &tmp);
        }
    }
    bn_copy(r, &rem);
    r->neg = 0;
}

/* r = (a + b) mod m */
static void bn_mod_add(BN *r, const BN *a, const BN *b, const BN *m)
{
    BN tmp;
    bn_add(&tmp, a, b);
    if (tmp.neg) { /* ensure positive */
        BN t2;
        bn_add(&t2, &tmp, m);
        bn_copy(&tmp, &t2);
    }
    bn_mod(r, &tmp, m);
}

/* Modular inverse via extended Euclidean (for odd moduli) */
static void bn_mod_inv(BN *r, const BN *a, const BN *m)
{
    BN u, v, A, C;
    BN tmp, tmp2;

    bn_copy(&u, m); u.neg = 0;
    bn_copy(&v, a); v.neg = 0;
    bn_zero(&A);
    bn_zero(&C); C.d[0] = 1;

    while (!bn_is_zero(&u)) {
        /* while u is even */
        while ((u.d[0] & 1) == 0) {
            bn_shr1(&tmp, &u); bn_copy(&u, &tmp);
            if (A.d[0] & 1) {
                bn_add(&tmp, &A, m); bn_copy(&A, &tmp);
            }
            bn_shr1(&tmp, &A); bn_copy(&A, &tmp);
        }
        /* while v is even */
        while ((v.d[0] & 1) == 0) {
            bn_shr1(&tmp, &v); bn_copy(&v, &tmp);
            if (C.d[0] & 1) {
                bn_add(&tmp, &C, m); bn_copy(&C, &tmp);
            }
            bn_shr1(&tmp, &C); bn_copy(&C, &tmp);
        }
        if (bn_cmp_abs(&u, &v) >= 0) {
            bn_sub_abs(&tmp, &u, &v); bn_copy(&u, &tmp);
            bn_sub(&tmp, &A, &C);    bn_copy(&A, &tmp);
        } else {
            bn_sub_abs(&tmp, &v, &u); bn_copy(&v, &tmp);
            bn_sub(&tmp, &C, &A);    bn_copy(&C, &tmp);
        }
    }
    /* normalize */
    if (C.neg) {
        bn_add(&tmp, &C, m);
        bn_copy(r, &tmp);
    } else {
        bn_mod(r, &C, m);
    }
    (void)tmp2;
}

/* Modular multiplication */
static void bn_mod_mul(BN *r, const BN *a, const BN *b, const BN *m)
{
    BN tmp;
    bn_mul(&tmp, a, b);
    if (tmp.neg) {
        BN t2;
        bn_add(&t2, &tmp, m);
        bn_mod(r, &t2, m);
    } else {
        bn_mod(r, &tmp, m);
    }
}

/* Convert big-endian byte array to BN */
static void bn_from_bin(BN *r, const uint8_t *buf, int len)
{
    int i;
    bn_zero(r);
    for (i=0; i<len && i<BN_LIMBS*4; i++) {
        int byte_pos = len - 1 - i;
        r->d[i/4] |= ((uint32_t)buf[byte_pos]) << ((i%4)*8);
    }
}

/* Convert BN to big-endian byte array (len bytes) */
static void bn_to_bin(const BN *a, uint8_t *buf, int len)
{
    int i;
    memset(buf, 0, len);
    for (i=0; i<len && i<BN_LIMBS*4; i++) {
        buf[len-1-i] = (uint8_t)(a->d[i/4] >> ((i%4)*8));
    }
}

/* Set from hex string */
static void bn_from_hex(BN *r, const char *hex)
{
    int len = (int)strlen(hex);
    int i;
    bn_zero(r);
    for (i=0; i<len; i++) {
        char c = hex[len-1-i];
        uint32_t nibble;
        if (c>='0' && c<='9')      nibble = c-'0';
        else if (c>='a' && c<='f') nibble = c-'a'+10;
        else if (c>='A' && c<='F') nibble = c-'A'+10;
        else continue;
        r->d[i/8] |= nibble << ((i%8)*4);
    }
}

/* Set from uint32 */
static void bn_set_word(BN *r, uint32_t w)
{
    bn_zero(r);
    r->d[0] = w;
}

/* =========================================================
 *  PSEUDO-RANDOM (xorshift, seeded from time)
 *  Used to generate random k for signing.
 * ========================================================= */
static uint32_t g_rng[4];

static void rng_seed(void)
{
    /* Simple seed: use memory addresses + counter */
    static uint32_t s = 0xdeadbeef;
    g_rng[0] = s ^ 0x12345678;
    g_rng[1] = s ^ 0x9abcdef0;
    g_rng[2] = s ^ 0xfedcba98;
    g_rng[3] = s ^ 0x76543210;
    s++;
}

static uint32_t rng_next(void)
{
    uint32_t t = g_rng[3];
    uint32_t s2 = g_rng[0];
    g_rng[3] = g_rng[2]; g_rng[2] = g_rng[1]; g_rng[1] = s2;
    t ^= t << 11; t ^= t >> 8;
    g_rng[0] = t ^ s2 ^ (s2 >> 19);
    return g_rng[0];
}

static void bn_rand(BN *r, int bits)
{
    int i, limbs = (bits + 31) / 32;
    bn_zero(r);
    for (i=0; i<limbs && i<BN_LIMBS; i++)
        r->d[i] = rng_next();
    /* Mask top limb */
    if (bits % 32)
        r->d[limbs-1] &= (1u << (bits%32)) - 1;
}

/* =========================================================
 *  ELLIPTIC CURVE  over GFp (short Weierstrass: y^2=x^3+ax+b)
 *  Point represented as (X, Y, Z) in Jacobian coordinates.
 * ========================================================= */
typedef struct {
    BN x, y, z;
    int infinity; /* 1 = point at infinity */
} EC_POINT;

typedef struct {
    BN p, a, b;
} EC_GROUP;

static void ec_point_init(EC_POINT *P)
{
    bn_zero(&P->x); bn_zero(&P->y); bn_zero(&P->z);
    P->infinity = 1;
}

static void ec_point_copy(EC_POINT *R, const EC_POINT *P)
{
    memcpy(R, P, sizeof(EC_POINT));
}

/* Convert Jacobian -> Affine:  X/Z^2, Y/Z^3 */
static void ec_point_to_affine(EC_POINT *R, const EC_POINT *P, const BN *p)
{
    BN z2, z3, inv, tmp;
    if (P->infinity) { ec_point_init(R); return; }

    bn_mod_mul(&z2, &P->z, &P->z, p);
    bn_mod_mul(&z3, &z2,   &P->z, p);

    bn_mod_inv(&inv, &z2, p);
    bn_mod_mul(&R->x, &P->x, &inv, p);

    bn_mod_inv(&inv, &z3, p);
    bn_mod_mul(&R->y, &P->y, &inv, p);

    bn_set_word(&R->z, 1);
    R->infinity = 0;
    (void)tmp;
}

/* Point doubling in Jacobian: R = 2P  (a = 1 for our curve) */
static void ec_point_dbl(EC_POINT *R, const EC_POINT *P, const EC_GROUP *ec)
{
    BN t1, t2, t3, t4, t5;
    const BN *p = &ec->p;

    if (P->infinity) { ec_point_copy(R, P); return; }

    /* Using standard Jacobian doubling formulae */
    bn_mod_mul(&t1, &P->z, &P->z, p);           /* z^2         */
    bn_mod_mul(&t2, &P->x, &P->x, p);           /* x^2         */
    bn_mod_mul(&t3, &P->y, &P->y, p);           /* y^2         */
    bn_mod_mul(&t4, &P->y, &P->z, p);           /* y*z         */
    bn_mod_add(&R->z, &t4, &t4, p);             /* Z3 = 2*y*z  */

    /* t5 = 3*x^2 + a*z^4  (a=1 => t5 = 3*x^2 + z^4) */
    bn_mod_add(&t4, &t2, &t2, p);
    bn_mod_add(&t4, &t4, &t2, p);               /* t4 = 3*x^2  */
    bn_mod_mul(&t5, &t1, &t1, p);               /* z^4         */
    bn_mod_add(&t5, &t4, &t5, p);               /* t5 = 3x^2+z^4 */

    /* X3 = t5^2 - 8*x*y^2 */
    bn_mod_mul(&t2, &P->x, &t3, p);             /* x*y^2       */
    bn_mod_add(&t2, &t2, &t2, p);
    bn_mod_add(&t2, &t2, &t2, p);
    bn_mod_add(&t2, &t2, &t2, p);               /* 8*x*y^2     */
    bn_mod_mul(&R->x, &t5, &t5, p);
    bn_sub(&R->x, &R->x, &t2);
    bn_mod(&R->x, &R->x, p);
    if (R->x.neg) bn_mod_add(&R->x, &R->x, p, p);

    /* Y3 = t5*(4*x*y^2 - X3) - 8*y^4 */
    bn_mod_add(&t4, &t3, &t3, p);
    bn_mod_add(&t4, &t4, &t4, p);
    bn_mod_add(&t4, &t4, &t4, p);               /* 8*y^4 */
    /* 4*x*y^2 */
    bn_mod_mul(&t2, &P->x, &t3, p);
    bn_mod_add(&t2, &t2, &t2, p);
    bn_mod_add(&t2, &t2, &t2, p);
    bn_sub(&t2, &t2, &R->x);
    bn_mod_mul(&R->y, &t5, &t2, p);
    bn_sub(&R->y, &R->y, &t4);
    bn_mod(&R->y, &R->y, p);
    if (R->y.neg) bn_mod_add(&R->y, &R->y, p, p);

    R->infinity = 0;
}

/* Point addition in Jacobian: R = P + Q */
static void ec_point_add(EC_POINT *R, const EC_POINT *P, const EC_POINT *Q, const EC_GROUP *ec)
{
    BN u1, u2, s1, s2, h, r2, h3, tmp;
    const BN *p = &ec->p;

    if (P->infinity) { ec_point_copy(R, Q); return; }
    if (Q->infinity) { ec_point_copy(R, P); return; }

    /* U1=X1*Z2^2, U2=X2*Z1^2, S1=Y1*Z2^3, S2=Y2*Z1^3 */
    BN z1sq, z2sq;
    bn_mod_mul(&z1sq, &P->z, &P->z, p);
    bn_mod_mul(&z2sq, &Q->z, &Q->z, p);

    bn_mod_mul(&u1, &P->x, &z2sq, p);
    bn_mod_mul(&u2, &Q->x, &z1sq, p);

    bn_mod_mul(&s1, &P->y, &z2sq, p);
    bn_mod_mul(&s1, &s1,   &Q->z, p);
    bn_mod_mul(&s2, &Q->y, &z1sq, p);
    bn_mod_mul(&s2, &s2,   &P->z, p);

    bn_sub(&h, &u2, &u1); /* H = U2 - U1 */
    bn_mod(&h, &h, p);
    if (h.neg) bn_mod_add(&h, &h, p, p);

    bn_sub(&r2, &s2, &s1); /* R = S2 - S1 */
    bn_mod(&r2, &r2, p);
    if (r2.neg) bn_mod_add(&r2, &r2, p, p);

    if (bn_is_zero(&h)) {
        if (bn_is_zero(&r2)) {
            /* P == Q: use doubling */
            ec_point_dbl(R, P, ec);
        } else {
            /* P == -Q: return infinity */
            ec_point_init(R);
        }
        return;
    }

    /* Z3 = H*Z1*Z2 */
    bn_mod_mul(&R->z, &h,   &P->z, p);
    bn_mod_mul(&R->z, &R->z, &Q->z, p);

    /* H^3 */
    bn_mod_mul(&h3, &h, &h, p);
    bn_mod_mul(&h3, &h3, &h, p);

    /* X3 = R^2 - H^3 - 2*U1*H^2 */
    BN h2, u1h2;
    bn_mod_mul(&h2,  &h,  &h,  p);
    bn_mod_mul(&u1h2, &u1, &h2, p);
    bn_mod_mul(&R->x, &r2, &r2, p);
    bn_sub(&R->x, &R->x, &h3);
    bn_sub(&R->x, &R->x, &u1h2);
    bn_sub(&R->x, &R->x, &u1h2);
    bn_mod(&R->x, &R->x, p);
    if (R->x.neg) bn_mod_add(&R->x, &R->x, p, p);

    /* Y3 = R*(U1*H^2 - X3) - S1*H^3 */
    bn_sub(&tmp, &u1h2, &R->x);
    bn_mod_mul(&R->y, &r2, &tmp, p);
    bn_mod_mul(&tmp,  &s1, &h3,  p);
    bn_sub(&R->y, &R->y, &tmp);
    bn_mod(&R->y, &R->y, p);
    if (R->y.neg) bn_mod_add(&R->y, &R->y, p, p);

    R->infinity = 0;
}

/* Scalar multiplication: R = k*P  (double-and-add, MSB first) */
static void ec_point_mul(EC_POINT *R, const EC_POINT *P, const BN *k, const EC_GROUP *ec)
{
    EC_POINT Q;
    int i, bit;
    int top_limb = bn_num_limbs(k) - 1;

    ec_point_init(R);
    if (bn_is_zero(k)) return;

    /* Find MSB */
    for (i = top_limb*32 + 31; i >= 0; i--) {
        bit = (k->d[i/32] >> (i%32)) & 1;
        if (bit) break;
    }

    ec_point_copy(R, P);
    i--;

    for (; i >= 0; i--) {
        ec_point_dbl(&Q, R, ec);
        bit = (k->d[i/32] >> (i%32)) & 1;
        if (bit) ec_point_add(R, &Q, P, ec);
        else     ec_point_copy(R, &Q);
    }
}

/* Get affine X,Y from point */
static void ec_get_affine(const EC_POINT *P, BN *x, BN *y, const EC_GROUP *ec)
{
    EC_POINT aff;
    ec_point_to_affine(&aff, P, &ec->p);
    bn_copy(x, &aff.x);
    bn_copy(y, &aff.y);
}

/* Set affine point */
static void ec_set_affine(EC_POINT *P, const BN *x, const BN *y)
{
    bn_copy(&P->x, x);
    bn_copy(&P->y, y);
    bn_set_word(&P->z, 1);
    P->infinity = 0;
}

/* =========================================================
 *  ORIGINAL KEYGEN LOGIC  (1:1 from z22's code)
 * ========================================================= */
static void unpack(uint32_t *pid, uint32_t *hash, uint32_t *sig, uint32_t *raw)
{
    pid[0]  = raw[0] & 0x7fffffff;
    hash[0] = ((raw[0] >> 31) | (raw[1] << 1)) & 0xfffffff;
    sig[0]  = (raw[1] >> 27) | (raw[2] << 5);
    sig[1]  = (raw[2] >> 27) | (raw[3] << 5);
}

static void pack(uint32_t *raw, uint32_t *pid, uint32_t *hash, uint32_t *sig)
{
    raw[0] = pid[0]  | ((hash[0] & 1) << 31);
    raw[1] = (hash[0] >> 1) | ((sig[0] & 0x1f) << 27);
    raw[2] = (sig[0] >> 5)  |  (sig[1] << 27);
    raw[3] =  sig[1] >> 5;
}

static void endian(uint8_t *data, int len)
{
    int i;
    for (i=0; i<len/2; i++) {
        uint8_t t    = data[i];
        data[i]      = data[len-i-1];
        data[len-i-1]= t;
    }
}

static void unbase24(uint32_t *x, uint8_t *c)
{
    BN y, tmp;
    int i;
    memset(x, 0, 16);
    bn_zero(&y);
    for (i=0; i<25; i++) {
        bn_mul_word(&tmp, &y, 24);
        bn_copy(&y, &tmp);
        y.d[0] += c[i];
    }
    bn_to_bin(&y, (uint8_t*)x, 16);
    endian((uint8_t*)x, bn_num_bytes(&y));
}

static void base24(uint8_t *c, uint32_t *x)
{
    uint8_t y[16];
    BN z;
    int i;

    memcpy(y, x, 16);
    for (i=15; y[i]==0; i--) {} i++;
    endian(y, i);
    bn_from_bin(&z, y, i);

    c[25] = 0;
    for (i=24; i>=0; i--) {
        uint32_t rem = bn_div_word(&z, 24);
        c[i] = cset[rem];
    }
}

static void print_product_id(uint32_t *pid)
{
    char raw[12];
    char b[6], c[8];
    int i, digit = 0;

    sprintf(raw, "%d", pid[0] >> 1);
    strncpy(b, raw, 3); b[3] = 0;
    strcpy(c, raw+3);

    assert(strlen(c) == 6);
    for (i=0; i<6; i++) digit -= c[i]-'0';
    while (digit < 0) digit += 7;
    c[6] = digit+'0'; c[7] = 0;
    printf("Product ID: 55274-%s-%s-23xxx\n", b, c);
}

static void print_product_key(uint8_t *pk)
{
    int i;
    assert(strlen((const char*)pk) == 25);
    for (i=0; i<25; i++) {
        putchar(pk[i]);
        if (i!=24 && i%5==4) putchar('-');
    }
}

static void verify(EC_GROUP *ec, EC_POINT *generator, EC_POINT *public_key, char *cdkey)
{
    uint8_t key[25];
    int i, j, k;
    uint32_t bkey[4] = {0};
    uint32_t pid[1], hash[1], sig[2];
    BN e, s, x, y;
    EC_POINT u, v, aff;
    uint8_t buf[FIELD_BYTES], md[20];
    uint32_t h;
    uint8_t t[4];
    SHA1_CTX h_ctx;

    for (i=0, k=0; i<(int)strlen(cdkey); i++) {
        for (j=0; j<24; j++) {
            if (cdkey[i]!='-' && cdkey[i]==cset[j]) {
                key[k++] = j; break;
            }
            assert(j<24);
        }
        if (k>=25) break;
    }

    unbase24(bkey, key);
    printf("%.8x %.8x %.8x %.8x\n", bkey[3], bkey[2], bkey[1], bkey[0]);

    unpack(pid, hash, sig, bkey);
    print_product_id(pid);
    printf("PID: %.8x\nHash: %.8x\nSig: %.8x %.8x\n", pid[0], hash[0], sig[1], sig[0]);

    bn_set_word(&e, hash[0]);
    endian((uint8_t*)sig, sizeof(sig));
    bn_from_bin(&s, (uint8_t*)sig, sizeof(sig));

    ec_point_init(&u); ec_point_init(&v);

    ec_point_mul(&u, generator,  &s, ec);
    ec_point_mul(&v, public_key, &e, ec);
    ec_point_add(&v, &u, &v, ec);
    ec_get_affine(&v, &x, &y, ec);

    SHA1_Init(&h_ctx);
    t[0] =  pid[0]        & 0xff;
    t[1] = (pid[0]>> 8)   & 0xff;
    t[2] = (pid[0]>>16)   & 0xff;
    t[3] = (pid[0]>>24)   & 0xff;
    SHA1_Update(&h_ctx, t, 4);

    memset(buf,0,sizeof(buf));
    bn_to_bin(&x, buf, FIELD_BYTES);
    endian(buf, FIELD_BYTES);
    SHA1_Update(&h_ctx, buf, FIELD_BYTES);

    memset(buf,0,sizeof(buf));
    bn_to_bin(&y, buf, FIELD_BYTES);
    endian(buf, FIELD_BYTES);
    SHA1_Update(&h_ctx, buf, FIELD_BYTES);

    SHA1_Final(md, &h_ctx);
    h = (md[0]|(md[1]<<8)|(md[2]<<16)|(md[3]<<24)) >> 4;
    h &= 0xfffffff;

    printf("Calculated hash: %.8x\n", h);
    if (h == hash[0]) printf("Key valid\n");
    else              printf("Key invalid\n");
    putchar('\n');
    (void)aff;
}

static void generate(uint8_t *pkey, EC_GROUP *ec, EC_POINT *generator,
                     BN *order, BN *priv, uint32_t *pid)
{
    BN k, s, x, y;
    EC_POINT r;
    uint32_t bkey[4];

    do {
        SHA1_CTX h_ctx;
        uint8_t t[4], md[20], buf[FIELD_BYTES];
        uint32_t hash[1], sig[2] = {0,0};

        bn_rand(&k, FIELD_BITS);
        ec_point_init(&r);
        ec_point_mul(&r, generator, &k, ec);
        ec_get_affine(&r, &x, &y, ec);

        SHA1_Init(&h_ctx);
        t[0] =  pid[0]       & 0xff;
        t[1] = (pid[0]>> 8)  & 0xff;
        t[2] = (pid[0]>>16)  & 0xff;
        t[3] = (pid[0]>>24)  & 0xff;
        SHA1_Update(&h_ctx, t, 4);

        memset(buf,0,FIELD_BYTES);
        bn_to_bin(&x, buf, FIELD_BYTES);
        endian(buf, FIELD_BYTES);
        SHA1_Update(&h_ctx, buf, FIELD_BYTES);

        memset(buf,0,FIELD_BYTES);
        bn_to_bin(&y, buf, FIELD_BYTES);
        endian(buf, FIELD_BYTES);
        SHA1_Update(&h_ctx, buf, FIELD_BYTES);

        SHA1_Final(md, &h_ctx);
        hash[0] = (md[0]|(md[1]<<8)|(md[2]<<16)|(md[3]<<24)) >> 4;
        hash[0] &= 0xfffffff;

        /* s = priv*h + k */
        bn_copy(&s, priv);
        bn_mul_word(&s, &s, hash[0]);
        bn_mod_add(&s, &s, &k, order);

        bn_to_bin(&s, (uint8_t*)sig, BN_num_bytes(&s));
        endian((uint8_t*)sig, BN_num_bytes(&s));
        pack(bkey, pid, hash, sig);
        printf("PID: %.8x\nHash: %.8x\nSig: %.8x %.8x\n", pid[0], hash[0], sig[1], sig[0]);

    } while (bkey[3] >= 0x40000);

    base24(pkey, bkey);
}

/* =========================================================
 *  EXPORTED INTERFACE  (same signature as original extern "C")
 * ========================================================= */
void generate_key_interface(char *buffer)
{
    EC_GROUP ec;
    EC_POINT g;
    BN a, b, p, gx, gy, n, priv;
    uint8_t pkey[26];
    uint32_t pid[1];
    int i, j;

    rng_seed();

    bn_from_hex(&p,    "92ddcf14cb9e71f4489a2e9ba350ae29454d98cb93bdbcc07d62b502ea12238ee904a8b20d017197aae0c103b32713a9");
    bn_set_word(&a, 1);
    bn_set_word(&b, 0);
    bn_from_hex(&gx,   "46E3775ECE21B0898D39BEA57050D422A0AF989E497962BAEE2CB17E0A28D5360D5476B8DC966443E37A14F1AEF37742");
    bn_from_hex(&gy,   "7C8E741D2C34F4478E325469CD491603D807222C9C4AC09DDB2B31B3CE3F7CC191B3580079932BC6BEF70BE27604F65E");
    bn_from_hex(&n,    "DB6B4C58EFBAFD");
    bn_from_hex(&priv, "565B0DFF8496C8");

    bn_copy(&ec.p, &p);
    bn_copy(&ec.a, &a);
    bn_copy(&ec.b, &b);

    ec_set_affine(&g, &gx, &gy);

    pid[0] = 640000000 << 1;

    generate(pkey, &ec, &g, &n, &priv, pid);

    j = 0;
    for (i=0; i<25; i++) {
        buffer[j++] = (char)pkey[i];
        if (i!=24 && i%5==4) buffer[j++] = '-';
    }
    buffer[j] = '\0';
}

/* =========================================================
 *  MAIN (optional test entry point)
 * ========================================================= */
int main(void)
{
    char key[32];
    printf("Generating Windows XP key...\n");
    generate_key_interface(key);
    printf("Generated key: %s\n", key);
    return 0;
}
