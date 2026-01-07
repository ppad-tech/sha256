#include <stdint.h>
#include <string.h>

#if defined(__aarch64__) && defined(__ARM_FEATURE_SHA2)

#include <arm_neon.h>

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/*
 * Process one 64-byte block using ARM SHA256 crypto instructions.
 *
 * state: pointer to 8 uint32_t words (a,b,c,d,e,f,g,h)
 * block: pointer to 64 bytes of message data
 *
 * The state is updated in place.
 */
void sha256_block_arm(uint32_t *state, const uint8_t *block) {
    /* Load current hash state */
    uint32x4_t abcd = vld1q_u32(&state[0]);
    uint32x4_t efgh = vld1q_u32(&state[4]);

    /* Save original for final addition */
    uint32x4_t abcd_orig = abcd;
    uint32x4_t efgh_orig = efgh;

    /* Load message and convert from big-endian */
    uint32x4_t m0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(&block[0])));
    uint32x4_t m1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(&block[16])));
    uint32x4_t m2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(&block[32])));
    uint32x4_t m3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(&block[48])));

    uint32x4_t tmp, tmp2;

    /* Rounds 0-3 */
    tmp = vaddq_u32(m0, vld1q_u32(&K[0]));
    tmp2 = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, tmp2, tmp);
    m0 = vsha256su1q_u32(vsha256su0q_u32(m0, m1), m2, m3);

    /* Rounds 4-7 */
    tmp = vaddq_u32(m1, vld1q_u32(&K[4]));
    tmp2 = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, tmp2, tmp);
    m1 = vsha256su1q_u32(vsha256su0q_u32(m1, m2), m3, m0);

    /* Rounds 8-11 */
    tmp = vaddq_u32(m2, vld1q_u32(&K[8]));
    tmp2 = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, tmp2, tmp);
    m2 = vsha256su1q_u32(vsha256su0q_u32(m2, m3), m0, m1);

    /* Rounds 12-15 */
    tmp = vaddq_u32(m3, vld1q_u32(&K[12]));
    tmp2 = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, tmp2, tmp);
    m3 = vsha256su1q_u32(vsha256su0q_u32(m3, m0), m1, m2);

    /* Rounds 16-19 */
    tmp = vaddq_u32(m0, vld1q_u32(&K[16]));
    tmp2 = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, tmp2, tmp);
    m0 = vsha256su1q_u32(vsha256su0q_u32(m0, m1), m2, m3);

    /* Rounds 20-23 */
    tmp = vaddq_u32(m1, vld1q_u32(&K[20]));
    tmp2 = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, tmp2, tmp);
    m1 = vsha256su1q_u32(vsha256su0q_u32(m1, m2), m3, m0);

    /* Rounds 24-27 */
    tmp = vaddq_u32(m2, vld1q_u32(&K[24]));
    tmp2 = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, tmp2, tmp);
    m2 = vsha256su1q_u32(vsha256su0q_u32(m2, m3), m0, m1);

    /* Rounds 28-31 */
    tmp = vaddq_u32(m3, vld1q_u32(&K[28]));
    tmp2 = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, tmp2, tmp);
    m3 = vsha256su1q_u32(vsha256su0q_u32(m3, m0), m1, m2);

    /* Rounds 32-35 */
    tmp = vaddq_u32(m0, vld1q_u32(&K[32]));
    tmp2 = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, tmp2, tmp);
    m0 = vsha256su1q_u32(vsha256su0q_u32(m0, m1), m2, m3);

    /* Rounds 36-39 */
    tmp = vaddq_u32(m1, vld1q_u32(&K[36]));
    tmp2 = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, tmp2, tmp);
    m1 = vsha256su1q_u32(vsha256su0q_u32(m1, m2), m3, m0);

    /* Rounds 40-43 */
    tmp = vaddq_u32(m2, vld1q_u32(&K[40]));
    tmp2 = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, tmp2, tmp);
    m2 = vsha256su1q_u32(vsha256su0q_u32(m2, m3), m0, m1);

    /* Rounds 44-47 */
    tmp = vaddq_u32(m3, vld1q_u32(&K[44]));
    tmp2 = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, tmp2, tmp);
    m3 = vsha256su1q_u32(vsha256su0q_u32(m3, m0), m1, m2);

    /* Rounds 48-51 */
    tmp = vaddq_u32(m0, vld1q_u32(&K[48]));
    tmp2 = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, tmp2, tmp);

    /* Rounds 52-55 */
    tmp = vaddq_u32(m1, vld1q_u32(&K[52]));
    tmp2 = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, tmp2, tmp);

    /* Rounds 56-59 */
    tmp = vaddq_u32(m2, vld1q_u32(&K[56]));
    tmp2 = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, tmp2, tmp);

    /* Rounds 60-63 */
    tmp = vaddq_u32(m3, vld1q_u32(&K[60]));
    tmp2 = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, tmp2, tmp);

    /* Add original state back */
    abcd = vaddq_u32(abcd, abcd_orig);
    efgh = vaddq_u32(efgh, efgh_orig);

    /* Store result */
    vst1q_u32(&state[0], abcd);
    vst1q_u32(&state[4], efgh);
}

/* Return 1 if ARM SHA2 is available, 0 otherwise */
int sha256_arm_available(void) {
    return 1;
}

#else

/* Stub implementations when ARM SHA2 is not available */
void sha256_block_arm(uint32_t *state, const uint8_t *block) {
    (void)state;
    (void)block;
    /* Should never be called - use pure Haskell fallback */
}

int sha256_arm_available(void) {
    return 0;
}

#endif
