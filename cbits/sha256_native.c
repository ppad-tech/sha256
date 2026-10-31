#include <stdint.h>
#include <string.h>

#if defined(__aarch64__)

#include <arm_neon.h>

#if defined(__linux__)
#include <sys/auxv.h>
#ifndef HWCAP_SHA2
#define HWCAP_SHA2 (1UL << 6)
#endif
#endif

#elif defined(__x86_64__)

#include <cpuid.h>
#include <immintrin.h>

#ifndef bit_SHA
#define bit_SHA (1 << 29)
#endif

#endif

#if defined(__aarch64__) || defined(__x86_64__)

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

#endif

#if defined(__aarch64__)

/*
 * Process one 64-byte block using ARM SHA256 crypto instructions.
 *
 * state: pointer to 8 uint32_t words (a,b,c,d,e,f,g,h)
 * block: pointer to 16 uint32_t words (already native endian)
 *
 * The state is updated in place.
 *
 * Compiled for the SHA2 extension only; callers must first check
 * 'sha256_native_available'.
 */
__attribute__((target("+sha2")))
void sha256_block_native(uint32_t *state, const uint32_t *block) {
    /* Load current hash state */
    uint32x4_t abcd = vld1q_u32(&state[0]);
    uint32x4_t efgh = vld1q_u32(&state[4]);

    /* Save original for final addition */
    uint32x4_t abcd_orig = abcd;
    uint32x4_t efgh_orig = efgh;

    /* Load message (already native endian) */
    uint32x4_t m0 = vld1q_u32(&block[0]);
    uint32x4_t m1 = vld1q_u32(&block[4]);
    uint32x4_t m2 = vld1q_u32(&block[8]);
    uint32x4_t m3 = vld1q_u32(&block[12]);

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

/*
 * Return 1 if the CPU implements the ARM SHA2 extension, 0 otherwise.
 * Every Apple arm64 core implements it.  Elsewhere we only know how to
 * ask Linux, and report 0 (selecting the pure Haskell fallback) on
 * any other OS.
 */
int sha256_native_available(void) {
#if defined(__APPLE__)
    return 1;
#elif defined(__linux__)
    return (getauxval(AT_HWCAP) & HWCAP_SHA2) != 0;
#else
    return 0;
#endif
}

#elif defined(__x86_64__)

/*
 * Four rounds.  'sha256rnds2' does two: it takes the (c,d,g,h) and
 * (a,b,e,f) halves of the state, and two message-plus-constant words in
 * the low lanes of its third argument, and returns the new (a,b,e,f).
 * The old (a,b,e,f) is then the new (c,d,g,h), so a second call with
 * the halves swapped does the next two.
 */
#define ROUNDS4(abef, cdgh, msg)                           \
    do {                                                   \
        cdgh = _mm_sha256rnds2_epu32(cdgh, abef, msg);     \
        msg  = _mm_shuffle_epi32(msg, 0x0e);               \
        abef = _mm_sha256rnds2_epu32(abef, cdgh, msg);     \
    } while (0)

/*
 * Process one 64-byte block using x86 SHA instructions.
 *
 * state: pointer to 8 uint32_t words (a,b,c,d,e,f,g,h)
 * block: pointer to 16 uint32_t words (already native endian)
 *
 * The state is updated in place.
 *
 * Compiled for the SHA and SSE4.1 extensions only; callers must first
 * check 'sha256_native_available'.
 *
 * Lane orders in comments are written from highest lane to lowest.
 */
__attribute__((target("sha,sse4.1")))
void sha256_block_native(uint32_t *state, const uint32_t *block) {
    __m128i abef, cdgh, abef_orig, cdgh_orig;
    __m128i m0, m1, m2, m3, msg, tmp;

    /* Load current hash state, rearranging it for the SHA instructions */
    tmp  = _mm_loadu_si128((const __m128i *)&state[0]); /* d c b a */
    cdgh = _mm_loadu_si128((const __m128i *)&state[4]); /* h g f e */
    tmp  = _mm_shuffle_epi32(tmp, 0xb1);                /* c d a b */
    cdgh = _mm_shuffle_epi32(cdgh, 0x1b);               /* e f g h */
    abef = _mm_alignr_epi8(tmp, cdgh, 8);               /* a b e f */
    cdgh = _mm_blend_epi16(cdgh, tmp, 0xf0);            /* c d g h */

    /* Save original for final addition */
    abef_orig = abef;
    cdgh_orig = cdgh;

    /* Load message (already native endian) */
    m0 = _mm_loadu_si128((const __m128i *)&block[0]);
    m1 = _mm_loadu_si128((const __m128i *)&block[4]);
    m2 = _mm_loadu_si128((const __m128i *)&block[8]);
    m3 = _mm_loadu_si128((const __m128i *)&block[12]);

    /* Rounds 0-3 */
    msg = _mm_add_epi32(m0, _mm_loadu_si128((const __m128i *)&K[0]));
    ROUNDS4(abef, cdgh, msg);

    /* Rounds 4-7 */
    msg = _mm_add_epi32(m1, _mm_loadu_si128((const __m128i *)&K[4]));
    ROUNDS4(abef, cdgh, msg);
    m0 = _mm_sha256msg1_epu32(m0, m1);

    /* Rounds 8-11 */
    msg = _mm_add_epi32(m2, _mm_loadu_si128((const __m128i *)&K[8]));
    ROUNDS4(abef, cdgh, msg);
    m1 = _mm_sha256msg1_epu32(m1, m2);

    /* Rounds 12-15 */
    msg = _mm_add_epi32(m3, _mm_loadu_si128((const __m128i *)&K[12]));
    ROUNDS4(abef, cdgh, msg);
    m0 = _mm_add_epi32(m0, _mm_alignr_epi8(m3, m2, 4));
    m0 = _mm_sha256msg2_epu32(m0, m3);
    m2 = _mm_sha256msg1_epu32(m2, m3);

    /* Rounds 16-19 */
    msg = _mm_add_epi32(m0, _mm_loadu_si128((const __m128i *)&K[16]));
    ROUNDS4(abef, cdgh, msg);
    m1 = _mm_add_epi32(m1, _mm_alignr_epi8(m0, m3, 4));
    m1 = _mm_sha256msg2_epu32(m1, m0);
    m3 = _mm_sha256msg1_epu32(m3, m0);

    /* Rounds 20-23 */
    msg = _mm_add_epi32(m1, _mm_loadu_si128((const __m128i *)&K[20]));
    ROUNDS4(abef, cdgh, msg);
    m2 = _mm_add_epi32(m2, _mm_alignr_epi8(m1, m0, 4));
    m2 = _mm_sha256msg2_epu32(m2, m1);
    m0 = _mm_sha256msg1_epu32(m0, m1);

    /* Rounds 24-27 */
    msg = _mm_add_epi32(m2, _mm_loadu_si128((const __m128i *)&K[24]));
    ROUNDS4(abef, cdgh, msg);
    m3 = _mm_add_epi32(m3, _mm_alignr_epi8(m2, m1, 4));
    m3 = _mm_sha256msg2_epu32(m3, m2);
    m1 = _mm_sha256msg1_epu32(m1, m2);

    /* Rounds 28-31 */
    msg = _mm_add_epi32(m3, _mm_loadu_si128((const __m128i *)&K[28]));
    ROUNDS4(abef, cdgh, msg);
    m0 = _mm_add_epi32(m0, _mm_alignr_epi8(m3, m2, 4));
    m0 = _mm_sha256msg2_epu32(m0, m3);
    m2 = _mm_sha256msg1_epu32(m2, m3);

    /* Rounds 32-35 */
    msg = _mm_add_epi32(m0, _mm_loadu_si128((const __m128i *)&K[32]));
    ROUNDS4(abef, cdgh, msg);
    m1 = _mm_add_epi32(m1, _mm_alignr_epi8(m0, m3, 4));
    m1 = _mm_sha256msg2_epu32(m1, m0);
    m3 = _mm_sha256msg1_epu32(m3, m0);

    /* Rounds 36-39 */
    msg = _mm_add_epi32(m1, _mm_loadu_si128((const __m128i *)&K[36]));
    ROUNDS4(abef, cdgh, msg);
    m2 = _mm_add_epi32(m2, _mm_alignr_epi8(m1, m0, 4));
    m2 = _mm_sha256msg2_epu32(m2, m1);
    m0 = _mm_sha256msg1_epu32(m0, m1);

    /* Rounds 40-43 */
    msg = _mm_add_epi32(m2, _mm_loadu_si128((const __m128i *)&K[40]));
    ROUNDS4(abef, cdgh, msg);
    m3 = _mm_add_epi32(m3, _mm_alignr_epi8(m2, m1, 4));
    m3 = _mm_sha256msg2_epu32(m3, m2);
    m1 = _mm_sha256msg1_epu32(m1, m2);

    /* Rounds 44-47 */
    msg = _mm_add_epi32(m3, _mm_loadu_si128((const __m128i *)&K[44]));
    ROUNDS4(abef, cdgh, msg);
    m0 = _mm_add_epi32(m0, _mm_alignr_epi8(m3, m2, 4));
    m0 = _mm_sha256msg2_epu32(m0, m3);
    m2 = _mm_sha256msg1_epu32(m2, m3);

    /* Rounds 48-51 */
    msg = _mm_add_epi32(m0, _mm_loadu_si128((const __m128i *)&K[48]));
    ROUNDS4(abef, cdgh, msg);
    m1 = _mm_add_epi32(m1, _mm_alignr_epi8(m0, m3, 4));
    m1 = _mm_sha256msg2_epu32(m1, m0);
    m3 = _mm_sha256msg1_epu32(m3, m0);

    /* Rounds 52-55 */
    msg = _mm_add_epi32(m1, _mm_loadu_si128((const __m128i *)&K[52]));
    ROUNDS4(abef, cdgh, msg);
    m2 = _mm_add_epi32(m2, _mm_alignr_epi8(m1, m0, 4));
    m2 = _mm_sha256msg2_epu32(m2, m1);

    /* Rounds 56-59 */
    msg = _mm_add_epi32(m2, _mm_loadu_si128((const __m128i *)&K[56]));
    ROUNDS4(abef, cdgh, msg);
    m3 = _mm_add_epi32(m3, _mm_alignr_epi8(m2, m1, 4));
    m3 = _mm_sha256msg2_epu32(m3, m2);

    /* Rounds 60-63 */
    msg = _mm_add_epi32(m3, _mm_loadu_si128((const __m128i *)&K[60]));
    ROUNDS4(abef, cdgh, msg);

    /* Add original state back */
    abef = _mm_add_epi32(abef, abef_orig);
    cdgh = _mm_add_epi32(cdgh, cdgh_orig);

    /* Restore the state's original order and store result */
    tmp  = _mm_shuffle_epi32(abef, 0x1b);               /* f e b a */
    cdgh = _mm_shuffle_epi32(cdgh, 0xb1);               /* d c h g */
    _mm_storeu_si128((__m128i *)&state[0],
                     _mm_blend_epi16(tmp, cdgh, 0xf0)); /* d c b a */
    _mm_storeu_si128((__m128i *)&state[4],
                     _mm_alignr_epi8(cdgh, tmp, 8));    /* h g f e */
}

/*
 * Return 1 if the CPU implements the x86 SHA extensions and the SSSE3
 * and SSE4.1 instructions used alongside them, 0 otherwise.
 */
int sha256_native_available(void) {
    unsigned int eax, ebx, ecx, edx;

    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx))
        return 0;
    if (!(ecx & bit_SSSE3) || !(ecx & bit_SSE4_1))
        return 0;
    if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx))
        return 0;
    return (ebx & bit_SHA) != 0;
}

#else

/* Stub implementations for builds without hardware support */
void sha256_block_native(uint32_t *state, const uint32_t *block) {
    (void)state;
    (void)block;
    /* Should never be called - use pure Haskell fallback */
}

int sha256_native_available(void) {
    return 0;
}

#endif
