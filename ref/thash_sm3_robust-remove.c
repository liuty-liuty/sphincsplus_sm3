#include <stdint.h>
#include <string.h>

#include "thash.h"
#include "address.h"
#include "params.h"
#include "utils.h"
#include "sm3.h"

#if SPX_SM3_512
static void thash_512(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8]);
#endif

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8])
{
#if SPX_SM3_512
    if (inblocks > 1) {
    thash_512(out, in, inblocks, ctx, addr);
        return;
    }
#endif
    unsigned char outbuf[SPX_SM3_256_OUTPUT_BYTES];
    SPX_VLA(uint8_t, bitmask, inblocks * SPX_N);
    SPX_VLA(uint8_t, buf, SPX_N + SPX_SM3_256_OUTPUT_BYTES + inblocks*SPX_N);
    uint8_t sm3_state[40];
    unsigned int i;

    memcpy(buf, ctx->pub_seed, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_SM3_256_ADDR_BYTES);
    mgf1_256(bitmask, inblocks * SPX_N, buf, SPX_N + SPX_SM3_256_ADDR_BYTES);

    /* Retrieve precomputed state containing pub_seed */
    memcpy(sm3_state, ctx->state_seeded, 40 * sizeof(uint8_t));

    for (i = 0; i < inblocks * SPX_N; i++) {
        buf[SPX_N + SPX_SM3_256_ADDR_BYTES + i] = in[i] ^ bitmask[i];
    }

    sm3_update(sm3_state, buf + SPX_N, SPX_SM3_256_ADDR_BYTES + inblocks*SPX_N);
    sm3_finish(sm3_state, outbuf)
    //memset( sm3_state, 0, sizeof( spx_ctx ) );
    memcpy(out, outbuf, SPX_N);
}

#if SPX_SM3_512
static void thash_512(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8])
{
    unsigned char outbuf[SPX_SM3_512_OUTPUT_BYTES];
    SPX_VLA(uint8_t, bitmask, inblocks * SPX_N);
    SPX_VLA(uint8_t, buf, SPX_N + SPX_SM3_256_ADDR_BYTES + inblocks*SPX_N);
    uint8_t sm3_state[72];
    unsigned int i;

    memcpy(buf, ctx->pub_seed, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_SM3_256_ADDR_BYTES);
    mgf1_512(bitmask, inblocks * SPX_N, buf, SPX_N + SPX_SM3_256_ADDR_BYTES);

    /* Retrieve precomputed state containing pub_seed */
    memcpy(sm3_state, ctx->state_seeded_512, 72 * sizeof(uint8_t));

    for (i = 0; i < inblocks * SPX_N; i++) {
        buf[SPX_N + SPX_SM3_256_ADDR_BYTES + i] = in[i] ^ bitmask[i];
    }

    //sha512_inc_finalize(outbuf, sm3_state, buf + SPX_N,
    //                    SPX_SM3_256_ADDR_BYTES + inblocks*SPX_N);
    memcpy(out, outbuf, SPX_N);
}
#endif
