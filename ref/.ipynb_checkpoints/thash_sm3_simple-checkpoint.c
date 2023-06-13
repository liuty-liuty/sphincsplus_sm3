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
    //uint8_t sm3_state[40];
    unsigned long sm3_state[10];
    SPX_VLA(uint8_t, buf, SPX_SM3_256_ADDR_BYTES + inblocks*SPX_SM3_256_BLOCK_BYTES);

    /* Retrieve precomputed state containing pub_seed */
    memcpy(sm3_state, ctx->state_seeded, 40 * sizeof(uint8_t));

    memcpy(buf, addr, SPX_SM3_256_ADDR_BYTES);
    memcpy(buf + SPX_SM3_256_ADDR_BYTES, in, inblocks * SPX_SM3_256_BLOCK_BYTES);

    //sha256_inc_finalize(outbuf, sha2_state, buf, SPX_SHA256_ADDR_BYTES + inblocks*SPX_N);
        
    sm3_update(sm3_state, buf, SPX_SM3_256_ADDR_BYTES + inblocks*SPX_SM3_256_BLOCK_BYTES);
    sm3_finish(sm3_state, outbuf);
    //m3(buf, SPX_SM3_256_ADDR_BYTES + inblocks*SPX_N, outbuf);
   
    memcpy(out, outbuf, SPX_N);
   
    //memset( sm3_state, 0, sizeof( spx_ctx ) );
    /*for(int i=0; i<32; i++)
	{
	printf("%02x",out[i]);
	if (((i+1) % 4 ) == 0) printf(" ");
	} 
	printf("\n");*/
    
}

#if SPX_SM3_512
static void thash_512(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8])
{
    unsigned char outbuf[SPX_SHA512_OUTPUT_BYTES];
    //uint8_t sm3_state[72];
    SPX_VLA(uint8_t, buf, SPX_SHA256_ADDR_BYTES + inblocks*SPX_N);

    /* Retrieve precomputed state containing pub_seed */
    memcpy(sm3_state, ctx->state_seeded_512, 72 * sizeof(uint8_t));

    memcpy(buf, addr, SPX_SHA256_ADDR_BYTES);
    memcpy(buf + SPX_SHA256_ADDR_BYTES, in, inblocks * SPX_N);

    //sha512_inc_finalize(outbuf, sm3_state, buf, SPX_SHA256_ADDR_BYTES + inblocks*SPX_N);
    memcpy(out, outbuf, SPX_N);
}
#endif
