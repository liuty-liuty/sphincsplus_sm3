/* Based on the public domain implementation in
 * crypto_hash/sha512/ref/ from http://bench.cr.yp.to/supercop.html
 * by D. J. Bernstein */

#include <stddef.h>
#include <stdint.h>

#include <string.h>
#include <stdio.h>
#include "utils.h"
//#include "sha2.h"
#include "sm3.h"
static unsigned int state[8] = {0};
static unsigned int T[64] = {0};
static uint32_t load_bigendian_32(const uint8_t *x) {
    return (uint32_t)(x[3]) 
    | (((uint32_t)(x[2])) << 8) 
    | (((uint32_t)(x[1])) << 16) 
    | (((uint32_t)(x[0])) << 24);
}


static void store_bigendian_32(uint8_t *x, uint64_t u) {
    x[3] = (uint8_t) u;
    u >>= 8;
    x[2] = (uint8_t) u;
    u >>= 8;
    x[1] = (uint8_t) u;
    u >>= 8;
    x[0] = (uint8_t) u;
}

static uint64_t load_bigendian_64(const uint8_t *x) {
    return (uint64_t)(x[7]) 
    | (((uint64_t)(x[6])) << 8) 
    | (((uint64_t)(x[5])) << 16) 
    | (((uint64_t)(x[4])) << 24) 
    | (((uint64_t)(x[3])) << 32) 
    | (((uint64_t)(x[2])) << 40) 
    | (((uint64_t)(x[1])) << 48) 
    | (((uint64_t)(x[0])) << 56);
}



static void store_bigendian_64(uint8_t *x, uint64_t u) {
    x[7] = (uint8_t) u;
    u >>= 8;
    x[6] = (uint8_t) u;
    u >>= 8;
    x[5] = (uint8_t) u;
    u >>= 8;
    x[4] = (uint8_t) u;
    u >>= 8;
    x[3] = (uint8_t) u;
    u >>= 8;
    x[2] = (uint8_t) u;
    u >>= 8;
    x[1] = (uint8_t) u;
    u >>= 8;
    x[0] = (uint8_t) u;
}

unsigned int rotate_left(unsigned int a, unsigned int k)
{
    k = k % 32;
    return ((a << k) & 0xFFFFFFFF) | ((a & 0xFFFFFFFF) >> (32 - k));
}


int init_T()
{
    int i = 0;
    for (i = 0; i < 16; i++)
    {
        T[i] = 0x79cc4519;
    }
    for (i = 16; i < 64; i++)
    {
        T[i] = 0x7a879d8a;
    }
    return 1;
}

unsigned int FF(X, Y, Z, j)
{
    unsigned int ret = 0;
    if (0 <= j && j < 16)
    {
        ret = X ^ Y ^ Z;
    }
    else if (16 <= j && j < 64)
    {
        ret = (X & Y) | (X & Z) | (Y & Z);
    }
    return ret;
}

unsigned int GG(X, Y, Z, j)
{
    unsigned int ret = 0;
    if (0 <= j && j < 16)
    {
        ret = X ^ Y ^ Z;
    }
    else if (16 <= j && j < 64)
    {
        ret = (X & Y) | ((~X) & Z);
    }
    return ret;
}

#define P_0(X) X ^ (rotate_left(X, 9)) ^ (rotate_left(X, 17))

#define P_1(X) X ^ (rotate_left(X, 15)) ^ (rotate_left(X, 23))

static size_t crypto_hashblocks_sm3_256(uint8_t *statebytes,
                                       const uint8_t *in) 
{
    unsigned int W[68];
    unsigned int W_1[64];
    unsigned int j;
    unsigned int A, B, C, D, E, F, G, H;
    unsigned int SS1, SS2, TT1, TT2;
    for (j = 0; j < 16; j++)
    {
        W[j] = in[j * 4 + 0] << 24 | in[j * 4 + 1] << 16 | in[j * 4 + 2] << 8 | in[j * 4 + 3];

    }
    for (j = 16; j < 68; j++)
    {
        W[j] = P_1(W[j - 16] ^ W[j - 9] ^ (rotate_left(W[j - 3], 15))) ^ (rotate_left(W[j - 13], 7)) ^ W[j - 6];
    }
    for (j = 0; j < 64; j++)
    {
        W_1[j] = W[j] ^ W[j + 4];
    }

    A = load_bigendian_32(statebytes + 0);
    state[0] = A;
    B = load_bigendian_32(statebytes + 4);
    state[1] = B;
    C = load_bigendian_32(statebytes + 8);
    state[2] = C;
    D = load_bigendian_32(statebytes + 12);
    state[3] = D;
    E = load_bigendian_32(statebytes + 16);
    state[4] = E;
    F = load_bigendian_32(statebytes + 20);
    state[5] = F;
    G = load_bigendian_32(statebytes + 24);
    state[6] = G;
    H = load_bigendian_32(statebytes + 28);
    state[7] = H;

    for (j = 0; j < 64; j++)
    {
        SS1 = rotate_left(((rotate_left(A, 12)) + E + (rotate_left(T[j], j))) & 0xFFFFFFFF, 7);
        SS2 = SS1 ^ (rotate_left(A, 12));
        TT1 = (FF(A, B, C, j) + D + SS2 + W_1[j]) & 0xFFFFFFFF;
        TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF;
        D = C;
        C = rotate_left(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = rotate_left(F, 19);
        F = E;
        E = P_0(TT2);

    }
    
    state[0] = (A ^ state[0]);
    state[1] = (B ^ state[1]);
    state[2] = (C ^ state[2]);
    state[3] = (D ^ state[3]);
    state[4] = (E ^ state[4]);
    state[5] = (F ^ state[5]);
    state[6] = (G ^ state[6]);
    state[7] = (H ^ state[7]);

    store_bigendian_32(statebytes + 0, state[0]);
    store_bigendian_32(statebytes + 4, state[1]);
    store_bigendian_32(statebytes + 8, state[2]);
    store_bigendian_32(statebytes + 12, state[3]);
    store_bigendian_32(statebytes + 16, state[4]);
    store_bigendian_32(statebytes + 20, state[5]);
    store_bigendian_32(statebytes + 24, state[6]);
    store_bigendian_32(statebytes + 28, state[7]);
    //return 1;
}

static size_t crypto_hashblocks_sm3_512(uint8_t *statebytes,
                                       const uint8_t *in) 
{
    unsigned int W[68];
    unsigned int W_1[64];
    unsigned int j;
    unsigned int A, B, C, D, E, F, G, H;
    unsigned int SS1, SS2, TT1, TT2;
    for (j = 0; j < 16; j++)
    {
        W[j] =  in[j * 8 + 0] << 56 | in[j * 8 + 1] << 48 | in[j * 8 + 2] << 40 | in[j * 8 + 3] << 32|
                in[j * 8 + 4] << 24 | in[j * 8 + 5] << 16 | in[j * 8 + 6] << 8 | in[j * 8 + 7];
    }
    for (j = 16; j < 68; j++)
    {
        W[j] = P_1(W[j - 16] ^ W[j - 9] ^ (rotate_left(W[j - 3], 15))) ^ (rotate_left(W[j - 13], 7)) ^ W[j - 6];
    }
    for (j = 0; j < 64; j++)
    {
        W_1[j] = W[j] ^ W[j + 4];
    }

    A = load_bigendian_64(statebytes + 0);
    state[0] = A;
    B = load_bigendian_64(statebytes + 8);
    state[1] = B;
    C = load_bigendian_64(statebytes + 16);
    state[2] = C;
    D = load_bigendian_64(statebytes + 24);
    state[3] = D;
    E = load_bigendian_64(statebytes + 32);
    state[4] = E;
    F = load_bigendian_64(statebytes + 40);
    state[5] = F;
    G = load_bigendian_64(statebytes + 48);
    state[6] = G;
    H = load_bigendian_64(statebytes + 56);
    state[7] = H;

    for (j = 0; j < 64; j++)
    {
        SS1 = rotate_left(((rotate_left(A, 12)) + E + (rotate_left(T[j], j))) & 0xFFFFFFFF, 7);
        SS2 = SS1 ^ (rotate_left(A, 12));
        TT1 = (FF(A, B, C, j) + D + SS2 + W_1[j]) & 0xFFFFFFFF;
        TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF;
        D = C;
        C = rotate_left(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = rotate_left(F, 19);
        F = E;
        E = P_0(TT2);

    }
    
    state[0] = (A ^ state[0]);
    state[1] = (B ^ state[1]);
    state[2] = (C ^ state[2]);
    state[3] = (D ^ state[3]);
    state[4] = (E ^ state[4]);
    state[5] = (F ^ state[5]);
    state[6] = (G ^ state[6]);
    state[7] = (H ^ state[7]);

    store_bigendian_64(statebytes + 0, state[0]);
    store_bigendian_64(statebytes + 8, state[1]);
    store_bigendian_64(statebytes + 16, state[2]);
    store_bigendian_64(statebytes + 24, state[3]);
    store_bigendian_64(statebytes + 32, state[4]);
    store_bigendian_64(statebytes + 40, state[5]);
    store_bigendian_64(statebytes + 48, state[6]);
    store_bigendian_64(statebytes + 56, state[7]);
    //return 1;
}


static const uint8_t iv_256[32] = {
    0x73, 0x80, 0x16, 0x6F, 0x49, 0x14, 0xB2, 0xB9,
    0x17, 0x24, 0x42, 0xD7, 0xDA, 0x8A, 0x06, 0x00,
    0xA9, 0x6F, 0x30, 0xBC, 0x16, 0x31, 0x38, 0xAA,
    0xE3, 0x8D, 0xEE, 0x4D, 0xB0, 0xFB, 0x0E, 0x4E
};

static const uint8_t iv_512[64] = {//wrong iv
    0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08, 0xbb, 0x67, 0xae,
    0x85, 0x84, 0xca, 0xa7, 0x3b, 0x3c, 0x6e, 0xf3, 0x72, 0xfe, 0x94,
    0xf8, 0x2b, 0xa5, 0x4f, 0xf5, 0x3a, 0x5f, 0x1d, 0x36, 0xf1, 0x51,
    0x0e, 0x52, 0x7f, 0xad, 0xe6, 0x82, 0xd1, 0x9b, 0x05, 0x68, 0x8c,
    0x2b, 0x3e, 0x6c, 0x1f, 0x1f, 0x83, 0xd9, 0xab, 0xfb, 0x41, 0xbd,
    0x6b, 0x5b, 0xe0, 0xcd, 0x19, 0x13, 0x7e, 0x21, 0x79
};


void sm3_256_inc_init(uint8_t *state) {//0和iv_256先后？
   

    for (size_t i = 0; i < 32; ++i) {
        state[i] = iv_256[i];
    }
    for (size_t i = 32; i < 40; ++i) {
        state[i] = 0;
    }
}

void sm3_512_inc_init(uint8_t *state) {
    for (size_t i = 0; i < 64; ++i) {
        state[i] = iv_512[i];
    }
    for (size_t i = 64; i < 72; ++i) {
        state[i] = 0;
    }
}

void sm3_256_inc_blocks(uint8_t *state, const uint8_t *in, size_t inblocks) {
    uint64_t bytes = load_bigendian_64(state + 32);
    unsigned char buffer[64] = {0};

    for(int i = 0; i < inblocks; i++){
        memcpy(buffer, in + i * 64, 64);
        crypto_hashblocks_sm3_256(state, buffer );
    }
    //crypto_hashblocks_sm3_256(state, in, 64 * inblocks);
    bytes += 64 * inblocks;

    store_bigendian_64(state + 32, bytes);
}
void sm3_512_inc_blocks(uint8_t *state, const uint8_t *in, size_t inblocks) {
    uint64_t bytes = load_bigendian_64(state + 64);
    unsigned char buffer[128] = {0};

    for(int i = 0; i < inblocks; i++){
        memcpy(buffer, in + i * 64, 64);
        crypto_hashblocks_sm3_256(state, buffer );
    }
    //crypto_hashblocks_sm3_512(state, in, 128 * inblocks);
    bytes += 128 * inblocks;

    store_bigendian_64(state + 64, bytes);
}

void sm3_256_inc_finalize(uint8_t *out, uint8_t *state, const uint8_t *in, size_t inlen){
    int i;
    int left = 0;
    unsigned long long total = 0;
    unsigned char buffer[64] = {0};
        
    for(i = 0; i < inlen/64; i++){
        memcpy(buffer, in + i * 64, 64);
        crypto_hashblocks_sm3_256(state, buffer );
    }

    total = inlen * 8;
    left = inlen%64;

    memset(&buffer[left], 0, 64 - left);    
    memcpy(buffer, in + i * 64, left);
    buffer[left] = 0x80;
    if(left <= 55){
        for (i = 0; i < 8; i++)
            buffer[56 + i] = (total >> ((8 - 1 - i) * 8)) & 0xFF;
        crypto_hashblocks_sm3_256( state, buffer );
    }else{
        crypto_hashblocks_sm3_256( state, buffer );
        memset(buffer, 0, 64);
        for (i = 0; i < 8; i++)
            buffer[56 + i] = (total >> ((8 - 1 - i) * 8)) & 0xFF;
        crypto_hashblocks_sm3_256( state, buffer );
    }

}
void sm3_512_inc_finalize(uint8_t *out, uint8_t *state, const uint8_t *in, size_t inlen){
    int i;
    int left = 0;
    unsigned long long total = 0;
    unsigned char buffer[128] = {0};
        
    for(i = 0; i < inlen/128; i++){
        memcpy(buffer, in + i * 128, 128);
        crypto_hashblocks_sm3_512(state, buffer );
    }

    total = inlen * 8;
    left = inlen%128;

    memset(&buffer[left], 0, 128 - left);    
    memcpy(buffer, in + i * 128, left);
    buffer[left] = 0x80;
    if(left <= 112){
        for (i = 0; i < 9; i++)
            buffer[119 + i] = (total >> ((9 - 1 - i) * 8)) & 0xFF;
        crypto_hashblocks_sm3_512( state, buffer );
    }else{
        crypto_hashblocks_sm3_512( state, buffer );
        memset(buffer, 0, 128);
        for (i = 0; i < 9; i++)
            buffer[119 + i] = (total >> ((9 - 1 - i) * 8)) & 0xFF;
        crypto_hashblocks_sm3_512( state, buffer );
    }

}


void sm3_256(uint8_t *out, const uint8_t *in, size_t inlen) {
    uint8_t state[40];

    sm3_256_inc_init(state);
    sm3_256_inc_finalize(out, state, in, inlen);
}

void sm3_512(uint8_t *out, const uint8_t *in, size_t inlen) {
    uint8_t state[72];

    sm3_256_inc_init(state);
    sm3_256_inc_finalize(out, state, in, inlen);
}
/**
 * mgf1 function based on the SM3-256 hash function
 * Note that inlen should be sufficiently small that it still allows for
 * an array to be allocated on the stack. Typically 'in' is merely a seed.
 * Outputs outlen number of bytes
 */
void mgf1_256(unsigned char *out, unsigned long outlen,
          const unsigned char *in, unsigned long inlen)
{
    SPX_VLA(uint8_t, inbuf, inlen+4);
    unsigned char outbuf[SPX_SM3_256_OUTPUT_BYTES];
    unsigned long i;

    memcpy(inbuf, in, inlen);

    /* While we can fit in at least another full block of SM3_256 output.. */
    for (i = 0; (i+1)*SPX_SM3_256_OUTPUT_BYTES <= outlen; i++) {
        u32_to_bytes(inbuf + inlen, i);
        sm3_256(out, inbuf, inlen + 4);
        out += SPX_SM3_256_OUTPUT_BYTES;
    }
    /* Until we cannot anymore, and we fill the remainder. */
    if (outlen > i*SPX_SM3_256_OUTPUT_BYTES) {
        u32_to_bytes(inbuf + inlen, i);
        sm3_256(outbuf, inbuf, inlen + 4);
        memcpy(out, outbuf, outlen - i*SPX_SM3_256_OUTPUT_BYTES);
    }
}

/*
 * mgf1 function based on the SM3-512 hash function
 */
void mgf1_512(unsigned char *out, unsigned long outlen,
          const unsigned char *in, unsigned long inlen)
{
    SPX_VLA(uint8_t, inbuf, inlen+4);
    unsigned char outbuf[SPX_SM3_512_OUTPUT_BYTES];
    unsigned long i;

    memcpy(inbuf, in, inlen);

    /* While we can fit in at least another full block of SM3_512 output.. */
    for (i = 0; (i+1)*SPX_SM3_512_OUTPUT_BYTES <= outlen; i++) {
        u32_to_bytes(inbuf + inlen, i);
        sm3_512(out, inbuf, inlen + 4);
        out += SPX_SM3_512_OUTPUT_BYTES;
    }
    /* Until we cannot anymore, and we fill the remainder. */
    if (outlen > i*SPX_SM3_512_OUTPUT_BYTES) {
        u32_to_bytes(inbuf + inlen, i);
        sm3_512(outbuf, inbuf, inlen + 4);
        memcpy(out, outbuf, outlen - i*SPX_SM3_512_OUTPUT_BYTES);
    }
}


/**
 * Absorb the constant pub_seed using one round of the compression function
 * This initializes state_seeded and state_seeded_512, which can then be
 * reused in thash
 **/
void seed_state(spx_ctx *ctx) {
    uint8_t block[SPX_SM3_512_BLOCK_BYTES];
    size_t i;

    for (i = 0; i < SPX_N; ++i) {
        block[i] = ctx->pub_seed[i];
    }
    for (i = SPX_N; i < SPX_SM3_512_BLOCK_BYTES; ++i) {
        block[i] = 0;
    }

    /* block has been properly initialized for both SM3_256 and SM3_512 */

    sm3_256_inc_init(ctx->state_seeded);
    sm3_256_inc_blocks(ctx->state_seeded, block, 1);
#if SPX_SM3_512
    sm3_512_inc_init(ctx->state_seeded_512);
    sm3_512_inc_blocks(ctx->state_seeded_512, block, 1);
#endif
}
