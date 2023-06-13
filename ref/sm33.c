#include "sm33.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
static unsigned char buffer[64] = {0};
static unsigned int state[8] = {0};
static unsigned int T[64] = {0};

void out_hex()
{
	unsigned int i = 0;
	for (i = 0; i < 8; i++)
	{
		printf("%08x ", state[i]);
	}
	printf("\n");
}
/*
void intToString(unsigned char *out_state)
{
	int i=0;
	for (i = 0; i < 8; i++)
	{
		out_state[i * 4] = (unsigned char)((state[i] >> 24) & 0xFF);
		out_state[i * 4 + 1] = (unsigned char)((state[i] >> 16) & 0xFF);
		out_state[i * 4 + 2] = (unsigned char)((state[i] >> 8) & 0xFF);
		out_state[i * 4 + 3] = (unsigned char)((state[i]) & 0xFF);
	}
	for (i = 0; i < 32; i++)
	printf("%c", out_state[i]);
	printf("\n");

}*/
static uint32_t load_bigendian_32(const uint8_t *x) {
    return (uint32_t)(x[3]) | (((uint32_t)(x[2])) << 8) |
           (((uint32_t)(x[1])) << 16) | (((uint32_t)(x[0])) << 24);
}

static uint64_t load_bigendian_64(const uint8_t *x) {
    return (uint64_t)(x[7]) | (((uint64_t)(x[6])) << 8) |
           (((uint64_t)(x[5])) << 16) | (((uint64_t)(x[4])) << 24) |
           (((uint64_t)(x[3])) << 32) | (((uint64_t)(x[2])) << 40) |
           (((uint64_t)(x[1])) << 48) | (((uint64_t)(x[0])) << 56);
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

int crypto_stateblocks_sm3_256(uint8_t *statebytes,
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
	return 1;
}


static const uint8_t iv_256[32] = {
    0x73, 0x80, 0x16, 0x6F, 0x49, 0x14, 0xB2, 0xB9,
    0x17, 0x24, 0x42, 0xD7, 0xDA, 0x8A, 0x06, 0x00,
    0xA9, 0x6F, 0x30, 0xBC, 0x16, 0x31, 0x38, 0xAA,
    0xE3, 0x8D, 0xEE, 0x4D, 0xB0, 0xFB, 0x0E, 0x4E
};


void sm3_256_inc_init(uint8_t *state) {//0和iv_256先后？
   	init_T();

    for (size_t i = 0; i < 32; ++i) {
        state[i] = iv_256[i];
    }
        for(int i=0; i<32; i++)
	{
		printf("%02x",state[i]);
		if (((i+1) % 4 ) == 0) printf(" ");
	} 
	printf("\n");
}

void sm3_256_inc_finalize(uint8_t *out, uint8_t *state, const uint8_t *in, size_t inlen){
    int i;
    int left = 0;
    unsigned long long total = 0;
        
    for(i = 0; i < inlen/64; i++){
        memcpy(buffer, in + i * 64, 64);
        crypto_stateblocks_sm3_256(state, buffer );
    }

    total = inlen * 8;
    left = inlen%64;

    memset(&buffer[left], 0, 64 - left);    
    memcpy(buffer, in + i * 64, left);
    buffer[left] = 0x80;
    if(left <= 55){
        for (i = 0; i < 8; i++)
            buffer[56 + i] = (total >> ((8 - 1 - i) * 8)) & 0xFF;
        crypto_stateblocks_sm3_256( state, buffer );
    }else{
        crypto_stateblocks_sm3_256( state, buffer );
        memset(buffer, 0, 64);
        for (i = 0; i < 8; i++)
            buffer[56 + i] = (total >> ((8 - 1 - i) * 8)) & 0xFF;
        crypto_stateblocks_sm3_256( state, buffer );
    }

}

void sm3_256(uint8_t *out, const uint8_t *in, size_t inlen) 
{
	uint8_t state[32];

    sm3_256_inc_init(state);
	//Block(in,inlen);
	//out_hex();
	//intToString(out_state);
	//sha256_inc_init(state);
    sm3_256_inc_finalize(out, state, in, inlen);
    out_hex();
	//return 1;
}

