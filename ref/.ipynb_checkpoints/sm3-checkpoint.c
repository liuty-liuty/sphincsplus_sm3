/*
 * SM3 Hash alogrith 
 * thanks to Xyssl
 * author:goldboar
 * email:goldboar@163.com
 * 2011-10-26
 */

//Testing data from SM3 Standards
//http://www.oscca.gov.cn/News/201012/News_1199.htm 
// Sample 1
// Input:"abc"  
// Output:66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0

// Sample 2 
// Input:"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
// Outpuf:debe9ff9 2275b8a1 38604889 c18e5a4d 6fdb70e5 387e5765 293dcba3 9c0c5732



#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "utils.h"
#include "sm3.h"
/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n,b,i)                             \
{                                                       \
    (n) = ( (unsigned long) (b)[(i)    ] << 24 )        \
        | ( (unsigned long) (b)[(i) + 1] << 16 )        \
        | ( (unsigned long) (b)[(i) + 2] <<  8 )        \
        | ( (unsigned long) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                             \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

/*
 * SM3 context setup
 */
void sm3_starts( sm3_context *cx )
{
    cx->total[0] = 0;
    cx->total[1] = 0;

    cx->state[0] = 0x7380166F;
    cx->state[1] = 0x4914B2B9;
    cx->state[2] = 0x172442D7;
    cx->state[3] = 0xDA8A0600;
    cx->state[4] = 0xA96F30BC;
    cx->state[5] = 0x163138AA;
    cx->state[6] = 0xE38DEE4D;
    cx->state[7] = 0xB0FB0E4E;

}

static void sm3_process( sm3_context *cx, unsigned char data[64] )
{
    unsigned long SS1, SS2, TT1, TT2, W[68],W1[64];
    unsigned long A, B, C, D, E, F, G, H;
	unsigned long T[64];
	unsigned long Temp1,Temp2,Temp3,Temp4,Temp5;
	int j;
#ifdef _DEBUG
	int i;
#endif

// 	for(j=0; j < 68; j++)
// 		W[j] = 0;
// 	for(j=0; j < 64; j++)
// 		W1[j] = 0;
	
	for(j = 0; j < 16; j++)
		T[j] = 0x79CC4519;
	for(j =16; j < 64; j++)
		T[j] = 0x7A879D8A;

    GET_ULONG_BE( W[ 0], data,  0 );
    GET_ULONG_BE( W[ 1], data,  4 );
    GET_ULONG_BE( W[ 2], data,  8 );
    GET_ULONG_BE( W[ 3], data, 12 );
    GET_ULONG_BE( W[ 4], data, 16 );
    GET_ULONG_BE( W[ 5], data, 20 );
    GET_ULONG_BE( W[ 6], data, 24 );
    GET_ULONG_BE( W[ 7], data, 28 );
    GET_ULONG_BE( W[ 8], data, 32 );
    GET_ULONG_BE( W[ 9], data, 36 );
    GET_ULONG_BE( W[10], data, 40 );
    GET_ULONG_BE( W[11], data, 44 );
    GET_ULONG_BE( W[12], data, 48 );
    GET_ULONG_BE( W[13], data, 52 );
    GET_ULONG_BE( W[14], data, 56 );
    GET_ULONG_BE( W[15], data, 60 );

#ifdef _DEBUG 
	printf("Message with padding:\n");
	for(i=0; i< 8; i++)
		printf("%08x ",W[i]);
	printf("\n");
	for(i=8; i< 16; i++)
		printf("%08x ",W[i]);
	printf("\n");
#endif

#define FF0(x,y,z) ( (x) ^ (y) ^ (z)) 
#define FF1(x,y,z) (((x) & (y)) | ( (x) & (z)) | ( (y) & (z)))

#define GG0(x,y,z) ( (x) ^ (y) ^ (z)) 
#define GG1(x,y,z) (((x) & (y)) | ( (~(x)) & (z)) )


#define  SHL(x,n) (((x) & 0xFFFFFFFF) << n)
#define ROTL(x,n) (SHL((x),n) | ((x) >> (32 - n)))

#define P0(x) ((x) ^  ROTL((x),9) ^ ROTL((x),17)) 
#define P1(x) ((x) ^  ROTL((x),15) ^ ROTL((x),23)) 

	for(j = 16; j < 68; j++ )
	{
		//W[j] = P1( W[j-16] ^ W[j-9] ^ ROTL(W[j-3],15)) ^ ROTL(W[j - 13],7 ) ^ W[j-6];
		//Why thd release's result is different with the debug's ?
		//Below is okay. Interesting, Perhaps VC6 has a bug of Optimizaiton.
		
		Temp1 = W[j-16] ^ W[j-9];
		Temp2 = ROTL(W[j-3],15);
		Temp3 = Temp1 ^ Temp2;
		Temp4 = P1(Temp3);
		Temp5 =  ROTL(W[j - 13],7 ) ^ W[j-6];
		W[j] = Temp4 ^ Temp5;
	}

#ifdef _DEBUG 
	printf("Expanding message W0-67:\n");
	for(i=0; i<68; i++)
	{
		printf("%08x ",W[i]);
		if(((i+1) % 8) == 0) printf("\n");
	}
	printf("\n");
#endif

	for(j =  0; j < 64; j++)
	{
        W1[j] = W[j] ^ W[j+4];
	}

#ifdef _DEBUG 
	printf("Expanding message W'0-63:\n");
	for(i=0; i<64; i++)
	{
		printf("%08x ",W1[i]);
		if(((i+1) % 8) == 0) printf("\n");
	}
	printf("\n");
#endif

    A = cx->state[0];
    B = cx->state[1];
    C = cx->state[2];
    D = cx->state[3];
    E = cx->state[4];
    F = cx->state[5];
    G = cx->state[6];
    H = cx->state[7];
#ifdef _DEBUG       
	printf("j     A       B        C         D         E        F        G       H\n");
	printf("   %08x %08x %08x %08x %08x %08x %08x %08x\n",A,B,C,D,E,F,G,H);
#endif

	for(j =0; j < 16; j++)
	{
		SS1 = ROTL((ROTL(A,12) + E + ROTL(T[j],j)), 7); 
		SS2 = SS1 ^ ROTL(A,12);
		TT1 = FF0(A,B,C) + D + SS2 + W1[j];
		TT2 = GG0(E,F,G) + H + SS1 + W[j];
		D = C;
		C = ROTL(B,9);
		B = A;
		A = TT1;
		H = G;
		G = ROTL(F,19);
		F = E;
		E = P0(TT2);
#ifdef _DEBUG 
		printf("%02d %08x %08x %08x %08x %08x %08x %08x %08x\n",j,A,B,C,D,E,F,G,H);
#endif
	}
	
	for(j =16; j < 64; j++)
	{
		SS1 = ROTL((ROTL(A,12) + E + ROTL(T[j],j)), 7); 
		SS2 = SS1 ^ ROTL(A,12);
		TT1 = FF1(A,B,C) + D + SS2 + W1[j];
		TT2 = GG1(E,F,G) + H + SS1 + W[j];
		D = C;
		C = ROTL(B,9);
		B = A;
		A = TT1;
		H = G;
		G = ROTL(F,19);
		F = E;
		E = P0(TT2);
#ifdef _DEBUG 
		printf("%02d %08x %08x %08x %08x %08x %08x %08x %08x\n",j,A,B,C,D,E,F,G,H);
#endif	
	}

    cx->state[0] ^= A;
    cx->state[1] ^= B;
    cx->state[2] ^= C;
    cx->state[3] ^= D;
    cx->state[4] ^= E;
    cx->state[5] ^= F;
    cx->state[6] ^= G;
    cx->state[7] ^= H;
#ifdef _DEBUG 
	   printf("   %08x %08x %08x %08x %08x %08x %08x %08x\n",cx->state[0],cx->state[1],cx->state[2],
		                          cx->state[3],cx->state[4],cx->state[5],cx->state[6],cx->state[7]);
#endif
}

/*
 * SM3 process buffer
 */
void sm3_update( sm3_context *cx, unsigned char *input, int ilen )
{
    int fill;
    unsigned long left;

    if( ilen <= 0 )
        return;
    //printf("OOOO");
    left = cx->total[0] & 0x3F;
    fill = 64 - left;

    cx->total[0] += ilen;
    cx->total[0] &= 0xFFFFFFFF;

    if( cx->total[0] < (unsigned long) ilen )
        cx->total[1]++;

    if( left && ilen >= fill )
    {
        memcpy( (void *) (cx->buffer + left),
                (void *) input, fill );
        sm3_process( cx, cx->buffer );
        input += fill;
        ilen  -= fill;
        left = 0;
    }

    while( ilen >= 64 )
    {
        sm3_process( cx, input );
        input += 64;
        ilen  -= 64;
    }

    if( ilen > 0 )
    {
        memcpy( (void *) (cx->buffer + left),
                (void *) input, ilen );
    }
}

static const unsigned char sm3_padding[64] =
{
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * SM3 final digest
 */
void sm3_finish( sm3_context *cx, uint8_t *output )//unsigned char output[32] )
{
    unsigned long last, padn;
    unsigned long high, low;
    unsigned char msglen[8];
    //printf("OOOO");
    high = ( cx->total[0] >> 29 )
         | ( cx->total[1] <<  3 );
    low  = ( cx->total[0] <<  3 );

    PUT_ULONG_BE( high, msglen, 0 );
    PUT_ULONG_BE( low,  msglen, 4 );

    last = cx->total[0] & 0x3F;
    padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

    sm3_update( cx, (unsigned char *) sm3_padding, padn );
    sm3_update( cx, msglen, 8 );

    PUT_ULONG_BE( cx->state[0], output,  0 );
    PUT_ULONG_BE( cx->state[1], output,  4 );
    PUT_ULONG_BE( cx->state[2], output,  8 );
    PUT_ULONG_BE( cx->state[3], output, 12 );
    PUT_ULONG_BE( cx->state[4], output, 16 );
    PUT_ULONG_BE( cx->state[5], output, 20 );
    PUT_ULONG_BE( cx->state[6], output, 24 );
    PUT_ULONG_BE( cx->state[7], output, 28 );
    
}

/*
 * output = SM3( input buffer )
 */
void sm3( unsigned char *input, int ilen,
           unsigned char output[64] )
{
    sm3_context cx;

    sm3_starts( &cx );
    sm3_update( &cx, input, ilen );
    sm3_finish( &cx, output );

    memset( &cx, 0, sizeof( sm3_context ) );
}

/*
 * output = SM3( file contents )
 */
int sm3_file( char *path, unsigned char output[32] )
{
    FILE *f;
    size_t n;
    sm3_context cx;
    unsigned char buf[1024];

    if( ( f = fopen( path, "rb" ) ) == NULL )
        return( 1 );

    sm3_starts( &cx );

    while( ( n = fread( buf, 1, sizeof( buf ), f ) ) > 0 )
        sm3_update( &cx, buf, (int) n );

    sm3_finish( &cx, output );

    memset( &cx, 0, sizeof( sm3_context ) );

    if( ferror( f ) != 0 )
    {
        fclose( f );
        return( 2 );
    }

    fclose( f );
    return( 0 );
}

/*
 * SM3 HMAC context setup
 */
void sm3_hmac_starts( sm3_context *cx, unsigned char *key, int keylen )
{
    int i;
    unsigned char sum[32];

    if( keylen > 64 )
    {
        sm3( key, keylen, sum );
        keylen = 32;
		//keylen = ( is224 ) ? 28 : 32;
        key = sum;
    }

    memset( cx->ipad, 0x36, 64 );
    memset( cx->opad, 0x5C, 64 );

    for( i = 0; i < keylen; i++ )
    {
        cx->ipad[i] = (unsigned char)( cx->ipad[i] ^ key[i] );
        cx->opad[i] = (unsigned char)( cx->opad[i] ^ key[i] );
    }

    sm3_starts( cx);
    sm3_update( cx, cx->ipad, 64 );

    memset( sum, 0, sizeof( sum ) );
}

/*
 * SM3 HMAC process buffer
 */
void sm3_hmac_update( sm3_context *cx, unsigned char *input, int ilen )
{
    sm3_update( cx, input, ilen );
}

/*
 * SM3 HMAC final digest
 */
void sm3_hmac_finish( sm3_context *cx, unsigned char output[32] )
{
    int hlen;
    unsigned char tmpbuf[32];

    //is224 = cx->is224;
    hlen =  32;

    sm3_finish( cx, tmpbuf );
    sm3_starts( cx );
    sm3_update( cx, cx->opad, 64 );
    sm3_update( cx, tmpbuf, hlen );
    sm3_finish( cx, output );

    memset( tmpbuf, 0, sizeof( tmpbuf ) );
}

/*
 * output = HMAC-SM#( hmac key, input buffer )
 */
void sm3_hmac( unsigned char *key, int keylen,
                unsigned char *input, int ilen,
                unsigned char output[32] )
{
    sm3_context cx;

    sm3_hmac_starts( &cx, key, keylen);
    sm3_hmac_update( &cx, input, ilen );
    sm3_hmac_finish( &cx, output );

    memset( &cx, 0, sizeof( sm3_context ) );
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

    /* While we can fit in at least another full block of sm3 output.. */
    for (i = 0; (i+1)*SPX_SM3_256_OUTPUT_BYTES <= outlen; i++) {
        u32_to_bytes(inbuf + inlen, i);
        sm3(out, inbuf, inlen + 4);
        out += SPX_SM3_256_OUTPUT_BYTES;
    }
    /* Until we cannot anymore, and we fill the remainder. */
    if (outlen > i*SPX_SM3_256_OUTPUT_BYTES) {
        u32_to_bytes(inbuf + inlen, i);
        sm3(outbuf, inbuf, inlen + 4);
        memcpy(out, outbuf, outlen - i*SPX_SM3_256_OUTPUT_BYTES);
    }
}




/**
 * Absorb the constant pub_seed using one round of the compression function
 * This initializes state_seeded and state_seeded_512, which can then be
 * reused in thash
 **/
void seed_state( spx_ctx *ctx) {
    uint8_t block[SPX_SM3_256_BLOCK_BYTES];
    size_t i;

    for (i = 0; i < SPX_N; ++i) {
        block[i] = ctx->pub_seed[i];
    }
    for (i = SPX_N; i < SPX_SM3_256_BLOCK_BYTES; ++i) {
        block[i] = 0;
    }
    /* block has been properly initialized for both SM3-256 and SM3-512 */

    sm3_starts(ctx->state_seeded);
    sm3_update(ctx->state_seeded, block, 1*SPX_SM3_256_BLOCK_BYTES);
//#if SPX_SM3_512
    //sm3_512_inc_init(ctx->state_seeded_512);
    //sm3_512_inc_blocks(ctx->state_seeded_512, block, 1SPX_SM3_256_BLOCK_BYTES);
//#endif
}


