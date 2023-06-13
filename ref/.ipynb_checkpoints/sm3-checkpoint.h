#ifndef SPX_SM3_H
#define SPX_SM3_H

#include "params.h"

#define SPX_SM3_256_BLOCK_BYTES 64
#define SPX_SM3_256_OUTPUT_BYTES 32  /* This does not necessarily equal SPX_N */

//#define SPX_SM3_512_BLOCK_BYTES 128
//#define SPX_SM3_512_OUTPUT_BYTES 64

#if SPX_SM3_256_OUTPUT_BYTES < SPX_N
    #error Linking against SM3-256 with N larger than 32 bytes is not supported
#endif

#define SPX_SM3_256_ADDR_BYTES 22
#include <stddef.h>
#include <stdint.h>

/**
 * \brief          SM3 context structure
 */
typedef struct
{
    unsigned long total[2];     /*!< number of bytes processed  */
    unsigned long state[8];     /*!< intermediate digest state  */
    unsigned char buffer[64];   /*!< data block being processed */

    unsigned char ipad[64];     /*!< HMAC: inner padding        */
    unsigned char opad[64];     /*!< HMAC: outer padding        */

}
sm3_context;

//#ifdef __cplusplus
//extern "C" {
//#endif

/**
 * \brief          SM3 context setup
 *
 * \param cx      context to be initialized
 */
void sm3_starts( sm3_context *cx );

/**
 * \brief          SM3 process buffer
 *
 * \param cx      SM3 context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void sm3_update( sm3_context *cx, unsigned char *input, int ilen );

/**
 * \brief          SM3 final digest
 *
 * \param cx      SM3 context
 */
void sm3_finish( sm3_context *cx, uint8_t *output);//unsigned char output[64] );

/**
 * \brief          Output = SM3( input buffer )
 *
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   SM3 checksum result
 */
void sm3( unsigned char *input, int ilen,
           unsigned char output[32]);

/**
 * \brief          Output = SM3( file contents )
 *
 * \param path     input file name
 * \param output   SM3 checksum result
 *
 * \return         0 if successful, 1 if fopen failed,
 *                 or 2 if fread failed
 */
int sm3_file( char *path, unsigned char output[32] );

/**
 * \brief          SM3 HMAC context setup
 *
 * \param cx      HMAC context to be initialized
 * \param key      HMAC secret key
 * \param keylen   length of the HMAC key
 */
void sm3_hmac_starts( sm3_context *cx, unsigned char *key, int keylen);

/**
 * \brief          SM3 HMAC process buffer
 *
 * \param cx      HMAC context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void sm3_hmac_update( sm3_context *cx, unsigned char *input, int ilen );

/**
 * \brief          SM3 HMAC final digest
 *
 * \param cx      HMAC context
 * \param output   SM3 HMAC checksum result
 */
void sm3_hmac_finish( sm3_context *cx, unsigned char output[32] );

/**
 * \brief          Output = HMAC-SM3( hmac key, input buffer )
 *
 * \param key      HMAC secret key
 * \param keylen   length of the HMAC key
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   HMAC-SM3 result
 */
void sm3_hmac( unsigned char *key, int keylen,
                unsigned char *input, int ilen,
                unsigned char output[32] );

#define mgf1_256 SPX_NAMESPACE(mgf1_256)
void mgf1_256(unsigned char *out, unsigned long outlen,
          const unsigned char *in, unsigned long inlen);

#define mgf1_512 SPX_NAMESPACE(mgf1_512)
void mgf1_512(unsigned char *out, unsigned long outlen,
          const unsigned char *in, unsigned long inlen);

#define seed_state SPX_NAMESPACE(seed_state)
void seed_state(spx_ctx *ctx);


//#ifdef __cplusplus
//}
//#endif

#endif /* sm3.h */
/**
 * \file sm3.h
 * thanks to Xyssl
 * SM3 standards:http://www.oscca.gov.cn/News/201012/News_1199.htm
 * author:goldboar
 * email:goldboar@163.com
 * 2011-10-26
 */