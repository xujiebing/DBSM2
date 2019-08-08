/*
 本代码在goldboar提供的版本的基础上进行修改，http://blog.csdn.net/goldboar/article/details/6932274
 包括
 1，参照网上的说法修改shl rotl宏 http://blog.csdn.net/wak0408/article/details/50372386
 2，在iphone6上long是8字节的，实际需要4字节的，导致iphone6s上计算结果不正确，所以把代码中的unsigned long 改成了 uint32_t
 
 mender：swibyn
 email:swibyn@qq.com
 */
/**
 * \file sm3.h
 * thanks to Xyssl
 * SM3 standards:http://www.oscca.gov.cn/News/201012/News_1199.htm
 * author:goldboar
 * email:goldboar@163.com
 * 2011-10-26
 */
#ifndef XYSSL_SM3_H_cc
#define XYSSL_SM3_H_cc


/**
 * \brief          SM3 context structure
 */
typedef struct
{
    uint32_t total[2];     /*!< number of bytes processed  */
    uint32_t state[8];     /*!< intermediate digest state  */
    unsigned char buffer[64];   /*!< data block being processed */
    
    unsigned char ipad[64];     /*!< HMAC: inner padding        */
    unsigned char opad[64];     /*!< HMAC: outer padding        */
    
}
sm3_context_cc;

#ifdef __cplusplus
extern "C" {
#endif
    
    /**
     * \brief          SM3 context setup
     *
     * \param ctx      context to be initialized
     */
    void sm3_starts( sm3_context_cc *ctx );
    
    /**
     * \brief          SM3 process buffer
     *
     * \param ctx      SM3 context
     * \param input    buffer holding the  data
     * \param ilen     length of the input data
     */
    void sm3_update( sm3_context_cc *ctx, unsigned char *input, int ilen );
    
    /**
     * \brief          SM3 final digest
     *
     * \param ctx      SM3 context
     */
    void sm3_finish( sm3_context_cc *ctx, unsigned char output[32] );
    
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
     * \param ctx      HMAC context to be initialized
     * \param key      HMAC secret key
     * \param keylen   length of the HMAC key
     */
    void sm3_hmac_starts( sm3_context_cc *ctx, unsigned char *key, int keylen);
    
    /**
     * \brief          SM3 HMAC process buffer
     *
     * \param ctx      HMAC context
     * \param input    buffer holding the  data
     * \param ilen     length of the input data
     */
    void sm3_hmac_update( sm3_context_cc *ctx, unsigned char *input, int ilen );
    
    /**
     * \brief          SM3 HMAC final digest
     *
     * \param ctx      HMAC context
     * \param output   SM3 HMAC checksum result
     */
    void sm3_hmac_finish( sm3_context_cc *ctx, unsigned char output[32] );
    
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
    
    
#ifdef __cplusplus
}
#endif

#endif /* sm3.h */
