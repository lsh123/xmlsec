/** 
 * XMLSec library
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/x509.h>

static int		xmlSecOpenSSLKeysInit			(void);
static int		xmlSecOpenSSLTransformsInit		(void);

/**
 * xmlSecOpenSSLInit:
 * 
 * XMLSec library specific crypto engine initialization. 
 *
 * Returns 0 on success or a negative value otherwise.
 */
int 
xmlSecOpenSSLInit (void)  {
    if(xmlSecOpenSSLKeysInit() < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register keys");
	return(-1);
    }
    if(xmlSecOpenSSLTransformsInit() < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register transforms");
	return(-1);
    }
    
    return(0);
}

/**
 * xmlSecOpenSSLShutdown:
 * 
 * XMLSec library specific crypto engine shutdown. 
 *
 * Returns 0 on success or a negative value otherwise.
 */
int 
xmlSecOpenSSLShutdown(void) {

    return(0);
}

int
xmlSecOpenSSLGenerateRandom(xmlBufferPtr buffer, size_t size) {	
    int ret;
    
    xmlSecAssert2(buffer != NULL, -1);
    xmlSecAssert2(size > 0, -1);

    /* clean up it just in case */
    xmlBufferEmpty(buffer);
    
    ret = xmlBufferResize(buffer, size);
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "xmlBufferResize");
	return(-1);
    }
        
    /* get random data */
    ret = RAND_bytes((unsigned char*)xmlBufferContent(buffer), size);
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "RAND_bytes");
	return(-1);    
    }	
    
    buffer->use = size;    
    return(0);
}

static int		
xmlSecOpenSSLKeysInit(void) {

#ifndef XMLSEC_NO_AES    
    if(xmlSecKeyDataIdsRegister(xmlSecKeyDataAesValueId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register aes key");
	return(-1);
    }
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_DES    
    if(xmlSecKeyDataIdsRegister(xmlSecKeyDataDesValueId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register des key");
	return(-1);
    }
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_DSA
    if(xmlSecKeyDataIdsRegister(xmlSecKeyDataDsaValueId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register dsa key");
	return(-1);
    }
#endif /* XMLSEC_NO_DSA */    

#ifndef XMLSEC_NO_HMAC  
    if(xmlSecKeyDataIdsRegister(xmlSecKeyDataHmacValueId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register hmac key");
	return(-1);
    }
#endif /* XMLSEC_NO_HMAC */    

#ifndef XMLSEC_NO_RSA
    if(xmlSecKeyDataIdsRegister(xmlSecKeyDataRsaValueId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register rsa key");
	return(-1);
    }
#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_X509
    if(xmlSecKeyDataIdsRegister(xmlSecKeyDataX509Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register x509 data");
	return(-1);
    }

    if(xmlSecKeyDataIdsRegister(xmlSecKeyDataRawX509CertId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register x509 data");
	return(-1);
    }
#endif /* XMLSEC_NO_X509 */

    return(0);
}

static int 
xmlSecOpenSSLTransformsInit(void) {
    /* digest methods */
#ifndef XMLSEC_NO_SHA1    
    if(xmlSecTransformRegister(xmlSecDigestSha1) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register sha1 digest transform");
	return(-1);
    }
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_RIPEMD160
    if(xmlSecTransformRegister(xmlSecDigestRipemd160) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register ripemd160 digest transform");
	return(-1);
    }
#endif /* XMLSEC_NO_RIPEMD160 */

    /* MAC */ 
#ifndef XMLSEC_NO_HMAC
    if(xmlSecTransformRegister(xmlSecMacHmacSha1) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register hmac sha1 transform");
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecMacHmacRipeMd160) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register hamc ripemd160 transform");
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecMacHmacMd5) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register hmac md5 transform");
	return(-1);
    }
#endif /* XMLSEC_NO_HMAC */

    /* signature */ 
#ifndef XMLSEC_NO_DSA
    if(xmlSecTransformRegister(xmlSecSignDsaSha1) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register dsa/sha1 transform");
	return(-1);
    }
#endif /* XMLSEC_NO_DSA */    

#ifndef XMLSEC_NO_RSA
    if(xmlSecTransformRegister(xmlSecSignRsaSha1) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register rsa/sha1 transform");
	return(-1);
    }
#endif /* XMLSEC_NO_RSA */
    

    /* encryption */
#ifndef XMLSEC_NO_DES    
    if(xmlSecTransformRegister(xmlSecEncDes3Cbc) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register des encryption transform");
	return(-1);
    }
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_AES    
    if(xmlSecTransformRegister(xmlSecEncAes128Cbc) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register aes128 encryption transform");
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecEncAes192Cbc) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register aes192 encryption transform");
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecEncAes256Cbc) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register aes256 encryption transform");
	return(-1);
    }
#endif /* XMLSEC_NO_AES */

    /* Key Transports */
#ifndef XMLSEC_NO_RSA
    if(xmlSecTransformRegister(xmlSecEncRsaPkcs1) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register rsa/pkcs1 transform");
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecEncRsaOaep) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register rsa/oaep transform");
	return(-1);
    }
#endif /* XMLSEC_NO_RSA */

    /* key wrappers */
#ifndef XMLSEC_NO_AES   
    if(xmlSecTransformRegister(xmlSecKWDes3Cbc) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register des key wrapper transform");
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecKWAes128) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register aes128 key wrapper transform");
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecKWAes192) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register aes192 key wrapper transform");
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecKWAes256) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register aes256 key wrapper transform");
	return(-1);
    }
#endif /* XMLSEC_NO_AES */
    
    return(0);
}


