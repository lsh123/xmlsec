/** 
 * XMLSec library
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/x509.h>

static int 		xmlSecOpenSSLErrorsInit			(void);
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
    if(xmlSecOpenSSLErrorsInit() < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to initiaze errors");
	return(-1);
    }
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
xmlSecOpenSSLGenerateRandom(xmlSecBufferPtr buffer, size_t size) {	
    int ret;
    
    xmlSecAssert2(buffer != NULL, -1);
    xmlSecAssert2(size > 0, -1);

    ret = xmlSecBufferSetSize(buffer, size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "xmlSecBufferSetSize`");
	return(-1);
    }
        
    /* get random data */
    ret = RAND_bytes((unsigned char*)xmlSecBufferGetData(buffer), size);
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "RAND_bytes");
	return(-1);    
    }	
    return(0);
}

void 
xmlSecOpenSSLErrorsDefaultCallback(const char* file, int line, const char* func,
				int reason, const char* msg) {

    ERR_put_error(XMLSEC_OPENSSL_ERRORS_LIB, XMLSEC_OPENSSL_ERRORS_FUNCTION, 
		  reason, file, line);
    xmlSecErrorsDefaultCallback(file, line, func, reason, msg);
}

static int 
xmlSecOpenSSLErrorsInit(void) {
    static ERR_STRING_DATA xmlSecOpenSSLStrReasons[XMLSEC_ERRORS_MAX_NUMBER + 1];
    static ERR_STRING_DATA xmlSecOpenSSLStrLib[]= {
	{ ERR_PACK(XMLSEC_OPENSSL_ERRORS_LIB,0,0),	"xmlsec routines"},
	{ 0,     					NULL}
    }; 
    static ERR_STRING_DATA xmlSecOpenSSLStrDefReason[]= {
	{ XMLSEC_OPENSSL_ERRORS_LIB,			"xmlsec lib"},
        { 0,						NULL}
    };
    size_t pos;

    /* initialize reasons array */
    memset(xmlSecOpenSSLStrReasons, 0, sizeof(xmlSecOpenSSLStrReasons));
    for(pos = 0; (pos < XMLSEC_ERRORS_MAX_NUMBER) && (xmlSecErrorsGetMsg(pos) != NULL); ++pos) {
	xmlSecOpenSSLStrReasons[pos].error  = xmlSecErrorsGetCode(pos);
	xmlSecOpenSSLStrReasons[pos].string = xmlSecErrorsGetMsg(pos);
    }
    
    /* finally load xmlsec strings in OpenSSL */
    ERR_load_strings(XMLSEC_OPENSSL_ERRORS_LIB, xmlSecOpenSSLStrLib); /* define xmlsec lib name */
    ERR_load_strings(XMLSEC_OPENSSL_ERRORS_LIB, xmlSecOpenSSLStrDefReason); /* define default reason */
    ERR_load_strings(XMLSEC_OPENSSL_ERRORS_LIB, xmlSecOpenSSLStrReasons);     
    
    /* and set default errors callback for xmlsec to us */
    xmlSecErrorsSetCallback(xmlSecOpenSSLErrorsDefaultCallback);
    
    return(0);
}

static int		
xmlSecOpenSSLKeysInit(void) {
#ifndef XMLSEC_NO_AES    
    if(xmlSecKeyDataIdsRegister(xmlSecOpenSSLKeyDataAesId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register aes key");
	return(-1);
    }
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_DES    
    if(xmlSecKeyDataIdsRegister(xmlSecOpenSSLKeyDataDesId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register des key");
	return(-1);
    }
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_DSA
    if(xmlSecKeyDataIdsRegister(xmlSecOpenSSLKeyDataDsaId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register dsa key");
	return(-1);
    }
#endif /* XMLSEC_NO_DSA */    

#ifndef XMLSEC_NO_HMAC  
    if(xmlSecKeyDataIdsRegister(xmlSecOpenSSLKeyDataHmacId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register hmac key");
	return(-1);
    }
#endif /* XMLSEC_NO_HMAC */    

#ifndef XMLSEC_NO_RSA
    if(xmlSecKeyDataIdsRegister(xmlSecOpenSSLKeyDataRsaId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register rsa key");
	return(-1);
    }
#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_X509
    if(xmlSecKeyDataIdsRegister(xmlSecOpenSSLKeyDataX509Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register x509 data");
	return(-1);
    }

    if(xmlSecKeyDataIdsRegister(xmlSecOpenSSLKeyDataRawX509CertId) < 0) {
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
#ifndef XMLSEC_NO_SHA1    
    if(xmlSecTransformRegister(xmlSecOpenSSLTransformSha1Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register sha1 digest transform");
	return(-1);
    }
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_RIPEMD160
    if(xmlSecTransformRegister(xmlSecOpenSSLTransformRipemd160Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register ripemd160 digest transform");
	return(-1);
    }
#endif /* XMLSEC_NO_RIPEMD160 */

    /* MAC */ 
#ifndef XMLSEC_NO_HMAC
    if(xmlSecTransformRegister(xmlSecOpenSSLTransformHmacSha1Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register hmac sha1 transform");
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecOpenSSLTransformHmacRipemd160Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register hamc ripemd160 transform");
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecOpenSSLTransformHmacMd5Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register hmac md5 transform");
	return(-1);
    }
#endif /* XMLSEC_NO_HMAC */

#ifndef XMLSEC_NO_DSA
    if(xmlSecTransformRegister(xmlSecOpenSSLTransformDsaSha1Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register dsa/sha1 transform");
	return(-1);
    }
#endif /* XMLSEC_NO_DSA */    

#ifndef XMLSEC_NO_RSA
    if(xmlSecTransformRegister(xmlSecOpenSSLTransformRsaSha1Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register rsa/sha1 transform");
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecOpenSSLTransformRsaPkcs1Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register rsa/pkcs1 transform");
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecOpenSSLTransformRsaOaepId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register rsa/oaep transform");
	return(-1);
    }
#endif /* XMLSEC_NO_RSA */
    
#ifndef XMLSEC_NO_DES    
    if(xmlSecTransformRegister(xmlSecOpenSSLTransformDes3CbcId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register des3-cbc encryption transform");
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecOpenSSLTransformKWDes3Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register des key wrapper transform");
	return(-1);
    }
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_AES    
    if(xmlSecTransformRegister(xmlSecOpenSSLTransformAes128CbcId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register aes128 encryption transform");
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecOpenSSLTransformAes192CbcId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register aes192 encryption transform");
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecOpenSSLTransformAes256CbcId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register aes256 encryption transform");
	return(-1);
    }

    if(xmlSecTransformRegister(xmlSecOpenSSLTransformKWAes128Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register aes128 key wrapper transform");
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecOpenSSLTransformKWAes192Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register aes192 key wrapper transform");
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecOpenSSLTransformKWAes256Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to register aes256 key wrapper transform");
	return(-1);
    }
#endif /* XMLSEC_NO_AES */

    return(0);
}


