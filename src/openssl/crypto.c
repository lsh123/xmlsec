/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/transforms.h>
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
		    NULL,
		    "xmlSecOpenSSLErrorsInit",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if(xmlSecOpenSSLKeysInit() < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecOpenSSLKeysInit",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if(xmlSecOpenSSLTransformsInit() < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecOpenSSLTransformsInit",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
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
    /* nothing to do */
    return(0);
}

/**
 * xmlSecOpenSSLKeysMngrInit:
 * @mngr:		the pointer to keys manager.
 *
 * Adds OpenSSL specific key data stores in keys manager.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecOpenSSLKeysMngrInit(xmlSecKeysMngrPtr mngr) {
    int ret;
    
    xmlSecAssert2(mngr != NULL, -1);

#ifndef XMLSEC_NO_X509
    /* create x509 store if needed */
    if(xmlSecKeysMngrGetDataStore(mngr, xmlSecOpenSSLX509StoreId) == NULL) {
	xmlSecKeyDataStorePtr x509Store;

        x509Store = xmlSecKeyDataStoreCreate(xmlSecOpenSSLX509StoreId);
	if(x509Store == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecKeyDataStoreCreate",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLX509StoreId");
	    return(-1);   
	}
    
        ret = xmlSecKeysMngrAdoptDataStore(mngr, x509Store);
        if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecKeysMngrAdoptDataStore",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    xmlSecKeyDataStoreDestroy(x509Store);
	    return(-1); 
	}
    }
#endif /* XMLSEC_NO_X509 */    
    return(0);
}

/**
 * xmlSecOpenSSLGenerateRandom:
 * @buffer:		the destination buffer.
 * @size:		the numer of bytes to generate.
 *
 * Generates @size random bytes and puts result in @buffer.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecOpenSSLGenerateRandom(xmlSecBufferPtr buffer, xmlSecSize size) {	
    int ret;
    
    xmlSecAssert2(buffer != NULL, -1);
    xmlSecAssert2(size > 0, -1);

    ret = xmlSecBufferSetSize(buffer, size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    "xmlSecBufferSetSize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", size);
	return(-1);
    }
        
    /* get random data */
    ret = RAND_bytes((xmlSecByte*)xmlSecBufferGetData(buffer), size);
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    "RAND_bytes",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "size=%d", size);
	return(-1);    
    }	
    return(0);
}

/**
 * xmlSecOpenSSLErrorsDefaultCallback:
 * @file:		the error location file name (__FILE__ macro).
 * @line:		the error location line number (__LINE__ macro).
 * @func:		the error location function name (__FUNCTION__ macro).
 * @errorObject:	the error specific error object 
 * @errorSubject:	the error specific error subject.
 * @reason:		the error code.
 * @msg:		the additional error message.
 *
 * The default OpenSSL errors reporting callback function.
 */
void 
xmlSecOpenSSLErrorsDefaultCallback(const char* file, int line, const char* func,
				const char* errorObject, const char* errorSubject,
				int reason, const char* msg) {

    ERR_put_error(XMLSEC_OPENSSL_ERRORS_LIB, 
		XMLSEC_OPENSSL_ERRORS_FUNCTION, 
		reason, file, line);
    xmlSecErrorsDefaultCallback(file, line, func, 
		errorObject, errorSubject, 
		reason, msg);
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
    xmlSecSize pos;

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
#ifndef XMLSEC_OPENSSL_096
    if(xmlSecKeyDataIdsRegister(xmlSecOpenSSLKeyDataAesId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(xmlSecOpenSSLKeyDataAesId)),
		    "xmlSecKeyDataIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_OPENSSL_096 */    
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_DES    
    if(xmlSecKeyDataIdsRegister(xmlSecOpenSSLKeyDataDesId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(xmlSecOpenSSLKeyDataDesId)),
		    "xmlSecKeyDataIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_DSA
    if(xmlSecKeyDataIdsRegister(xmlSecOpenSSLKeyDataDsaId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(xmlSecOpenSSLKeyDataDsaId)),
		    "xmlSecKeyDataIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_DSA */    

#ifndef XMLSEC_NO_HMAC  
    if(xmlSecKeyDataIdsRegister(xmlSecOpenSSLKeyDataHmacId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(xmlSecOpenSSLKeyDataHmacId)),
		    "xmlSecKeyDataIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_HMAC */    

#ifndef XMLSEC_NO_RSA
    if(xmlSecKeyDataIdsRegister(xmlSecOpenSSLKeyDataRsaId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(xmlSecOpenSSLKeyDataRsaId)),
		    "xmlSecKeyDataIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_X509
    if(xmlSecKeyDataIdsRegister(xmlSecOpenSSLKeyDataX509Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(xmlSecOpenSSLKeyDataX509Id)),
		    "xmlSecKeyDataIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    if(xmlSecKeyDataIdsRegister(xmlSecOpenSSLKeyDataRawX509CertId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(xmlSecOpenSSLKeyDataRawX509CertId)),
		    "xmlSecKeyDataIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_X509 */

    return(0);
}

static int 
xmlSecOpenSSLTransformsInit(void) {
#ifndef XMLSEC_NO_SHA1    
    if(xmlSecTransformIdsRegister(xmlSecOpenSSLTransformSha1Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecOpenSSLTransformSha1Id)),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_RIPEMD160
    if(xmlSecTransformIdsRegister(xmlSecOpenSSLTransformRipemd160Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecOpenSSLTransformRipemd160Id)),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_RIPEMD160 */

#ifndef XMLSEC_NO_HMAC
    if(xmlSecTransformIdsRegister(xmlSecOpenSSLTransformHmacSha1Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecOpenSSLTransformHmacSha1Id)),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if(xmlSecTransformIdsRegister(xmlSecOpenSSLTransformHmacRipemd160Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecOpenSSLTransformHmacRipemd160Id)),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if(xmlSecTransformIdsRegister(xmlSecOpenSSLTransformHmacMd5Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecOpenSSLTransformHmacMd5Id)),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_HMAC */

#ifndef XMLSEC_NO_DSA
    if(xmlSecTransformIdsRegister(xmlSecOpenSSLTransformDsaSha1Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecOpenSSLTransformDsaSha1Id)),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_DSA */    

#ifndef XMLSEC_NO_RSA
    if(xmlSecTransformIdsRegister(xmlSecOpenSSLTransformRsaSha1Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecOpenSSLTransformRsaSha1Id)),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if(xmlSecTransformIdsRegister(xmlSecOpenSSLTransformRsaPkcs1Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecOpenSSLTransformRsaPkcs1Id)),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if(xmlSecTransformIdsRegister(xmlSecOpenSSLTransformRsaOaepId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecOpenSSLTransformRsaOaepId)),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_RSA */
    
#ifndef XMLSEC_NO_DES    
    if(xmlSecTransformIdsRegister(xmlSecOpenSSLTransformDes3CbcId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecOpenSSLTransformDes3CbcId)),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if(xmlSecTransformIdsRegister(xmlSecOpenSSLTransformKWDes3Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecOpenSSLTransformKWDes3Id)),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_AES    
#ifndef XMLSEC_OPENSSL_096
    if(xmlSecTransformIdsRegister(xmlSecOpenSSLTransformAes128CbcId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecOpenSSLTransformAes128CbcId)),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if(xmlSecTransformIdsRegister(xmlSecOpenSSLTransformAes192CbcId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecOpenSSLTransformAes192CbcId)),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if(xmlSecTransformIdsRegister(xmlSecOpenSSLTransformAes256CbcId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecOpenSSLTransformAes256CbcId)),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    if(xmlSecTransformIdsRegister(xmlSecOpenSSLTransformKWAes128Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecOpenSSLTransformKWAes128Id)),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if(xmlSecTransformIdsRegister(xmlSecOpenSSLTransformKWAes192Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecOpenSSLTransformKWAes192Id)),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if(xmlSecTransformIdsRegister(xmlSecOpenSSLTransformKWAes256Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecOpenSSLTransformKWAes256Id)),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_OPENSSL_096 */    
#endif /* XMLSEC_NO_AES */

    return(0);
}
