/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2003 Cordys R&D BV, All rights reserved.
 */
#include "globals.h"

#include <string.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/mscrypto/crypto.h>
#include <xmlsec/mscrypto/x509.h>

static int		xmlSecMSCryptoKeysInit			(void);
static int		xmlSecMSCryptoTransformsInit		(void);

/**
 * xmlSecMSCryptoInit:
 * 
 * XMLSec library specific crypto engine initialization. 
 *
 * Returns 0 on success or a negative value otherwise.
 */
int 
xmlSecMSCryptoInit (void)  {
    /* TODO: if necessary do, additional initialization here */
    
    if(xmlSecMSCryptoKeysInit() < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecMSCryptoKeysInit",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if(xmlSecMSCryptoTransformsInit() < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecMSCryptoTransformsInit",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }    
    return(0);
}

/**
 * xmlSecMSCryptoShutdown:
 * 
 * XMLSec library specific crypto engine shutdown. 
 *
 * Returns 0 on success or a negative value otherwise.
 */
int 
xmlSecMSCryptoShutdown(void) {
    /* TODO: if necessary, do additional shutdown here */
    return(0);
}

/**
 * xmlSecMSCryptoKeysMngrInit:
 * @mngr:		the pointer to keys manager.
 *
 * Adds MSCrypto specific key data stores in keys manager.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int 
xmlSecMSCryptoKeysMngrInit(xmlSecKeysMngrPtr mngr) {
    xmlSecAssert2(mngr != NULL, -1);

    /* TODO: add key data stores */
    return(0);
}


/**
 * xmlSecMSCryptoGenerateRandom:
 * @buffer:		the destination buffer.
 * @size:		the numer of bytes to generate.
 *
 * Generates @size random bytes and puts result in @buffer
 * (not implemented yet).
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecMSCryptoGenerateRandom(xmlSecBufferPtr buffer, size_t size) {	
    int ret;
    HCRYPTPROV hProv;
    
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

    if (FALSE == CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "CryptAcquireContext",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "Error number: %d", GetLastError());
	return(-1);
    }
    if (FALSE == CryptGenRandom(hProv, (DWORD)size, xmlSecBufferGetData(buffer))) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "CryptGenRandom",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "Error number: %d", GetLastError());
	return(-1);
    }

    if (0!= hProv) {
	CryptReleaseContext(hProv,0);
    }

    return(0);
}


static int		
xmlSecMSCryptoKeysInit(void) {
    /* TODO: register key data here */
#ifndef XMLSEC_NO_DES    
    if(xmlSecKeyDataIdsRegister(xmlSecMSCryptoKeyDataDesId) < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
				xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(xmlSecMSCryptoKeyDataDesId)),
				"xmlSecKeyDataIdsRegister",
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
    }
#endif /* XMLSEC_NO_DES */
	/*
	#ifndef XMLSEC_NO_RSA
    if(xmlSecKeyDataIdsRegister(xmlSecMSCryptoKeyDataRsaId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(xmlSecMSCryptoKeyDataRsaId)),
		    "xmlSecKeyDataIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_RSA */
	

#ifndef XMLSEC_NO_X509
    if(xmlSecKeyDataIdsRegister(xmlSecMSCryptoKeyDataX509Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(xmlSecMSCryptoKeyDataX509Id)),
		    "xmlSecKeyDataIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    if(xmlSecKeyDataIdsRegister(xmlSecMSCryptoKeyDataRawX509CertId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(xmlSecMSCryptoKeyDataRawX509CertId)),
		    "xmlSecKeyDataIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_X509 */

    return(0);
}

static int 
xmlSecMSCryptoTransformsInit(void) {
    /* TODO: register transforms here */
#ifndef XMLSEC_NO_SHA1    
    if(xmlSecTransformIdsRegister(xmlSecMSCryptoTransformSha1Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecMSCryptoTransformSha1Id)),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_HMAC
    if(xmlSecTransformIdsRegister(xmlSecMSCryptoTransformHmacSha1Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecMSCryptoTransformHmacSha1Id)),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_HMAC */

#ifndef XMLSEC_NO_RSA
    if(xmlSecTransformIdsRegister(xmlSecMSCryptoTransformRsaSha1Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecMSCryptoTransformRsaSha1Id)),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    if(xmlSecTransformIdsRegister(xmlSecMSCryptoTransformRsaPkcs1Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecMSCryptoTransformRsaPkcs1Id)),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_DES    
    if(xmlSecTransformIdsRegister(xmlSecMSCryptoTransformDes3CbcId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecMSCryptoTransformDes3CbcId)),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_DES */
    return(0);
}

