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
#include <xmlsec/dl.h>
#include <xmlsec/private.h>

#include <xmlsec/mscrypto/app.h>
#include <xmlsec/mscrypto/crypto.h>
#include <xmlsec/mscrypto/x509.h>

static xmlSecCryptoDLFunctionsPtr gXmlSecMSCryptoFunctions = NULL;

xmlSecCryptoDLFunctionsPtr
xmlSecCryptoGetFunctions_mscrypto(void) {
    static xmlSecCryptoDLFunctions functions;
    
    if(gXmlSecMSCryptoFunctions != NULL) {
	return(gXmlSecMSCryptoFunctions);
    }

    memset(&functions, 0, sizeof(functions));
    gXmlSecMSCryptoFunctions = &functions;

    /**  
     * Crypto Init/shutdown
     */
    gXmlSecMSCryptoFunctions->cryptoInit 			= xmlSecMSCryptoInit;
    gXmlSecMSCryptoFunctions->cryptoShutdown 			= xmlSecMSCryptoShutdown;
    gXmlSecMSCryptoFunctions->cryptoKeysMngrInit 		= xmlSecMSCryptoKeysMngrInit;

    /**
     * Key data ids
     */
#ifndef XMLSEC_NO_DES    
    gXmlSecMSCryptoFunctions->keyDataDesGetKlass 		= xmlSecMSCryptoKeyDataDesGetKlass;
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_RSA
    gXmlSecMSCryptoFunctions->keyDataRsaGetKlass 		= xmlSecMSCryptoKeyDataRsaGetKlass;
#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_X509
    gXmlSecMSCryptoFunctions->keyDataX509GetKlass 		= xmlSecMSCryptoKeyDataX509GetKlass;
    gXmlSecMSCryptoFunctions->keyDataRawX509CertGetKlass	= xmlSecMSCryptoKeyDataRawX509CertGetKlass;
#endif /* XMLSEC_NO_X509 */

    /**
     * Key data store ids
     */
#ifndef XMLSEC_NO_X509
    gXmlSecMSCryptoFunctions->x509StoreGetKlass 		= xmlSecMSCryptoX509StoreGetKlass;
#endif /* XMLSEC_NO_X509 */

    /**
     * Crypto transforms ids
     */
#ifndef XMLSEC_NO_AES    
    gXmlSecMSCryptoFunctions->transformAes128CbcGetKlass	= xmlSecMSCryptoTransformAes128CbcGetKlass;
    gXmlSecMSCryptoFunctions->transformAes192CbcGetKlass	= xmlSecMSCryptoTransformAes192CbcGetKlass;
    gXmlSecMSCryptoFunctions->transformAes256CbcGetKlass	= xmlSecMSCryptoTransformAes256CbcGetKlass;
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_DES    
    gXmlSecMSCryptoFunctions->transformDes3CbcGetKlass 		= xmlSecMSCryptoTransformDes3CbcGetKlass;
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_HMAC
    gXmlSecMSCryptoFunctions->transformHmacSha1GetKlass 	= xmlSecMSCryptoTransformHmacSha1GetKlass;
#endif /* XMLSEC_NO_HMAC */

#ifndef XMLSEC_NO_RSA
    gXmlSecMSCryptoFunctions->transformRsaSha1GetKlass 		= xmlSecMSCryptoTransformRsaSha1GetKlass;
    gXmlSecMSCryptoFunctions->transformRsaPkcs1GetKlass 	= xmlSecMSCryptoTransformRsaPkcs1GetKlass;
#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_SHA1    
    gXmlSecMSCryptoFunctions->transformSha1GetKlass 		= xmlSecMSCryptoTransformSha1GetKlass;
#endif /* XMLSEC_NO_SHA1 */

    /**
     * High level routines form xmlsec command line utility
     */ 
    gXmlSecMSCryptoFunctions->cryptoAppInit 			= xmlSecMSCryptoAppInit;
    gXmlSecMSCryptoFunctions->cryptoAppShutdown 		= xmlSecMSCryptoAppShutdown;
    gXmlSecMSCryptoFunctions->cryptoAppDefaultKeysMngrInit 	= xmlSecMSCryptoAppDefaultKeysMngrInit;
    gXmlSecMSCryptoFunctions->cryptoAppDefaultKeysMngrAdoptKey 	= xmlSecMSCryptoAppDefaultKeysMngrAdoptKey;
    gXmlSecMSCryptoFunctions->cryptoAppDefaultKeysMngrLoad 	= xmlSecMSCryptoAppDefaultKeysMngrLoad;
    gXmlSecMSCryptoFunctions->cryptoAppDefaultKeysMngrSave 	= xmlSecMSCryptoAppDefaultKeysMngrSave;
#ifndef XMLSEC_NO_X509
    gXmlSecMSCryptoFunctions->cryptoAppKeysMngrCertLoad 	= xmlSecMSCryptoAppKeysMngrCertLoad;
    gXmlSecMSCryptoFunctions->cryptoAppPkcs12Load  		= xmlSecMSCryptoAppPkcs12Load; 
    gXmlSecMSCryptoFunctions->cryptoAppKeyCertLoad 		= xmlSecMSCryptoAppKeyCertLoad;
#endif /* XMLSEC_NO_X509 */
    gXmlSecMSCryptoFunctions->cryptoAppKeyLoad 			= xmlSecMSCryptoAppKeyLoad; 
    gXmlSecMSCryptoFunctions->cryptoAppDefaultPwdCallback	= (void*)xmlSecMSCryptoAppGetDefaultPwdCallback;

    return(gXmlSecMSCryptoFunctions);
}

/**
 * xmlSecMSCryptoInit:
 * 
 * XMLSec library specific crypto engine initialization. 
 *
 * Returns 0 on success or a negative value otherwise.
 */
int 
xmlSecMSCryptoInit (void)  {
    /* Check loaded xmlsec library version */
    if(xmlSecCheckVersionExact() != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecCheckVersionExact",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    /* register our klasses */
    if(xmlSecCryptoDLFunctionsRegisterKeyDataAndTransforms(xmlSecCryptoGetFunctions_mscrypto()) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecCryptoDLFunctionsRegisterKeyDataAndTransforms",
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


