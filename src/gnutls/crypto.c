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

#include <gnutls/gnutls.h>
#include <gcrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/dl.h>
#include <xmlsec/private.h>

#include <xmlsec/gnutls/app.h>
#include <xmlsec/gnutls/crypto.h>

static xmlSecCryptoDLFunctionsPtr gXmlSecGnuTLSFunctions = NULL;

xmlSecCryptoDLFunctionsPtr
xmlSecCryptoGetFunctions_gnutls(void) {
    static xmlSecCryptoDLFunctions functions;
    
    if(gXmlSecGnuTLSFunctions != NULL) {
	return(gXmlSecGnuTLSFunctions);
    }

    memset(&functions, 0, sizeof(functions));
    gXmlSecGnuTLSFunctions = &functions;

    /**  
     * Crypto Init/shutdown
     */
    gXmlSecGnuTLSFunctions->cryptoInit 			= xmlSecGnuTLSInit;
    gXmlSecGnuTLSFunctions->cryptoShutdown 		= xmlSecGnuTLSShutdown;
    gXmlSecGnuTLSFunctions->cryptoKeysMngrInit 		= xmlSecGnuTLSKeysMngrInit;

    /**
     * Key data ids
     */
#ifndef XMLSEC_NO_AES    
    gXmlSecGnuTLSFunctions->keyDataAesGetKlass		= xmlSecGnuTLSKeyDataAesGetKlass;
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_DES    
    gXmlSecGnuTLSFunctions->keyDataDesGetKlass 		= xmlSecGnuTLSKeyDataDesGetKlass;
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_HMAC  
    gXmlSecGnuTLSFunctions->keyDataHmacGetKlass 	= xmlSecGnuTLSKeyDataHmacGetKlass;
#endif /* XMLSEC_NO_HMAC */    

    /**
     * Key data store ids
     */

    /**
     * Crypto transforms ids
     */
#ifndef XMLSEC_NO_AES    
    gXmlSecGnuTLSFunctions->transformAes128CbcGetKlass 		= xmlSecGnuTLSTransformAes128CbcGetKlass;
    gXmlSecGnuTLSFunctions->transformAes192CbcGetKlass 		= xmlSecGnuTLSTransformAes192CbcGetKlass;
    gXmlSecGnuTLSFunctions->transformAes256CbcGetKlass 		= xmlSecGnuTLSTransformAes256CbcGetKlass;
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_DES    
    gXmlSecGnuTLSFunctions->transformDes3CbcGetKlass 		= xmlSecGnuTLSTransformDes3CbcGetKlass;
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_HMAC
    gXmlSecGnuTLSFunctions->transformHmacSha1GetKlass 		= xmlSecGnuTLSTransformHmacSha1GetKlass;
    gXmlSecGnuTLSFunctions->transformHmacRipemd160GetKlass 	= xmlSecGnuTLSTransformHmacRipemd160GetKlass;
    gXmlSecGnuTLSFunctions->transformHmacMd5GetKlass 		= xmlSecGnuTLSTransformHmacMd5GetKlass;
#endif /* XMLSEC_NO_HMAC */

#ifndef XMLSEC_NO_SHA1    
    gXmlSecGnuTLSFunctions->transformSha1GetKlass 		= xmlSecGnuTLSTransformSha1GetKlass;
#endif /* XMLSEC_NO_SHA1 */

    /**
     * High level routines form xmlsec command line utility
     */ 
    gXmlSecGnuTLSFunctions->cryptoAppInit 			= xmlSecGnuTLSAppInit;
    gXmlSecGnuTLSFunctions->cryptoAppShutdown 			= xmlSecGnuTLSAppShutdown;
    gXmlSecGnuTLSFunctions->cryptoAppDefaultKeysMngrInit 	= xmlSecGnuTLSAppDefaultKeysMngrInit;
    gXmlSecGnuTLSFunctions->cryptoAppDefaultKeysMngrAdoptKey 	= xmlSecGnuTLSAppDefaultKeysMngrAdoptKey;
    gXmlSecGnuTLSFunctions->cryptoAppDefaultKeysMngrLoad 	= xmlSecGnuTLSAppDefaultKeysMngrLoad;
    gXmlSecGnuTLSFunctions->cryptoAppDefaultKeysMngrSave 	= xmlSecGnuTLSAppDefaultKeysMngrSave;
#ifndef XMLSEC_NO_X509
    gXmlSecGnuTLSFunctions->cryptoAppKeysMngrCertLoad 		= xmlSecGnuTLSAppKeysMngrCertLoad;
    gXmlSecGnuTLSFunctions->cryptoAppPkcs12Load  		= xmlSecGnuTLSAppPkcs12Load; 
    gXmlSecGnuTLSFunctions->cryptoAppKeyCertLoad 		= xmlSecGnuTLSAppKeyCertLoad;
#endif /* XMLSEC_NO_X509 */
    gXmlSecGnuTLSFunctions->cryptoAppKeyLoad 			= xmlSecGnuTLSAppKeyLoad; 
    gXmlSecGnuTLSFunctions->cryptoAppDefaultPwdCallback		= (void*)xmlSecGnuTLSAppGetDefaultPwdCallback;

    return(gXmlSecGnuTLSFunctions);
}


/**
 * xmlSecGnuTLSInit:
 * 
 * XMLSec library specific crypto engine initialization. 
 *
 * Returns 0 on success or a negative value otherwise.
 */
int 
xmlSecGnuTLSInit (void)  {
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
    if(xmlSecCryptoDLFunctionsRegisterKeyDataAndTransforms(xmlSecCryptoGetFunctions_gnutls()) < 0) {
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
 * xmlSecGnuTLSShutdown:
 * 
 * XMLSec library specific crypto engine shutdown. 
 *
 * Returns 0 on success or a negative value otherwise.
 */
int 
xmlSecGnuTLSShutdown(void) {
    return(0);
}

/**
 * xmlSecGnuTLSKeysMngrInit:
 * @mngr:		the pointer to keys manager.
 *
 * Adds GnuTLS specific key data stores in keys manager.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSKeysMngrInit(xmlSecKeysMngrPtr mngr) {
    xmlSecAssert2(mngr != NULL, -1);

    /* TODO: add key data stores */
    return(0);
}

/**
 * xmlSecGnuTLSGenerateRandom:
 * @buffer:		the destination buffer.
 * @size:		the numer of bytes to generate.
 *
 * Generates @size random bytes and puts result in @buffer.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSGenerateRandom(xmlSecBufferPtr buffer, xmlSecSize size) {	
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
    gcry_randomize(xmlSecBufferGetData(buffer), size, GCRY_STRONG_RANDOM);
    return(0);
}
