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

/* TODO: add Skeleton include files */

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/dl.h>
#include <xmlsec/private.h>

#include <xmlsec/skeleton/app.h>
#include <xmlsec/skeleton/crypto.h>

static xmlSecCryptoDLFunctionsPtr gXmlSecSkeletonFunctions = NULL;

/**
 * xmlSecCryptoGetFunctions_skeleton:
 *
 * Gets the pointer to xmlsec-skeleton functions table.
 *
 * Returns the xmlsec-skeleton functions table or NULL if an error occurs.
 */
xmlSecCryptoDLFunctionsPtr
xmlSecCryptoGetFunctions_skeleton(void) {
    static xmlSecCryptoDLFunctions functions;
    
    if(gXmlSecSkeletonFunctions != NULL) {
	return(gXmlSecSkeletonFunctions);
    }

    memset(&functions, 0, sizeof(functions));
    gXmlSecSkeletonFunctions = &functions;

    /**  
     * Crypto Init/shutdown
     */
    gXmlSecSkeletonFunctions->cryptoInit 		= xmlSecSkeletonInit;
    gXmlSecSkeletonFunctions->cryptoShutdown 		= xmlSecSkeletonShutdown;
    gXmlSecSkeletonFunctions->cryptoKeysMngrInit 	= xmlSecSkeletonKeysMngrInit;

    /**
     * Key data ids
     */
#ifndef XMLSEC_NO_AES    
    gXmlSecSkeletonFunctions->keyDataAesGetKlass	= xmlSecSkeletonKeyDataAesGetKlass;
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_DES    
    gXmlSecSkeletonFunctions->keyDataDesGetKlass 	= xmlSecSkeletonKeyDataDesGetKlass;
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_DSA
    gXmlSecSkeletonFunctions->keyDataDsaGetKlass 	= xmlSecSkeletonKeyDataDsaGetKlass;
#endif /* XMLSEC_NO_DSA */    

#ifndef XMLSEC_NO_HMAC  
    gXmlSecSkeletonFunctions->keyDataHmacGetKlass 	= xmlSecSkeletonKeyDataHmacGetKlass;
#endif /* XMLSEC_NO_HMAC */    

#ifndef XMLSEC_NO_RSA
    gXmlSecSkeletonFunctions->keyDataRsaGetKlass 	= xmlSecSkeletonKeyDataRsaGetKlass;
#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_X509
    gXmlSecSkeletonFunctions->keyDataX509GetKlass 		= xmlSecSkeletonKeyDataX509GetKlass;
    gXmlSecSkeletonFunctions->keyDataRawX509CertGetKlass 	= xmlSecSkeletonKeyDataRawX509CertGetKlass;
#endif /* XMLSEC_NO_X509 */

    /**
     * Key data store ids
     */
#ifndef XMLSEC_NO_X509
    gXmlSecSkeletonFunctions->x509StoreGetKlass 		= xmlSecSkeletonX509StoreGetKlass;
#endif /* XMLSEC_NO_X509 */

    /**
     * Crypto transforms ids
     */
#ifndef XMLSEC_NO_AES    
    gXmlSecSkeletonFunctions->transformAes128CbcGetKlass 	= xmlSecSkeletonTransformAes128CbcGetKlass;
    gXmlSecSkeletonFunctions->transformAes192CbcGetKlass 	= xmlSecSkeletonTransformAes192CbcGetKlass;
    gXmlSecSkeletonFunctions->transformAes256CbcGetKlass 	= xmlSecSkeletonTransformAes256CbcGetKlass;
    gXmlSecSkeletonFunctions->transformKWAes128GetKlass 	= xmlSecSkeletonTransformKWAes128GetKlass;
    gXmlSecSkeletonFunctions->transformKWAes192GetKlass 	= xmlSecSkeletonTransformKWAes192GetKlass;
    gXmlSecSkeletonFunctions->transformKWAes256GetKlass 	= xmlSecSkeletonTransformKWAes256GetKlass;
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_DES    
    gXmlSecSkeletonFunctions->transformDes3CbcGetKlass 		= xmlSecSkeletonTransformDes3CbcGetKlass;
    gXmlSecSkeletonFunctions->transformKWDes3GetKlass 		= xmlSecSkeletonTransformKWDes3GetKlass;
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_DSA
    gXmlSecSkeletonFunctions->transformDsaSha1GetKlass 		= xmlSecSkeletonTransformDsaSha1GetKlass;
#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_HMAC
    gXmlSecSkeletonFunctions->transformHmacSha1GetKlass 	= xmlSecSkeletonTransformHmacSha1GetKlass;
    gXmlSecSkeletonFunctions->transformHmacRipemd160GetKlass 	= xmlSecSkeletonTransformHmacRipemd160GetKlass;
    gXmlSecSkeletonFunctions->transformHmacMd5GetKlass 		= xmlSecSkeletonTransformHmacMd5GetKlass;
#endif /* XMLSEC_NO_HMAC */

#ifndef XMLSEC_NO_RIPEMD160
    gXmlSecSkeletonFunctions->transformRipemd160GetKlass 	= xmlSecSkeletonTransformRipemd160GetKlass;
#endif /* XMLSEC_NO_RIPEMD160 */

#ifndef XMLSEC_NO_RSA
    gXmlSecSkeletonFunctions->transformRsaSha1GetKlass 		= xmlSecSkeletonTransformRsaSha1GetKlass;
    gXmlSecSkeletonFunctions->transformRsaPkcs1GetKlass 	= xmlSecSkeletonTransformRsaPkcs1GetKlass;
    gXmlSecSkeletonFunctions->transformRsaOaepGetKlass 		= xmlSecSkeletonTransformRsaOaepGetKlass;
#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_SHA1    
    gXmlSecSkeletonFunctions->transformSha1GetKlass 		= xmlSecSkeletonTransformSha1GetKlass;
#endif /* XMLSEC_NO_SHA1 */

    /**
     * High level routines form xmlsec command line utility
     */ 
    gXmlSecSkeletonFunctions->cryptoAppInit 			= xmlSecSkeletonAppInit;
    gXmlSecSkeletonFunctions->cryptoAppShutdown 		= xmlSecSkeletonAppShutdown;
    gXmlSecSkeletonFunctions->cryptoAppDefaultKeysMngrInit 	= xmlSecSkeletonAppDefaultKeysMngrInit;
    gXmlSecSkeletonFunctions->cryptoAppDefaultKeysMngrAdoptKey 	= xmlSecSkeletonAppDefaultKeysMngrAdoptKey;
    gXmlSecSkeletonFunctions->cryptoAppDefaultKeysMngrLoad 	= xmlSecSkeletonAppDefaultKeysMngrLoad;
    gXmlSecSkeletonFunctions->cryptoAppDefaultKeysMngrSave 	= xmlSecSkeletonAppDefaultKeysMngrSave;
#ifndef XMLSEC_NO_X509
    gXmlSecSkeletonFunctions->cryptoAppKeysMngrCertLoad 	= xmlSecSkeletonAppKeysMngrCertLoad;
    gXmlSecSkeletonFunctions->cryptoAppKeysMngrCertLoadMemory 	= xmlSecSkeletonAppKeysMngrCertLoadMemory;
    gXmlSecSkeletonFunctions->cryptoAppPkcs12Load  		= xmlSecSkeletonAppPkcs12Load; 
    gXmlSecSkeletonFunctions->cryptoAppPkcs12LoadMemory		= xmlSecSkeletonAppPkcs12LoadMemory; 
    gXmlSecSkeletonFunctions->cryptoAppKeyCertLoad 		= xmlSecSkeletonAppKeyCertLoad;
    gXmlSecSkeletonFunctions->cryptoAppKeyCertLoadMemory	= xmlSecSkeletonAppKeyCertLoadMemory;
#endif /* XMLSEC_NO_X509 */
    gXmlSecSkeletonFunctions->cryptoAppKeyLoad 			= xmlSecSkeletonAppKeyLoad; 
    gXmlSecSkeletonFunctions->cryptoAppKeyLoadMemory		= xmlSecSkeletonAppKeyLoadMemory; 
    gXmlSecSkeletonFunctions->cryptoAppDefaultPwdCallback	= (void*)xmlSecSkeletonAppGetDefaultPwdCallback;

    return(gXmlSecSkeletonFunctions);
}


/**
 * xmlSecSkeletonInit:
 * 
 * XMLSec library specific crypto engine initialization. 
 *
 * Returns 0 on success or a negative value otherwise.
 */
int 
xmlSecSkeletonInit (void)  {
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
    if(xmlSecCryptoDLFunctionsRegisterKeyDataAndTransforms(xmlSecCryptoGetFunctions_skeleton()) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecCryptoDLFunctionsRegisterKeyDataAndTransforms",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    return(0);

    /* TODO: if necessary do, additional initialization here */
}

/**
 * xmlSecSkeletonShutdown:
 * 
 * XMLSec library specific crypto engine shutdown. 
 *
 * Returns 0 on success or a negative value otherwise.
 */
int 
xmlSecSkeletonShutdown(void) {
    /* TODO: if necessary, do additional shutdown here */
    return(0);
}

/**
 * xmlSecSkeletonKeysMngrInit:
 * @mngr:		the pointer to keys manager.
 *
 * Adds Skeleton specific key data stores in keys manager.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecSkeletonKeysMngrInit(xmlSecKeysMngrPtr mngr) {
    xmlSecAssert2(mngr != NULL, -1);

    /* TODO: add key data stores */
    return(0);
}


