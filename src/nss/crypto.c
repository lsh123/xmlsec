/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 */
#include "globals.h"

#include <string.h>

#include <nss.h>
#include <pk11func.h>
#include <prinit.h>


#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/dl.h>
#include <xmlsec/private.h>

#include <xmlsec/nss/app.h>
#include <xmlsec/nss/crypto.h>
#include <xmlsec/nss/x509.h>

static xmlSecCryptoDLFunctionsPtr gXmlSecNssFunctions = NULL;

xmlSecCryptoDLFunctionsPtr
xmlSecCryptoGetFunctions_nss(void) {
    static xmlSecCryptoDLFunctions functions;
    
    if(gXmlSecNssFunctions != NULL) {
	return(gXmlSecNssFunctions);
    }

    memset(&functions, 0, sizeof(functions));
    gXmlSecNssFunctions = &functions;

    /**  
     * Crypto Init/shutdown
     */
    gXmlSecNssFunctions->cryptoInit 			= xmlSecNssInit;
    gXmlSecNssFunctions->cryptoShutdown 		= xmlSecNssShutdown;
    gXmlSecNssFunctions->cryptoKeysMngrInit 		= xmlSecNssKeysMngrInit;

    /**
     * Key data ids
     */
#ifndef XMLSEC_NO_AES    
    gXmlSecNssFunctions->keyDataAesGetKlass		= xmlSecNssKeyDataAesGetKlass;
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_DES    
    gXmlSecNssFunctions->keyDataDesGetKlass 		= xmlSecNssKeyDataDesGetKlass;
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_DSA
    gXmlSecNssFunctions->keyDataDsaGetKlass 		= xmlSecNssKeyDataDsaGetKlass;
#endif /* XMLSEC_NO_DSA */    

#ifndef XMLSEC_NO_HMAC  
    gXmlSecNssFunctions->keyDataHmacGetKlass 		= xmlSecNssKeyDataHmacGetKlass;
#endif /* XMLSEC_NO_HMAC */    

#ifndef XMLSEC_NO_RSA
    gXmlSecNssFunctions->keyDataRsaGetKlass 		= xmlSecNssKeyDataRsaGetKlass;
#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_X509
    gXmlSecNssFunctions->keyDataX509GetKlass 		= xmlSecNssKeyDataX509GetKlass;
    gXmlSecNssFunctions->keyDataRawX509CertGetKlass 	= xmlSecNssKeyDataRawX509CertGetKlass;
#endif /* XMLSEC_NO_X509 */

    /**
     * Key data store ids
     */
#ifndef XMLSEC_NO_X509
    gXmlSecNssFunctions->x509StoreGetKlass 		= xmlSecNssX509StoreGetKlass;
#endif /* XMLSEC_NO_X509 */

    /**
     * Crypto transforms ids
     */
#ifndef XMLSEC_NO_AES    
    gXmlSecNssFunctions->transformAes128CbcGetKlass 	= xmlSecNssTransformAes128CbcGetKlass;
    gXmlSecNssFunctions->transformAes192CbcGetKlass 	= xmlSecNssTransformAes192CbcGetKlass;
    gXmlSecNssFunctions->transformAes256CbcGetKlass 	= xmlSecNssTransformAes256CbcGetKlass;
    gXmlSecNssFunctions->transformKWAes128GetKlass 	= xmlSecNssTransformKWAes128GetKlass;
    gXmlSecNssFunctions->transformKWAes192GetKlass 	= xmlSecNssTransformKWAes192GetKlass;
    gXmlSecNssFunctions->transformKWAes256GetKlass 	= xmlSecNssTransformKWAes256GetKlass;
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_DES    
    gXmlSecNssFunctions->transformDes3CbcGetKlass 	= xmlSecNssTransformDes3CbcGetKlass;
    gXmlSecNssFunctions->transformKWDes3GetKlass 	= xmlSecNssTransformKWDes3GetKlass;
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_DSA
    gXmlSecNssFunctions->transformDsaSha1GetKlass 	= xmlSecNssTransformDsaSha1GetKlass;
#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_HMAC
    gXmlSecNssFunctions->transformHmacSha1GetKlass 	= xmlSecNssTransformHmacSha1GetKlass;
    gXmlSecNssFunctions->transformHmacRipemd160GetKlass = xmlSecNssTransformHmacRipemd160GetKlass;
    gXmlSecNssFunctions->transformHmacMd5GetKlass 	= xmlSecNssTransformHmacMd5GetKlass;
#endif /* XMLSEC_NO_HMAC */

#ifndef XMLSEC_NO_RSA
    gXmlSecNssFunctions->transformRsaSha1GetKlass 	= xmlSecNssTransformRsaSha1GetKlass;
    gXmlSecNssFunctions->transformRsaPkcs1GetKlass 	= xmlSecNssTransformRsaPkcs1GetKlass;
#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_SHA1    
    gXmlSecNssFunctions->transformSha1GetKlass 		= xmlSecNssTransformSha1GetKlass;
#endif /* XMLSEC_NO_SHA1 */

    /**
     * High level routines form xmlsec command line utility
     */ 
    gXmlSecNssFunctions->cryptoAppInit 			= xmlSecNssAppInit;
    gXmlSecNssFunctions->cryptoAppShutdown 		= xmlSecNssAppShutdown;
    gXmlSecNssFunctions->cryptoAppDefaultKeysMngrInit 	= xmlSecNssAppDefaultKeysMngrInit;
    gXmlSecNssFunctions->cryptoAppDefaultKeysMngrAdoptKey 	= xmlSecNssAppDefaultKeysMngrAdoptKey;
    gXmlSecNssFunctions->cryptoAppDefaultKeysMngrLoad 	= xmlSecNssAppDefaultKeysMngrLoad;
    gXmlSecNssFunctions->cryptoAppDefaultKeysMngrSave 	= xmlSecNssAppDefaultKeysMngrSave;
#ifndef XMLSEC_NO_X509
    gXmlSecNssFunctions->cryptoAppKeysMngrCertLoad 	= xmlSecNssAppKeysMngrCertLoad;
    gXmlSecNssFunctions->cryptoAppPkcs12Load  		= xmlSecNssAppPkcs12Load; 
    gXmlSecNssFunctions->cryptoAppKeyCertLoad 		= xmlSecNssAppKeyCertLoad;
#endif /* XMLSEC_NO_X509 */
    gXmlSecNssFunctions->cryptoAppKeyLoad 		= xmlSecNssAppKeyLoad; 
    gXmlSecNssFunctions->cryptoAppDefaultPwdCallback	= (void*)xmlSecNssAppGetDefaultPwdCallback;

    return(gXmlSecNssFunctions);
}

/**
 * xmlSecNssInit:
 * 
 * XMLSec library specific crypto engine initialization. 
 *
 * Returns 0 on success or a negative value otherwise.
 */
int 
xmlSecNssInit (void)  {
    if(xmlSecCryptoDLFunctionsRegisterKeyDataAndTransforms(xmlSecCryptoGetFunctions_nss()) < 0) {
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
 * xmlSecNssShutdown:
 * 
 * XMLSec library specific crypto engine shutdown. 
 *
 * Returns 0 on success or a negative value otherwise.
 */
int 
xmlSecNssShutdown(void) {
    return(0);
}

/**
 * xmlSecNssKeysMngrInit:
 * @mngr:		the pointer to keys manager.
 *
 * Adds NSS specific key data stores in keys manager.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecNssKeysMngrInit(xmlSecKeysMngrPtr mngr) {
    int ret;
   
    xmlSecAssert2(mngr != NULL, -1);

#ifndef XMLSEC_NO_X509
    /* create x509 store if needed */
    if(xmlSecKeysMngrGetDataStore(mngr, xmlSecNssX509StoreId) == NULL) {
        xmlSecKeyDataStorePtr x509Store;

        x509Store = xmlSecKeyDataStoreCreate(xmlSecNssX509StoreId);
        if(x509Store == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecKeyDataStoreCreate",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "xmlSecNssX509StoreId");
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
 * xmlSecNssGenerateRandom:
 * @buffer:		the destination buffer.
 * @size:		the numer of bytes to generate.
 *
 * Generates @size random bytes and puts result in @buffer.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecNssGenerateRandom(xmlSecBufferPtr buffer, xmlSecSize size) {	
    SECStatus rv;
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
    rv = PK11_GenerateRandom((xmlSecByte*)xmlSecBufferGetData(buffer), size);
    if(rv != SECSuccess) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    "PK11_GenerateRandom",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "size=%d, error code=%d", size, PORT_GetError());
	return(-1);    
    }    
    return(0);
}



