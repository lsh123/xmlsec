/** 
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#ifndef XMLSEC_NO_CRYPTO_DYNAMIC_LOADING

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/app.h>
#include <xmlsec/list.h>
#include <xmlsec/keysdata.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/transforms.h>
#include <xmlsec/private.h>
#include <xmlsec/errors.h>

			
/******************************************************************************
 *
 * Crypto Init/shutdown
 *
 *****************************************************************************/
/**
 * xmlSecCryptoInit:
 * 
 * XMLSec library specific crypto engine initialization. 
 *
 * Returns 0 on success or a negative value otherwise.
 */
int 
xmlSecCryptoInit(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoInit == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "cryptoInit",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }
    
    return(xmlSecCryptoDLGetFunctions()->cryptoInit());
}

/**
 * xmlSecCryptoShutdown:
 * 
 * XMLSec library specific crypto engine shutdown. 
 *
 * Returns 0 on success or a negative value otherwise.
 */
int 
xmlSecCryptoShutdown(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoShutdown == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "cryptoShutdown",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }
    
    return(xmlSecCryptoDLGetFunctions()->cryptoShutdown());
}

/**
 * xmlSecCryptoKeysMngrInit:
 * @mngr:		the pointer to keys manager.
 *
 * Adds crypto specific key data stores in keys manager.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int 
xmlSecCryptoKeysMngrInit(xmlSecKeysMngrPtr mngr) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoKeysMngrInit == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "cryptoKeysMngrInit",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }
    
    return(xmlSecCryptoDLGetFunctions()->cryptoKeysMngrInit(mngr));
}

/******************************************************************************
 *
 * Key data ids
 *
 *****************************************************************************/
/** 
 * xmlSecKeyDataAesGetKlass:
 * 
 * The AES key data klass.
 *
 * Returns AES key data klass.
 */
xmlSecKeyDataId 
xmlSecKeyDataAesGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->keyDataAesGetKlass == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "keyDataAesId",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(xmlSecKeyDataIdUnknown);
    }
    
    return(xmlSecCryptoDLGetFunctions()->keyDataAesGetKlass());
}

xmlSecKeyDataId 
xmlSecKeyDataDesGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->keyDataDesGetKlass == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "keyDataDesId",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(xmlSecKeyDataIdUnknown);
    }
    
    return(xmlSecCryptoDLGetFunctions()->keyDataDesGetKlass());
}

xmlSecKeyDataId	
xmlSecKeyDataDsaGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->keyDataDsaGetKlass == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "keyDataDsaId",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(xmlSecKeyDataIdUnknown);
    }
    
    return(xmlSecCryptoDLGetFunctions()->keyDataDsaGetKlass());
}

xmlSecKeyDataId	
xmlSecKeyDataHmacGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->keyDataHmacGetKlass == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "keyDataHmacId",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(xmlSecKeyDataIdUnknown);
    }
    
    return(xmlSecCryptoDLGetFunctions()->keyDataHmacGetKlass());
}

xmlSecKeyDataId	
xmlSecKeyDataRsaGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->keyDataRsaGetKlass == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "keyDataRsaId",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(xmlSecKeyDataIdUnknown);
    }
    
    return(xmlSecCryptoDLGetFunctions()->keyDataRsaGetKlass());
}

xmlSecKeyDataId	
xmlSecKeyDataX509GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->keyDataX509GetKlass == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "keyDataX509Id",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(xmlSecKeyDataIdUnknown);
    }
    
    return(xmlSecCryptoDLGetFunctions()->keyDataX509GetKlass());
}

xmlSecKeyDataId	
xmlSecKeyDataRawX509CertGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->keyDataRawX509CertGetKlass == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "keyDataRawX509CertId",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(xmlSecKeyDataIdUnknown);
    }
    
    return(xmlSecCryptoDLGetFunctions()->keyDataRawX509CertGetKlass());
}

/******************************************************************************
 *
 * Key data store ids
 *
 *****************************************************************************/
xmlSecKeyDataStoreId 
xmlSecX509StoreGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->x509StoreGetKlass == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "x509StoreId",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(xmlSecKeyStoreIdUnknown);
    }
    
    return(xmlSecCryptoDLGetFunctions()->x509StoreGetKlass());
}

/******************************************************************************
 *
 * Crypto transforms ids
 *
 *****************************************************************************/
xmlSecTransformId 
xmlSecTransformAes128CbcGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformAes128CbcGetKlass == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "transformAes128CbcId",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(xmlSecTransformIdUnknown);
    }
    
    return(xmlSecCryptoDLGetFunctions()->transformAes128CbcGetKlass());
}

xmlSecTransformId 
xmlSecTransformAes192CbcGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformAes192CbcGetKlass == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "transformAes192CbcId",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(xmlSecTransformIdUnknown);
    }
    
    return(xmlSecCryptoDLGetFunctions()->transformAes192CbcGetKlass());
}

xmlSecTransformId 
xmlSecTransformAes256CbcGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformAes256CbcGetKlass == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "transformAes256CbcId",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(xmlSecTransformIdUnknown);
    }
    
    return(xmlSecCryptoDLGetFunctions()->transformAes256CbcGetKlass());
}

xmlSecTransformId 
xmlSecTransformKWAes128GetKlass(void) {	
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformKWAes128GetKlass == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "transformKWAes128Id",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(xmlSecTransformIdUnknown);
    }
    
    return(xmlSecCryptoDLGetFunctions()->transformKWAes128GetKlass());
}

xmlSecTransformId 
xmlSecTransformKWAes192GetKlass(void) {	
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformKWAes192GetKlass == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "transformKWAes192Id",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(xmlSecTransformIdUnknown);
    }
    
    return(xmlSecCryptoDLGetFunctions()->transformKWAes192GetKlass());
}

xmlSecTransformId 
xmlSecTransformKWAes256GetKlass(void) {	
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformKWAes256GetKlass == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "transformKWAes256Id",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(xmlSecTransformIdUnknown);
    }
    
    return(xmlSecCryptoDLGetFunctions()->transformKWAes256GetKlass());
}

xmlSecTransformId 
xmlSecTransformDes3CbcGetKlass(void) {	
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformDes3CbcGetKlass == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "transformDes3CbcId",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(xmlSecTransformIdUnknown);
    }
    
    return(xmlSecCryptoDLGetFunctions()->transformDes3CbcGetKlass());
}

xmlSecTransformId 
xmlSecTransformKWDes3GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformKWDes3GetKlass == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "transformKWDes3Id",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(xmlSecTransformIdUnknown);
    }
    
    return(xmlSecCryptoDLGetFunctions()->transformKWDes3GetKlass());
}

xmlSecTransformId 
xmlSecTransformDsaSha1GetKlass(void) {	
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformDsaSha1GetKlass == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "transformDsaSha1Id",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(xmlSecTransformIdUnknown);
    }
    
    return(xmlSecCryptoDLGetFunctions()->transformDsaSha1GetKlass());
}

xmlSecTransformId 
xmlSecTransformHmacSha1GetKlass(void) {	
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformHmacSha1GetKlass == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "transformHmacSha1Id",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(xmlSecTransformIdUnknown);
    }
    
    return(xmlSecCryptoDLGetFunctions()->transformHmacSha1GetKlass());
}

xmlSecTransformId 
xmlSecTransformHmacRipemd160GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformHmacRipemd160GetKlass == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "transformHmacRipemd160Id",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(xmlSecTransformIdUnknown);
    }
    
    return(xmlSecCryptoDLGetFunctions()->transformHmacRipemd160GetKlass());
}

xmlSecTransformId 
xmlSecTransformHmacMd5GetKlass(void) {	
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformHmacMd5GetKlass == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "transformHmacMd5Id",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(xmlSecTransformIdUnknown);
    }
    
    return(xmlSecCryptoDLGetFunctions()->transformHmacMd5GetKlass());
}

xmlSecTransformId 
xmlSecTransformRipemd160GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformRipemd160GetKlass == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "transformRipemd160Id",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(xmlSecTransformIdUnknown);
    }
    
    return(xmlSecCryptoDLGetFunctions()->transformRipemd160GetKlass());
}

xmlSecTransformId
xmlSecTransformRsaSha1GetKlass(void) {	
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformRsaSha1GetKlass == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "transformRsaSha1Id",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(xmlSecTransformIdUnknown);
    }
    
    return(xmlSecCryptoDLGetFunctions()->transformRsaSha1GetKlass());
}

xmlSecTransformId 
xmlSecTransformRsaPkcs1GetKlass(void) {	
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformRsaPkcs1GetKlass == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "transformRsaPkcs1Id",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(xmlSecTransformIdUnknown);
    }
    
    return(xmlSecCryptoDLGetFunctions()->transformRsaPkcs1GetKlass());
}

xmlSecTransformId 
xmlSecTransformRsaOaepGetKlass(void) {	
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformRsaOaepGetKlass == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "transformRsaOaepId",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(xmlSecTransformIdUnknown);
    }
    
    return(xmlSecCryptoDLGetFunctions()->transformRsaOaepGetKlass());
}

xmlSecTransformId 
xmlSecTransformSha1GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformSha1GetKlass == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "transformSha1Id",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(xmlSecTransformIdUnknown);
    }
    
    return(xmlSecCryptoDLGetFunctions()->transformSha1GetKlass());
}

/******************************************************************************
 *
 * High level routines form xmlsec command line utility
 *
 *****************************************************************************/ 
int 
xmlSecCryptoAppInit(const char* config) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoAppInit == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "cryptoAppInit",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }
    
    return(xmlSecCryptoDLGetFunctions()->cryptoAppInit(config));
}


int 
xmlSecCryptoAppShutdown(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoAppShutdown == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "cryptoAppShutdown",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }
    
    return(xmlSecCryptoDLGetFunctions()->cryptoAppShutdown());
}


int 
xmlSecCryptoAppDefaultKeysMngrInit(xmlSecKeysMngrPtr mngr) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoAppDefaultKeysMngrInit == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "cryptoAppDefaultKeysMngrInit",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }
    
    return(xmlSecCryptoDLGetFunctions()->cryptoAppDefaultKeysMngrInit(mngr));
}


int 
xmlSecCryptoAppDefaultKeysMngrAdoptKey(xmlSecKeysMngrPtr mngr, xmlSecKeyPtr key) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoAppDefaultKeysMngrAdoptKey == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "cryptoAppDefaultKeysMngrAdoptKey",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }
    
    return(xmlSecCryptoDLGetFunctions()->cryptoAppDefaultKeysMngrAdoptKey(mngr, key));
}


int 
xmlSecCryptoAppDefaultKeysMngrLoad(xmlSecKeysMngrPtr mngr, const char* uri) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoAppDefaultKeysMngrLoad == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "cryptoAppDefaultKeysMngrLoad",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }
    
    return(xmlSecCryptoDLGetFunctions()->cryptoAppDefaultKeysMngrLoad(mngr, uri));
}


int 
xmlSecCryptoAppDefaultKeysMngrSave(xmlSecKeysMngrPtr mngr, const char* filename,
				   xmlSecKeyDataType type) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoAppDefaultKeysMngrSave == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "cryptoAppDefaultKeysMngrSave",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }
    
    return(xmlSecCryptoDLGetFunctions()->cryptoAppDefaultKeysMngrSave(mngr, filename, type));
}

int 
xmlSecCryptoAppKeysMngrCertLoad(xmlSecKeysMngrPtr mngr, const char *filename, 
				xmlSecKeyDataFormat format, xmlSecKeyDataType type) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoAppKeysMngrCertLoad == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "cryptoAppKeysMngrCertLoad",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }
    
    return(xmlSecCryptoDLGetFunctions()->cryptoAppKeysMngrCertLoad(mngr, filename, format, type));
}

				
xmlSecKeyPtr 
xmlSecCryptoAppKeyLoad(const char *filename, xmlSecKeyDataFormat format,
		       const char *pwd, void* pwdCallback, void* pwdCallbackCtx) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoAppKeyLoad == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "cryptoAppKeyLoad",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(NULL);
    }
    
    return(xmlSecCryptoDLGetFunctions()->cryptoAppKeyLoad(filename, format, pwd, pwdCallback, pwdCallbackCtx));
}

				
xmlSecKeyPtr 
xmlSecCryptoAppPkcs12Load(const char* filename, const char* pwd, void* pwdCallback, 
			  void* pwdCallbackCtx) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoAppPkcs12Load == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "cryptoAppPkcs12Load",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(NULL);
    }
    
    return(xmlSecCryptoDLGetFunctions()->cryptoAppPkcs12Load(filename, pwd, pwdCallback, pwdCallbackCtx));
}

int 
xmlSecCryptoAppKeyCertLoad(xmlSecKeyPtr key, const char* filename, xmlSecKeyDataFormat format) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoAppKeyCertLoad == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "cryptoAppKeyCertLoad",
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }
    
    return(xmlSecCryptoDLGetFunctions()->cryptoAppKeyCertLoad(key, filename, format));
}

void* 
xmlSecCryptoAppGetDefaultPwdCallback(void) {
    if(xmlSecCryptoDLGetFunctions() == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(NULL);
    }
    
    return(xmlSecCryptoDLGetFunctions()->cryptoAppDefaultPwdCallback);
}

#endif /* XMLSEC_NO_CRYPTO_DYNAMIC_LOADING */

