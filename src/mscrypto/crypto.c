/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2003 Cordys R&D BV, All rights reserved.
 * Copyright (C) 2003 Aleksey Sanin <aleksey@aleksey.com>
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

#if defined(_MSC_VER)
#define snprintf _snprintf
#endif

static xmlSecCryptoDLFunctionsPtr gXmlSecMSCryptoFunctions = NULL;

/**
 * xmlSecCryptoGetFunctions_mscrypto:
 *
 * Gets MSCrypto specific functions table.
 *
 * Returns xmlsec-mscrypto functions table.
 */
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

#ifndef XMLSEC_NO_AES    
    gXmlSecMSCryptoFunctions->keyDataAesGetKlass		= xmlSecMSCryptoKeyDataAesGetKlass;
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_RSA
    gXmlSecMSCryptoFunctions->keyDataRsaGetKlass 		= xmlSecMSCryptoKeyDataRsaGetKlass;
#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_DSA
    gXmlSecMSCryptoFunctions->keyDataDsaGetKlass 		= xmlSecMSCryptoKeyDataDsaGetKlass;
#endif /* XMLSEC_NO_DSA */

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

#ifndef XMLSEC_NO_RSA
    gXmlSecMSCryptoFunctions->transformRsaSha1GetKlass 		= xmlSecMSCryptoTransformRsaSha1GetKlass;
    gXmlSecMSCryptoFunctions->transformRsaPkcs1GetKlass 	= xmlSecMSCryptoTransformRsaPkcs1GetKlass;
#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_DSA
    gXmlSecMSCryptoFunctions->transformDsaSha1GetKlass 		= xmlSecMSCryptoTransformDsaSha1GetKlass;
#endif /* XMLSEC_NO_DSA */

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
    gXmlSecMSCryptoFunctions->cryptoAppKeysMngrCertLoadMemory 	= xmlSecMSCryptoAppKeysMngrCertLoadMemory;
    gXmlSecMSCryptoFunctions->cryptoAppPkcs12Load  		= xmlSecMSCryptoAppPkcs12Load; 
    gXmlSecMSCryptoFunctions->cryptoAppPkcs12LoadMemory		= xmlSecMSCryptoAppPkcs12LoadMemory; 
    gXmlSecMSCryptoFunctions->cryptoAppKeyCertLoad 		= xmlSecMSCryptoAppKeyCertLoad;
    gXmlSecMSCryptoFunctions->cryptoAppKeyCertLoadMemory	= xmlSecMSCryptoAppKeyCertLoadMemory;
#endif /* XMLSEC_NO_X509 */
    gXmlSecMSCryptoFunctions->cryptoAppKeyLoad 			= xmlSecMSCryptoAppKeyLoad; 
    gXmlSecMSCryptoFunctions->cryptoAppKeyLoadMemory		= xmlSecMSCryptoAppKeyLoadMemory; 
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

    /* set default errors callback for xmlsec to us */
    xmlSecErrorsSetCallback(xmlSecMSCryptoErrorsDefaultCallback);

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
    int ret;
   
    xmlSecAssert2(mngr != NULL, -1);

#ifndef XMLSEC_NO_X509
    /* create x509 store if needed */
    if(xmlSecKeysMngrGetDataStore(mngr, xmlSecMSCryptoX509StoreId) == NULL) {
        xmlSecKeyDataStorePtr x509Store;

        x509Store = xmlSecKeyDataStoreCreate(xmlSecMSCryptoX509StoreId);
        if(x509Store == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecKeyDataStoreCreate",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "xmlSecMSCryptoX509StoreId");
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
    HCRYPTPROV hProv = 0;
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

    if (FALSE == CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "CryptAcquireContext",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if (FALSE == CryptGenRandom(hProv, (DWORD)size, xmlSecBufferGetData(buffer))) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "CryptGenRandom",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	CryptReleaseContext(hProv,0);
	return(-1);
    }

    CryptReleaseContext(hProv, 0);
    return(0);
}

/**
 * xmlSecMSCryptoErrorsDefaultCallback:
 * @file:		the error location file name (__FILE__ macro).
 * @line:		the error location line number (__LINE__ macro).
 * @func:		the error location function name (__FUNCTION__ macro).
 * @errorObject:	the error specific error object 
 * @errorSubject:	the error specific error subject.
 * @reason:		the error code.
 * @msg:		the additional error message.
 *
 * The default errors reporting callback function.
 */
void 
xmlSecMSCryptoErrorsDefaultCallback(const char* file, int line, const char* func,
				const char* errorObject, const char* errorSubject,
				int reason, const char* msg) {
    DWORD dwError;
    LPVOID lpMsgBuf;
    char buf[500];

    dwError = GetLastError();
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | 
		  FORMAT_MESSAGE_FROM_SYSTEM | 
		  FORMAT_MESSAGE_IGNORE_INSERTS,
		  NULL,
		  dwError,
		  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), /* Default language */
		  (LPTSTR) &lpMsgBuf,
		  0,
		  NULL);
    if((msg != NULL) && ((*msg) != '\0')) {
        snprintf(buf, sizeof(buf), "%s;last error=%d (0x%08x);last error msg=%s", msg, dwError, dwError, (LPTSTR)lpMsgBuf);
    } else {
        snprintf(buf, sizeof(buf), "last error=%d (0x%08x);last error msg=%s", dwError, dwError, (LPTSTR)lpMsgBuf);
    }
    xmlSecErrorsDefaultCallback(file, line, func, 
		errorObject, errorSubject, 
		reason, buf);

    LocalFree(lpMsgBuf);
}

/**
 * xmlSecMSCryptoCertStrToName:
 * @dwCertEncodingType:		the encoding used.
 * @pszX500:			the string to convert.
 * @dsStrType:			the string type.
 * @len:			the result len.
 *
 * Converts input string to name by calling @CertStrToName function.
 *
 * Returns a pointer to newly allocated string or NULL if an error occurs.
 */
BYTE* 
xmlSecMSCryptoCertStrToName(DWORD dwCertEncodingType, LPCTSTR pszX500, DWORD dwStrType, DWORD* len) {
    BYTE* str = NULL; 
    
    xmlSecAssert2(pszX500 != NULL, NULL);
    xmlSecAssert2(len != NULL, NULL);

    if (!CertStrToName(dwCertEncodingType, pszX500, dwStrType, 
			NULL, NULL, len, NULL)) {
	/* this might not be an error, string might just not exist */
	return(NULL);
    }
	
    str = (BYTE *)xmlMalloc((*len) + 1);
    if(str == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "len=%d", (*len));
	return(NULL);
    }
    memset(str, 0, (*len) + 1);
	
    if (!CertStrToName(dwCertEncodingType, pszX500, dwStrType, 
			NULL, str, len, NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"CertStrToName",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	xmlFree(str);
	return(NULL);
    }

    return(str);
}


