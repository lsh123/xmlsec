/** 
 * XMLSec library
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <string.h>

#include <nss/nss.h>
#include <nss/pk11func.h>
#include <nspr/prinit.h>


#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/errors.h>

#include <xmlsec/nss/crypto.h>

static int		xmlSecNssKeysInit			(void);
static int		xmlSecNssTransformsInit			(void);

/**
 * xmlSecNssInit:
 * 
 * XMLSec library specific crypto engine initialization. 
 *
 * Returns 0 on success or a negative value otherwise.
 */
int 
xmlSecNssInit (void)  {
    if(xmlSecNssKeysInit() < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecNssKeysInit",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if(xmlSecNssTransformsInit() < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecNssTransformsInit",
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

int
xmlSecNssGenerateRandom(xmlSecBufferPtr buffer, size_t size) {	
    SECStatus rv;
    int ret;
    
    xmlSecAssert2(buffer != NULL, -1);
    xmlSecAssert2(size > 0, -1);

    ret = xmlSecBufferSetSize(buffer, size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    "xmlSecBufferSetSize",
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "size=%d", size);
	return(-1);
    }
        
    /* get random data */
    rv = PK11_GenerateRandom((unsigned char*)xmlSecBufferGetData(buffer), size);
    if(rv != SECSuccess) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    "PK11_GenerateRandom",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "size=%d", size);
	return(-1);    
    }    
    return(0);
}


static int		
xmlSecNssKeysInit(void) {

#ifndef XMLSEC_NO_AES    
    if(xmlSecKeyDataIdsRegister(xmlSecNssKeyDataAesId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(xmlSecNssKeyDataAesId)),
		    "xmlSecKeyDataIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_DES    
    if(xmlSecKeyDataIdsRegister(xmlSecNssKeyDataDesId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(xmlSecNssKeyDataDesId)),
		    "xmlSecKeyDataIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_DES */


#ifndef XMLSEC_NO_HMAC  
    if(xmlSecKeyDataIdsRegister(xmlSecNssKeyDataHmacId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(xmlSecNssKeyDataHmacId)),
		    "xmlSecKeyDataIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_HMAC */    

    return(0);
}

static int 
xmlSecNssTransformsInit(void) {
#ifndef XMLSEC_NO_HMAC
    if(xmlSecTransformsRegister(xmlSecNssTransformHmacSha1Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecNssTransformHmacSha1Id)),
		    "xmlSecTransformsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if(xmlSecTransformsRegister(xmlSecNssTransformHmacRipemd160Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecNssTransformHmacRipemd160Id)),
		    "xmlSecTransformsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if(xmlSecTransformsRegister(xmlSecNssTransformHmacMd5Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecNssTransformHmacMd5Id)),
		    "xmlSecTransformsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_HMAC */


#ifndef XMLSEC_NO_SHA1    
    if(xmlSecTransformsRegister(xmlSecNssTransformSha1Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecNssTransformSha1Id)),
		    "xmlSecTransformsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_DES    
    if(xmlSecTransformsRegister(xmlSecNssTransformDes3CbcId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecNssTransformDes3CbcId)),
		    "xmlSecTransformsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_AES    
    if(xmlSecTransformsRegister(xmlSecNssTransformAes128CbcId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecNssTransformAes128CbcId)),
		    "xmlSecTransformsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if(xmlSecTransformsRegister(xmlSecNssTransformAes192CbcId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecNssTransformAes192CbcId)),
		    "xmlSecTransformsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if(xmlSecTransformsRegister(xmlSecNssTransformAes256CbcId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecNssTransformAes256CbcId)),
		    "xmlSecTransformsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_AES */

    return(0);
}


