/** 
 *
 * XMLSec library
 * 
 * HMAC Algorithm support (http://www.w3.org/TR/xmldsig-core/#sec-HMAC):
 * The HMAC algorithm (RFC2104 [HMAC]) takes the truncation length in bits 
 * as a parameter; if the parameter is not specified then all the bits of the 
 * hash are output. An example of an HMAC SignatureMethod element:  
 * <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1">
 *   <HMACOutputLength>128</HMACOutputLength>
 * </SignatureMethod>
 * 
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2003 Cordys R&D BV, All rights reserved.
 */
#ifndef XMLSEC_NO_HMAC
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

//ms crypto includes here

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/mscrypto/crypto.h>


typedef struct _xmlSecMSCryptoHmacCtx		xmlSecMSCryptoHmacCtx, *xmlSecMSCryptoHmacCtxPtr;
struct _xmlSecMSCryptoHmacCtx {
    //const EVP_MD*	hmacDgst;
    //HMAC_CTX		hmacCtx;
    int			ctxInitialized;
    unsigned char 	dgst[128]; // EVP_MAX_MD_SIZE
    size_t		dgstSize;	/* dgst size in bits */
};	    

#define xmlSecMSCryptoHmacSize	\
    (sizeof(xmlSecTransform) + sizeof(xmlSecMSCryptoHmacCtx))

/** 
 * HMAC SHA1
 */
static xmlSecTransformKlass xmlSecMSCryptoHmacSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    xmlSecMSCryptoHmacSize,			/* size_t objSize */

    xmlSecNameHmacSha1,				/* const xmlChar* name; */
    xmlSecHrefHmacSha1, 			/* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,	/* xmlSecTransformUsage usage; */
    
    NULL,					/* xmlSecTransformInitializeMethod initialize; */
    NULL,					/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    NULL,					/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,					/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    NULL,					/* xmlSecTransformGetDataTypeMethod getDataType; */
    NULL,					/* xmlSecTransformPushBinMethod pushBin; */
    NULL,					/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    NULL,					/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/** 
 * xmlSecMSCryptoTransformHmacSha1GetKlass:
 *
 * The HMAC-SHA1 transform klass.
 *
 * Returns the HMAC-SHA1 transform klass.
 */
xmlSecTransformId 
xmlSecMSCryptoTransformHmacSha1GetKlass(void) {
    return(&xmlSecMSCryptoHmacSha1Klass);
}

#endif /* XMLSEC_NO_HMAC */
