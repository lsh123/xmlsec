/**
 * HMAC transform
 */
static xmlSecTransformPtr xmlSecMacHmacCreate		(xmlSecTransformId id);
static void 		xmlSecMacHmacDestroy		(xmlSecTransformPtr transform);
static int 		xmlSecMacHmacReadNode		(xmlSecTransformPtr transform,
							 xmlNodePtr transformNode);
static int  		xmlSecMacHmacSetKeyReq		(xmlSecTransformPtr transform, 
							 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int  		xmlSecMacHmacSetKey		(xmlSecTransformPtr transform, 
							 xmlSecKeyPtr key);
static int 		xmlSecMacHmacUpdate		(xmlSecDigestTransformPtr digest,
							 const unsigned char *buffer,
							 size_t size);
static int 		xmlSecMacHmacSign		(xmlSecDigestTransformPtr digest,
							 unsigned char **buffer,
							 size_t *size);
static int 		xmlSecMacHmacVerify		(xmlSecDigestTransformPtr digest,
							 const unsigned char *buffer,
							 size_t size);
/** 
 * HMAC SHA1
 */
struct _xmlSecDigestTransformIdStruct xmlSecMacHmacSha1Id = {
    /* same as xmlSecTransformId */    
    BAD_CAST "hmac-sha1",
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecTransformUsageSignatureMethod,		/* xmlSecTransformUsage usage; */
    BAD_CAST "http://www.w3.org/2000/09/xmldsig#hmac-sha1", /* xmlChar *href; */
    
    xmlSecMacHmacCreate,		/* xmlSecTransformCreateMethod create; */
    xmlSecMacHmacDestroy,		/* xmlSecTransformDestroyMethod destroy; */
    xmlSecMacHmacReadNode,		/* xmlSecTransformReadNodeMethod read; */
    xmlSecMacHmacSetKeyReq,		/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecMacHmacSetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    NULL,				/* xmlSecTransformValidateMethod validate; */
    NULL,				/* xmlSecTransformExecuteMethod execute; */
    
    /* xmlSecTransform data/methods */
    NULL,
    xmlSecDigestTransformRead,		/* xmlSecTransformReadMethod readBin; */
    xmlSecDigestTransformWrite,		/* xmlSecTransformWriteMethod writeBin; */
    xmlSecDigestTransformFlush,		/* xmlSecTransformFlushMethod flushBin; */
    NULL,
    NULL,
        
    /* xmlSecDigestTransform data/methods */
    xmlSecMacHmacUpdate,		/* xmlSecDigestUpdateMethod digestUpdate; */
    xmlSecMacHmacSign,			/* xmlSecDigestSignMethod digestSign; */
    xmlSecMacHmacVerify			/* xmlSecDigestVerifyMethod digestVerify; */
};
xmlSecTransformId xmlSecMacHmacSha1 = (xmlSecTransformId)&xmlSecMacHmacSha1Id;


/** 
 * HMAC MD5
 */
struct _xmlSecDigestTransformIdStruct xmlSecMacHmacMd5Id = {
    /* same as xmlSecTransformId */    
    BAD_CAST "hmac-md5",
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecTransformUsageSignatureMethod,		/* xmlSecTransformUsage usage; */
    BAD_CAST "http://www.w3.org/2001/04/xmldsig-more#hmac-md5", /* xmlChar *href; */
    
    xmlSecMacHmacCreate,		/* xmlSecTransformCreateMethod create; */
    xmlSecMacHmacDestroy,		/* xmlSecTransformDestroyMethod destroy; */
    xmlSecMacHmacReadNode,		/* xmlSecTransformReadNodeMethod read; */
    xmlSecMacHmacSetKeyReq,		/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecMacHmacSetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    NULL,				/* xmlSecTransformValidateMethod validate; */
    NULL,				/* xmlSecTransformExecuteMethod execute; */
    
    /* xmlSecTransform data/methods */
    NULL,
    xmlSecDigestTransformRead,		/* xmlSecTransformReadMethod readBin; */
    xmlSecDigestTransformWrite,		/* xmlSecTransformWriteMethod writeBin; */
    xmlSecDigestTransformFlush,		/* xmlSecTransformFlushMethod flushBin; */

    NULL,
    NULL,
    
    /* xmlSecDigestTransform data/methods */
    xmlSecMacHmacUpdate,		/* xmlSecDigestUpdateMethod digestUpdate; */
    xmlSecMacHmacSign,			/* xmlSecDigestSignMethod digestSign; */
    xmlSecMacHmacVerify			/* xmlSecDigestVerifyMethod digestVerify; */
};
xmlSecTransformId xmlSecMacHmacMd5 = (xmlSecTransformId)&xmlSecMacHmacMd5Id;

/** 
 * HMAC RIPEMD160 
 */
struct _xmlSecDigestTransformIdStruct xmlSecMacHmacRipeMd160Id = {
    /* same as xmlSecTransformId */    
    BAD_CAST "hmac-ripemd160",
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecTransformUsageSignatureMethod,		/* xmlSecTransformUsage usage; */
    BAD_CAST "http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160", /* xmlChar *href; */
    
    xmlSecMacHmacCreate,		/* xmlSecTransformCreateMethod create; */
    xmlSecMacHmacDestroy,		/* xmlSecTransformDestroyMethod destroy; */
    xmlSecMacHmacReadNode,		/* xmlSecTransformReadNodeMethod read; */
    xmlSecMacHmacSetKeyReq,		/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecMacHmacSetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    NULL,				/* xmlSecTransformValidateMethod validate; */
    NULL,				/* xmlSecTransformExecuteMethod execute; */
    
    /* xmlSecTransform data/methods */
    NULL,
    xmlSecDigestTransformRead,		/* xmlSecTransformReadMethod readBin; */
    xmlSecDigestTransformWrite,		/* xmlSecTransformWriteMethod writeBin; */
    xmlSecDigestTransformFlush,		/* xmlSecTransformFlushMethod flushBin; */

    NULL,
    NULL,
    
    /* xmlSecDigestTransform data/methods */
    xmlSecMacHmacUpdate,		/* xmlSecDigestUpdateMethod digestUpdate; */
    xmlSecMacHmacSign,			/* xmlSecDigestSignMethod digestSign; */
    xmlSecMacHmacVerify			/* xmlSecDigestVerifyMethod digestVerify; */
};
xmlSecTransformId xmlSecMacHmacRipeMd160 = (xmlSecTransformId)&xmlSecMacHmacRipeMd160Id;

/**
 * HMAC transform
 */
#define XMLSEC_HMACSHA1_TRANSFORM_SIZE \
    (sizeof(xmlSecDigestTransform) + sizeof(HMAC_CTX) + EVP_MAX_MD_SIZE)
#define xmlSecMacHmacContext(t) \
    ((HMAC_CTX*)(((xmlSecDigestTransformPtr)( t ))->digestData))

/**
 * xmlSecMacHmacCreate:
 */
static xmlSecTransformPtr 
xmlSecMacHmacCreate(xmlSecTransformId id) {
    xmlSecDigestTransformPtr digest;

    xmlSecAssert2(id != NULL, NULL);
        
    if((id != xmlSecMacHmacSha1) && 	
	(id != xmlSecMacHmacMd5) && 
	(id != xmlSecMacHmacRipeMd160)){
	
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecMacHmacSha1,xmlSecMacHmacMd5,xmlSecMacHmacRipeMd160");
	return(NULL);
    }

    /*
     * Allocate a new xmlSecTransform and fill the fields.
     */
    digest = (xmlSecDigestTransformPtr) xmlMalloc(XMLSEC_HMACSHA1_TRANSFORM_SIZE);
    if(digest == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", XMLSEC_HMACSHA1_TRANSFORM_SIZE);
	return(NULL);
    }
    memset(digest, 0, XMLSEC_HMACSHA1_TRANSFORM_SIZE);
    
    digest->id = id;
    digest->digestData = ((unsigned char*)digest) + sizeof(xmlSecDigestTransform);
    digest->digest = ((unsigned char*)digest->digestData) + sizeof(HMAC_CTX);
    digest->digestSize = EVP_MAX_MD_SIZE;
    digest->digestLastByteMask = 0xFF;

    return((xmlSecTransformPtr)digest);
}

/**
 * xmlSecMacHmacDestroy:
 */
static void 
xmlSecMacHmacDestroy(xmlSecTransformPtr transform) {
    xmlSecDigestTransformPtr digest;

    xmlSecAssert(transform != NULL);
    
    if(!xmlSecTransformCheckId(transform, xmlSecMacHmacSha1) && 
       !xmlSecTransformCheckId(transform, xmlSecMacHmacRipeMd160) &&
       !xmlSecTransformCheckId(transform, xmlSecMacHmacMd5)) {

	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecMacHmacSha1,xmlSecMacHmacMd5,xmlSecMacHmacRipeMd160");
	return;
    }    
    digest = (xmlSecDigestTransformPtr)transform;

#ifndef XMLSEC_OPENSSL096
    HMAC_CTX_cleanup(xmlSecMacHmacContext(transform));
#else /* XMLSEC_OPENSSL096 */
    HMAC_cleanup(xmlSecMacHmacContext(transform));
#endif /* XMLSEC_OPENSSL096 */    
    
    memset(digest, 0, XMLSEC_HMACSHA1_TRANSFORM_SIZE);
    xmlFree(digest);
}

/**
 * xmlSecMacHmacReadNode:
 *
 * HMAC (http://www.w3.org/TR/xmldsig-core/#sec-HMAC):
 *
 * The HMAC algorithm (RFC2104 [HMAC]) takes the truncation length in bits 
 * as a parameter; if the parameter is not specified then all the bits of the 
 * hash are output. An example of an HMAC SignatureMethod element:  
 * <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1">
 *   <HMACOutputLength>128</HMACOutputLength>
 * </SignatureMethod>
 * 
 * Schema Definition:
 * 
 * <simpleType name="HMACOutputLengthType">
 *   <restriction base="integer"/>
 * </simpleType>
 *     
 * DTD:
 *     
 * <!ELEMENT HMACOutputLength (#PCDATA)>
 */
static int
xmlSecMacHmacReadNode(xmlSecTransformPtr transform, xmlNodePtr transformNode) {
    xmlNodePtr cur;
    xmlSecDigestTransformPtr digest;

    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(transformNode!= NULL, -1);
    
    if(!xmlSecTransformCheckId(transform, xmlSecMacHmacSha1) && 
        !xmlSecTransformCheckId(transform, xmlSecMacHmacRipeMd160) &&
	!xmlSecTransformCheckId(transform, xmlSecMacHmacMd5)) {

	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecMacHmacSha1,xmlSecMacHmacMd5,xmlSecMacHmacRipeMd160");
	return(-1);
    }    
    digest = (xmlSecDigestTransformPtr)transform;
    
    cur = xmlSecGetNextElementNode(transformNode->children); 
    if((cur != NULL) && xmlSecCheckNodeName(cur, BAD_CAST "HMACOutputLength", xmlSecDSigNs)) {  
	xmlChar *content;
        int res = 0;
	
	content = xmlNodeGetContent(cur);
	if(content != NULL) {
	    res = atoi((char*)content);	    
	    xmlFree(content);
	}
	if(res > 0) {
	    static unsigned char masks[] = 	
		{ 0xFF, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE };
		  
	    digest->digestSize = (res + 7) / 8;
	    digest->digestLastByteMask = masks[res % 8];
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }
    
    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_NODE_NOT_FOUND,
		    (cur->name != NULL) ? (char*)cur->name : "NULL");
	return(-1);
    }
    return(0);    
}

/**
 * xmlSecHmacAddOutputLength:
 * @transformNode: the pointer to <dsig:Transform> node
 * @bitsLen: the required length in bits
 *
 * Creates <dsig:HMACOutputLength>child for the HMAC transform 
 * node @transformNode.
 *
 * Returns 0 on success and a negatie value otherwise.
 */
int
xmlSecHmacAddOutputLength(xmlNodePtr transformNode, size_t bitsLen) {
    xmlNodePtr node;
    char buf[32];

    xmlSecAssert2(transformNode != NULL, -1);
    xmlSecAssert2(bitsLen > 0, -1);

    node = xmlSecFindChild(transformNode, BAD_CAST "HMACOutputLength", xmlSecDSigNs);
    if(node != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    "HMACOutputLength");
	return(-1);
    }
    
    node = xmlSecAddChild(transformNode, BAD_CAST "HMACOutputLength", xmlSecDSigNs);
    if(node == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild");
	return(-1);
    }    
    
    sprintf(buf, "%u", bitsLen);
    xmlNodeSetContent(node, BAD_CAST buf);
    return(0);
}


/**
 * xmlSecMacHmacUpdate:
 */
static int
xmlSecMacHmacUpdate(xmlSecDigestTransformPtr digest, const unsigned char *buffer, size_t size) {

    xmlSecAssert2(digest != NULL, -1);
    
    if(!xmlSecTransformCheckId(digest, xmlSecMacHmacSha1) && 
	!xmlSecTransformCheckId(digest, xmlSecMacHmacRipeMd160) &&
	!xmlSecTransformCheckId(digest, xmlSecMacHmacMd5)) {

	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecMacHmacSha1,xmlSecMacHmacMd5,xmlSecMacHmacRipeMd160");
	return(-1);
    }    
    
    if((buffer == NULL) || (size == 0) || (digest->status != xmlSecTransformStatusNone)) {
	/* nothing to update */
	return(0);
    }
    
    HMAC_Update(xmlSecMacHmacContext(digest), buffer, size); 
    return(0);
}

/**
 * xmlSecMacHmacSign:
 */
static int
xmlSecMacHmacSign(xmlSecDigestTransformPtr digest,
			unsigned char **buffer, size_t *size) {
    size_t digestSize = 0;

    xmlSecAssert2(digest != NULL, -1);
        
    if(!xmlSecTransformCheckId(digest, xmlSecMacHmacSha1) && 
       !xmlSecTransformCheckId(digest, xmlSecMacHmacRipeMd160) &&
       !xmlSecTransformCheckId(digest, xmlSecMacHmacMd5)) {

	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecMacHmacSha1,xmlSecMacHmacMd5,xmlSecMacHmacRipeMd160");
	return(-1);
    }    
    if(digest->status != xmlSecTransformStatusNone) {
	return(0);
    }
    
    HMAC_Final(xmlSecMacHmacContext(digest), digest->digest, &digestSize); 
    if(digestSize < digest->digestSize) {
	digest->digestSize = digestSize;
    }
    if(digest->digestSize > 0) {
	digest->digest[digest->digestSize - 1] &= digest->digestLastByteMask;
    }
    if(buffer != NULL) {
	(*buffer) = digest->digest;
    }        
    if(size != NULL) {
	(*size) = digest->digestSize;
    }        
    digest->status = xmlSecTransformStatusOk;
    return(0);
}

/**
 * xmlSecMacHmacVerify:
 */
static int
xmlSecMacHmacVerify(xmlSecDigestTransformPtr digest,
			const unsigned char *buffer, size_t size) {
    size_t digestSize = 0;

    xmlSecAssert2(digest != NULL, -1);
    
    if(!xmlSecTransformCheckId(digest, xmlSecMacHmacSha1) && 
       !xmlSecTransformCheckId(digest, xmlSecMacHmacRipeMd160) &&
       !xmlSecTransformCheckId(digest, xmlSecMacHmacMd5)) {

	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecMacHmacSha1,xmlSecMacHmacMd5,xmlSecMacHmacRipeMd160");
	return(-1);
    }    

    if(digest->status != xmlSecTransformStatusNone) {
	return(0);
    }
    
    HMAC_Final(xmlSecMacHmacContext(digest), digest->digest, &digestSize); 
    if(digestSize < digest->digestSize) {
	digest->digestSize = digestSize;
    }
    
    if((buffer == NULL) || (size != digest->digestSize) || 
    	    (digest->digest == NULL) || (digest->digestSize == 0)) {
	digest->status = xmlSecTransformStatusFail;
    } else if(memcmp(digest->digest, buffer, digest->digestSize - 1) != 0) {
	digest->status = xmlSecTransformStatusFail;
    } else if((digest->digest[digest->digestSize - 1] & 
		digest->digestLastByteMask) != 
	       (buffer[digest->digestSize - 1] & 
		digest->digestLastByteMask)) {
	digest->status = xmlSecTransformStatusFail;
    } else {
	digest->status = xmlSecTransformStatusOk;
    }
    return(0);
}

static int  
xmlSecMacHmacSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMacHmacSha1) || xmlSecTransformCheckId(transform, xmlSecMacHmacRipeMd160) || xmlSecTransformCheckId(transform, xmlSecMacHmacMd5), -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    keyInfoCtx->keyId 	 = xmlSecKeyDataHmacValueId;
    keyInfoCtx->keyType  = xmlSecKeyDataTypeSymmetric;
    if(transform->encode) {
	keyInfoCtx->keyUsage = xmlSecKeyUsageSign;
    } else {
	keyInfoCtx->keyUsage = xmlSecKeyUsageVerify;
    }
    
    return(0);
}

/**
 * xmlSecMacHmacSetKey:
 */																 
static int
xmlSecMacHmacSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecDigestTransformPtr digest;
    xmlSecBufferPtr buffer;
    const EVP_MD *md = NULL;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMacHmacSha1) || xmlSecTransformCheckId(transform, xmlSecMacHmacRipeMd160) || xmlSecTransformCheckId(transform, xmlSecMacHmacMd5), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(key->value != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(key->value, xmlSecKeyDataHmacValueId), -1);
    
    digest = (xmlSecDigestTransformPtr)transform;
    buffer = xmlSecKeyDataBinaryValueGetBuffer(key->value);
    xmlSecAssert2(buffer != NULL, -1);

    if((size_t)xmlSecBufferGetSize(buffer) < 1) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_KEY_SIZE,
		    "%d bytes < %d bytes", 
		    xmlSecBufferGetSize(buffer),
		    1);
	return(-1);    
    }
    
    if(xmlSecTransformCheckId(transform, xmlSecMacHmacSha1)) {
	md = EVP_sha1();
    } else if(xmlSecTransformCheckId(transform, xmlSecMacHmacRipeMd160)) {
	md = EVP_ripemd160();	   
    } else if(xmlSecTransformCheckId(transform, xmlSecMacHmacMd5)) {
	md = EVP_md5();
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecMacHmacSha1,xmlSecMacHmacMd5,xmlSecMacHmacRipeMd160");
	return(-1);
    }

    HMAC_Init(xmlSecMacHmacContext(digest), 
		xmlSecBufferGetData(buffer),  
		xmlSecBufferGetSize(buffer), md); 
    return(0);
}


