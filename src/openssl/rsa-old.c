/**
 * RSA transform
 */
static xmlSecTransformPtr xmlSecSignRsaSha1Create(xmlSecTransformId id);
static void 		xmlSecSignRsaSha1Destroy(xmlSecTransformPtr transform);
static int  		xmlSecSignRsaSha1SetKeyReq(xmlSecTransformPtr transform, 
						 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int  		xmlSecSignRsaSha1SetKey	(xmlSecTransformPtr transform, 
						 xmlSecKeyPtr key);
static int 		xmlSecSignRsaSha1Update	(xmlSecDigestTransformPtr digest,
						 const unsigned char *buffer,
						 size_t size);
static int 		xmlSecSignRsaSha1Sign	(xmlSecDigestTransformPtr digest,
						 unsigned char **buffer,
						 size_t *size);
static int 		xmlSecSignRsaSha1Verify	(xmlSecDigestTransformPtr digest,
						 const unsigned char *buffer,
						 size_t size);

struct _xmlSecDigestTransformIdStruct xmlSecSignRsaSha1Id = {
    /* same as xmlSecTransformId */    
    BAD_CAST "sign-rsa-sha1",
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecTransformUsageSignatureMethod,		/* xmlSecTransformUsage usage; */
    BAD_CAST "http://www.w3.org/2000/09/xmldsig#rsa-sha1", /* xmlChar *href; */
    
    xmlSecSignRsaSha1Create,		/* xmlSecTransformCreateMethod create; */
    xmlSecSignRsaSha1Destroy,		/* xmlSecTransformDestroyMethod destroy; */
    NULL,				/* xmlSecTransformReadNodeMethod read; */
    xmlSecSignRsaSha1SetKeyReq,		/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecSignRsaSha1SetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    
    /* xmlSecTransform data/methods */
    NULL,
    xmlSecDigestTransformRead,		/* xmlSecTransformReadMethod readBin; */
    xmlSecDigestTransformWrite,		/* xmlSecTransformWriteMethod writeBin; */
    xmlSecDigestTransformFlush,		/* xmlSecTransformFlushMethod flushBin; */

    NULL,
    NULL,
        
    /* xmlSecDigestTransform data/methods */
    xmlSecSignRsaSha1Update,		/* xmlSecDigestUpdateMethod digestUpdate; */
    xmlSecSignRsaSha1Sign,		/* xmlSecDigestSignMethod digestSign; */
    xmlSecSignRsaSha1Verify		/* xmlSecDigestVerifyMethod digestVerify; */
};
xmlSecTransformId xmlSecSignRsaSha1 = (xmlSecTransformId)&xmlSecSignRsaSha1Id;

/**
 * RSA-PKCS1 
 */
static xmlSecTransformPtr xmlSecRsaPkcs1Create	(xmlSecTransformId id);
static void 	xmlSecRsaPkcs1Destroy		(xmlSecTransformPtr transform);
static int  	xmlSecRsaPkcs1SetKeyReq		(xmlSecTransformPtr transform, 
						 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int  	xmlSecRsaPkcs1SetKey		(xmlSecTransformPtr transform, 
						 xmlSecKeyPtr key);
static int  	xmlSecRsaPkcs1Process		(xmlSecBufferedTransformPtr buffered, 
						 xmlBufferPtr buffer);

static const struct _xmlSecBufferedTransformIdStruct xmlSecEncRsaPkcs1Id = {
    /* same as xmlSecTransformId */    
    BAD_CAST "enc-rsa-pkcs",
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    BAD_CAST "http://www.w3.org/2001/04/xmlenc#rsa-1_5", /* const xmlChar href; */

    xmlSecRsaPkcs1Create, 		/* xmlSecTransformCreateMethod create; */
    xmlSecRsaPkcs1Destroy,		/* xmlSecTransformDestroyMethod destroy; */
    NULL,				/* xmlSecTransformReadMethod read; */
    xmlSecRsaPkcs1SetKeyReq,		/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecRsaPkcs1SetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    
    /* binary data/methods */
    NULL,
    xmlSecBufferedTransformRead,	/* xmlSecTransformReadMethod readBin; */
    xmlSecBufferedTransformWrite,	/* xmlSecTransformWriteMethod writeBin; */
    xmlSecBufferedTransformFlush,	/* xmlSecTransformFlushMethod flushBin; */

    NULL,
    NULL,
        
    
    /* xmlSecBufferedTransform data/methods */                                      
    xmlSecRsaPkcs1Process		/* xmlSecBufferedProcessMethod bufferedProcess; */
};
xmlSecTransformId xmlSecEncRsaPkcs1 = (xmlSecTransformId)&xmlSecEncRsaPkcs1Id;

/**
 * RSA-OAEP
 */
static xmlSecTransformPtr xmlSecRsaOaepCreate	(xmlSecTransformId id);
static void 	xmlSecRsaOaepDestroy		(xmlSecTransformPtr transform);
static int  	xmlSecRsaOaepSetKeyReq		(xmlSecTransformPtr transform, 
						 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int  	xmlSecRsaOaepSetKey		(xmlSecTransformPtr transform, 
						 xmlSecKeyPtr key);
static int 	xmlSecRsaOaepReadNode	 	(xmlSecTransformPtr transform,
						 xmlNodePtr transformNode);
static int  	xmlSecRsaOaepProcess		(xmlSecBufferedTransformPtr buffered, 
						 xmlBufferPtr buffer);

static const struct _xmlSecBufferedTransformIdStruct xmlSecEncRsaOaepId = {
    /* same as xmlSecTransformId */    
    BAD_CAST "enc-rsa-oaep",
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    BAD_CAST "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p", /* const xmlChar href; */

    xmlSecRsaOaepCreate, 		/* xmlSecTransformCreateMethod create; */
    xmlSecRsaOaepDestroy,		/* xmlSecTransformDestroyMethod destroy; */
    xmlSecRsaOaepReadNode,		/* xmlSecTransformReadMethod read; */
    xmlSecRsaOaepSetKeyReq,		/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecRsaOaepSetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    
    /* binary data/methods */
    NULL,
    xmlSecBufferedTransformRead,	/* xmlSecTransformReadMethod readBin; */
    xmlSecBufferedTransformWrite,	/* xmlSecTransformWriteMethod writeBin; */
    xmlSecBufferedTransformFlush,	/* xmlSecTransformFlushMethod flushBin; */

    NULL,
    NULL,
            
    /* xmlSecBufferedTransform data/methods */                                      
    xmlSecRsaOaepProcess		/* xmlSecBufferedProcessMethod bufferedProcess; */
};
xmlSecTransformId xmlSecEncRsaOaep = (xmlSecTransformId)&xmlSecEncRsaOaepId;

/**
 * RSA-SHA1 transform
 */
#define XMLSEC_RSASHA1_TRANSFORM_SIZE \
    (sizeof(xmlSecDigestTransform) + sizeof(SHA_CTX))
#define xmlSecSignRsaSha1Context(t) \
    ((SHA_CTX*)(((xmlSecDigestTransformPtr)( t ))->digestData))
#define xmlSecSignRsaSha1ContextRsa(t) \
    ((RSA*)(((xmlSecDigestTransformPtr)( t ))->reserved1))


/**
 * xmlSecSignRsaSha1Create:
 */
static xmlSecTransformPtr 
xmlSecSignRsaSha1Create(xmlSecTransformId id) {
    xmlSecDigestTransformPtr digest;
    
    xmlSecAssert2(id != NULL, NULL);
        
    if(id != xmlSecSignRsaSha1){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecSignRsaSha1");
	return(NULL);
    }

    /*
     * Allocate a new xmlSecTransform and fill the fields.
     */
    digest = (xmlSecDigestTransformPtr) xmlMalloc(XMLSEC_RSASHA1_TRANSFORM_SIZE);
    if(digest == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", XMLSEC_RSASHA1_TRANSFORM_SIZE);
	return(NULL);
    }
    memset(digest, 0, XMLSEC_RSASHA1_TRANSFORM_SIZE);
    
    digest->id = id;
    digest->digestData = ((unsigned char*)digest) + sizeof(xmlSecDigestTransform);

    SHA1_Init(xmlSecSignRsaSha1Context(digest)); 
    return((xmlSecTransformPtr)digest);
}

/**
 * xmlSecSignRsaSha1Destroy:
 */
static void 
xmlSecSignRsaSha1Destroy(xmlSecTransformPtr transform) {
    xmlSecDigestTransformPtr digest;

    xmlSecAssert(transform != NULL);
    
    if(!xmlSecTransformCheckId(transform, xmlSecSignRsaSha1)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecSignRsaSha1");
	return;
    }    
    digest = (xmlSecDigestTransformPtr)transform;

    if(xmlSecSignRsaSha1ContextRsa(transform) != NULL) {
	RSA_free(xmlSecSignRsaSha1ContextRsa(transform));
    }
    
    if(digest->digest != NULL) {
	memset(digest->digest, 0, digest->digestSize);
	xmlFree(digest->digest);
    }    
        
    memset(digest, 0, XMLSEC_RSASHA1_TRANSFORM_SIZE);
    xmlFree(digest);
}

/**
 * xmlSecSignRsaSha1Update:
 */
static int
xmlSecSignRsaSha1Update(xmlSecDigestTransformPtr digest,
			const unsigned char *buffer, size_t size) {
    xmlSecAssert2(digest != NULL, -1);
    
    if(!xmlSecTransformCheckId(digest, xmlSecSignRsaSha1)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecSignRsaSha1");
	return(-1);
    }    
    
    if((buffer == NULL) || (size == 0) || (digest->status != xmlSecTransformStatusNone)) {
	/* nothing to update */
	return(0);
    }
    
    SHA1_Update(xmlSecSignRsaSha1Context(digest), buffer, size); 
    return(0);
}

/**
 * xmlSecSignRsaSha1Sign:
 */
static int
xmlSecSignRsaSha1Sign(xmlSecDigestTransformPtr digest,
			unsigned char **buffer, size_t *size) {
    unsigned char buf[SHA_DIGEST_LENGTH]; 
    int ret;

    xmlSecAssert2(digest != NULL, -1);
    xmlSecAssert2(digest->digest != NULL, -1);
        
    if(!xmlSecTransformCheckId(digest, xmlSecSignRsaSha1) || 
      (xmlSecSignRsaSha1ContextRsa(digest) == NULL) ||
      ((xmlSecSignRsaSha1ContextRsa(digest)->d) == NULL)) {

	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecSignRsaSha1");
	return(-1);
    }    
    if(digest->status != xmlSecTransformStatusNone) {
	return(0);
    }    
    SHA1_Final(buf, xmlSecSignRsaSha1Context(digest)); 
    
    ret = RSA_sign(NID_sha1, buf, SHA_DIGEST_LENGTH, 
		digest->digest, &(digest->digestSize), 
		xmlSecSignRsaSha1ContextRsa(digest));
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "RSA_sign - %d", ret);
	return(-1);	    
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
 * xmlSecSignRsaSha1Verify:
 */
static int
xmlSecSignRsaSha1Verify(xmlSecDigestTransformPtr digest,
			const unsigned char *buffer, size_t size) {
    unsigned char buf[SHA_DIGEST_LENGTH]; 
    int ret;

    xmlSecAssert2(digest != NULL, -1);
    xmlSecAssert2(buffer != NULL, -1);
        
    if(!xmlSecTransformCheckId(digest, xmlSecSignRsaSha1) ||
       (xmlSecSignRsaSha1ContextRsa(digest) == NULL)) {

	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecSignRsaSha1");
	return(-1);
    }    

    SHA1_Final(buf, xmlSecSignRsaSha1Context(digest)); 
    
    ret = RSA_verify(NID_sha1, buf, SHA_DIGEST_LENGTH, 
		     (unsigned char *)buffer, size, 
		     xmlSecSignRsaSha1ContextRsa(digest));
    if(ret == 1) {
	digest->status = xmlSecTransformStatusOk;
    } else if(ret == 0) {
	digest->status = xmlSecTransformStatusFail;
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "RSA_verify - %d", ret);
	return(-1);
    }
    
    return(0);
}

static int  
xmlSecSignRsaSha1SetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecSignRsaSha1), -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    keyInfoCtx->keyId 	 = xmlSecKeyDataRsaValueId;
    
    if(transform->encode) {
        keyInfoCtx->keyType  = xmlSecKeyDataTypePrivate;
	keyInfoCtx->keyUsage = xmlSecKeyUsageSign;
    } else {
        keyInfoCtx->keyType  = xmlSecKeyDataTypePublic;
	keyInfoCtx->keyUsage = xmlSecKeyUsageVerify;
    }
    return(0);
}

/**
 * xmlSecSignRsaSha1SetKey:
 */
static int
xmlSecSignRsaSha1SetKey	(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecDigestTransformPtr digest;
    RSA *rsa;
    void *digestBuf;

    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(key->value != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(key->value, xmlSecKeyDataRsaValueId), -1);
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecSignRsaSha1), -1);

    digest = (xmlSecDigestTransformPtr)transform;
    rsa = xmlSecOpenSSLKeyDataRsaValueGet(key->value);
    xmlSecAssert2(rsa != NULL, -1);

    /* set key */
    if(xmlSecSignRsaSha1ContextRsa(transform) != NULL) {
	RSA_free(xmlSecSignRsaSha1ContextRsa(transform));
    }    
    transform->reserved1 = xmlSecOpenSSLRsaDup(rsa);
    if(transform->reserved1 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLRsaDup");
	return(-1);
    }

    /* create digest buffer */
    digestBuf = xmlMalloc(sizeof(unsigned char) * RSA_size(rsa));
    if(digestBuf == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", sizeof(unsigned char) * RSA_size(rsa));
	return(-1);
    }    
    if(digest->digest != NULL) {
	memset(digest->digest, 0, digest->digestSize);
	xmlFree(digest->digest);  
    }    
    digest->digest = digestBuf;
    digest->digestSize = RSA_size(rsa);
        
    return(0);
}

/**************************************************************************
 *
 * RSA-PKCS1 
 *
 **************************************************************************/
#define xmlSecRsaPkcs1Rsa(t) \
    ((RSA*)(((xmlSecBufferedTransformPtr)( t ))->reserved1))
    
static xmlSecTransformPtr 
xmlSecRsaPkcs1Create(xmlSecTransformId id) {
    xmlSecBufferedTransformPtr buffered;

    xmlSecAssert2(id != NULL, NULL);
    
    if(id != xmlSecEncRsaPkcs1){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecEncRsaPkcs1");
	return(NULL);
    }

    /*
     * Allocate a new xmlSecBufferedTransform and fill the fields.
     */
    buffered = (xmlSecBufferedTransformPtr)xmlMalloc(sizeof(xmlSecBufferedTransform));
    if(buffered == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecBufferedTransform)=%d",
		    sizeof(xmlSecBufferedTransform));
	return(NULL);
    }
    memset(buffered, 0, sizeof(xmlSecBufferedTransform));
    
    buffered->id = id;
    return((xmlSecTransformPtr)buffered);
}

static void 	
xmlSecRsaPkcs1Destroy(xmlSecTransformPtr transform) {
    xmlSecBufferedTransformPtr buffered;
    
    xmlSecAssert(transform != NULL);

    if(!xmlSecTransformCheckId(transform, xmlSecEncRsaPkcs1)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecEncRsaPkcs1");
	return;
    }    
    buffered = (xmlSecBufferedTransformPtr)transform;

    if(xmlSecRsaPkcs1Rsa(buffered) != NULL) {
	RSA_free(xmlSecRsaPkcs1Rsa(buffered));
    }    
    xmlSecBufferedDestroy(buffered);        
    memset(buffered, 0, sizeof(xmlSecBufferedTransform));
    xmlFree(buffered);
}

static int  
xmlSecRsaPkcs1SetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecEncRsaPkcs1), -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    keyInfoCtx->keyId 	 = xmlSecKeyDataRsaValueId;
    
    if(transform->encode) {
        keyInfoCtx->keyType  = xmlSecKeyDataTypePublic;
	keyInfoCtx->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
        keyInfoCtx->keyType  = xmlSecKeyDataTypePrivate;
	keyInfoCtx->keyUsage = xmlSecKeyUsageDecrypt;
    }
    
    return(0);
}

static int
xmlSecRsaPkcs1SetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecBufferedTransformPtr buffered;
    RSA *rsa;

    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(key->value != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(key->value, xmlSecKeyDataRsaValueId), -1);
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecEncRsaPkcs1), -1);
    
    buffered = (xmlSecBufferedTransformPtr)transform;
    rsa = xmlSecOpenSSLKeyDataRsaValueGet(key->value);
    xmlSecAssert2(rsa != NULL, -1);

    if(xmlSecRsaPkcs1Rsa(buffered) != NULL) {
	RSA_free(xmlSecRsaPkcs1Rsa(buffered));
    }    
    transform->reserved1 = xmlSecOpenSSLRsaDup(rsa);
    if(transform->reserved1 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLRsaDup");
	return(-1);
    }

    return(0);
}

static int
xmlSecRsaPkcs1Process(xmlSecBufferedTransformPtr buffered,  xmlBufferPtr buffer) {
    size_t size;
    int ret;    

    xmlSecAssert2(buffered != NULL, -1);
    xmlSecAssert2(buffer != NULL, -1);
    
    if(!xmlSecTransformCheckId(buffered, xmlSecEncRsaPkcs1) ||
       (xmlSecRsaPkcs1Rsa(buffered) == NULL)) {

	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecEncRsaPkcs1");
	return(-1);
    }    

    size = xmlBufferLength(buffer);
    if(buffered->encode) {
	xmlBufferResize(buffer, RSA_size(xmlSecRsaPkcs1Rsa(buffered)));
	ret = RSA_public_encrypt(size, xmlBufferContent(buffer),
				 (unsigned char*)xmlBufferContent(buffer), 
				 xmlSecRsaPkcs1Rsa(buffered),
				 RSA_PKCS1_PADDING);
    } else if(size == (size_t)RSA_size(xmlSecRsaPkcs1Rsa(buffered))) {
	ret = RSA_private_decrypt(size, xmlBufferContent(buffer),
				 (unsigned char*)xmlBufferContent(buffer), 
				 xmlSecRsaPkcs1Rsa(buffered),
				 RSA_PKCS1_PADDING);
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "%d", size);
	return(-1);	
    }
    if(ret <= 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    (buffered->encode) ? "RSA_public_encrypt" : "RSA_private_decrypt");
	return(-1);	
    }
    buffer->use = ret;
    return(0);
}

/***************************************************************************
 *
 * RSA-OAEP
 *
 ***************************************************************************/
#define xmlSecRsaOaepRsa(t) \
    ((RSA*)(((xmlSecBufferedTransformPtr)( t ))->reserved1))
    
static xmlSecTransformPtr 
xmlSecRsaOaepCreate(xmlSecTransformId id) {
    xmlSecBufferedTransformPtr buffered;

    xmlSecAssert2(id != NULL, NULL);
    
    if(id != xmlSecEncRsaOaep){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecEncRsaOaep");
	return(NULL);
    }

    /*
     * Allocate a new xmlSecBufferedTransform and fill the fields.
     */
    buffered = (xmlSecBufferedTransformPtr)xmlMalloc(sizeof(xmlSecBufferedTransform));
    if(buffered == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecBufferedTransform)=%d",
		    sizeof(xmlSecBufferedTransform));
	return(NULL);
    }
    memset(buffered, 0, sizeof(xmlSecBufferedTransform));
    
    buffered->id = id;
    return((xmlSecTransformPtr)buffered);
}

static void 	
xmlSecRsaOaepDestroy(xmlSecTransformPtr transform) {
    xmlSecBufferedTransformPtr buffered;

    xmlSecAssert(transform != NULL);
    
    if(!xmlSecTransformCheckId(transform, xmlSecEncRsaOaep)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecEncRsaOaep");
	return;
    }    
    buffered = (xmlSecBufferedTransformPtr)transform;

    if(xmlSecRsaOaepRsa(buffered) != NULL) {
	RSA_free(xmlSecRsaOaepRsa(buffered));
    } 
    if(buffered->reserved2 != NULL) {
	xmlBufferFree((xmlBufferPtr)buffered->reserved2);
    }   
    xmlSecBufferedDestroy(buffered);        
    memset(buffered, 0, sizeof(xmlSecBufferedTransform));
    xmlFree(buffered);
}

static int 	
xmlSecRsaOaepReadNode(xmlSecTransformPtr transform, xmlNodePtr transformNode) {
    xmlSecBufferedTransformPtr buffered;

    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(transformNode != NULL, -1);
    
    if(!xmlSecTransformCheckId(transform, xmlSecEncRsaOaep) ) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecEncRsaOaep");
	return(-1);
    }    
    buffered = (xmlSecBufferedTransformPtr)transform;
    
    /* TODO: */
    return(0);
}

/**
 * xmlSecEncRsaOaepAddParam::
 * @transformNode: the pointer to <dsig:Transform> node.
 * @buf: the OAEP param buffer.
 * @size: the OAEP param buffer size.
 * 
 * Creates <enc:OAEPParam> child node in the @transformNode.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int  	
xmlSecEncRsaOaepAddParam(xmlNodePtr transformNode, const unsigned char *buf, 
			 size_t size) {
    xmlNodePtr oaepParamNode;
    xmlChar *base64;

    xmlSecAssert2(transformNode != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(size > 0, -1);

    oaepParamNode = xmlSecFindChild(transformNode, BAD_CAST "OAEPParam", xmlSecEncNs);
    if(oaepParamNode != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    "OAEPParam");
	return(-1);    
    }

    oaepParamNode = xmlSecAddChild(transformNode, BAD_CAST "OAEPParam", xmlSecEncNs);
    if(oaepParamNode == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(OAEPParam)");
	return(-1);    
    }
    
    base64 = xmlSecBase64Encode(buf, size, 0);
    if(base64 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBase64Encode");
	return(-1);    
    }
    
    xmlNodeSetContent(oaepParamNode, base64);
    xmlFree(base64);
    return(0);
}

static int  
xmlSecRsaOaepSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecEncRsaOaep), -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    keyInfoCtx->keyId 	 = xmlSecKeyDataRsaValueId;
    
    if(transform->encode) {
        keyInfoCtx->keyType  = xmlSecKeyDataTypePublic;
	keyInfoCtx->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
        keyInfoCtx->keyType  = xmlSecKeyDataTypePrivate;
	keyInfoCtx->keyUsage = xmlSecKeyUsageDecrypt;
    }
    return(0);
}

static int
xmlSecRsaOaepSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecBufferedTransformPtr buffered;
    RSA *rsa;

    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(key->value != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(key->value, xmlSecKeyDataRsaValueId), -1);
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecEncRsaOaep), -1);
    
    buffered = (xmlSecBufferedTransformPtr)transform;
    rsa = xmlSecOpenSSLKeyDataRsaValueGet(key->value);
    xmlSecAssert2(rsa != NULL, -1);

    if(xmlSecRsaOaepRsa(buffered) != NULL) {
	RSA_free(xmlSecRsaOaepRsa(buffered));
    }    
    transform->reserved1 = xmlSecOpenSSLRsaDup(rsa);
    if(transform->reserved1 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLRsaDup");
	return(-1);
    }

    return(0);
}

static int
xmlSecRsaOaepProcess(xmlSecBufferedTransformPtr buffered,  xmlBufferPtr buffer) {
    size_t size;
    int rsa_size = 0;
    int ret;    
    RSA *rsa;

    xmlSecAssert2(buffered != NULL, -1);
    xmlSecAssert2(buffer != NULL, -1);
    
    if(!xmlSecTransformCheckId(buffered, xmlSecEncRsaOaep) ||
        (xmlSecRsaOaepRsa(buffered) == NULL)) {

	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecEncRsaOaep");
	return(-1);
    }    
    rsa = xmlSecRsaOaepRsa(buffered);
    rsa_size = RSA_size(rsa);
    size = xmlBufferLength(buffer);
    if(buffered->encode) {
	xmlBufferResize(buffer, rsa_size);
	
	if(buffered->reserved2 == NULL) {    
	    /* 
	     * simple case: OAEPparams not specified
	     * we can use standard OpenSSL function
	     */
    	    ret = RSA_public_encrypt(size, xmlBufferContent(buffer),  
	                           (unsigned char*)xmlBufferContent(buffer), 
				   rsa, RSA_PKCS1_OAEP_PADDING); 
	    if(ret <= 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    "RSA_public_encrypt - %d", ret);
		return(-1);	
	    }
	} else {
	    ret = RSA_padding_add_PKCS1_OAEP(
			    (unsigned char*)xmlBufferContent(buffer), rsa_size, 
			    xmlBufferContent(buffer), size,
			    xmlBufferContent((xmlBufferPtr)buffered->reserved2), 
			    xmlBufferLength((xmlBufferPtr)buffered->reserved2));
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    "RSA_padding_add_PKCS1_OAEP - %d", ret);
		return(-1);
	    }	
	    ret = RSA_public_encrypt(rsa_size, xmlBufferContent(buffer),
				 (unsigned char*)xmlBufferContent(buffer), 
				 rsa, RSA_NO_PADDING);
	    if(ret <= 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    "RSA_public_encrypt - %d", ret);
		return(-1);	
	    }
	}
    } else if(size == (size_t)rsa_size) {
	
	if(buffered->reserved2 == NULL) {    
	    /* 
	     * simple case: OAEPparams not specified
	     * we can use standard OpenSSL function
	     */
    	    ret = RSA_private_decrypt(size, xmlBufferContent(buffer),  
	                           (unsigned char*)xmlBufferContent(buffer), 
				   rsa, RSA_PKCS1_OAEP_PADDING); 
	    if(ret <= 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    "RSA_private_decrypt - %d", ret);
		return(-1);	
	    }
	} else {
	    BIGNUM bn;
	
	    ret = RSA_private_decrypt(size, xmlBufferContent(buffer),
				 (unsigned char*)xmlBufferContent(buffer), 
				 rsa, RSA_NO_PADDING);
	    if(ret <= 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    "RSA_private_decrypt - %d", ret);
		return(-1);	
	    }
	
	    /* 
    	     * the private decrypt w/o padding adds '0's at the begginning.
	     * it's not clear for me can I simply skip all '0's from the
	     * beggining so I have to do decode it back to BIGNUM and dump
	     * buffer again
	     */
	    BN_init(&bn);
	    if(BN_bin2bn(xmlBufferContent(buffer), ret, &bn) == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    "BN_bin2bn");
		return(-1);		    
	    }
	    ret = BN_bn2bin(&bn, (unsigned char*)xmlBufferContent(buffer));
	    BN_clear_free(&bn);
	
	    ret = RSA_padding_check_PKCS1_OAEP(
			    (unsigned char*)xmlBufferContent(buffer), size, 
			    xmlBufferContent(buffer), ret, rsa_size,
			    xmlBufferContent((xmlBufferPtr)buffered->reserved2), 
			    xmlBufferLength((xmlBufferPtr)buffered->reserved2));
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    "RSA_padding_check_PKCS1_OAEP - %d", ret);
		return(-1);
	    }
	}				    
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "size %d != rsa size %d", size, rsa_size);
	return(-1);	
    }
    buffer->use = ret;
    return(0);
}




