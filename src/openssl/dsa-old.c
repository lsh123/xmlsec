/**
 * DSA transform
 */
static xmlSecTransformPtr xmlSecSignDsaSha1Create(xmlSecTransformId id);
static void 	xmlSecSignDsaSha1Destroy	(xmlSecTransformPtr transform);
static int  	xmlSecSignDsaSha1SetKeyReq	(xmlSecTransformPtr transform, 
						 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int  	xmlSecSignDsaSha1SetKey		(xmlSecTransformPtr transform, 
						 xmlSecKeyPtr key);
static int 	xmlSecSignDsaSha1Update		(xmlSecDigestTransformPtr digest,
						 const unsigned char *buffer,
						 size_t size);
static int 	xmlSecSignDsaSha1Sign		(xmlSecDigestTransformPtr digest,
						 unsigned char **buffer,
						 size_t *size);
static int 	xmlSecSignDsaSha1Verify		(xmlSecDigestTransformPtr digest,
						 const unsigned char *buffer,
						 size_t size);
struct _xmlSecDigestTransformIdStruct xmlSecSignDsaSha1Id = {
    /* same as xmlSecTransformId */    
    BAD_CAST "sign-dsa",
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecTransformUsageSignatureMethod,	/* xmlSecTransformUsage usage; */
    BAD_CAST "http://www.w3.org/2000/09/xmldsig#dsa-sha1", /* xmlChar *href; */
    
    xmlSecSignDsaSha1Create,		/* xmlSecTransformCreateMethod create; */
    xmlSecSignDsaSha1Destroy,		/* xmlSecTransformDestroyMethod destroy; */
    NULL,				/* xmlSecTransformReadNodeMethod read; */
    xmlSecSignDsaSha1SetKeyReq,		/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecSignDsaSha1SetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    
    /* xmlSecTransform data/methods */
    NULL,
    xmlSecDigestTransformRead,		/* xmlSecTransformReadMethod readBin; */
    xmlSecDigestTransformWrite,		/* xmlSecTransformWriteMethod writeBin; */
    xmlSecDigestTransformFlush,		/* xmlSecTransformFlushMethod flushBin; */
    NULL,
    NULL,
        
    /* xmlSecDigestTransform data/methods */
    xmlSecSignDsaSha1Update,		/* xmlSecDigestUpdateMethod digestUpdate; */
    xmlSecSignDsaSha1Sign,		/* xmlSecDigestSignMethod digestSign; */
    xmlSecSignDsaSha1Verify		/* xmlSecDigestVerifyMethod digestVerify; */
};
xmlSecTransformId xmlSecSignDsaSha1 = (xmlSecTransformId)&xmlSecSignDsaSha1Id;


#define XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE		20

/****************************************************************************
 *
 *    DSA transform
 *
 ****************************************************************************/
#define XMLSEC_DSASHA1_TRANSFORM_SIZE \
    (sizeof(xmlSecDigestTransform) + sizeof(SHA_CTX) + \
    2 * sizeof(unsigned char) * XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE)
#define xmlSecSignDsaSha1Context(t) \
    ((SHA_CTX*)(((xmlSecDigestTransformPtr)( t ))->digestData))
#define xmlSecSignDsaSha1ContextDsa(t) \
    ((DSA*)(((xmlSecDigestTransformPtr)( t ))->reserved1))

/**
 * xmlSecSignDsaSha1Create:
 */
static xmlSecTransformPtr 
xmlSecSignDsaSha1Create(xmlSecTransformId id) {
    xmlSecDigestTransformPtr digest;

    xmlSecAssert2(id != NULL, NULL);
        
    if(id != xmlSecSignDsaSha1){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecSignDsaSha1");
	return(NULL);
    }

    /*
     * Allocate a new xmlSecTransform and fill the fields.
     */
    digest = (xmlSecDigestTransformPtr) xmlMalloc(XMLSEC_DSASHA1_TRANSFORM_SIZE);
    if(digest == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", XMLSEC_DSASHA1_TRANSFORM_SIZE);
	return(NULL);
    }
    memset(digest, 0, XMLSEC_DSASHA1_TRANSFORM_SIZE);
    
    digest->id = id;
    digest->digestData = ((unsigned char*)digest) + sizeof(xmlSecDigestTransform);
    digest->digest = ((unsigned char*)digest->digestData) + sizeof(SHA_CTX);
    digest->digestSize = 2 * XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE;

    SHA1_Init(xmlSecSignDsaSha1Context(digest)); 
    return((xmlSecTransformPtr)digest);
}

/**
 * xmlSecSignDsaSha1Destroy:
 */
static void 
xmlSecSignDsaSha1Destroy(xmlSecTransformPtr transform) {
    xmlSecDigestTransformPtr digest;
    
    xmlSecAssert(transform!= NULL);
    
    if(!xmlSecTransformCheckId(transform, xmlSecSignDsaSha1)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecSignDsaSha1");
	return;
    }    
    digest = (xmlSecDigestTransformPtr)transform;

    if(xmlSecSignDsaSha1ContextDsa(transform) != NULL) {
	DSA_free(xmlSecSignDsaSha1ContextDsa(transform));
    }
    
    memset(digest, 0, XMLSEC_DSASHA1_TRANSFORM_SIZE);
    xmlFree(digest);
}

/**
 * xmlSecSignDsaSha1Update:
 */
static int
xmlSecSignDsaSha1Update(xmlSecDigestTransformPtr digest,
			const unsigned char *buffer, size_t size) {
    xmlSecAssert2(digest != NULL, -1);
    
    if(!xmlSecTransformCheckId(digest, xmlSecSignDsaSha1)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecSignDsaSha1");
	return(-1);
    }    
    
    if((buffer == NULL) || (size == 0) || (digest->status != xmlSecTransformStatusNone)) {
	/* nothing to update */
	return(0);
    }
    
    SHA1_Update(xmlSecSignDsaSha1Context(digest), buffer, size); 
    return(0);
}

/**
 * xmlSecSignDsaSha1Sign:
 */
static int
xmlSecSignDsaSha1Sign(xmlSecDigestTransformPtr digest,
			unsigned char **buffer, size_t *size) {
    unsigned char buf[SHA_DIGEST_LENGTH]; 
    DSA_SIG *sig;
    int rSize, sSize;
        
    xmlSecAssert2(digest != NULL, -1);

    if(!xmlSecTransformCheckId(digest, xmlSecSignDsaSha1) || 
      (xmlSecSignDsaSha1ContextDsa(digest) == NULL) ||
      ((xmlSecSignDsaSha1ContextDsa(digest)->priv_key) == NULL)) {

	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecSignDsaSha1");
	return(-1);
    }    
    if(digest->status != xmlSecTransformStatusNone) {
	return(0);
    }    
    SHA1_Final(buf, xmlSecSignDsaSha1Context(digest)); 
    
    sig = DSA_do_sign(buf, SHA_DIGEST_LENGTH, 
		     xmlSecSignDsaSha1ContextDsa(digest));
    if(sig == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "DSA_do_sign");
	return(-1);	    
    }
    
    rSize = BN_num_bytes(sig->r);
    sSize = BN_num_bytes(sig->s);
    if((rSize > XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE) ||
       (sSize > XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE)) {

	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "size(r)=%d or size(s)=%d > %d", rSize, sSize, XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE);
	DSA_SIG_free(sig);
	return(-1);
    }	

    memset(digest->digest, 0, digest->digestSize);
    BN_bn2bin(sig->r, digest->digest + XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE - rSize);
    BN_bn2bin(sig->s, digest->digest + 2 * XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE - sSize);
    DSA_SIG_free(sig);
    
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
 * xmlSecSignDsaSha1Verify:
 */
static int
xmlSecSignDsaSha1Verify(xmlSecDigestTransformPtr digest,
			const unsigned char *buffer, size_t size) {
    unsigned char buf[SHA_DIGEST_LENGTH]; 
    DSA_SIG* sig;
    int ret;
        
    xmlSecAssert2(digest != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);

    if(!xmlSecTransformCheckId(digest, xmlSecSignDsaSha1) ||
       (xmlSecSignDsaSha1ContextDsa(digest) == NULL)) {

	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecSignDsaSha1");
	return(-1);
    }    
    if(size != 2 * XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "%d != %d", size, XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE);
	return(-1);
    }

    SHA1_Final(buf, xmlSecSignDsaSha1Context(digest)); 
    

    sig = DSA_SIG_new();
    if(sig == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "DSA_SIG_new");
	return(-1);
    }
	
    sig->r = BN_bin2bn(buffer, XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE, NULL);
    sig->s = BN_bin2bn(buffer + XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE, 
		       XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE, NULL);
    if((sig->r == NULL) || (sig->s == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "BN_bin2bn");
	DSA_SIG_free(sig); 
	return(-1);
    }
	
    ret = DSA_do_verify(buf, SHA_DIGEST_LENGTH, sig, 
			xmlSecSignDsaSha1ContextDsa(digest));
    if(ret == 1) {
	digest->status = xmlSecTransformStatusOk;
    } else if(ret == 0) {
	digest->status = xmlSecTransformStatusFail;
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "DSA_do_verify - %d", ret);
	DSA_SIG_free(sig); 
	return(-1);
    }
    
    DSA_SIG_free(sig); 
    return(0);
}

static int  
xmlSecSignDsaSha1SetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecSignDsaSha1), -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    keyInfoCtx->keyId 	 = xmlSecKeyDataDsaValueId;
    
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
 * xmlSecSignDsaSha1SetKey:
 */																 
static int
xmlSecSignDsaSha1SetKey	(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecDigestTransformPtr digest;
    DSA *dsa;
    
    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(key->value != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(key->value, xmlSecKeyDataDsaValueId), -1);
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecSignDsaSha1), -1);

    digest = (xmlSecDigestTransformPtr)transform;
    dsa = xmlSecOpenSSLKeyDataDsaValueGet(key->value);
    xmlSecAssert2(dsa != NULL, -1);

    if(xmlSecSignDsaSha1ContextDsa(transform) != NULL) {
	DSA_free(xmlSecSignDsaSha1ContextDsa(transform));
    }    
    transform->reserved1 = xmlSecOpenSSLDsaDup(dsa);
    if(transform->reserved1 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLDsaDup");
	return(-1);
    }
    
    return(0);
}

