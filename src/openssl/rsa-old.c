static RSA*
xmlSecOpenSSLRsaDup(RSA* rsa) {
    RSA *newRsa;
    
    xmlSecAssert2(rsa != NULL, NULL);

    /* increment reference counter instead of coping if possible */
#ifndef XMLSEC_OPENSSL096
    RSA_up_ref(rsa);
    newRsa =  rsa;
#else /* XMLSEC_OPENSSL096 */     
    
    newRsa = RSA_new();
    if(newRsa == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "RSA_new");
	return(NULL);
    }

    if(rsa->n != NULL) {
	newRsa->n = BN_dup(rsa->n);
    }
    if(rsa->e != NULL) {
	newRsa->e = BN_dup(rsa->e);
    }
    if(rsa->d != NULL) {
	newRsa->d = BN_dup(rsa->d);
    }
#endif /* XMLSEC_OPENSSL096 */     
    return(newRsa);
}

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
						 xmlSecBufferPtr buffer);

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
    NULL,				/* xmlSecTransformValidateMethod validate; */
    NULL,				/* xmlSecTransformExecuteMethod execute; */
    
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
						 xmlSecBufferPtr buffer);

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
    NULL,				/* xmlSecTransformValidateMethod validate; */
    NULL,				/* xmlSecTransformExecuteMethod execute; */
    
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
    rsa = xmlSecOpenSSLKeyDataRsaValueGetRsa(key->value);
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
xmlSecRsaPkcs1Process(xmlSecBufferedTransformPtr buffered,  xmlSecBufferPtr buffer) {
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

    size = xmlSecBufferGetSize(buffer);
    if(buffered->encode) {
	xmlSecBufferSetMaxSize(buffer, RSA_size(xmlSecRsaPkcs1Rsa(buffered)));
	ret = RSA_public_encrypt(size, xmlSecBufferGetData(buffer),
				 (unsigned char*)xmlSecBufferGetData(buffer), 
				 xmlSecRsaPkcs1Rsa(buffered),
				 RSA_PKCS1_PADDING);
    } else if(size == (size_t)RSA_size(xmlSecRsaPkcs1Rsa(buffered))) {
	ret = RSA_private_decrypt(size, xmlSecBufferGetData(buffer),
				 (unsigned char*)xmlSecBufferGetData(buffer), 
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
    xmlSecBufferSetSize(buffer, ret);
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
	xmlSecBufferDestroy((xmlSecBufferPtr)buffered->reserved2);
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
    rsa = xmlSecOpenSSLKeyDataRsaValueGetRsa(key->value);
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
xmlSecRsaOaepProcess(xmlSecBufferedTransformPtr buffered,  xmlSecBufferPtr buffer) {
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
    size = xmlSecBufferGetSize(buffer);
    if(buffered->encode) {
	xmlSecBufferSetMaxSize(buffer, rsa_size);
	
	if(buffered->reserved2 == NULL) {    
	    /* 
	     * simple case: OAEPparams not specified
	     * we can use standard OpenSSL function
	     */
    	    ret = RSA_public_encrypt(size, xmlSecBufferGetData(buffer),  
	                           (unsigned char*)xmlSecBufferGetData(buffer), 
				   rsa, RSA_PKCS1_OAEP_PADDING); 
	    if(ret <= 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    "RSA_public_encrypt - %d", ret);
		return(-1);	
	    }
	} else {
	    ret = RSA_padding_add_PKCS1_OAEP(
			    (unsigned char*)xmlSecBufferGetData(buffer), rsa_size, 
			    xmlSecBufferGetData(buffer), size,
			    xmlSecBufferGetData((xmlSecBufferPtr)buffered->reserved2), 
			    xmlSecBufferGetSize((xmlSecBufferPtr)buffered->reserved2));
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    "RSA_padding_add_PKCS1_OAEP - %d", ret);
		return(-1);
	    }	
	    ret = RSA_public_encrypt(rsa_size, xmlSecBufferGetData(buffer),
				 (unsigned char*)xmlSecBufferGetData(buffer), 
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
    	    ret = RSA_private_decrypt(size, xmlSecBufferGetData(buffer),  
	                           (unsigned char*)xmlSecBufferGetData(buffer), 
				   rsa, RSA_PKCS1_OAEP_PADDING); 
	    if(ret <= 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    "RSA_private_decrypt - %d", ret);
		return(-1);	
	    }
	} else {
	    BIGNUM bn;
	
	    ret = RSA_private_decrypt(size, xmlSecBufferGetData(buffer),
				 (unsigned char*)xmlSecBufferGetData(buffer), 
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
	    if(BN_bin2bn(xmlSecBufferGetData(buffer), ret, &bn) == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    "BN_bin2bn");
		return(-1);		    
	    }
	    ret = BN_bn2bin(&bn, (unsigned char*)xmlSecBufferGetData(buffer));
	    BN_clear_free(&bn);
	
	    ret = RSA_padding_check_PKCS1_OAEP(
			    xmlSecBufferGetData(buffer), size, 
			    xmlSecBufferGetData(buffer), ret, rsa_size,
			    xmlSecBufferGetData((xmlSecBufferPtr)buffered->reserved2), 
			    xmlSecBufferGetSize((xmlSecBufferPtr)buffered->reserved2));
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
    xmlSecBufferSetSize(buffer, ret);
    return(0);
}




