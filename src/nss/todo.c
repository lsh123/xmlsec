int
xmlSecNssGenerateRandom(xmlSecBufferPtr buffer, size_t size) {	
    int ret;
    
    xmlSecAssert2(buffer != NULL, -1);
    xmlSecAssert2(size > 0, -1);

    ret = xmlSecBufferSetSize(buffer, size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    "xmlSecBufferSetSize",
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", size);
	return(-1);
    }
        
    /* get random data */
    ret = RAND_bytes((unsigned char*)xmlSecBufferGetData(buffer), size);
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    "RAND_bytes",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "%d", size);
	return(-1);    
    }	
    return(0);
}

void 
xmlSecNssErrorsDefaultCallback(const char* file, int line, const char* func,
				const char* errorObject, const char* errorSubject,
				int reason, const char* msg) {

    ERR_put_error(XMLSEC_NSS_ERRORS_LIB, 
		XMLSEC_NSS_ERRORS_FUNCTION, 
		reason, file, line);
    xmlSecErrorsDefaultCallback(file, line, func, 
		errorObject, errorSubject, 
		reason, msg);
}

static int 
xmlSecNssErrorsInit(void) {
    static ERR_STRING_DATA xmlSecNssStrReasons[XMLSEC_ERRORS_MAX_NUMBER + 1];
    static ERR_STRING_DATA xmlSecNssStrLib[]= {
	{ ERR_PACK(XMLSEC_NSS_ERRORS_LIB,0,0),	"xmlsec routines"},
	{ 0,     					NULL}
    }; 
    static ERR_STRING_DATA xmlSecNssStrDefReason[]= {
	{ XMLSEC_NSS_ERRORS_LIB,			"xmlsec lib"},
        { 0,						NULL}
    };
    size_t pos;

    /* initialize reasons array */
    memset(xmlSecNssStrReasons, 0, sizeof(xmlSecNssStrReasons));
    for(pos = 0; (pos < XMLSEC_ERRORS_MAX_NUMBER) && (xmlSecErrorsGetMsg(pos) != NULL); ++pos) {
	xmlSecNssStrReasons[pos].error  = xmlSecErrorsGetCode(pos);
	xmlSecNssStrReasons[pos].string = xmlSecErrorsGetMsg(pos);
    }
    
    /* finally load xmlsec strings in Nss */
    ERR_load_strings(XMLSEC_NSS_ERRORS_LIB, xmlSecNssStrLib); /* define xmlsec lib name */
    ERR_load_strings(XMLSEC_NSS_ERRORS_LIB, xmlSecNssStrDefReason); /* define default reason */
    ERR_load_strings(XMLSEC_NSS_ERRORS_LIB, xmlSecNssStrReasons);     
    
    /* and set default errors callback for xmlsec to us */
    xmlSecErrorsSetCallback(xmlSecNssErrorsDefaultCallback);
    
    return(0);
}

static int		
xmlSecNssKeysInit(void) {
#ifndef XMLSEC_NO_AES    
#ifndef XMLSEC_NSS_096
    if(xmlSecKeyDataIdsRegister(xmlSecNssKeyDataAesId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(xmlSecNssKeyDataAesId)),
		    "xmlSecKeyDataIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NSS_096 */    
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

#ifndef XMLSEC_NO_DSA
    if(xmlSecKeyDataIdsRegister(xmlSecNssKeyDataDsaId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(xmlSecNssKeyDataDsaId)),
		    "xmlSecKeyDataIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_DSA */    


#ifndef XMLSEC_NO_RSA
    if(xmlSecKeyDataIdsRegister(xmlSecNssKeyDataRsaId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(xmlSecNssKeyDataRsaId)),
		    "xmlSecKeyDataIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_X509
    if(xmlSecKeyDataIdsRegister(xmlSecNssKeyDataX509Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(xmlSecNssKeyDataX509Id)),
		    "xmlSecKeyDataIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    if(xmlSecKeyDataIdsRegister(xmlSecNssKeyDataRawX509CertId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(xmlSecNssKeyDataRawX509CertId)),
		    "xmlSecKeyDataIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_X509 */

    return(0);
}

static int 
xmlSecNssTransformsInit(void) {

#ifndef XMLSEC_NO_RIPEMD160
    if(xmlSecTransformRegister(xmlSecNssTransformRipemd160Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecNssTransformRipemd160Id)),
		    "xmlSecTransformRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_RIPEMD160 */

#ifndef XMLSEC_NO_HMAC
    if(xmlSecTransformRegister(xmlSecNssTransformHmacSha1Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecNssTransformHmacSha1Id)),
		    "xmlSecTransformRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecNssTransformHmacRipemd160Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecNssTransformHmacRipemd160Id)),
		    "xmlSecTransformRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecNssTransformHmacMd5Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecNssTransformHmacMd5Id)),
		    "xmlSecTransformRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_HMAC */

#ifndef XMLSEC_NO_DSA
    if(xmlSecTransformRegister(xmlSecNssTransformDsaSha1Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecNssTransformDsaSha1Id)),
		    "xmlSecTransformRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_DSA */    

#ifndef XMLSEC_NO_RSA
    if(xmlSecTransformRegister(xmlSecNssTransformRsaSha1Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecNssTransformRsaSha1Id)),
		    "xmlSecTransformRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecNssTransformRsaPkcs1Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecNssTransformRsaPkcs1Id)),
		    "xmlSecTransformRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecNssTransformRsaOaepId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecNssTransformRsaOaepId)),
		    "xmlSecTransformRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_RSA */
    
#ifndef XMLSEC_NO_DES    
    if(xmlSecTransformRegister(xmlSecNssTransformDes3CbcId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecNssTransformDes3CbcId)),
		    "xmlSecTransformRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecNssTransformKWDes3Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecNssTransformKWDes3Id)),
		    "xmlSecTransformRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_AES    
#ifndef XMLSEC_NSS_096
    if(xmlSecTransformRegister(xmlSecNssTransformAes128CbcId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecNssTransformAes128CbcId)),
		    "xmlSecTransformRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecNssTransformAes192CbcId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecNssTransformAes192CbcId)),
		    "xmlSecTransformRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecNssTransformAes256CbcId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecNssTransformAes256CbcId)),
		    "xmlSecTransformRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    if(xmlSecTransformRegister(xmlSecNssTransformKWAes128Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecNssTransformKWAes128Id)),
		    "xmlSecTransformRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecNssTransformKWAes192Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecNssTransformKWAes192Id)),
		    "xmlSecTransformRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if(xmlSecTransformRegister(xmlSecNssTransformKWAes256Id) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecNssTransformKWAes256Id)),
		    "xmlSecTransformRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NSS_096 */    
#endif /* XMLSEC_NO_AES */

    return(0);
}


