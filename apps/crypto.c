/** 
 *
 * XMLSec library
 * 
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#if defined(_MSC_VER)
#define snprintf _snprintf
#endif

#include <string.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include "crypto.h"

int
xmlSecAppCryptoInit(void) {
    if(xmlSecCryptoAppInit() < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecCryptoAppInit");
	return(-1);
    }
    if(xmlSecCryptoInit() < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecCryptoInit");
	return(-1);
    }
    
    return(0);
}

int
xmlSecAppCryptoShutdown(void) {
    if(xmlSecCryptoShutdown() < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecCryptoShutdown");
	return(-1);
    }

    if(xmlSecCryptoAppShutdown() < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecCryptoAppShutdown");
	return(-1);
    }
    return(0);
}

int
xmlSecAppCryptoSimpleKeysMngrInit(xmlSecKeysMngrPtr mngr) {
    xmlSecAssert2(mngr != NULL, -1);

    return(xmlSecOpenSSLAppSimpleKeysMngrInit(mngr));
}

int
xmlSecAppCryptoSimpleKeysMngrLoad(xmlSecKeysMngrPtr mngr, const char *filename) {
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    
    return(xmlSecOpenSSLAppSimpleKeysMngrLoad(mngr, filename));
}

int 
xmlSecAppCryptoSimpleKeysMngrSave(xmlSecKeysMngrPtr mngr, const char *filename, xmlSecKeyDataType type) {
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    
    return(xmlSecOpenSSLAppSimpleKeysMngrSave(mngr, filename, type));
}

int 
xmlSecAppCryptoSimpleKeysMngrPemCertLoad(xmlSecKeysMngrPtr mngr, const char *filename, int trusted) {
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);

#ifndef XMLSEC_NO_X509	    
    return(xmlSecOpenSSLAppKeysMngrPemCertLoad(mngr, filename, trusted));
#else /* XMLSEC_NO_X509 */
    return(-1);
#endif /* XMLSEC_NO_X509 */    
}


int 
xmlSecAppCryptoSimpleKeysMngrPemKeyAndCertsLoad(xmlSecKeysMngrPtr mngr, char *params, const char* pwd, 
						const char* name, int privateKey) {
    xmlSecKeyPtr key;
    char *p;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(params != NULL, -1);

    p = strtok(params, ","); 
    key = xmlSecCryptoAppPemKeyLoad(p, pwd, NULL, privateKey);
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecCryptoAppPemKeyLoad(%s)", p);
	return(-1);
    }
    
    if(name != NULL) {
	ret = xmlSecKeySetName(key, BAD_CAST name);
	if(ret < 0) {	
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecKeySetName(%s)", name);
	    xmlSecKeyDestroy(key);
	    return(-1);
	}
    }

    p = strtok(NULL, ",");
#ifndef XMLSEC_NO_X509     
    while((p != NULL) && (privateKey)) {
	ret = xmlSecCryptoAppKeyPemCertLoad(key, p);
	if(ret < 0){
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecCryptoAppKeyPemCertLoad(%s)", p);
	    xmlSecKeyDestroy(key);
	    return(-1);
	}
	p = strtok(NULL, ","); 
    }
#else /* XMLSEC_NO_X509 */
    if(p != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "x509 support disabled");
	return(-1);
    }
#endif /* XMLSEC_NO_X509 */        

    ret = xmlSecCryptoAppSimpleKeysMngrAdoptKey(mngr, key);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecCryptoAppSimpleKeysMngrAdoptKey");
	xmlSecKeyDestroy(key);
	return(-1);
    }
    
    return(0);
}

int 
xmlSecAppCryptoSimpleKeysMngrPkcs12KeyLoad(xmlSecKeysMngrPtr mngr, const char *filename, const char* pwd, const char *name) {
    xmlSecKeyPtr key;
    char buf[1024] = "";
    char prompt[1024];
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);

#ifndef XMLSEC_NO_X509
    if(pwd == NULL) {
	snprintf(prompt, sizeof(prompt), "Password for pkcs12 file \"%s\": ", filename); 
	ret = EVP_read_pw_string(buf, sizeof(buf), prompt, 0);
	if(ret != 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"EVP_read_pw_string");
	    return(-1);
	}
	pwd = buf;
    } 

    key = xmlSecCryptoAppPkcs12Load(filename, pwd);
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecCryptoAppPkcs12Load");
	memset(buf, 0, sizeof(buf));
	return(-1);
    }
    memset(buf, 0, sizeof(buf));
        
    if(name != NULL) {
	ret = xmlSecKeySetName(key, BAD_CAST name);
	if(ret < 0) {	
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecKeySetName(%s)", name);
	    xmlSecKeyDestroy(key);
	    return(-1);
	}
    }
    
    ret = xmlSecCryptoAppSimpleKeysMngrAdoptKey(mngr, key);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecCryptoAppSimpleKeysMngrAdoptKey");
	xmlSecKeyDestroy(key);
	return(-1);
    }
    
    return(0);
#else /* XMLSEC_NO_X509 */
    xmlSecError(XMLSEC_ERRORS_HERE,
		XMLSEC_ERRORS_R_XMLSEC_FAILED,
		"x509 support disabled");
    return(-1);
#endif /* XMLSEC_NO_X509 */
}

int 
xmlSecAppCryptoSimpleKeysMngrBinaryKeyLoad(xmlSecKeysMngrPtr mngr, const char* keyKlass, const char *filename, const char *name) {
    FILE *f;
    unsigned char buf[1024];
    xmlSecBufferPtr buffer;
    xmlSecKeyPtr key;
    xmlSecKeyDataId dataId;
    xmlSecKeyInfoCtx keyInfoCtx;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(keyKlass != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);

    /* find requested data */
    dataId = xmlSecKeyDataIdsFindByName(BAD_CAST keyKlass, xmlSecKeyDataUsageAny);
    if(dataId == xmlSecKeyDataIdUnknown) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyDataIdsFindByName");
	return(-1);    
    }

    /* read file to buffer */
    buffer = xmlSecBufferCreate(0);
    if(buffer == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBufferCreate");
	return(-1);	
    }

    f = fopen(filename, "r");
    if(f == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "fopen(%s)", filename);
	xmlSecBufferDestroy(buffer);
	return(-1);
    }

    while(1) {
        ret = fread(buf, 1, sizeof(buf), f);
	if(ret > 0) {
	    xmlSecBufferAppend(buffer, buf, ret);
	} else if(ret == 0) {
	    break;
	} else {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"fread(%s)", filename);
	    fclose(f);
	    xmlSecBufferDestroy(buffer);
	    return(-1);
	}
    }
    fclose(f);    
    
    /* create key data */
    key = xmlSecKeyCreate();
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyCreate");
	xmlSecBufferDestroy(buffer);
	return(-1);    
    }

    memset(&keyInfoCtx, 0, sizeof(keyInfoCtx));
    keyInfoCtx.keyType = xmlSecKeyDataTypeAny;
    ret = xmlSecKeyDataBinRead(dataId, key, 
			xmlSecBufferGetData(buffer),
			xmlSecBufferGetSize(buffer),
			&keyInfoCtx);	
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyDataBinRead");
	xmlSecBufferDestroy(buffer);
	xmlSecKeyDestroy(key);
	return(-1);    
    }
    xmlSecBufferDestroy(buffer);
    
    ret = xmlSecKeySetName(key, BAD_CAST name);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeySetName");
	xmlSecKeyDestroy(key);
	return(-1);    
    }

    /* finally add it to keys manager */    
    ret = xmlSecCryptoAppSimpleKeysMngrAdoptKey(mngr, key);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecCryptoAppSimpleKeysMngrAdoptKey");
	xmlSecKeyDestroy(key);
	return(-1);
    }
    return(0);
}


int 
xmlSecAppCryptoSimpleKeysMngrKeyGenerate(xmlSecKeysMngrPtr mngr, char* keyKlassAndSize, const char* name) {
    xmlSecKeyPtr key;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(keyKlassAndSize != NULL, -1);
    
    key = xmlSecAppCryptoKeyGenerate(keyKlassAndSize, name);
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAppCryptoKeyGenerate");
	return(-1);    
    }    

    ret = xmlSecCryptoAppSimpleKeysMngrAdoptKey(mngr, key);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecCryptoAppSimpleKeysMngrAdoptKey");
	xmlSecKeyDestroy(key);
	return(-1);
    }
    return(0);
}

xmlSecKeyPtr 
xmlSecAppCryptoKeyGenerate(char* keyKlassAndSize, const char* name) {
    xmlSecKeyPtr key;
    char* p;
    int size;

    xmlSecAssert2(keyKlassAndSize != NULL, NULL);
    
    /* separate key klass and size */
    p = strchr(keyKlassAndSize, '-');
    if(p == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "key size is not specified %s", 
		    keyKlassAndSize);
	return(NULL);
    }
    *(p++) = '\0';
    size = atoi(p);
    
    key = xmlSecKeyGenerate(BAD_CAST keyKlassAndSize, BAD_CAST name, size);
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyGenerate(%s, %d)",
		    keyKlassAndSize, size);
	return(NULL);	
    }
    
    return(key);
}
