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
xmlSecAppCryptoInit(const char* config) {
    if(xmlSecCryptoAppInit(config) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecCryptoAppInit",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if(xmlSecCryptoInit() < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecCryptoInit",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    return(0);
}

int
xmlSecAppCryptoShutdown(void) {
    if(xmlSecCryptoShutdown() < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecCryptoShutdown",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    if(xmlSecCryptoAppShutdown() < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecCryptoAppShutdown",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    return(0);
}

int
xmlSecAppCryptoSimpleKeysMngrInit(xmlSecKeysMngrPtr mngr) {
    xmlSecAssert2(mngr != NULL, -1);

    return(xmlSecCryptoAppSimpleKeysMngrInit(mngr));
}

int
xmlSecAppCryptoSimpleKeysMngrLoad(xmlSecKeysMngrPtr mngr, const char *filename) {
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    
    return(xmlSecCryptoAppSimpleKeysMngrLoad(mngr, filename));
}

int 
xmlSecAppCryptoSimpleKeysMngrSave(xmlSecKeysMngrPtr mngr, const char *filename, xmlSecKeyDataType type) {
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    
    return(xmlSecCryptoAppSimpleKeysMngrSave(mngr, filename, type));
}

int 
xmlSecAppCryptoSimpleKeysMngrCertLoad(xmlSecKeysMngrPtr mngr, const char *filename, 
				      xmlSecKeyDataFormat format, xmlSecKeyDataType type) {
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);

#ifndef XMLSEC_NO_X509	    
    return(xmlSecCryptoAppKeysMngrCertLoad(mngr, filename, format, type));
#else /* XMLSEC_NO_X509 */
    return(-1);
#endif /* XMLSEC_NO_X509 */    
}


int 
xmlSecAppCryptoSimpleKeysMngrPemKeyAndCertsLoad(xmlSecKeysMngrPtr mngr, 
					     const char* files, const char* pwd, 
					     const char* name) {
    xmlSecKeyPtr key;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(files != NULL, -1);

    /* first is the key file */
    key = xmlSecCryptoAppKeyLoad(files, xmlSecKeyDataFormatPem, pwd, NULL, NULL);
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecCryptoAppKeyLoad",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "uri=%s", 
		    xmlSecErrorsSafeString(files));
	return(-1);
    }
    
    if(name != NULL) {
	ret = xmlSecKeySetName(key, BAD_CAST name);
	if(ret < 0) {	
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecKeySetName",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"name=%s", 
			xmlSecErrorsSafeString(name));
	    xmlSecKeyDestroy(key);
	    return(-1);
	}
    }

#ifndef XMLSEC_NO_X509     
    for(files += strlen(files) + 1; (files[0] != '\0'); files += strlen(files) + 1) {
	ret = xmlSecCryptoAppKeyCertLoad(key, files, xmlSecKeyDataFormatPem);
	if(ret < 0){
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecCryptoAppKeyCertLoad",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"uri=%s", 
			xmlSecErrorsSafeString(files));
	    xmlSecKeyDestroy(key);
	    return(-1);
	}
    }
#else /* XMLSEC_NO_X509 */
    files += strlen(files) + 1;
    if(files[0] != '\0') {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "x509",
		    XMLSEC_ERRORS_R_DISABLED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_X509 */        

    ret = xmlSecCryptoAppSimpleKeysMngrAdoptKey(mngr, key);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecCryptoAppSimpleKeysMngrAdoptKey",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
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
#ifdef XMLSEC_CRYPTO_OPENSSL
    if(pwd == NULL) {
	snprintf(prompt, sizeof(prompt), "Password for pkcs12 file \"%s\": ", filename); 
	ret = EVP_read_pw_string(buf, sizeof(buf), prompt, 0);
	if(ret != 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"EVP_read_pw_string",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	pwd = buf;
    } 

    key = xmlSecCryptoAppPkcs12Load(filename, pwd, NULL, NULL);
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecCryptoAppPkcs12Load",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "filename=%s",
		    xmlSecErrorsSafeString(filename));
	memset(buf, 0, sizeof(buf));
	return(-1);
    }
    memset(buf, 0, sizeof(buf));
        
    if(name != NULL) {
	ret = xmlSecKeySetName(key, BAD_CAST name);
	if(ret < 0) {	
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecKeySetName",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"name=%s",
			xmlSecErrorsSafeString(name));			
	    xmlSecKeyDestroy(key);
	    return(-1);
	}
    }
    
    ret = xmlSecCryptoAppSimpleKeysMngrAdoptKey(mngr, key);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecCryptoAppSimpleKeysMngrAdoptKey",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecKeyDestroy(key);
	return(-1);
    }
#endif /* XMLSEC_CRYPTO_OPENSSL */
    
    return(0);
#else /* XMLSEC_NO_X509 */
    xmlSecError(XMLSEC_ERRORS_HERE,
		NULL,
		"x509",
		XMLSEC_ERRORS_R_DISABLED,
		XMLSEC_ERRORS_NO_MESSAGE);
    return(-1);
#endif /* XMLSEC_NO_X509 */
}

int 
xmlSecAppCryptoSimpleKeysMngrBinaryKeyLoad(xmlSecKeysMngrPtr mngr, const char* keyKlass, const char *filename, const char *name) {
    xmlSecKeyPtr key;
    xmlSecKeyDataId dataId;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(keyKlass != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);

    /* find requested data */
    dataId = xmlSecKeyDataIdListFindByName(xmlSecKeyDataIdsGet(), BAD_CAST keyKlass, 
					   xmlSecKeyDataUsageAny);
    if(dataId == xmlSecKeyDataIdUnknown) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeyDataIdListFindByName",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "name=%s",
		    xmlSecErrorsSafeString(keyKlass));
	return(-1);    
    }

    key = xmlSecKeyReadBinaryFile(dataId, filename);
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeyReadBinaryFile",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);    
    }
    
    ret = xmlSecKeySetName(key, BAD_CAST name);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeySetName",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "name=%s",
		    xmlSecErrorsSafeString(name));
	xmlSecKeyDestroy(key);
	return(-1);    
    }

    /* finally add it to keys manager */    
    ret = xmlSecCryptoAppSimpleKeysMngrAdoptKey(mngr, key);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecCryptoAppSimpleKeysMngrAdoptKey",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecKeyDestroy(key);
	return(-1);
    }

    return(0);
}


int 
xmlSecAppCryptoSimpleKeysMngrKeyGenerate(xmlSecKeysMngrPtr mngr, const char* keyKlassAndSize, const char* name) {
    xmlSecKeyPtr key;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(keyKlassAndSize != NULL, -1);
    
    key = xmlSecAppCryptoKeyGenerate(keyKlassAndSize, name, xmlSecKeyDataTypePermanent);
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAppCryptoSimpleKeysMngrKeyGenerate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "name=%s",
		    xmlSecErrorsSafeString(name));
	return(-1);    
    }    

    ret = xmlSecCryptoAppSimpleKeysMngrAdoptKey(mngr, key);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecCryptoAppSimpleKeysMngrAdoptKey",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecKeyDestroy(key);
	return(-1);
    }
    return(0);
}

xmlSecKeyPtr 
xmlSecAppCryptoKeyGenerate(const char* keyKlassAndSize, const char* name, xmlSecKeyDataType type) {
    xmlSecKeyPtr key;
    char* buf;
    char* p;
    int size;
    int ret;
    
    xmlSecAssert2(keyKlassAndSize != NULL, NULL);

    buf = (char*) xmlStrdup(BAD_CAST keyKlassAndSize);
    if(buf == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "strdup",
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "name=%s",
		    xmlSecErrorsSafeString(name));
	return(NULL);    
    }
        
    /* separate key klass and size */
    p = strchr(buf, '-');
    if(p == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_DATA,
		    "key size is not specified %s", 
		    xmlSecErrorsSafeString(buf));
	xmlFree(buf);
	return(NULL);
    }
    *(p++) = '\0';
    size = atoi(p);
    
    key = xmlSecKeyGenerateByName(BAD_CAST buf, size, type);
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeyGenerate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "klass=%s;size=%d",
		    xmlSecErrorsSafeString(buf), 
		    size);
	xmlFree(buf);
	return(NULL);	
    }
    
    ret = xmlSecKeySetName(key, BAD_CAST name);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeySetName",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "name=\"%s\"", 
		    xmlSecErrorsSafeString(name));
	xmlSecKeyDestroy(key);
	xmlFree(buf);
	return(NULL);
    }
    
    xmlFree(buf);
    return(key);
}
