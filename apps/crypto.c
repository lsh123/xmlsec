/** 
 *
 * XMLSec library
 * 
 * 
 * See Copyright for the status of this software.
 * 
 * Copyright (C) 2002-2016 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#if defined(_MSC_VER) && _MSC_VER < 1900
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
        xmlSecInternalError(NULL, "xmlSecCryptoAppInit");
        return(-1);
    }
    if(xmlSecCryptoInit() < 0) {
        xmlSecInternalError(NULL, "xmlSecCryptoInit");
        return(-1);
    }
    
    return(0);
}

int
xmlSecAppCryptoShutdown(void) {
    if(xmlSecCryptoShutdown() < 0) {
        xmlSecInternalError(NULL, "xmlSecCryptoShutdown");
        return(-1);
    }

    if(xmlSecCryptoAppShutdown() < 0) {
        xmlSecInternalError(NULL, "xmlSecCryptoAppShutdown");
        return(-1);
    }
    return(0);
}

int
xmlSecAppCryptoSimpleKeysMngrInit(xmlSecKeysMngrPtr mngr) {
    xmlSecAssert2(mngr != NULL, -1);

    return(xmlSecCryptoAppDefaultKeysMngrInit(mngr));
}

int
xmlSecAppCryptoSimpleKeysMngrLoad(xmlSecKeysMngrPtr mngr, const char *filename) {
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    
    return(xmlSecCryptoAppDefaultKeysMngrLoad(mngr, filename));
}

int 
xmlSecAppCryptoSimpleKeysMngrSave(xmlSecKeysMngrPtr mngr, const char *filename, xmlSecKeyDataType type) {
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    
    return(xmlSecCryptoAppDefaultKeysMngrSave(mngr, filename, type));
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
xmlSecAppCryptoSimpleKeysMngrKeyAndCertsLoad(xmlSecKeysMngrPtr mngr, 
                                             const char* files, const char* pwd, 
                                             const char* name, 
                                             xmlSecKeyDataFormat format) {
    xmlSecKeyPtr key;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(files != NULL, -1);

    /* first is the key file */
    key = xmlSecCryptoAppKeyLoad(files, format, pwd, 
                xmlSecCryptoAppGetDefaultPwdCallback(), (void*)files);
    if(key == NULL) {
        xmlSecInternalError(files, "xmlSecCryptoAppKeyLoad");
        return(-1);
    }
    
    if(name != NULL) {
        ret = xmlSecKeySetName(key, BAD_CAST name);
        if(ret < 0) {
            xmlSecInternalError(name, "xmlSecKeySetName");
            xmlSecKeyDestroy(key);
            return(-1);
        }
    }

#ifndef XMLSEC_NO_X509     
    for(files += strlen(files) + 1; (files[0] != '\0'); files += strlen(files) + 1) {
        ret = xmlSecCryptoAppKeyCertLoad(key, files, format);
        if(ret < 0) {
            xmlSecInternalError(files, "xmlSecCryptoAppKeyCertLoad");
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

    ret = xmlSecCryptoAppDefaultKeysMngrAdoptKey(mngr, key);
    if(ret < 0) {
        xmlSecInternalError(NULL, "xmlSecCryptoAppDefaultKeysMngrAdoptKey");
        xmlSecKeyDestroy(key);
        return(-1);
    }
    
    return(0);
}


int 
xmlSecAppCryptoSimpleKeysMngrPkcs12KeyLoad(xmlSecKeysMngrPtr mngr, const char *filename, const char* pwd, const char *name) {
    xmlSecKeyPtr key;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);

#ifndef XMLSEC_NO_X509
    key = xmlSecCryptoAppKeyLoad(filename, xmlSecKeyDataFormatPkcs12, pwd, 
                    xmlSecCryptoAppGetDefaultPwdCallback(), (void*)filename);
    if(key == NULL) {
        xmlSecInternalError(filename, "xmlSecCryptoAppKeyLoad");
        return(-1);
    }
        
    if(name != NULL) {
        ret = xmlSecKeySetName(key, BAD_CAST name);
        if(ret < 0) {   
            xmlSecInternalError(name, "xmlSecKeySetName");
            xmlSecKeyDestroy(key);
            return(-1);
        }
    }
    
    ret = xmlSecCryptoAppDefaultKeysMngrAdoptKey(mngr, key);
    if(ret < 0) {
        xmlSecInternalError(NULL, "xmlSecCryptoAppDefaultKeysMngrAdoptKey");
        xmlSecKeyDestroy(key);
        return(-1);
    }
    
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
        xmlSecInternalError(keyKlass, "xmlSecKeyDataIdListFindByName");
        return(-1);    
    }

    key = xmlSecKeyReadBinaryFile(dataId, filename);
    if(key == NULL) {
        xmlSecInternalError(NULL, "xmlSecKeyReadBinaryFile");
        return(-1);    
    }
    
    ret = xmlSecKeySetName(key, BAD_CAST name);
    if(ret < 0) {
        xmlSecInternalError(name, "xmlSecKeySetName");
        xmlSecKeyDestroy(key);
        return(-1);    
    }

    /* finally add it to keys manager */    
    ret = xmlSecCryptoAppDefaultKeysMngrAdoptKey(mngr, key);
    if(ret < 0) {
        xmlSecInternalError(NULL, "xmlSecCryptoAppDefaultKeysMngrAdoptKey");
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
        xmlSecInternalError(name, "xmlSecAppCryptoSimpleKeysMngrKeyGenerate");
        return(-1);    
    }    

    ret = xmlSecCryptoAppDefaultKeysMngrAdoptKey(mngr, key);
    if(ret < 0) {
        xmlSecInternalError(NULL, "xmlSecCryptoAppDefaultKeysMngrAdoptKey");
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
                    NULL,
                    XMLSEC_ERRORS_R_STRDUP_FAILED,
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
        xmlSecInternalError(keyKlassAndSize, "xmlSecKeyGenerate");
        xmlFree(buf);
        return(NULL);   
    }
    
    ret = xmlSecKeySetName(key, BAD_CAST name);
    if(ret < 0) {
        xmlSecInternalError(name, "xmlSecKeySetName");
        xmlSecKeyDestroy(key);
        xmlFree(buf);
        return(NULL);
    }
    
    xmlFree(buf);
    return(key);
}
