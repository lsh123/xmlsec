/**
 *
 * XMLSec library
 *
 *
 * See Copyright for the status of this software.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#if defined(_MSC_VER) && _MSC_VER < 1900
#define snprintf _snprintf
#endif

#include <string.h>
#include <stdlib.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include "crypto.h"

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(param)   ((void)(param))
#endif /* UNREFERENCED_PARAMETER */

int
xmlSecAppCryptoInit(const char* config) {
    if(xmlSecCryptoAppInit(config) < 0) {
        fprintf(stderr, "Error: xmlSecCryptoAppInit failed\n");
        return(-1);
    }
    if(xmlSecCryptoInit() < 0) {
        fprintf(stderr, "Error: xmlSecCryptoInit failed\n");
        return(-1);
    }

    return(0);
}

int
xmlSecAppCryptoShutdown(void) {
    if(xmlSecCryptoShutdown() < 0) {
        fprintf(stderr, "Error: xmlSecCryptoShutdown failed\n");
        return(-1);
    }

    if(xmlSecCryptoAppShutdown() < 0) {
        fprintf(stderr, "Error: xmlSecCryptoAppShutdown failed\n");
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

    UNREFERENCED_PARAMETER(format);
    UNREFERENCED_PARAMETER(type);

    fprintf(stderr, "Error: X509 support is disabled\n");
    return(-1);
#endif /* XMLSEC_NO_X509 */
}


int
xmlSecAppCryptoSimpleKeysMngrCrlLoad(xmlSecKeysMngrPtr mngr, const char *filename, xmlSecKeyDataFormat format) {
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);

#ifndef XMLSEC_NO_X509

    return(xmlSecCryptoAppKeysMngrCrlLoad(mngr, filename, format));

#else /* XMLSEC_NO_X509 */

    UNREFERENCED_PARAMETER(format);

    fprintf(stderr, "Error: X509 support is disabled\n");
    return(-1);
#endif /* XMLSEC_NO_X509 */
}

int
xmlSecAppCryptoSimpleKeysMngrKeyAndCertsLoad(xmlSecKeysMngrPtr mngr,
    const char* files, const char* pwd, const char* name,
    xmlSecKeyDataType type, xmlSecKeyDataFormat format,
    xmlSecKeyInfoCtxPtr keyInfoCtx, int verifyKey
) {
    const char* cert_file;
    xmlSecKeyPtr key;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(files != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    /* first is the key file */
    key = xmlSecCryptoAppKeyLoadEx(files, type, format, pwd, xmlSecCryptoAppGetDefaultPwdCallback(), (void*)files);
    if(key == NULL) {
        fprintf(stderr, "Error: xmlSecCryptoAppKeyLoadEx failed: file=%s\n",
                xmlSecErrorsSafeString(files));
        return(-1);
    }

    if(name != NULL) {
        ret = xmlSecKeySetName(key, BAD_CAST name);
        if(ret < 0) {
            fprintf(stderr, "Error: xmlSecKeySetName failed: name=%s\n",
                    xmlSecErrorsSafeString(name));
            xmlSecKeyDestroy(key);
            return(-1);
        }
    }

#ifndef XMLSEC_NO_X509
    for(cert_file = files + strlen(files) + 1; (cert_file[0] != '\0'); cert_file += strlen(cert_file) + 1) {
        ret = xmlSecCryptoAppKeyCertLoad(key, cert_file, format);
        if(ret < 0) {
            fprintf(stderr, "Error: xmlSecCryptoAppKeyCertLoad failed: file=%s\n",
                    xmlSecErrorsSafeString(cert_file));
            xmlSecKeyDestroy(key);
            return(-1);
        }
    }
#else /* XMLSEC_NO_X509 */
    cert_file = files + strlen(files) + 1;
    if(cert_file[0] != '\0') {
        fprintf(stderr, "Error: X509 support is disabled\n");
        return(-1);
    }
#endif /* XMLSEC_NO_X509 */


    if(verifyKey != 0) {
        ret = xmlSecCryptoAppDefaultKeysMngrVerifyKey(mngr, key, keyInfoCtx);
        if(ret < 0) {
            fprintf(stderr, "Error: xmlSecCryptoAppDefaultKeysMngrVerifyKey failed: filename='%s'\n",
            xmlSecErrorsSafeString(files));
            xmlSecKeyDestroy(key);
            return(-1);
        } else if(ret != 1) {
            fprintf(stderr, "Error: key cannot be verified: filename='%s'\n",
            xmlSecErrorsSafeString(files));
            xmlSecKeyDestroy(key);
            return(-1);
        }
    }

    ret = xmlSecCryptoAppDefaultKeysMngrAdoptKey(mngr, key);
    if(ret < 0) {
        fprintf(stderr, "Error: xmlSecCryptoAppDefaultKeysMngrAdoptKey failed\n");
        xmlSecKeyDestroy(key);
        return(-1);
    }

    return(0);
}

int
xmlSecAppCryptoSimpleKeysMngrEngineKeyAndCertsLoad(xmlSecKeysMngrPtr mngr,
    const char* engineAndKeyId, const char* certFiles,
    const char* pwd, const char* name,
    xmlSecKeyDataType type, xmlSecKeyDataFormat keyFormat, xmlSecKeyDataFormat certFormat,
    xmlSecKeyInfoCtxPtr keyInfoCtx, int verifyKey
) {
    xmlSecKeyPtr key;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(engineAndKeyId != NULL, -1);
    xmlSecAssert2(certFiles != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    /* load key */
    key = xmlSecCryptoAppKeyLoadEx(engineAndKeyId, type, keyFormat, pwd,
        xmlSecCryptoAppGetDefaultPwdCallback(), (void*)engineAndKeyId);
    if(key == NULL) {
        fprintf(stderr, "Error: xmlSecCryptoAppKeyLoadEx failed: engineAndKeyId=%s\n",
                xmlSecErrorsSafeString(engineAndKeyId));
        return(-1);
    }

    if(name != NULL) {
        ret = xmlSecKeySetName(key, BAD_CAST name);
        if(ret < 0) {
            fprintf(stderr, "Error: xmlSecKeySetName failed: name=%s\n",
                    xmlSecErrorsSafeString(name));
            xmlSecKeyDestroy(key);
            return(-1);
        }
    }

    /* load certs (if any) */
#ifndef XMLSEC_NO_X509
    for(const char *file = certFiles; (file[0] != '\0'); file += strlen(file) + 1) {
        ret = xmlSecCryptoAppKeyCertLoad(key, file, certFormat);
        if(ret < 0) {
            fprintf(stderr, "Error: xmlSecCryptoAppKeyCertLoad failed: file=%s\n",
                    xmlSecErrorsSafeString(file));
            xmlSecKeyDestroy(key);
            return(-1);
        }
    }
#else /* XMLSEC_NO_X509 */
    UNREFERENCED_PARAMETER(certFormat);

    if(certFiles[0] != '\0') {
        fprintf(stderr, "Error: X509 support is disabled\n");
        xmlSecKeyDestroy(key);
        return(-1);
    }
#endif /* XMLSEC_NO_X509 */

    if(verifyKey != 0) {
        ret = xmlSecCryptoAppDefaultKeysMngrVerifyKey(mngr, key, keyInfoCtx);
        if(ret < 0) {
            fprintf(stderr, "Error: xmlSecCryptoAppDefaultKeysMngrVerifyKey failed: engineAndKeyId='%s'\n",
            xmlSecErrorsSafeString(engineAndKeyId));
            xmlSecKeyDestroy(key);
            return(-1);
        } else if(ret != 1) {
            fprintf(stderr, "Error: key cannot be verified: engineAndKeyId='%s'\n",
            xmlSecErrorsSafeString(engineAndKeyId));
            xmlSecKeyDestroy(key);
            return(-1);
        }
    }

    /* add key to KM */
    ret = xmlSecCryptoAppDefaultKeysMngrAdoptKey(mngr, key);
    if(ret < 0) {
        fprintf(stderr, "Error: xmlSecCryptoAppDefaultKeysMngrAdoptKey failed\n");
        xmlSecKeyDestroy(key);
        return(-1);
    }

    return(0);
}

int
xmlSecAppCryptoSimpleKeysMngrPkcs12KeyLoad(xmlSecKeysMngrPtr mngr, const char *filename, const char* pwd,
    const char *name, xmlSecKeyInfoCtxPtr keyInfoCtx, int verifyKey
) {
#ifndef XMLSEC_NO_X509
    xmlSecKeyPtr key;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    key = xmlSecCryptoAppKeyLoadEx(filename, xmlSecKeyDataTypePrivate, xmlSecKeyDataFormatPkcs12, pwd,
                    xmlSecCryptoAppGetDefaultPwdCallback(), (void*)filename);
    if(key == NULL) {
        fprintf(stderr, "Error: xmlSecCryptoAppKeyLoadEx failed: filename='%s'\n",
                xmlSecErrorsSafeString(filename));
        return(-1);
    }

    if(name != NULL) {
        ret = xmlSecKeySetName(key, BAD_CAST name);
        if(ret < 0) {
            fprintf(stderr, "Error: xmlSecKeySetName failed: name='%s'\n",
                    xmlSecErrorsSafeString(name));
            xmlSecKeyDestroy(key);
            return(-1);
        }
    }

    if(verifyKey != 0) {
            ret = xmlSecCryptoAppDefaultKeysMngrVerifyKey(mngr, key, keyInfoCtx);
            if(ret < 0) {
                fprintf(stderr, "Error: xmlSecCryptoAppDefaultKeysMngrVerifyKey failed: filename='%s'\n",
                xmlSecErrorsSafeString(filename));
                xmlSecKeyDestroy(key);
                return(-1);
            } else if(ret != 1) {
                fprintf(stderr, "Error: key cannot be verified: filename='%s'\n",
                xmlSecErrorsSafeString(filename));
                xmlSecKeyDestroy(key);
                return(-1);
            }
    }

    ret = xmlSecCryptoAppDefaultKeysMngrAdoptKey(mngr, key);
    if(ret < 0) {
        fprintf(stderr, "Error: xmlSecCryptoAppDefaultKeysMngrAdoptKey failed\n");
        xmlSecKeyDestroy(key);
        return(-1);
    }

    return(0);
#else /* XMLSEC_NO_X509 */
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    UNREFERENCED_PARAMETER(pwd);
    UNREFERENCED_PARAMETER(name);
    UNREFERENCED_PARAMETER(verifyKey);

    fprintf(stderr, "Error: X509 support is disabled\n");
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
    dataId = xmlSecKeyDataIdListFindByName(xmlSecKeyDataIdsGet(), BAD_CAST keyKlass, xmlSecKeyDataUsageReadFromFile);
    if(dataId == xmlSecKeyDataIdUnknown) {
        fprintf(stderr, "Error: xmlSecKeyDataIdListFindByName failed keyKlass=%s\n",
                xmlSecErrorsSafeString(keyKlass));
        return(-1);
    }

    key = xmlSecKeyReadBinaryFile(dataId, filename);
    if(key == NULL) {
        fprintf(stderr, "Error: xmlSecKeyReadBinaryFile failed filename=%s\n",
                xmlSecErrorsSafeString(filename));
        return(-1);
    }

    ret = xmlSecKeySetName(key, BAD_CAST name);
    if(ret < 0) {
        fprintf(stderr, "Error: xmlSecKeySetName failed: name=%s\n",
                xmlSecErrorsSafeString(name));
        xmlSecKeyDestroy(key);
        return(-1);
    }

    /* finally add it to keys manager */
    ret = xmlSecCryptoAppDefaultKeysMngrAdoptKey(mngr, key);
    if(ret < 0) {
        fprintf(stderr, "Error: xmlSecCryptoAppDefaultKeysMngrAdoptKey failed\n");
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
        fprintf(stderr, "Error: xmlSecAppCryptoSimpleKeysMngrKeyGenerate failed: name=%s\n",
                xmlSecErrorsSafeString(name));
        return(-1);
    }

    ret = xmlSecCryptoAppDefaultKeysMngrAdoptKey(mngr, key);
    if(ret < 0) {
        fprintf(stderr, "Error: xmlSecCryptoAppDefaultKeysMngrAdoptKey failed\n");
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
        fprintf(stderr, "Error: xmlSecStrdupError(keyKlassAndSize) failed\n");
        return(NULL);
    }

    /* separate key klass and size */
    p = strchr(buf, '-');
    if(p == NULL) {
        fprintf(stderr, "Error: key size is not specified in the key definition \"%s\"\n",
                    xmlSecErrorsSafeString(buf));
        xmlFree(buf);
        return(NULL);
    }
    *(p++) = '\0';
    size = atoi(p);
    if(size <= 0) {
       fprintf(stderr, "Error: key size should be greater than zero \"%s\"\n",
                    xmlSecErrorsSafeString(buf));
        xmlFree(buf);
        return(NULL);
    }

    key = xmlSecKeyGenerateByName(BAD_CAST buf, (xmlSecSize)size, type);
    if(key == NULL) {
        fprintf(stderr, "Error: xmlSecKeyGenerateByName() failed: name=%s;size=%d;type=%u\n",
                xmlSecErrorsSafeString(buf), size, type);
        xmlFree(buf);
        return(NULL);
    }

    ret = xmlSecKeySetName(key, BAD_CAST name);
    if(ret < 0) {
        fprintf(stderr, "Error: xmlSecKeySetName failed: name=%s\n",
                xmlSecErrorsSafeString(name));
        xmlSecKeyDestroy(key);
        xmlFree(buf);
        return(NULL);
    }

    xmlFree(buf);
    return(key);
}
