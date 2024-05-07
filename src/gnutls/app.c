/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:app
 * @Short_description: Application support functions for GnuTLS.
 * @Stability: Stable
 *
 * Common functions for xmlsec1 command line utility tool for GnuTLS.
 */

#include "globals.h"

#include <string.h>

#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>
#include <xmlsec/transforms.h>

#include <xmlsec/gnutls/app.h>
#include <xmlsec/gnutls/crypto.h>
#include <xmlsec/gnutls/keysstore.h>
#include <xmlsec/gnutls/x509.h>

#include "../cast_helpers.h"
#include "private.h"


static xmlSecKeyPtr     xmlSecGnuTLSAppPemDerKeyLoadMemory      (const xmlSecByte * data,
                                                                 xmlSecSize dataSize,
                                                                 gnutls_x509_crt_fmt_t fmt);

static xmlSecKeyPtr     xmlSecGnuTLSAppPkcs8KeyLoadMemory       (const xmlSecByte * data,
                                                                 xmlSecSize dataSize,
                                                                 gnutls_x509_crt_fmt_t fmt,
                                                                 const char *pwd,
                                                                 void* pwdCallback,
                                                                 void* pwdCallbackCtx);

#ifndef XMLSEC_NO_X509
static xmlSecKeyPtr     xmlSecGnuTLSAppKeyFromCertLoadMemory    (const xmlSecByte* data,
                                                                 xmlSecSize dataSize,
                                                                 xmlSecKeyDataFormat format);
#endif /* XMLSEC_NO_X509 */


/**
 * xmlSecGnuTLSAppInit:
 * @config:             the path to GnuTLS configuration (unused).
 *
 * General crypto engine initialization. This function is used
 * by XMLSec command line utility and called before
 * @xmlSecInit function.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSAppInit(const char* config ATTRIBUTE_UNUSED) {
    int err;

    err = gnutls_global_init();
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_global_init", err, NULL);
        return(-1);
    }

    return(0);
}

/**
 * xmlSecGnuTLSAppShutdown:
 *
 * General crypto engine shutdown. This function is used
 * by XMLSec command line utility and called after
 * @xmlSecShutdown function.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSAppShutdown(void) {
    gnutls_global_deinit();
    return(0);
}

/**
 * xmlSecGnuTLSAppKeyLoadEx:
 * @filename:           the key filename.
 * @type:               the expected key type.
 * @format:             the key file format.
 * @pwd:                the key file password.
 * @pwdCallback:        the key password callback.
 * @pwdCallbackCtx:     the user context for password callback.
 *
 * Reads key from the a file.
 *
 * Returns: pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecGnuTLSAppKeyLoadEx(const char *filename, xmlSecKeyDataType type ATTRIBUTE_UNUSED, xmlSecKeyDataFormat format,
    const char *pwd, void* pwdCallback, void* pwdCallbackCtx
) {
    xmlSecKeyPtr key;
    xmlSecBuffer buffer;
    xmlSecByte * data;
    xmlSecSize dataSize;
    int ret;

    xmlSecAssert2(filename != NULL, NULL);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, NULL);
    UNREFERENCED_PARAMETER(type);

    /* read file into memory */
    ret = xmlSecBufferInitialize(&buffer, 4*1024);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", NULL);
        return(NULL);
    }
    ret = xmlSecBufferReadFile(&buffer, filename);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferReadFile", NULL,
            "filename=%s", xmlSecErrorsSafeString(filename));
        xmlSecBufferFinalize(&buffer);
        return(NULL);
    }
    data = xmlSecBufferGetData(&buffer);
    dataSize = xmlSecBufferGetSize(&buffer);
    if((data == NULL) || (dataSize <= 0)) {
        xmlSecInternalError2("xmlSecBufferReadFile", NULL,
            "filename=%s", xmlSecErrorsSafeString(filename));
        xmlSecBufferFinalize(&buffer);
        return(NULL);
    }

    /* read key */
    key = xmlSecGnuTLSAppKeyLoadMemory(data, dataSize, format, pwd, pwdCallback, pwdCallbackCtx);
    if(key == NULL) {
        xmlSecInternalError2("xmlSecGnuTLSAppKeyLoadMemory", NULL,
            "filename=%s", xmlSecErrorsSafeString(filename));
        xmlSecBufferFinalize(&buffer);
        return(NULL);
    }

    /* success */
    xmlSecBufferFinalize(&buffer);
    return(key);
}

/**
 * xmlSecGnuTLSAppKeyLoadMemory:
 * @data:               the binary key data.
 * @dataSize:           the size of binary key.
 * @format:             the key file format.
 * @pwd:                the key file password.
 * @pwdCallback:        the key password callback.
 * @pwdCallbackCtx:     the user context for password callback.
 *
 * Reads key from the memory buffer.
 *
 * Returns: pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecGnuTLSAppKeyLoadMemory(const xmlSecByte* data, xmlSecSize dataSize,  xmlSecKeyDataFormat format,
    const char *pwd, void* pwdCallback, void* pwdCallbackCtx)
{
    xmlSecKeyPtr key;

    xmlSecAssert2(data != NULL, NULL);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, NULL);

    switch(format) {
    /* "raw" pem / der keys */
    case xmlSecKeyDataFormatPem:
        key = xmlSecGnuTLSAppPemDerKeyLoadMemory(data, dataSize, GNUTLS_X509_FMT_PEM);
        break;
    case xmlSecKeyDataFormatDer:
        key = xmlSecGnuTLSAppPemDerKeyLoadMemory(data, dataSize, GNUTLS_X509_FMT_DER);
        break;

    case xmlSecKeyDataFormatPkcs8Pem:
        key = xmlSecGnuTLSAppPkcs8KeyLoadMemory(data, dataSize, GNUTLS_X509_FMT_PEM, pwd, pwdCallback, pwdCallbackCtx);
        break;
    case xmlSecKeyDataFormatPkcs8Der:
        key = xmlSecGnuTLSAppPkcs8KeyLoadMemory(data, dataSize, GNUTLS_X509_FMT_DER, pwd, pwdCallback, pwdCallbackCtx);
        break;

#ifndef XMLSEC_NO_X509
    case xmlSecKeyDataFormatPkcs12:
        key = xmlSecGnuTLSAppPkcs12LoadMemory(data, dataSize, pwd, pwdCallback, pwdCallbackCtx);
        break;
    case xmlSecKeyDataFormatCertPem:
    case xmlSecKeyDataFormatCertDer:
        key = xmlSecGnuTLSAppKeyFromCertLoadMemory(data, dataSize, format);
        break;
#endif /* XMLSEC_NO_X509 */
    default:
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_FORMAT, NULL,
            "format=" XMLSEC_ENUM_FMT, XMLSEC_ENUM_CAST(format));
        return(NULL);
    }

    /* done */
    return(key);
}

#ifndef XMLSEC_NO_X509

/**
 * xmlSecGnuTLSAppKeyCertLoad:
 * @key:                the pointer to key.
 * @filename:           the certificate filename.
 * @format:             the certificate file format.
 *
 * Reads the certificate from $@filename and adds it to key.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSAppKeyCertLoad(xmlSecKeyPtr key, const char* filename, xmlSecKeyDataFormat format) {
    xmlSecBuffer buffer;
    int ret;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    ret = xmlSecBufferInitialize(&buffer, 4*1024);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", NULL);
        return(-1);
    }

    ret = xmlSecBufferReadFile(&buffer, filename);
    if((ret < 0) || (xmlSecBufferGetData(&buffer) == NULL) || (xmlSecBufferGetSize(&buffer) <= 0)) {
        xmlSecInternalError2("xmlSecBufferReadFile", NULL,
                             "filename=%s", xmlSecErrorsSafeString(filename));
        xmlSecBufferFinalize(&buffer);
        return(-1);
    }

    ret = xmlSecGnuTLSAppKeyCertLoadMemory(key,
                    xmlSecBufferGetData(&buffer),
                    xmlSecBufferGetSize(&buffer),
                    format);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecGnuTLSAppKeyCertLoadMemory", NULL,
                             "filename=%s", xmlSecErrorsSafeString(filename));
        xmlSecBufferFinalize(&buffer);
        return(-1);
    }

    /* cleanup */
    xmlSecBufferFinalize(&buffer);
    return(0);
}


/* returns 1 if matches, 0 if not, or a negative value on error */
static int
xmlSecGnuTLSAppCheckCertMatchesKey(xmlSecKeyPtr key,  gnutls_x509_crt_t cert) {
    xmlSecKeyDataPtr keyData = NULL;
    gnutls_pubkey_t pubkey = NULL;
    gnutls_pubkey_t cert_pubkey = NULL;
    gnutls_datum_t der_pubkey = { NULL, 0 };
    gnutls_datum_t der_cert_pubkey = { NULL, 0 };
    int err;
    int res = -1;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(cert != NULL, -1);

    /* get key's pubkey and its der encoding */
    keyData = xmlSecKeyGetValue(key);
    if(keyData == NULL) {
        res = 0; /* no key -> no match */
        goto done;
    }
    pubkey = xmlSecGnuTLSAsymKeyDataGetPublicKey(keyData);
    if(pubkey == NULL) {
        xmlSecInternalError("xmlSecGnuTLSAsymKeyDataGetPublicKey", NULL);
        goto done;
    }
    err = gnutls_pubkey_export2(pubkey, GNUTLS_X509_FMT_DER, &der_pubkey);
    if((err != GNUTLS_E_SUCCESS) || (der_pubkey.data == NULL)) {
        xmlSecGnuTLSError("gnutls_pubkey_export2", err, NULL);
        goto done;
    }

    /* get certs's pubkey and its der encoding */
    err = gnutls_pubkey_init(&cert_pubkey);
    if (err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_pubkey_init", err, NULL);
        goto done;
    }

    err = gnutls_pubkey_import_x509(cert_pubkey, cert, 0);
    if (err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_pubkey_import_x509", err, NULL);
        goto done;
    }
    err = gnutls_pubkey_export2(cert_pubkey, GNUTLS_X509_FMT_DER, &der_cert_pubkey);
    if((err != GNUTLS_E_SUCCESS) || (der_cert_pubkey.data == NULL)) {
        xmlSecGnuTLSError("gnutls_pubkey_export2", err, NULL);
        goto done;
    }

    /* compare */
    if(der_pubkey.size != der_cert_pubkey.size) {
        res = 0; /* different size -> no match */
        goto done;
    }
    if(memcmp(der_pubkey.data, der_cert_pubkey.data, der_pubkey.size) != 0) {
        res = 0; /* different data -> no match */
        goto done;
    }

    /* match! */
    res = 1;

done:
    if (cert_pubkey) {
        gnutls_pubkey_deinit(cert_pubkey);
    }
    if(der_pubkey.data != NULL) {
        gnutls_free(der_pubkey.data);
    }
    if(der_cert_pubkey.data != NULL) {
        gnutls_free(der_cert_pubkey.data);
    }
    return(res);
}


/**
 * xmlSecGnuTLSAppKeyCertLoadMemory:
 * @key:                the pointer to key.
 * @data:               the certificate binary data.
 * @dataSize:           the certificate binary data size.
 * @format:             the certificate file format.
 *
 * Reads the certificate from memory buffer and adds it to key.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSAppKeyCertLoadMemory(xmlSecKeyPtr key, const xmlSecByte* data, xmlSecSize dataSize,
    xmlSecKeyDataFormat format
) {
    gnutls_x509_crt_t cert = NULL;
    xmlSecKeyDataPtr x509Data;
    int isKeyCert = 0;
    int ret;
    int res = -1;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(dataSize > 0, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    /* read cert */
    cert = xmlSecGnuTLSX509CertRead(data, dataSize, format);
    if(cert == NULL) {
        xmlSecInternalError("xmlSecGnuTLSX509CertRead", NULL);
        goto done;
    }

    /* add cert to key */
    x509Data = xmlSecKeyEnsureData(key, xmlSecGnuTLSKeyDataX509Id);
    if(x509Data == NULL) {
        xmlSecInternalError("xmlSecKeyEnsureData", NULL);
        goto done;
    }

    /* do we want to add this cert as a key cert? */
    if(xmlSecGnuTLSKeyDataX509GetKeyCert(x509Data) == NULL) {
        ret = xmlSecGnuTLSAppCheckCertMatchesKey(key, cert);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGnuTLSAppCheckCertMatchesKey", NULL);
            goto done;
        }
        if(ret == 1) {
            isKeyCert = 1;
        }
    }
    if(isKeyCert != 0) {
        ret = xmlSecGnuTLSKeyDataX509AdoptKeyCert(x509Data, cert);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGnuTLSKeyDataX509AdoptKeyCert", NULL);
            goto done;
        }
    } else {
        ret = xmlSecGnuTLSKeyDataX509AdoptCert(x509Data, cert);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGnuTLSKeyDataX509AdoptCert", NULL);
            goto done;
        }
    }
    cert = NULL; /* owned by x509Data now */

    /* success */
    res = 0;

done:
    if(cert != NULL) {
        gnutls_x509_crt_deinit(cert);
    }
    return(res);
}

/**
 * xmlSecGnuTLSAppPkcs12Load:
 * @filename:           the PKCS12 key filename.
 * @pwd:                the PKCS12 file password.
 * @pwdCallback:        the password callback.
 * @pwdCallbackCtx:     the user context for password callback.
 *
 * Reads key and all associated certificates from the PKCS12 file.
 * For uniformity, call @xmlSecGnuTLSAppKeyLoadEx instead of this function. Pass
 * in format=xmlSecKeyDataFormatPkcs12.
 *
 * Returns: pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecGnuTLSAppPkcs12Load(const char *filename,
                          const char *pwd,
                          void* pwdCallback,
                          void* pwdCallbackCtx) {
    return(xmlSecGnuTLSAppKeyLoadEx(filename, xmlSecKeyDataTypePrivate, xmlSecKeyDataFormatPkcs12,
        pwd, pwdCallback, pwdCallbackCtx));
}

/**
 * xmlSecGnuTLSAppPkcs12LoadMemory:
 * @data:               the PKCS12 binary data.
 * @dataSize:           the PKCS12 binary data size.
 * @pwd:                the PKCS12 file password.
 * @pwdCallback:        the password callback.
 * @pwdCallbackCtx:     the user context for password callback.
 *
 * Reads key and all associated certificates from the PKCS12 data in memory buffer.
 * For uniformity, call xmlSecGnuTLSAppKeyLoadMemory instead of this function. Pass
 * in format=xmlSecKeyDataFormatPkcs12.
 *
 * Returns: pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecGnuTLSAppPkcs12LoadMemory(const xmlSecByte* data, xmlSecSize dataSize,
    const char *pwd, void* pwdCallback ATTRIBUTE_UNUSED, void* pwdCallbackCtx ATTRIBUTE_UNUSED
) {
    xmlSecKeyPtr key = NULL;
    xmlSecKeyPtr res = NULL;
    xmlSecPtrList certsList;
    xmlSecKeyDataPtr x509Data = NULL;
    gnutls_x509_privkey_t x509_privkey = NULL;
    gnutls_privkey_t privkey = NULL;
    gnutls_x509_crt_t key_cert = NULL;
    xmlChar * keyName = NULL;
    xmlSecSize certsSize;
    int err;
    int ret;

    xmlSecAssert2(data != NULL, NULL);
    xmlSecAssert2(dataSize > 0, NULL);

    /* prepare */
    ret = xmlSecPtrListInitialize(&(certsList), xmlSecGnuTLSX509CrtListId);
    if(ret < 0) {
        xmlSecInternalError("xmlSecPtrListInitialize(certsListId)", NULL);
        return(NULL);
    }

    /* load pkcs12 */
    ret = xmlSecGnuTLSPkcs12LoadMemory(data, dataSize, pwd, &x509_privkey, &key_cert, &certsList, &keyName);
    if((ret < 0) || (x509_privkey == NULL)) {
        xmlSecInternalError("xmlSecGnuTLSPkcs12LoadMemory", NULL);
        goto done;
    }

    /* convert x509 privkey to privkey */
    err = gnutls_privkey_init(&privkey);
    if (err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_privkey_init", err, NULL);
        goto done;
    }

    err = gnutls_privkey_import_x509(privkey, x509_privkey, GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE);
    if (err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_privkey_import_x509", err, NULL);
       goto done;
    }
    x509_privkey = NULL; /* owned by privkey now */


    /* create key */
    key = xmlSecGCryptAsymetricKeyCreatePriv(privkey);
    if(key == NULL) {
        xmlSecInternalError("xmlSecGCryptAsymetricKeyCreatePriv", NULL);
        goto done;
    }
    privkey = NULL; /* owned by key now */

    /* set key name */
    if(keyName != NULL) {
        ret = xmlSecKeySetName(key, keyName);
        if(ret < 0) {
            xmlSecInternalError("xmlSecKeySetName", NULL);
            goto done;
        }
    }

    /* create x509 certs data */
    certsSize = xmlSecPtrListGetSize(&certsList);
    if((certsSize > 0) || (key_cert != NULL)) {
        xmlSecSize ii;

        x509Data = xmlSecKeyDataCreate(xmlSecGnuTLSKeyDataX509Id);
        if(x509Data == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(xmlSecGnuTLSKeyDataX509Id)", NULL);
            goto done;
        }

        /* set key's cert */
        if(key_cert != NULL) {
            ret = xmlSecGnuTLSKeyDataX509AdoptKeyCert(x509Data, key_cert);
            if(ret < 0) {
                xmlSecInternalError("xmlSecGnuTLSKeyDataX509AdoptKeyCert", NULL);
                goto done;
            }
            key_cert = NULL; /* owned by x509Data now */
        }

        /* copy all other certs */
        for(ii = 0; ii < certsSize; ++ii) {
            gnutls_x509_crt_t cert = xmlSecPtrListRemoveAndReturn(&certsList, ii);
            if(cert == NULL) {
                continue;
            }

            ret = xmlSecGnuTLSKeyDataX509AdoptCert(x509Data, cert);
            if(ret < 0) {
                xmlSecInternalError("xmlSecGnuTLSKeyDataX509AdoptCert", NULL);
                gnutls_x509_crt_deinit(cert);
                goto done;
            }
        }

        /* set in the key */
        ret = xmlSecKeyAdoptData(key, x509Data);
        if(ret < 0) {
            xmlSecInternalError("xmlSecKeyAdoptData",
                                xmlSecKeyDataGetName(x509Data));
            goto done;
        }
        x509Data = NULL; /* owned by key now */
    }

    /* success!!! */
    res = key;
    key = NULL;

done:
    if(keyName != NULL) {
        xmlFree(keyName);
    }
    if(key_cert != NULL) {
        gnutls_x509_crt_deinit(key_cert);
    }
    if(x509_privkey != NULL) {
        gnutls_x509_privkey_deinit(x509_privkey);
    }
    if(privkey != NULL) {
        gnutls_privkey_deinit(privkey);
    }
    if(x509Data != NULL) {
        xmlSecKeyDataDestroy(x509Data);
    }
    if(key != NULL) {
        xmlSecKeyDestroy(key);
    }
    xmlSecPtrListFinalize(&certsList);
    return(res);
}
#endif /* XMLSEC_NO_X509 */


static gnutls_privkey_t
xmlSecGnuTLSAppPemDerPrivKeyLoadMemory(const gnutls_datum_t * datum, gnutls_x509_crt_fmt_t fmt) {
    gnutls_x509_privkey_t x509_privkey = NULL;
    gnutls_privkey_t privkey = NULL;
    int err;

    xmlSecAssert2(datum != NULL, NULL);

    err = gnutls_x509_privkey_init(&x509_privkey);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_x509_privkey_init", err, NULL);
        return(NULL);
    }

    err = gnutls_x509_privkey_import(x509_privkey, datum, fmt);
    if(err != GNUTLS_E_SUCCESS) {
        /* ignore this error so we don't pollute logs when trying to read public keys */
        /* xmlSecGnuTLSError("gnutls_x509_privkey_import", err, NULL); */
        gnutls_x509_privkey_deinit(x509_privkey);
        return(NULL);
    }

    err = gnutls_privkey_init(&privkey);
    if (err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_privkey_init", err, NULL);
        gnutls_x509_privkey_deinit(x509_privkey);
        return(NULL);
    }

    err = gnutls_privkey_import_x509(privkey, x509_privkey, GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE);
    if (err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_privkey_import_x509", err, NULL);
        gnutls_x509_privkey_deinit(x509_privkey);
        gnutls_privkey_deinit(privkey);
        return(NULL);
    }
    x509_privkey = NULL; /* owned by privkey now */

    /* success */
    return(privkey);
}

static gnutls_pubkey_t
xmlSecGnuTLSAppPemDerPubKeyLoadMemory(const gnutls_datum_t * datum, gnutls_x509_crt_fmt_t fmt) {
    gnutls_pubkey_t pubkey = NULL;
    int err;

    xmlSecAssert2(datum != NULL, NULL);

	err = gnutls_pubkey_init(&pubkey);
	if(err < 0) {
        xmlSecGnuTLSError("gnutls_pubkey_init", err, NULL);
        return(NULL);
	}

	/* Convert our raw public-key to a gnutls_pubkey_t structure */
	err = gnutls_pubkey_import(pubkey, datum, fmt);
	if(err < 0) {
        xmlSecGnuTLSError("gnutls_pubkey_init", err, NULL);
        gnutls_pubkey_deinit(pubkey);
        return(NULL);
	}

    /* done! */
    return(pubkey);
}

static xmlSecKeyPtr
xmlSecGnuTLSAppPemDerKeyLoadMemory(const xmlSecByte * data, xmlSecSize dataSize, gnutls_x509_crt_fmt_t fmt) {
    gnutls_privkey_t privkey = NULL;
    gnutls_pubkey_t pubkey = NULL;
    xmlSecKeyPtr key = NULL;
    gnutls_datum_t datum;

    xmlSecAssert2(data != NULL, NULL);
    xmlSecAssert2(dataSize > 0, NULL);

    datum.data = (xmlSecByte*)data; /* for const */
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(dataSize, datum.size, return(NULL), NULL);

    /* try private key first */
    privkey = xmlSecGnuTLSAppPemDerPrivKeyLoadMemory(&datum, fmt);
    if(privkey != NULL) {
        key = xmlSecGCryptAsymetricKeyCreatePriv(privkey);
        if(key == NULL) {
            xmlSecInternalError("xmlSecGCryptAsymetricKeyCreatePriv", NULL);
            gnutls_privkey_deinit(privkey);
            return(NULL);
        }
        return(key);
    }

    /* then public key */
    pubkey = xmlSecGnuTLSAppPemDerPubKeyLoadMemory(&datum, fmt);
    if(pubkey != NULL) {
        key = xmlSecGCryptAsymetricKeyCreatePub(pubkey);
        if(key == NULL) {
            xmlSecInternalError("xmlSecGCryptAsymetricKeyCreatePub", NULL);
            gnutls_pubkey_deinit(pubkey);
            return(NULL);
        }
        return(key);
    }

    xmlSecInternalError3("Cannot read private or public keys", NULL,
            "format=%d; keySize=" XMLSEC_SIZE_FMT, (int)fmt, dataSize);
    return(NULL);
}

static xmlSecKeyPtr
xmlSecGnuTLSAppPkcs8KeyLoadMemory(const xmlSecByte * data, xmlSecSize dataSize, gnutls_x509_crt_fmt_t fmt,
    const char *pwd, void* pwdCallback ATTRIBUTE_UNUSED, void* pwdCallbackCtx ATTRIBUTE_UNUSED)
{
    gnutls_x509_privkey_t x509_privkey = NULL;
    gnutls_privkey_t privkey = NULL;
    xmlSecKeyPtr key = NULL;
    gnutls_datum_t datum;
    int err;

    xmlSecAssert2(data != NULL, NULL);
    xmlSecAssert2(dataSize > 0, NULL);

    datum.data = (xmlSecByte*)data; /* for const */
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(dataSize, datum.size, return(NULL), NULL);

    /* read the private key from pkcs8 */
    err = gnutls_x509_privkey_init(&x509_privkey);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_x509_privkey_init", err, NULL);
        return(NULL);
    }
    err = gnutls_x509_privkey_import_pkcs8(x509_privkey, &datum, fmt, pwd, 0);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_x509_privkey_import_pkcs8", err, NULL);
        gnutls_x509_privkey_deinit(x509_privkey);
        return(NULL);
    }

    /* create privkey from x509 privkey */
    err = gnutls_privkey_init(&privkey);
    if (err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_privkey_init", err, NULL);
        gnutls_x509_privkey_deinit(x509_privkey);
        return(NULL);
    }

    err = gnutls_privkey_import_x509(privkey, x509_privkey, GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE);
    if (err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_privkey_import_x509", err, NULL);
        gnutls_x509_privkey_deinit(x509_privkey);
        gnutls_privkey_deinit(privkey);
        return(NULL);
    }
    x509_privkey = NULL; /* owned by privkey now */

    key = xmlSecGCryptAsymetricKeyCreatePriv(privkey);
    if(key == NULL) {
        xmlSecInternalError("xmlSecGCryptAsymetricKeyCreatePriv", NULL);
        gnutls_privkey_deinit(privkey);
        return(NULL);
    }

    /* done */
    return(key);
}

#ifndef XMLSEC_NO_X509
static xmlSecKeyPtr
xmlSecGnuTLSAppKeyFromCertLoadMemory(const xmlSecByte* data, xmlSecSize dataSize, xmlSecKeyDataFormat format)
{
    xmlSecKeyPtr key = NULL;
    xmlSecKeyDataPtr keyData = NULL;
    xmlSecKeyDataPtr x509Data = NULL;
    gnutls_x509_crt_t cert = NULL;
    xmlSecKeyPtr res = NULL;
    int ret;

    xmlSecAssert2(data != NULL, NULL);
    xmlSecAssert2(dataSize > 0, NULL);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, NULL);

    /* read cert  */
    cert = xmlSecGnuTLSX509CertRead(data, dataSize, format);
    if(cert == NULL) {
        xmlSecInternalError("xmlSecGnuTLSX509CertRead", NULL);
        goto done;
    }

    /* create key */
    key = xmlSecKeyCreate();
    if(key == NULL) {
        xmlSecInternalError("xmlSecKeyCreate", NULL);
        goto done;
    }

    /* create key value data */
    keyData = xmlSecGnuTLSX509CertGetKey(cert);
    if(keyData == NULL) {
        xmlSecInternalError("xmlSecGnuTLSX509CertGetKey", NULL);
        goto done;
    }
    ret = xmlSecKeySetValue(key, keyData);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeySetValue", NULL);
        goto done;
    }
    keyData = NULL; /* owned by key now */

    /* create x509 data and add key cert */
    x509Data = xmlSecKeyEnsureData(key, xmlSecGnuTLSKeyDataX509Id);
    if(x509Data == NULL) {
        xmlSecInternalError("xmlSecKeyEnsureData", NULL);
        goto done;
    }
    ret = xmlSecGnuTLSKeyDataX509AdoptKeyCert(x509Data, cert);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGnuTLSKeyDataX509AdoptKeyCert", NULL);
        goto done;
    }
    cert = NULL; /* owned by x509Data now */

    /* success */
    res = key;
    key = NULL;

done:
    if(cert != NULL) {
        gnutls_x509_crt_deinit(cert);
    }
    if(keyData != NULL) {
        xmlSecKeyDataDestroy(keyData);
    }
    if(key != NULL) {
        xmlSecKeyDestroy(key);
    }
    return(res);
}

/**
 * xmlSecGnuTLSAppKeysMngrCertLoad:
 * @mngr:               the keys manager.
 * @filename:           the certificate file.
 * @format:             the certificate file format.
 * @type:               the flag that indicates is the certificate in @filename
 *                      trusted or not.
 *
 * Reads cert from @filename and adds to the list of trusted or known
 * untrusted certs in @store.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSAppKeysMngrCertLoad(xmlSecKeysMngrPtr mngr,
                                const char *filename,
                                xmlSecKeyDataFormat format,
                                xmlSecKeyDataType type) {
    xmlSecBuffer buffer;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    ret = xmlSecBufferInitialize(&buffer, 4*1024);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", NULL);
        return(-1);
    }

    ret = xmlSecBufferReadFile(&buffer, filename);
    if((ret < 0) || (xmlSecBufferGetData(&buffer) == NULL) || (xmlSecBufferGetSize(&buffer) <= 0)) {
        xmlSecInternalError2("xmlSecBufferReadFile", NULL,
                            "filename=%s", xmlSecErrorsSafeString(filename));
        xmlSecBufferFinalize(&buffer);
        return(-1);
    }

    ret = xmlSecGnuTLSAppKeysMngrCertLoadMemory(mngr,
                    xmlSecBufferGetData(&buffer),
                    xmlSecBufferGetSize(&buffer),
                    format,
                    type);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecGnuTLSAppKeysMngrCertLoadMemory", NULL,
                             "filename=%s", xmlSecErrorsSafeString(filename));
        xmlSecBufferFinalize(&buffer);
        return(-1);
    }

    /* cleanup */
    xmlSecBufferFinalize(&buffer);
    return(0);
}

/**
 * xmlSecGnuTLSAppKeysMngrCertLoadMemory:
 * @mngr:               the keys manager.
 * @data:               the certificate binary data.
 * @dataSize:           the certificate binary data size.
 * @format:             the certificate file format.
 * @type:               the flag that indicates is the certificate trusted or not.
 *
 * Reads cert from binary buffer @data and adds to the list of trusted or known
 * untrusted certs in @store.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSAppKeysMngrCertLoadMemory(xmlSecKeysMngrPtr mngr,
                                      const xmlSecByte* data,
                                      xmlSecSize dataSize,
                                      xmlSecKeyDataFormat format,
                                      xmlSecKeyDataType type) {
    xmlSecKeyDataStorePtr x509Store;
    gnutls_x509_crt_t cert;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(dataSize > 0, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    x509Store = xmlSecKeysMngrGetDataStore(mngr, xmlSecGnuTLSX509StoreId);
    if(x509Store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetDataStore(StoreId)", NULL);
        return(-1);
    }

    cert = xmlSecGnuTLSX509CertRead(data, dataSize, format);
    if(cert == NULL) {
        xmlSecInternalError("xmlSecGnuTLSX509CertRead", NULL);
        return(-1);
    }

    ret = xmlSecGnuTLSX509StoreAdoptCert(x509Store, cert, type);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGnuTLSX509StoreAdoptCert", NULL);
        gnutls_x509_crt_deinit(cert);
        return(-1);
    }

    return(0);
}

/**
 * xmlSecGnuTLSAppKeysMngrCrlLoad:
 * @mngr:               the keys manager.
 * @filename:           the CRL file.
 * @format:             the CRL file format.
 *
 * Reads crls from @filename and adds to the list of crls in @store.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSAppKeysMngrCrlLoad(xmlSecKeysMngrPtr mngr, const char *filename, xmlSecKeyDataFormat format) {
    xmlSecBuffer buffer;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    ret = xmlSecBufferInitialize(&buffer, 4*1024);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", NULL);
        return(-1);
    }

    ret = xmlSecBufferReadFile(&buffer, filename);
    if((ret < 0) || (xmlSecBufferGetData(&buffer) == NULL) || (xmlSecBufferGetSize(&buffer) <= 0)) {
        xmlSecInternalError2("xmlSecBufferReadFile", NULL,
                            "filename=%s", xmlSecErrorsSafeString(filename));
        xmlSecBufferFinalize(&buffer);
        return(-1);
    }

    ret = xmlSecGnuTLSAppKeysMngrCrlLoadMemory(mngr,
                    xmlSecBufferGetData(&buffer),
                    xmlSecBufferGetSize(&buffer),
                    format);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecGnuTLSAppKeysMngrCrlLoadMemory", NULL,
                             "filename=%s", xmlSecErrorsSafeString(filename));
        xmlSecBufferFinalize(&buffer);
        return(-1);
    }

    /* cleanup */
    xmlSecBufferFinalize(&buffer);
    return(0);
}


/**
 * xmlSecGnuTLSAppKeysMngrCrlLoadMemory:
 * @mngr:               the keys manager.
 * @data:               the CRL binary data.
 * @dataSize:           the CRL binary data size.
 * @format:             the CRL file format.
 *
 * Reads CRL from binary buffer @data and adds to the list of trusted or known
 * untrusted CRL in @store.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSAppKeysMngrCrlLoadMemory(xmlSecKeysMngrPtr mngr,
    const xmlSecByte* data, xmlSecSize dataSize, xmlSecKeyDataFormat format
) {
    xmlSecKeyDataStorePtr x509Store;
    gnutls_x509_crl_t crl;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(dataSize > 0, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    x509Store = xmlSecKeysMngrGetDataStore(mngr, xmlSecGnuTLSX509StoreId);
    if(x509Store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetDataStore(StoreId)", NULL);
        return(-1);
    }

    crl = xmlSecGnuTLSX509CrlRead(data, dataSize, format);
    if(crl == NULL) {
        xmlSecInternalError("xmlSecGnuTLSX509CrlRead", NULL);
        return(-1);
    }

    ret = xmlSecGnuTLSX509StoreAdoptCrl(x509Store, crl);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGnuTLSX509StoreAdoptCrl", NULL);
        gnutls_x509_crl_deinit(crl);
        return(-1);
    }

    return(0);
}


#endif /* XMLSEC_NO_X509 */

/**
 * xmlSecGnuTLSAppDefaultKeysMngrInit:
 * @mngr:               the pointer to keys manager.
 *
 * Initializes @mngr with simple keys store #xmlSecGnuTLSKeysStoreId
 * and a default GnuTLS crypto key data stores.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSAppDefaultKeysMngrInit(xmlSecKeysMngrPtr mngr) {
    int ret;

    xmlSecAssert2(mngr != NULL, -1);

    /* create simple keys store if needed */
    if(xmlSecKeysMngrGetKeysStore(mngr) == NULL) {
        xmlSecKeyStorePtr keysStore;

        keysStore = xmlSecKeyStoreCreate(xmlSecGnuTLSKeysStoreId);
        if(keysStore == NULL) {
            xmlSecInternalError("xmlSecKeyStoreCreate(xmlSecGnuTLSKeysStoreId)", NULL);
            return(-1);
        }

        ret = xmlSecKeysMngrAdoptKeysStore(mngr, keysStore);
        if(ret < 0) {
            xmlSecInternalError("xmlSecKeysMngrAdoptKeysStore", NULL);
            xmlSecKeyStoreDestroy(keysStore);
            return(-1);
        }
    }

    ret = xmlSecGnuTLSKeysMngrInit(mngr);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGnuTLSKeysMngrInit", NULL);
        return(-1);
    }

    /* TODO */
    mngr->getKey = xmlSecKeysMngrGetKey;
    return(0);
}

/**
 * xmlSecGnuTLSAppDefaultKeysMngrAdoptKey:
 * @mngr:               the pointer to keys manager.
 * @key:                the pointer to key.
 *
 * Adds @key to the keys manager @mngr created with #xmlSecGnuTLSAppDefaultKeysMngrInit
 * function.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSAppDefaultKeysMngrAdoptKey(xmlSecKeysMngrPtr mngr, xmlSecKeyPtr key) {
    xmlSecKeyStorePtr store;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(key != NULL, -1);

    store = xmlSecKeysMngrGetKeysStore(mngr);
    if(store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetKeysStore", NULL);
        return(-1);
    }

    ret = xmlSecGnuTLSKeysStoreAdoptKey(store, key);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGnuTLSKeysStoreAdoptKey", NULL);
        return(-1);
    }

    return(0);
}

/**
 * xmlSecGnuTLSAppDefaultKeysMngrVerifyKey:
 * @mngr:               the pointer to keys manager.
 * @key:                the pointer to key.
 * @keyInfoCtx:         the key info context for verification.
 *
 * Verifies @key with the keys manager @mngr created with #xmlSecCryptoAppDefaultKeysMngrInit
 * function:
 * - Checks that key certificate is present
 * - Checks that key certificate is valid
 *
 * Adds @key to the keys manager @mngr created with #xmlSecCryptoAppDefaultKeysMngrInit
 * function.
 *
 * Returns: 1 if key is verified, 0 otherwise, or a negative value if an error occurs.
 */
int
xmlSecGnuTLSAppDefaultKeysMngrVerifyKey(xmlSecKeysMngrPtr mngr, xmlSecKeyPtr key, xmlSecKeyInfoCtxPtr keyInfoCtx) {
#ifndef XMLSEC_NO_X509
    xmlSecKeyDataStorePtr x509Store;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    x509Store = xmlSecKeysMngrGetDataStore(mngr, xmlSecGnuTLSX509StoreId);
    if(x509Store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetDataStore(xmlSecGnuTLSX509StoreId)", NULL);
        return(-1);
    }

    return(xmlSecGnuTLSX509StoreVerifyKey(x509Store, key, keyInfoCtx));

#else  /* XMLSEC_NO_X509 */

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    xmlSecNotImplementedError("X509 support is disabled");
    return(-1);

#endif /* XMLSEC_NO_X509 */
}

/**
 * xmlSecGnuTLSAppDefaultKeysMngrLoad:
 * @mngr:               the pointer to keys manager.
 * @uri:                the uri.
 *
 * Loads XML keys file from @uri to the keys manager @mngr created
 * with #xmlSecGnuTLSAppDefaultKeysMngrInit function.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSAppDefaultKeysMngrLoad(xmlSecKeysMngrPtr mngr, const char* uri) {
    xmlSecKeyStorePtr store;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(uri != NULL, -1);

    store = xmlSecKeysMngrGetKeysStore(mngr);
    if(store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetKeysStore", NULL);
        return(-1);
    }

    ret = xmlSecGnuTLSKeysStoreLoad(store, uri, mngr);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecGnuTLSKeysStoreLoad", NULL,
                             "uri=%s", xmlSecErrorsSafeString(uri));
        return(-1);
    }

    return(0);
}

/**
 * xmlSecGnuTLSAppDefaultKeysMngrSave:
 * @mngr:               the pointer to keys manager.
 * @filename:           the destination filename.
 * @type:               the type of keys to save (public/private/symmetric).
 *
 * Saves keys from @mngr to  XML keys file.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSAppDefaultKeysMngrSave(xmlSecKeysMngrPtr mngr, const char* filename, xmlSecKeyDataType type) {
    xmlSecKeyStorePtr store;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);

    store = xmlSecKeysMngrGetKeysStore(mngr);
    if(store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetKeysStore", NULL);
        return(-1);
    }

    ret = xmlSecGnuTLSKeysStoreSave(store, filename, type);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecGnuTLSKeysStoreSave", NULL,
                             "filename=%s", xmlSecErrorsSafeString(filename));
        return(-1);
    }

    return(0);
}

/**
 * xmlSecGnuTLSAppGetDefaultPwdCallback:
 *
 * Gets default password callback.
 *
 * Returns: default password callback.
 */
void*
xmlSecGnuTLSAppGetDefaultPwdCallback(void) {
    return(NULL);
}
