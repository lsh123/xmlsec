/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2016 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#include "globals.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <libxml/tree.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/conf.h>
#include <openssl/engine.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/private.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/app.h>
#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/evp.h>
#include <xmlsec/openssl/x509.h>

static int      xmlSecOpenSSLAppLoadRANDFile            (const char *filename);
static int      xmlSecOpenSSLAppSaveRANDFile            (const char *filename);
static int      xmlSecOpenSSLDefaultPasswordCallback    (char *buf,
                                                         int bufsiz,
                                                         int verify,
                                                         void *userdata);
static int      xmlSecOpenSSLDummyPasswordCallback      (char *buf,
                                                         int bufsize,
                                                         int verify,
                                                         void *userdata);

/* conversion from ptr to func "the right way" */
XMLSEC_PTR_TO_FUNC_IMPL(pem_password_cb)
XMLSEC_FUNC_TO_PTR_IMPL(pem_password_cb)


/**
 * xmlSecOpenSSLAppInit:
 * @config:             the path to certs.
 *
 * General crypto engine initialization. This function is used
 * by XMLSec command line utility and called before
 * @xmlSecInit function.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecOpenSSLAppInit(const char* config) {
#if !defined(XMLSEC_OPENSSL_API_110)

    ERR_load_crypto_strings();
    OPENSSL_config(NULL);
    OpenSSL_add_all_algorithms();

#else /* !defined(XMLSEC_OPENSSL_API_110) */
    int ret;

    ret = OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | 
                              OPENSSL_INIT_ADD_ALL_CIPHERS |
                              OPENSSL_INIT_ADD_ALL_DIGESTS |
                              OPENSSL_INIT_LOAD_CONFIG |
                              OPENSSL_INIT_ASYNC |
                              OPENSSL_INIT_ENGINE_ALL_BUILTIN,
                              NULL);
    if(ret != 1) {
        xmlSecOpenSSLError("OPENSSL_init_crypto", NULL);
        return(-1);
    }
#endif /* !defined(XMLSEC_OPENSSL_API_110) */

    if((RAND_status() != 1) && (xmlSecOpenSSLAppLoadRANDFile(NULL) != 1)) {
        xmlSecInternalError("xmlSecOpenSSLAppLoadRANDFile", NULL);
        return(-1);
    }

    if((config != NULL) && (xmlSecOpenSSLSetDefaultTrustedCertsFolder(BAD_CAST config) < 0)) {
        xmlSecInternalError("xmlSecOpenSSLSetDefaultTrustedCertsFolder", NULL);
        return(-1);
    }

    return(0);
}

/**
 * xmlSecOpenSSLAppShutdown:
 *
 * General crypto engine shutdown. This function is used
 * by XMLSec command line utility and called after
 * @xmlSecShutdown function.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecOpenSSLAppShutdown(void) {
    xmlSecOpenSSLAppSaveRANDFile(NULL);

    /* OpenSSL 1.1.0+ does not require explicit cleanup */
#if !defined(XMLSEC_OPENSSL_API_110)

#ifndef XMLSEC_NO_X509
    X509_TRUST_cleanup();
#endif /* XMLSEC_NO_X509 */

    RAND_cleanup();
    EVP_cleanup();

    ENGINE_cleanup();
    CONF_modules_unload(1);
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_thread_state(NULL);
    ERR_free_strings();
#endif /* !defined(XMLSEC_OPENSSL_API_110) */

    /* done */
    return(0);
}

/**
 * xmlSecOpenSSLAppKeyLoad:
 * @filename:           the key filename.
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
xmlSecOpenSSLAppKeyLoad(const char *filename, xmlSecKeyDataFormat format,
                        const char *pwd, void* pwdCallback,
                        void* pwdCallbackCtx) {
    BIO* bio;
    xmlSecKeyPtr key;

    xmlSecAssert2(filename != NULL, NULL);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, NULL);

    bio = BIO_new_file(filename, "rb");
    if(bio == NULL) {
        xmlSecOpenSSLError2("BIO_new_file", NULL,
                            "filename=%s", xmlSecErrorsSafeString(filename));
        return(NULL);
    }

    key = xmlSecOpenSSLAppKeyLoadBIO (bio, format, pwd, pwdCallback, pwdCallbackCtx);
    if(key == NULL) {
        xmlSecInternalError2("xmlSecOpenSSLAppKeyLoadBIO", NULL,
                            "filename=%s", xmlSecErrorsSafeString(filename));
        BIO_free(bio);
        return(NULL);
    }

    BIO_free(bio);
    return(key);
}

/**
 * xmlSecOpenSSLAppKeyLoadMemory:
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
xmlSecOpenSSLAppKeyLoadMemory(const xmlSecByte* data, xmlSecSize dataSize,
                        xmlSecKeyDataFormat format, const char *pwd,
                        void* pwdCallback, void* pwdCallbackCtx) {
    BIO* bio;
    xmlSecKeyPtr key;

    xmlSecAssert2(data != NULL, NULL);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, NULL);

    /* this would be a read only BIO, cast from const is ok */
    bio = BIO_new_mem_buf((void*)data, dataSize);
    if(bio == NULL) {
        xmlSecOpenSSLError2("BIO_new_mem_buf", NULL,
                            "dataSize=%lu", (unsigned long)dataSize);
        return(NULL);
    }

    key = xmlSecOpenSSLAppKeyLoadBIO (bio, format, pwd, pwdCallback, pwdCallbackCtx);
    if(key == NULL) {
        xmlSecInternalError("xmlSecOpenSSLAppKeyLoadBIO", NULL);
        BIO_free(bio);
        return(NULL);
    }

    BIO_free(bio);
    return(key);
}


/**
 * xmlSecOpenSSLAppKeyLoadBIO:
 * @bio:                the key BIO.
 * @format:             the key file format.
 * @pwd:                the key file password.
 * @pwdCallback:        the key password callback.
 * @pwdCallbackCtx:     the user context for password callback.
 *
 * Reads key from the an OpenSSL BIO object.
 *
 * Returns: pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecOpenSSLAppKeyLoadBIO(BIO* bio, xmlSecKeyDataFormat format,
                        const char *pwd, void* pwdCallback,
                        void* pwdCallbackCtx) {

    xmlSecKeyPtr key = NULL;
    xmlSecKeyDataPtr data;
    EVP_PKEY* pKey = NULL;
    int ret;

    xmlSecAssert2(bio != NULL, NULL);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, NULL);

    switch(format) {
    case xmlSecKeyDataFormatPem:
        /* try to read private key first */
        if(pwd != NULL) {
            pKey = PEM_read_bio_PrivateKey(bio, NULL,
                        xmlSecOpenSSLDummyPasswordCallback,
                        (void*)pwd);
        } else {
            pKey = PEM_read_bio_PrivateKey(bio, NULL,
                            XMLSEC_PTR_TO_FUNC(pem_password_cb, pwdCallback),
                            pwdCallbackCtx);
        }
        if(pKey == NULL) {
            /* go to start of the file and try to read public key */
            (void)BIO_reset(bio);
            pKey = PEM_read_bio_PUBKEY(bio, NULL,
                            XMLSEC_PTR_TO_FUNC(pem_password_cb, pwdCallback),
                            pwdCallbackCtx);
            if(pKey == NULL) {
                xmlSecOpenSSLError("PEM_read_bio_PrivateKey and PEM_read_bio_PUBKEY", NULL);
                return(NULL);
            }
        }
        break;
    case xmlSecKeyDataFormatDer:
        /* try to read private key first */
        pKey = d2i_PrivateKey_bio(bio, NULL);
        if(pKey == NULL) {
            /* go to start of the file and try to read public key */
            (void)BIO_reset(bio);
            pKey = d2i_PUBKEY_bio(bio, NULL);
            if(pKey == NULL) {
                xmlSecOpenSSLError("d2i_PrivateKey_bio and d2i_PUBKEY_bio", NULL);
                return(NULL);
            }
        }
        break;
    case xmlSecKeyDataFormatPkcs8Pem:
        /* try to read private key first */
        pKey = PEM_read_bio_PrivateKey(bio, NULL,
                            XMLSEC_PTR_TO_FUNC(pem_password_cb, pwdCallback),
                            pwdCallbackCtx);
        if(pKey == NULL) {
            xmlSecOpenSSLError("PEM_read_bio_PrivateKey", NULL);
            return(NULL);
        }
        break;
    case xmlSecKeyDataFormatPkcs8Der:
        /* try to read private key first */
        pKey = d2i_PKCS8PrivateKey_bio(bio, NULL,
                            XMLSEC_PTR_TO_FUNC(pem_password_cb, pwdCallback),
                            pwdCallbackCtx);
        if(pKey == NULL) {
            xmlSecOpenSSLError("d2i_PrivateKey_bio and d2i_PUBKEY_bio", NULL);
            return(NULL);
        }
        break;
#ifndef XMLSEC_NO_X509
    case xmlSecKeyDataFormatPkcs12:
        key = xmlSecOpenSSLAppPkcs12LoadBIO(bio, pwd, pwdCallback, pwdCallbackCtx);
        if(key == NULL) {
            xmlSecInternalError("xmlSecOpenSSLAppPkcs12LoadBIO", NULL);
            return(NULL);
        }
        return(key);

    case xmlSecKeyDataFormatCertPem:
    case xmlSecKeyDataFormatCertDer:
        key = xmlSecOpenSSLAppKeyFromCertLoadBIO(bio, format);
        if(key == NULL) {
            xmlSecInternalError("xmlSecOpenSSLAppKeyFromCertLoadBIO", NULL);
            return(NULL);
        }
        return(key);
#endif /* XMLSEC_NO_X509 */

    default:
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_FORMAT, NULL,
                         "format=%d", (int)format);
        return(NULL);
    }

    data = xmlSecOpenSSLEvpKeyAdopt(pKey);
    if(data == NULL) {
        xmlSecInternalError("xmlSecOpenSSLEvpKeyAdopt", NULL);
        EVP_PKEY_free(pKey);
        return(NULL);
    }

    key = xmlSecKeyCreate();
    if(key == NULL) {
        xmlSecInternalError("xmlSecKeyCreate",
                            xmlSecKeyDataGetName(data));
        xmlSecKeyDataDestroy(data);
        return(NULL);
    }

    ret = xmlSecKeySetValue(key, data);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeySetValue",
                            xmlSecKeyDataGetName(data));
        xmlSecKeyDestroy(key);
        xmlSecKeyDataDestroy(data);
        return(NULL);
    }

    return(key);
}


#ifndef XMLSEC_NO_X509
static X509*            xmlSecOpenSSLAppCertLoadBIO             (BIO* bio,
                                                                 xmlSecKeyDataFormat format);
/**
 * xmlSecOpenSSLAppKeyCertLoad:
 * @key:                the pointer to key.
 * @filename:           the certificate filename.
 * @format:             the certificate file format.
 *
 * Reads the certificate from $@filename and adds it to key.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecOpenSSLAppKeyCertLoad(xmlSecKeyPtr key, const char* filename, xmlSecKeyDataFormat format) {
    BIO* bio;
    int ret;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    bio = BIO_new_file(filename, "rb");
    if(bio == NULL) {
        xmlSecOpenSSLError2("BIO_new_file", NULL,
                            "filename=%s", xmlSecErrorsSafeString(filename));
        return(-1);
    }

    ret = xmlSecOpenSSLAppKeyCertLoadBIO (key, bio, format);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecOpenSSLAppKeyCertLoadBIO", NULL,
                             "filename=%s", xmlSecErrorsSafeString(filename));
        BIO_free(bio);
        return(-1);
    }

    BIO_free(bio);
    return(0);
}

/**
 * xmlSecOpenSSLAppKeyCertLoadMemory:
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
xmlSecOpenSSLAppKeyCertLoadMemory(xmlSecKeyPtr key, const xmlSecByte* data, xmlSecSize dataSize,
                                xmlSecKeyDataFormat format) {
    BIO* bio;
    int ret;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    /* this would be a read only BIO, cast from const is ok */
    bio = BIO_new_mem_buf((void*)data, dataSize);
    if(bio == NULL) {
        xmlSecOpenSSLError2("BIO_new_mem_buf", NULL,
                            "dataSize=%lu", (unsigned long)dataSize);
        return(-1);
    }

    ret = xmlSecOpenSSLAppKeyCertLoadBIO (key, bio, format);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLAppKeyCertLoadBIO", NULL);
        BIO_free(bio);
        return(-1);
    }

    BIO_free(bio);
    return(0);
}

/**
 * xmlSecOpenSSLAppKeyCertLoadBIO:
 * @key:                the pointer to key.
 * @bio:                the certificate bio.
 * @format:             the certificate file format.
 *
 * Reads the certificate from memory buffer and adds it to key.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecOpenSSLAppKeyCertLoadBIO(xmlSecKeyPtr key, BIO* bio, xmlSecKeyDataFormat format) {

    xmlSecKeyDataFormat certFormat;
    xmlSecKeyDataPtr data;
    X509 *cert;
    int ret;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(bio != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    data = xmlSecKeyEnsureData(key, xmlSecOpenSSLKeyDataX509Id);
    if(data == NULL) {
        xmlSecInternalError("xmlSecKeyEnsureData",
                            xmlSecTransformKlassGetName(xmlSecOpenSSLKeyDataX509Id));
        return(-1);
    }

    /* adjust cert format */
    switch(format) {
    case xmlSecKeyDataFormatPkcs8Pem:
        certFormat = xmlSecKeyDataFormatPem;
        break;
    case xmlSecKeyDataFormatPkcs8Der:
        certFormat = xmlSecKeyDataFormatDer;
        break;
    default:
        certFormat = format;
    }

    cert = xmlSecOpenSSLAppCertLoadBIO(bio, certFormat);
    if(cert == NULL) {
        xmlSecInternalError("xmlSecOpenSSLAppCertLoad",
                            xmlSecKeyDataGetName(data));
        return(-1);
    }

    ret = xmlSecOpenSSLKeyDataX509AdoptCert(data, cert);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataX509AdoptCert",
                            xmlSecKeyDataGetName(data));
        X509_free(cert);
        return(-1);
    }

    return(0);
}

/**
 * xmlSecOpenSSLAppPkcs12Load:
 * @filename:           the PKCS12 key filename.
 * @pwd:                the PKCS12 file password.
 * @pwdCallback:        the password callback.
 * @pwdCallbackCtx:     the user context for password callback.
 *
 * Reads key and all associated certificates from the PKCS12 file.
 * For uniformity, call xmlSecOpenSSLAppKeyLoad instead of this function. Pass
 * in format=xmlSecKeyDataFormatPkcs12.
 *
 * Returns: pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecOpenSSLAppPkcs12Load(const char *filename, const char *pwd,
                           void* pwdCallback, void* pwdCallbackCtx) {
    BIO* bio;
    xmlSecKeyPtr key;

    xmlSecAssert2(filename != NULL, NULL);

    bio = BIO_new_file(filename, "rb");
    if(bio == NULL) {
        xmlSecOpenSSLError2("BIO_new_file", NULL,
                            "filename=%s", xmlSecErrorsSafeString(filename));
        return(NULL);
    }

    key = xmlSecOpenSSLAppPkcs12LoadBIO (bio, pwd, pwdCallback, pwdCallbackCtx);
    if(key == NULL) {
        xmlSecInternalError2("xmlSecOpenSSLAppPkcs12LoadBIO", NULL,
                             "filename=%s", xmlSecErrorsSafeString(filename));
        BIO_free(bio);
        return(NULL);
    }

    BIO_free(bio);
    return(key);
}

/**
 * xmlSecOpenSSLAppPkcs12LoadMemory:
 * @data:               the PKCS12 binary data.
 * @dataSize:           the PKCS12 binary data size.
 * @pwd:                the PKCS12 file password.
 * @pwdCallback:        the password callback.
 * @pwdCallbackCtx:     the user context for password callback.
 *
 * Reads key and all associated certificates from the PKCS12 data in memory buffer.
 * For uniformity, call xmlSecOpenSSLAppKeyLoad instead of this function. Pass
 * in format=xmlSecKeyDataFormatPkcs12.
 *
 * Returns: pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecOpenSSLAppPkcs12LoadMemory(const xmlSecByte* data, xmlSecSize dataSize,
                           const char *pwd, void* pwdCallback,
                           void* pwdCallbackCtx) {
    BIO* bio;
    xmlSecKeyPtr key;

    xmlSecAssert2(data != NULL, NULL);

    /* this would be a read only BIO, cast from const is ok */
    bio = BIO_new_mem_buf((void*)data, dataSize);
    if(bio == NULL) {
        xmlSecOpenSSLError2("BIO_new_mem_buf", NULL,
                            "dataSize=%lu", (unsigned long)dataSize);
        return(NULL);
    }

    key = xmlSecOpenSSLAppPkcs12LoadBIO (bio, pwd, pwdCallback, pwdCallbackCtx);
    if(key == NULL) {
        xmlSecInternalError("xmlSecOpenSSLAppPkcs12LoadBIO", NULL);
        BIO_free(bio);
        return(NULL);
    }

    BIO_free(bio);
    return(key);
}

/**
 * xmlSecOpenSSLAppPkcs12LoadBIO:
 * @bio:                the PKCS12 key bio.
 * @pwd:                the PKCS12 file password.
 * @pwdCallback:        the password callback.
 * @pwdCallbackCtx:     the user context for password callback.
 *
 * Reads key and all associated certificates from the PKCS12 data in an OpenSSL BIO object.
 * For uniformity, call xmlSecOpenSSLAppKeyLoad instead of this function. Pass
 * in format=xmlSecKeyDataFormatPkcs12.
 *
 * Returns: pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecOpenSSLAppPkcs12LoadBIO(BIO* bio, const char *pwd,
                           void* pwdCallback ATTRIBUTE_UNUSED,
                           void* pwdCallbackCtx ATTRIBUTE_UNUSED) {

    PKCS12 *p12 = NULL;
    EVP_PKEY *pKey = NULL;
    STACK_OF(X509) *chain = NULL;
    xmlSecKeyPtr key = NULL;
    xmlSecKeyDataPtr data = NULL;
    xmlSecKeyDataPtr x509Data = NULL;
    X509 *cert = NULL;
    X509 *tmpcert = NULL;
    int i;
    int has_cert;
    int ret;

    xmlSecAssert2(bio != NULL, NULL);

    p12 = d2i_PKCS12_bio(bio, NULL);
    if(p12 == NULL) {
        xmlSecOpenSSLError("d2i_PKCS12_fp", NULL);
        goto done;
    }

    ret = PKCS12_verify_mac(p12, pwd, (pwd != NULL) ? strlen(pwd) : 0);
    if(ret != 1) {
        xmlSecOpenSSLError("PKCS12_verify_mac", NULL);
        goto done;
    }

    ret = PKCS12_parse(p12, pwd, &pKey, &cert, &chain);
    if(ret < 0) {
        xmlSecOpenSSLError("PKCS12_parse", NULL);
        goto done;
    }

    data = xmlSecOpenSSLEvpKeyAdopt(pKey);
    if(data == NULL) {
        xmlSecInternalError("xmlSecOpenSSLEvpKeyAdopt", NULL);
        EVP_PKEY_free(pKey);
        goto done;
    }

    x509Data = xmlSecKeyDataCreate(xmlSecOpenSSLKeyDataX509Id);
    if(x509Data == NULL) {
        xmlSecInternalError("xmlSecKeyDataCreate",
                            xmlSecTransformKlassGetName(xmlSecOpenSSLKeyDataX509Id));
        goto done;
    }

    /* starting from openssl 1.0.0 the PKCS12_parse() call will not create certs
       chain object if there is no certificates in the pkcs12 file and it will be null
     */
    if(chain == NULL) {
        chain = sk_X509_new_null();
        if(chain == NULL) {
            xmlSecOpenSSLError("sk_X509_new_null", NULL);
            goto done;
        }
    }

    /*
        The documentation states (http://www.openssl.org/docs/crypto/PKCS12_parse.html):

        If successful the private key will be written to "*pkey", the
        corresponding certificate to "*cert" and any additional certificates
        to "*ca".

        In reality, the function sometime returns in the "ca" the certificates
        including the one it is already returned in "cert".
    */
    has_cert = 0;
    for(i = 0; i < sk_X509_num(chain); ++i) {
        xmlSecAssert2(sk_X509_value(chain, i), NULL);

        if(X509_cmp(sk_X509_value(chain, i), cert) == 0) {
            has_cert = 1;
            break;
        }
    }

    if(has_cert == 0) {
        tmpcert = X509_dup(cert);
        if(tmpcert == NULL) {
            xmlSecOpenSSLError("X509_dup",
                               xmlSecKeyDataGetName(x509Data));
            goto done;
        }

        ret = sk_X509_push(chain, tmpcert);
        if(ret < 1) {
            xmlSecOpenSSLError("sk_X509_push",
                               xmlSecKeyDataGetName(x509Data));
            X509_free(tmpcert);
            goto done;
        }
    }

    ret = xmlSecOpenSSLKeyDataX509AdoptKeyCert(x509Data, cert);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataX509AdoptKeyCert",
                            xmlSecKeyDataGetName(x509Data));
        goto done;
    }
    cert = NULL;

    for(i = 0; i < sk_X509_num(chain); ++i) {
        xmlSecAssert2(sk_X509_value(chain, i), NULL);

        tmpcert = X509_dup(sk_X509_value(chain, i));
        if(tmpcert == NULL) {
            xmlSecOpenSSLError("X509_dup",
                               xmlSecKeyDataGetName(x509Data));
            X509_free(tmpcert);
            goto done;
        }

        ret = xmlSecOpenSSLKeyDataX509AdoptCert(x509Data, tmpcert);
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLKeyDataX509AdoptCert",
                                xmlSecKeyDataGetName(x509Data));
            goto done;
        }
    }

    key = xmlSecKeyCreate();
    if(key == NULL) {
        xmlSecInternalError("xmlSecKeyCreate", NULL);
        goto done;
    }

    ret = xmlSecKeySetValue(key, data);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeySetValue",
                            xmlSecKeyDataGetName(x509Data));
        xmlSecKeyDestroy(key);
        key = NULL;
        goto done;
    }
    data = NULL;

    ret = xmlSecKeyAdoptData(key, x509Data);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyAdoptData",
                            xmlSecKeyDataGetName(x509Data));
        xmlSecKeyDestroy(key);
        key = NULL;
        goto done;
    }
    x509Data = NULL;

done:
    if(x509Data != NULL) {
        xmlSecKeyDataDestroy(x509Data);
    }
    if(data != NULL) {
        xmlSecKeyDataDestroy(data);
    }
    if(chain != NULL) {
        sk_X509_pop_free(chain, X509_free);
    }
    if(cert != NULL) {
        X509_free(cert);
    }
    if(p12 != NULL) {
        PKCS12_free(p12);
    }
    return(key);
}

/**
 * xmlSecOpenSSLAppKeyFromCertLoadBIO:
 * @bio:                the BIO.
 * @format:             the cert format.
 *
 * Loads public key from cert.
 *
 * Returns: pointer to key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecOpenSSLAppKeyFromCertLoadBIO(BIO* bio, xmlSecKeyDataFormat format) {
    xmlSecKeyPtr key;
    xmlSecKeyDataPtr keyData;
    xmlSecKeyDataPtr certData;
    X509 *cert;
    int ret;

    xmlSecAssert2(bio != NULL, NULL);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, NULL);

    /* load cert */
    cert = xmlSecOpenSSLAppCertLoadBIO(bio, format);
    if(cert == NULL) {
        xmlSecInternalError("xmlSecOpenSSLAppCertLoadBIO", NULL);
        return(NULL);
    }

    /* get key value */
    keyData = xmlSecOpenSSLX509CertGetKey(cert);
    if(keyData == NULL) {
        xmlSecInternalError("xmlSecOpenSSLX509CertGetKey", NULL);
        X509_free(cert);
        return(NULL);
    }

    /* create key */
    key = xmlSecKeyCreate();
    if(key == NULL) {
        xmlSecInternalError("xmlSecKeyCreate", NULL);
        xmlSecKeyDataDestroy(keyData);
        X509_free(cert);
        return(NULL);
    }

    /* set key value */
    ret = xmlSecKeySetValue(key, keyData);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeySetValue", NULL);
        xmlSecKeyDestroy(key);
        xmlSecKeyDataDestroy(keyData);
        X509_free(cert);
        return(NULL);
    }

    /* create cert data */
    certData = xmlSecKeyEnsureData(key, xmlSecOpenSSLKeyDataX509Id);
    if(certData == NULL) {
        xmlSecInternalError("xmlSecKeyEnsureData", NULL);
        xmlSecKeyDestroy(key);
        X509_free(cert);
        return(NULL);
    }

    /* put cert in the cert data */
    ret = xmlSecOpenSSLKeyDataX509AdoptCert(certData, cert);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataX509AdoptCert", NULL);
        xmlSecKeyDestroy(key);
        X509_free(cert);
        return(NULL);
    }

    return(key);
}


/**
 * xmlSecOpenSSLAppKeysMngrCertLoad:
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
xmlSecOpenSSLAppKeysMngrCertLoad(xmlSecKeysMngrPtr mngr, const char *filename,
                            xmlSecKeyDataFormat format, xmlSecKeyDataType type) {
    BIO* bio;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    bio = BIO_new_file(filename, "rb");
    if(bio == NULL) {
        xmlSecOpenSSLError2("BIO_new_file", NULL,
                            "filename=%s", xmlSecErrorsSafeString(filename));
        return(-1);
    }

    ret = xmlSecOpenSSLAppKeysMngrCertLoadBIO(mngr, bio, format, type);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecOpenSSLAppKeysMngrCertLoadBIO", NULL,
                             "filename=%s", xmlSecErrorsSafeString(filename));
        BIO_free(bio);
        return(-1);
    }

    BIO_free(bio);
    return(0);
}

/**
 * xmlSecOpenSSLAppKeysMngrCertLoadMemory:
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
xmlSecOpenSSLAppKeysMngrCertLoadMemory(xmlSecKeysMngrPtr mngr, const xmlSecByte* data,
                                    xmlSecSize dataSize, xmlSecKeyDataFormat format,
                                    xmlSecKeyDataType type) {
    BIO* bio;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    /* this would be a read only BIO, cast from const is ok */
    bio = BIO_new_mem_buf((void*)data, dataSize);
    if(bio == NULL) {
        xmlSecOpenSSLError2("BIO_new_mem_buf", NULL,
                            "dataSize=%lu", (unsigned long)dataSize);
        return(-1);
    }

    ret = xmlSecOpenSSLAppKeysMngrCertLoadBIO(mngr, bio, format, type);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLAppKeysMngrCertLoadBIO", NULL);
        BIO_free(bio);
        return(-1);
    }

    BIO_free(bio);
    return(0);
}

/**
 * xmlSecOpenSSLAppKeysMngrCertLoadBIO:
 * @mngr:               the keys manager.
 * @bio:                the certificate BIO.
 * @format:             the certificate file format.
 * @type:               the flag that indicates is the certificate trusted or not.
 *
 * Reads cert from an OpenSSL BIO object and adds to the list of trusted or known
 * untrusted certs in @store.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecOpenSSLAppKeysMngrCertLoadBIO(xmlSecKeysMngrPtr mngr, BIO* bio,
                                    xmlSecKeyDataFormat format, xmlSecKeyDataType type) {
    xmlSecKeyDataStorePtr x509Store;
    X509* cert;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(bio != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    x509Store = xmlSecKeysMngrGetDataStore(mngr, xmlSecOpenSSLX509StoreId);
    if(x509Store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetDataStore(xmlSecOpenSSLX509StoreId)", NULL);
        return(-1);
    }

    cert = xmlSecOpenSSLAppCertLoadBIO(bio, format);
    if(cert == NULL) {
        xmlSecInternalError("xmlSecOpenSSLAppCertLoadBIO", NULL);
        return(-1);
    }

    ret = xmlSecOpenSSLX509StoreAdoptCert(x509Store, cert, type);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLX509StoreAdoptCert", NULL);
        X509_free(cert);
        return(-1);
    }

    return(0);
}

/**
 * xmlSecOpenSSLAppKeysMngrAddCertsPath:
 * @mngr:               the keys manager.
 * @path:               the path to trusted certificates.
 *
 * Reads cert from @path and adds to the list of trusted certificates.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecOpenSSLAppKeysMngrAddCertsPath(xmlSecKeysMngrPtr mngr, const char *path) {
    xmlSecKeyDataStorePtr x509Store;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(path != NULL, -1);

    x509Store = xmlSecKeysMngrGetDataStore(mngr, xmlSecOpenSSLX509StoreId);
    if(x509Store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetDataStore(xmlSecOpenSSLX509StoreId)", NULL);
        return(-1);
    }

    ret = xmlSecOpenSSLX509StoreAddCertsPath(x509Store, path);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecOpenSSLX509StoreAddCertsPath", NULL,
                             "path=%s", xmlSecErrorsSafeString(path));
        return(-1);
    }

    return(0);
}

/**
 * xmlSecOpenSSLAppKeysMngrAddCertsFile:
 * @mngr:               the keys manager.
 * @filename:           the file containing trusted certificates.
 *
 * Reads certs from @file and adds to the list of trusted certificates.
 * It is possible for @file to contain multiple certs.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecOpenSSLAppKeysMngrAddCertsFile(xmlSecKeysMngrPtr mngr, const char *filename) {
    xmlSecKeyDataStorePtr x509Store;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);

    x509Store = xmlSecKeysMngrGetDataStore(mngr, xmlSecOpenSSLX509StoreId);
    if(x509Store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetDataStore(xmlSecOpenSSLX509StoreId)", NULL);
        return(-1);
    }

    ret = xmlSecOpenSSLX509StoreAddCertsFile(x509Store, filename);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecOpenSSLX509StoreAddCertsFile", NULL,
                            "filename=%s", xmlSecErrorsSafeString(filename));
        return(-1);
    }

    return(0);
}

static X509*
xmlSecOpenSSLAppCertLoadBIO(BIO* bio, xmlSecKeyDataFormat format) {
    X509 *cert;

    xmlSecAssert2(bio != NULL, NULL);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, NULL);

    switch(format) {
    case xmlSecKeyDataFormatPem:
    case xmlSecKeyDataFormatCertPem:
        cert = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
        if(cert == NULL) {
            xmlSecOpenSSLError("PEM_read_bio_X509_AUX", NULL);
            return(NULL);
        }
        break;
    case xmlSecKeyDataFormatDer:
    case xmlSecKeyDataFormatCertDer:
        cert = d2i_X509_bio(bio, NULL);
        if(cert == NULL) {
            xmlSecOpenSSLError("d2i_X509_bio", NULL);
            return(NULL);
        }
        break;
    default:
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_FORMAT, NULL,
                         "format=%d", (int)format);
        return(NULL);
    }

    return(cert);
}

#endif /* XMLSEC_NO_X509 */

/**
 * xmlSecOpenSSLAppDefaultKeysMngrInit:
 * @mngr:               the pointer to keys manager.
 *
 * Initializes @mngr with simple keys store #xmlSecSimpleKeysStoreId
 * and a default OpenSSL crypto key data stores.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecOpenSSLAppDefaultKeysMngrInit(xmlSecKeysMngrPtr mngr) {
    int ret;

    xmlSecAssert2(mngr != NULL, -1);

    /* create simple keys store if needed */
    if(xmlSecKeysMngrGetKeysStore(mngr) == NULL) {
        xmlSecKeyStorePtr keysStore;

        keysStore = xmlSecKeyStoreCreate(xmlSecSimpleKeysStoreId);
        if(keysStore == NULL) {
            xmlSecInternalError("xmlSecKeyStoreCreate(xmlSecSimpleKeysStoreId)", NULL);
            return(-1);
        }

        ret = xmlSecKeysMngrAdoptKeysStore(mngr, keysStore);
        if(ret < 0) {
            xmlSecInternalError("xmlSecKeysMngrAdoptKeysStore", NULL);
            xmlSecKeyStoreDestroy(keysStore);
            return(-1);
        }
    }

    ret = xmlSecOpenSSLKeysMngrInit(mngr);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeysMngrInit", NULL);
        return(-1);
    }

    /* TODO */
    mngr->getKey = xmlSecKeysMngrGetKey;
    return(0);
}

/**
 * xmlSecOpenSSLAppDefaultKeysMngrAdoptKey:
 * @mngr:               the pointer to keys manager.
 * @key:                the pointer to key.
 *
 * Adds @key to the keys manager @mngr created with #xmlSecOpenSSLAppDefaultKeysMngrInit
 * function.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecOpenSSLAppDefaultKeysMngrAdoptKey(xmlSecKeysMngrPtr mngr, xmlSecKeyPtr key) {
    xmlSecKeyStorePtr store;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(key != NULL, -1);

    store = xmlSecKeysMngrGetKeysStore(mngr);
    if(store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetKeysStore", NULL);
        return(-1);
    }

    ret = xmlSecSimpleKeysStoreAdoptKey(store, key);
    if(ret < 0) {
        xmlSecInternalError("xmlSecSimpleKeysStoreAdoptKey", NULL);
        return(-1);
    }

    return(0);
}

/**
 * xmlSecOpenSSLAppDefaultKeysMngrLoad:
 * @mngr:               the pointer to keys manager.
 * @uri:                the uri.
 *
 * Loads XML keys file from @uri to the keys manager @mngr created
 * with #xmlSecOpenSSLAppDefaultKeysMngrInit function.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecOpenSSLAppDefaultKeysMngrLoad(xmlSecKeysMngrPtr mngr, const char* uri) {
    xmlSecKeyStorePtr store;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(uri != NULL, -1);

    store = xmlSecKeysMngrGetKeysStore(mngr);
    if(store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetKeysStore", NULL);
        return(-1);
    }

    ret = xmlSecSimpleKeysStoreLoad(store, uri, mngr);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecSimpleKeysStoreLoad", NULL,
                             "uri=%s", xmlSecErrorsSafeString(uri));
        return(-1);
    }

    return(0);
}

/**
 * xmlSecOpenSSLAppDefaultKeysMngrSave:
 * @mngr:               the pointer to keys manager.
 * @filename:           the destination filename.
 * @type:               the type of keys to save (public/private/symmetric).
 *
 * Saves keys from @mngr to  XML keys file.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecOpenSSLAppDefaultKeysMngrSave(xmlSecKeysMngrPtr mngr, const char* filename,
                                    xmlSecKeyDataType type) {
    xmlSecKeyStorePtr store;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);

    store = xmlSecKeysMngrGetKeysStore(mngr);
    if(store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetKeysStore", NULL);
        return(-1);
    }

    ret = xmlSecSimpleKeysStoreSave(store, filename, type);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecSimpleKeysStoreSave", NULL,
                             "filename=%s", xmlSecErrorsSafeString(filename));
        return(-1);
    }

    return(0);
}


/*
 * Random numbers initialization from openssl (apps/app_rand.c)
 */
static int seeded = 0;
static int egdsocket = 0;

static int
xmlSecOpenSSLAppLoadRANDFile(const char *filename) {
    char buffer[1024];

    if(filename == NULL) {
        filename = RAND_file_name(buffer, sizeof(buffer));
#ifndef OPENSSL_NO_EGD
    }else if(RAND_egd(filename) > 0) {
        /* we try if the given filename is an EGD socket.
         * if it is, we don't write anything back to the file. */
        egdsocket = 1;
        return 1;
#endif
    }

    if((filename == NULL) || !RAND_load_file(filename, -1)) {
        if(RAND_status() == 0) {
            xmlSecOpenSSLError2("RAND_load_file", NULL,
                                "filename=%s",
                                xmlSecErrorsSafeString(filename));
            return 0;
        }
    }
    seeded = 1;
    return 1;
}

static int
xmlSecOpenSSLAppSaveRANDFile(const char *filename) {
    char buffer[1024];

    if(egdsocket || !seeded) {
        /* If we did not manage to read the seed file,
         * we should not write a low-entropy seed file back --
         * it would suppress a crucial warning the next time
         * we want to use it. */
        return 0;
    }

    if(filename == NULL) {
        filename = RAND_file_name(buffer, sizeof(buffer));
    }
    if((filename == NULL) || !RAND_write_file(filename)) {
        xmlSecOpenSSLError2("RAND_write_file", NULL,
                            "filename=%s", xmlSecErrorsSafeString(filename));
        return 0;
    }

    return 1;
}

/**
 * xmlSecOpenSSLAppGetDefaultPwdCallback:
 *
 * Gets default password callback.
 *
 * Returns: default password callback.
 */
void*
xmlSecOpenSSLAppGetDefaultPwdCallback(void) {
    return XMLSEC_FUNC_TO_PTR(pem_password_cb, xmlSecOpenSSLDefaultPasswordCallback);
}

static int
xmlSecOpenSSLDefaultPasswordCallback(char *buf, int bufsize, int verify, void *userdata) {
    char* filename = (char*)userdata;
    char* buf2;
    xmlChar prompt[2048];
    int i, ret;

    xmlSecAssert2(buf != NULL, -1);

    /* try 3 times */
    for(i = 0; i < 3; i++) {
        if(filename != NULL) {
            ret = xmlStrPrintf(prompt, sizeof(prompt), "Enter password for \"%s\" file: ", filename);
        } else {
            ret = xmlStrPrintf(prompt, sizeof(prompt), "Enter password: ");
        }
        if(ret < 0) {
            xmlSecXmlError("xmlStrPrintf", NULL);
            return(-1);
        }

        ret = EVP_read_pw_string(buf, bufsize, (char*)prompt, 0);
        if(ret != 0) {
            xmlSecOpenSSLError("EVP_read_pw_string", NULL);
            return(-1);
        }

        /* if we don't need to verify password then we are done */
        if(verify == 0) {
            return(strlen(buf));
        }

        if(filename != NULL) {
            ret = xmlStrPrintf(prompt, sizeof(prompt), "Enter password for \"%s\" file again: ", filename);
        } else {
            ret = xmlStrPrintf(prompt, sizeof(prompt), "Enter password again: ");
        }
        if(ret < 0) {
            xmlSecXmlError("xmlStrPrintf", NULL);
            return(-1);
        }

        buf2 = (char*)xmlMalloc(bufsize);
        if(buf2 == NULL) {
            xmlSecMallocError(bufsize, NULL);
            return(-1);
        }
        ret = EVP_read_pw_string(buf2, bufsize, (char*)prompt, 0);
        if(ret != 0) {
            xmlSecOpenSSLError("EVP_read_pw_string", NULL);
            memset(buf2, 0, bufsize);
            xmlFree(buf2);
            return(-1);
        }

        /* check if passwords match */
        if(strcmp(buf, buf2) == 0) {
            memset(buf2, 0, bufsize);
            xmlFree(buf2);
            return(strlen(buf));
        }

        /* try again */
        memset(buf2, 0, bufsize);
        xmlFree(buf2);
    }

    return(-1);
}

static int
xmlSecOpenSSLDummyPasswordCallback(char *buf, int bufsize,
                                   int verify ATTRIBUTE_UNUSED,
                                   void *userdata) {
    char* password = (char*)userdata;

    if((password == NULL) || ((int)strlen(password) + 1 > bufsize)) {
        return(-1);
    }

    strcpy(buf, password);
    return (strlen(buf));
}

