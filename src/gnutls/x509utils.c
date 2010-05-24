/**
 * XMLSec library
 *
 * X509 support
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2010 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#ifndef XMLSEC_NO_X509

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>

#include <libxml/tree.h>



#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/pkcs12.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/x509.h>
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>

#include <xmlsec/gnutls/crypto.h>
#include <xmlsec/gnutls/x509.h>

#include "x509utils.h"


/**************************************************************************
 *
 * X509 crt list
 *
 *****************************************************************************/
static xmlSecPtr        xmlSecGnuTLSX509CrtListDuplicateItem    (xmlSecPtr ptr);
static void             xmlSecGnuTLSX509CrtListDestroyItem      (xmlSecPtr ptr);
static void             xmlSecGnuTLSX509CrtListDebugDumpItem    (xmlSecPtr ptr,
                                                                 FILE* output);
static void             xmlSecGnuTLSX509CrtListDebugXmlDumpItem (xmlSecPtr ptr,
                                                                 FILE* output);

static xmlSecPtrListKlass xmlSecGnuTLSX509CrtListKlass = {
    BAD_CAST "gnutls-x509-crt-list",
    xmlSecGnuTLSX509CrtListDuplicateItem,       /* xmlSecPtrDuplicateItemMethod duplicateItem; */
    xmlSecGnuTLSX509CrtListDestroyItem,         /* xmlSecPtrDestroyItemMethod destroyItem; */
    xmlSecGnuTLSX509CrtListDebugDumpItem,       /* xmlSecPtrDebugDumpItemMethod debugDumpItem; */
    xmlSecGnuTLSX509CrtListDebugXmlDumpItem,    /* xmlSecPtrDebugDumpItemMethod debugXmlDumpItem; */
};

xmlSecPtrListId
xmlSecGnuTLSX509CrtListGetKlass(void) {
    return(&xmlSecGnuTLSX509CrtListKlass);
}

static xmlSecPtr
xmlSecGnuTLSX509CrtListDuplicateItem(xmlSecPtr ptr) {
    xmlSecAssert2(ptr != NULL, NULL);

    return xmlSecGnuTLSX509CertDup((gnutls_x509_crt_t)ptr);
}

static void
xmlSecGnuTLSX509CrtListDestroyItem(xmlSecPtr ptr) {
    xmlSecAssert(ptr != NULL);

    gnutls_x509_crt_deinit((gnutls_x509_crt_t)ptr);
}

static void
xmlSecGnuTLSX509CrtListDebugDumpItem(xmlSecPtr ptr, FILE* output) {
    xmlSecAssert(ptr != NULL);
    xmlSecAssert(output != NULL);

    xmlSecGnuTLSX509CertDebugDump((gnutls_x509_crt_t)ptr, output);
}


static void
xmlSecGnuTLSX509CrtListDebugXmlDumpItem(xmlSecPtr ptr, FILE* output) {
    xmlSecAssert(ptr != NULL);
    xmlSecAssert(output != NULL);

    xmlSecGnuTLSX509CertDebugXmlDump((gnutls_x509_crt_t)ptr, output);
}

/*************************************************************************
 *
 * Utils/helpers
 *
 ************************************************************************/

/* HACK: gnutls doesn't have cert duplicate function, so we simply 
 write cert out and then read it back */
gnutls_x509_crt_t
xmlSecGnuTLSX509CertDup(gnutls_x509_crt_t src) {
    xmlChar * buf = NULL;
    gnutls_x509_crt_t res = NULL;

    xmlSecAssert2(src != NULL, NULL);

    buf = xmlSecGnuTLSX509CertBase64DerWrite(src, 0);
    if(buf == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecGnuTLSX509CertBase64DerWrite",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return (NULL);
    }

    res = xmlSecGnuTLSX509CertBase64DerRead(buf);
    if(res == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecGnuTLSX509CertBase64DerRead",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        xmlFree(buf);
        return (NULL);
    }

    /* done */
    xmlFree(buf);
    return (res);
}

xmlChar *
xmlSecGnuTLSX509CertGetSubjectDN(gnutls_x509_crt_t cert) {
    char* buf = NULL;
    size_t bufSize = 0;
    int err;

    xmlSecAssert2(cert != NULL, NULL);

    /* get subject size */
    err = gnutls_x509_crt_get_dn(cert, NULL, &bufSize);
    if((err != GNUTLS_E_SHORT_MEMORY_BUFFER) || (bufSize <= 0)) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gnutls_x509_crt_get_dn",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_GNUTLS_REPORT_ERROR(err));
        return(NULL);
    }

    /* allocate buffer */
    buf = (char *)xmlMalloc(bufSize + 1);
    if(buf == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlMalloc",
                    XMLSEC_ERRORS_R_MALLOC_FAILED,
                    "size=%d", (int)bufSize);
        return(NULL);
    }

    /* finally write it out */
    err = gnutls_x509_crt_get_dn(cert, buf, &bufSize);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gnutls_x509_crt_get_dn",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_GNUTLS_REPORT_ERROR(err));
        xmlFree(buf);
        return(NULL);
    }

    /* done */
    return(BAD_CAST buf);
}

xmlChar *
xmlSecGnuTLSX509CertGetIssuerDN(gnutls_x509_crt_t cert) {
    char* buf = NULL;
    size_t bufSize = 0;
    int err;

    xmlSecAssert2(cert != NULL, NULL);

    /* get issuer size */
    err = gnutls_x509_crt_get_issuer_dn(cert, NULL, &bufSize);
    if((err != GNUTLS_E_SHORT_MEMORY_BUFFER) || (bufSize <= 0)) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gnutls_x509_crt_get_issuer_dn",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_GNUTLS_REPORT_ERROR(err));
        return(NULL);
    }

    /* allocate buffer */
    buf = (char *)xmlMalloc(bufSize + 1);
    if(buf == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlMalloc",
                    XMLSEC_ERRORS_R_MALLOC_FAILED,
                    "size=%d", (int)bufSize);
        return(NULL);
    }

    /* finally write it out */
    err = gnutls_x509_crt_get_issuer_dn(cert, buf, &bufSize);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gnutls_x509_crt_get_issuer_dn",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_GNUTLS_REPORT_ERROR(err));
        xmlFree(buf);
        return(NULL);
    }

    /* done */
    return(BAD_CAST buf);
}

xmlChar *
xmlSecGnuTLSX509CertGetIssuerSerial(gnutls_x509_crt_t cert) {
    xmlChar * res = NULL;
    unsigned char* buf = NULL;
    size_t bufSize = 0;
    int err;

    xmlSecAssert2(cert != NULL, NULL);

    /* get issuer serial size */
    err = gnutls_x509_crt_get_serial(cert, NULL, &bufSize);
    if((err != GNUTLS_E_SHORT_MEMORY_BUFFER) || (bufSize <= 0)) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gnutls_x509_crt_get_serial",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_GNUTLS_REPORT_ERROR(err));
        return(NULL);
    }

    /* allocate buffer */
    buf = (unsigned char *)xmlMalloc(bufSize + 1);
    if(buf == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlMalloc",
                    XMLSEC_ERRORS_R_MALLOC_FAILED,
                    "size=%d", (int)bufSize);
        return(NULL);
    }

    /* write it out */
    err = gnutls_x509_crt_get_serial(cert, buf, &bufSize);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gnutls_x509_crt_get_serial",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_GNUTLS_REPORT_ERROR(err));
        xmlFree(buf);
        return(NULL);
    }

    /* convert to string */
    res = xmlSecGnuTLSASN1IntegerWrite(buf, bufSize);
    if(res == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecGnuTLSASN1IntegerWrite",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        xmlFree(buf);
        return(NULL);
    }

    /* done */
    xmlFree(buf);
    return(res);
}

xmlChar *
xmlSecGnuTLSX509CertGetSKI(gnutls_x509_crt_t cert) {
    xmlChar * res = NULL;
    xmlSecByte* buf = NULL;
    size_t bufSize = 0;
    unsigned int critical = 0;
    int err;

    xmlSecAssert2(cert != NULL, NULL);

    /* get ski size */
    err = gnutls_x509_crt_get_subject_key_id(cert, NULL, &bufSize, &critical);
    if((err != GNUTLS_E_SHORT_MEMORY_BUFFER) || (bufSize <= 0)) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gnutls_x509_crt_get_subject_key_id",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_GNUTLS_REPORT_ERROR(err));
        return(NULL);
    }

    /* allocate buffer */
    buf = (xmlSecByte *)xmlMalloc(bufSize + 1);
    if(buf == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlMalloc",
                    XMLSEC_ERRORS_R_MALLOC_FAILED,
                    "size=%d", (int)bufSize);
        return(NULL);
    }

    /* write it out */
    err = gnutls_x509_crt_get_subject_key_id(cert, buf, &bufSize, &critical);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gnutls_x509_crt_get_subject_key_id",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_GNUTLS_REPORT_ERROR(err));
        xmlFree(buf);
        return(NULL);
    }

    /* convert to string */
    res = xmlSecBase64Encode(buf, bufSize, 0);
    if(res == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecBase64Encode",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        xmlFree(buf);
        return(NULL);
    }

    /* done */
    xmlFree(buf);
    return(res);
}


gnutls_x509_crt_t
xmlSecGnuTLSX509CertBase64DerRead(xmlChar* buf) {
    int ret;

    xmlSecAssert2(buf != NULL, NULL);

    /* usual trick with base64 decoding "in-place" */
    ret = xmlSecBase64Decode(buf, (xmlSecByte*)buf, xmlStrlen(buf));
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecBase64Decode",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(NULL);
    }

    return(xmlSecGnuTLSX509CertRead((const xmlSecByte*)buf, ret, xmlSecKeyDataFormatCertDer));
}

gnutls_x509_crt_t
xmlSecGnuTLSX509CertRead(const xmlSecByte* buf, xmlSecSize size, xmlSecKeyDataFormat format) {
    gnutls_x509_crt_t cert = NULL;
    gnutls_x509_crt_fmt_t fmt;
    gnutls_datum_t data;
    int err;

    xmlSecAssert2(buf != NULL, NULL);
    xmlSecAssert2(size > 0, NULL);

    /* figure out format */
    switch(format) {
    case xmlSecKeyDataFormatCertPem:
        fmt = GNUTLS_X509_FMT_PEM;
        break;
    case xmlSecKeyDataFormatCertDer:
        fmt = GNUTLS_X509_FMT_DER;
        break;
    default:
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    NULL,
                    XMLSEC_ERRORS_R_INVALID_FORMAT,
                    "format=%d", format);
        return(NULL);
    }

    /* read cert */
    err = gnutls_x509_crt_init(&cert);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gnutls_x509_crt_init",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_GNUTLS_REPORT_ERROR(err));
        return(NULL);
    }

    data.data = (unsigned char*)buf;
    data.size = size;
    err = gnutls_x509_crt_import(cert, &data, fmt);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gnutls_x509_crt_import",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_GNUTLS_REPORT_ERROR(err));
        gnutls_x509_crt_deinit(cert);
        return(NULL);
    }

    return(cert);
}

xmlChar*
xmlSecGnuTLSX509CertBase64DerWrite(gnutls_x509_crt_t cert, int base64LineWrap) {
    xmlChar * res = NULL;
    xmlSecByte* buf = NULL;
    size_t bufSize = 0;
    int err;

    xmlSecAssert2(cert != NULL, NULL);

    /* get size */
    err = gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, NULL, &bufSize);
    if((err != GNUTLS_E_SHORT_MEMORY_BUFFER) || (bufSize <= 0)) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gnutls_x509_crt_export(GNUTLS_X509_FMT_DER)",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_GNUTLS_REPORT_ERROR(err));
        return(NULL);
    }

    /* allocate buffer */
    buf = (xmlSecByte *)xmlMalloc(bufSize + 1);
    if(buf == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlMalloc",
                    XMLSEC_ERRORS_R_MALLOC_FAILED,
                    "size=%d", (int)bufSize);
        return(NULL);
    }

    /* write it out */
    err = gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, buf, &bufSize);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gnutls_x509_crt_export(GNUTLS_X509_FMT_DER)",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_GNUTLS_REPORT_ERROR(err));
        xmlFree(buf);
        return(NULL);
    }

    /* convert to string */
    res = xmlSecBase64Encode(buf, bufSize, base64LineWrap);
    if(res == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecBase64Encode",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        xmlFree(buf);
        return(NULL);
    }

    /* done */
    xmlFree(buf);
    return(res);
}

void
xmlSecGnuTLSX509CertDebugDump(gnutls_x509_crt_t cert, FILE* output) {
    xmlChar * buf;

    xmlSecAssert(cert != NULL);
    xmlSecAssert(output != NULL);

    buf = xmlSecGnuTLSX509CertGetSubjectDN(cert);
    if(buf != NULL) {
        fprintf(output, "==== Subject Name: %s\n", buf);
        xmlFree(buf);
    } else {
        fprintf(output, "==== Subject Name: unknown\n");
    }

    buf = xmlSecGnuTLSX509CertGetIssuerDN(cert);
    if(buf != NULL) {
        fprintf(output, "==== Issuer Name: %s\n", buf);
        xmlFree(buf);
    } else {
        fprintf(output, "==== Issuer Name: unknown\n");
    }

    buf = xmlSecGnuTLSX509CertGetIssuerSerial(cert);
    if(buf != NULL) {
        fprintf(output, "==== Issuer Serial: %s\n", buf);
        xmlFree(buf);
    } else {
        fprintf(output, "==== Issuer Serial: unknown\n");
    }
}

void
xmlSecGnuTLSX509CertDebugXmlDump(gnutls_x509_crt_t cert, FILE* output) {
    xmlChar * buf;

    xmlSecAssert(cert != NULL);
    xmlSecAssert(output != NULL);

    buf = xmlSecGnuTLSX509CertGetSubjectDN(cert);
    if(buf != NULL) {
        fprintf(output, "<SubjectName>%s</SubjectName>\n", buf);
        xmlFree(buf);
    } else {
        fprintf(output, "<SubjectName>unknown</SubjectName>\n");
    }

    buf = xmlSecGnuTLSX509CertGetIssuerDN(cert);
    if(buf != NULL) {
        fprintf(output, "<IssuerName>%s</IssuerName>\n", buf);
        xmlFree(buf);
    } else {
        fprintf(output, "<IssuerName>unknown</IssuerName>\n");
    }

    buf = xmlSecGnuTLSX509CertGetIssuerSerial(cert);
    if(buf != NULL) {
        fprintf(output, "<SerialNumber>%s</SerialNumber>\n", buf);
        xmlFree(buf);
    } else {
        fprintf(output, "<SerialNumber>unknown</SerialNumber>\n");
    }
}

xmlChar*
xmlSecGnuTLSASN1IntegerWrite(const unsigned char * data, size_t len) {
    xmlChar *res = NULL;
    int resLen = 64; /* not more than 64 chars */
    unsigned long long int val = 0;
    size_t ii = 0;
    int shift = 0;

    xmlSecAssert2(data != NULL, NULL);
    xmlSecAssert2(len <= 9, NULL);

    /* HACK : to be fixed after GnuTLS provides a way to read opaque ASN1 integer */
    for(ii = len; ii > 0; --ii, shift += 8) {
        val |= ((unsigned long long)data[ii - 1]) << shift;
    }

    res = (xmlChar*)xmlMalloc(resLen + 1);
    if(res == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlMalloc",
                    XMLSEC_ERRORS_R_MALLOC_FAILED,
                    "size=%d", (int)resLen);
        return (NULL);
    }

    xmlSecStrPrintf(res, resLen, BAD_CAST "%llu", val);
    return(res);
}

/*************************************************************************
 *
 * pkcs12 utils/helpers
 *
 ************************************************************************/
int
xmlSecGnuTLSPkcs12LoadMemory(const xmlSecByte* data, xmlSecSize dataSize,
                             const char *pwd,
                             gnutls_x509_privkey_t * priv_key,
                             xmlSecPtrListPtr certsList)
{
    gnutls_pkcs12_t pkcs12 = NULL;
    gnutls_pkcs12_bag_t bag = NULL;
    gnutls_x509_crt_t cert = NULL;
    gnutls_datum_t datum;
    int res = -1;
    int idx;
    int err;
    int ret;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(dataSize > 0, -1);
    xmlSecAssert2(priv_key != NULL, -1);
    xmlSecAssert2((*priv_key) == NULL, -1);
    xmlSecAssert2(certsList != NULL, -1);

    /* read pkcs12 in internal structure */
    err = gnutls_pkcs12_init(&pkcs12);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gnutls_pkcs12_init",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_GNUTLS_REPORT_ERROR(err));
        goto done;
    }

    datum.data = (unsigned char *)data;
    datum.size = dataSize;
    err = gnutls_pkcs12_import(pkcs12, &datum, GNUTLS_X509_FMT_DER, 0);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gnutls_pkcs12_import",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_GNUTLS_REPORT_ERROR(err));
        goto done;
    }

    /* verify */
    err = gnutls_pkcs12_verify_mac(pkcs12, pwd);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gnutls_pkcs12_verify_mac",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_GNUTLS_REPORT_ERROR(err));
        goto done;
    }

    /* scan the pkcs structure and find the first private key */
    for(idx = 0; ; ++idx) {
        int bag_type;
        int elements_in_bag;
        int ii;

        err = gnutls_pkcs12_bag_init(&bag);
        if(err != GNUTLS_E_SUCCESS) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "gnutls_pkcs12_bag_init",
                        XMLSEC_ERRORS_R_CRYPTO_FAILED,
                        XMLSEC_GNUTLS_REPORT_ERROR(err));
            goto done;
        }

        err = gnutls_pkcs12_get_bag(pkcs12, idx, bag);
        if(err == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
            /* scanned the whole pkcs12, stop */
            break;
        } else if(err != GNUTLS_E_SUCCESS) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "gnutls_pkcs12_get_bag",
                        XMLSEC_ERRORS_R_CRYPTO_FAILED,
                        XMLSEC_GNUTLS_REPORT_ERROR(err));
            goto done;
        }

        /* check if we need to decrypt the bag */
        bag_type = gnutls_pkcs12_bag_get_type(bag, 0);
        if(bag_type < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "gnutls_pkcs12_bag_get_type",
                        XMLSEC_ERRORS_R_CRYPTO_FAILED,
                        XMLSEC_GNUTLS_REPORT_ERROR(bag_type));
            goto done;
        }
        if(bag_type == GNUTLS_BAG_ENCRYPTED) {
            err = gnutls_pkcs12_bag_decrypt(bag, pwd);
            if(err != GNUTLS_E_SUCCESS) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            NULL,
                            "gnutls_pkcs12_bag_decrypt",
                            XMLSEC_ERRORS_R_CRYPTO_FAILED,
                            XMLSEC_GNUTLS_REPORT_ERROR(err));
                goto done;
            }
        }

        /* scan elements in bag */
        elements_in_bag = gnutls_pkcs12_bag_get_count(bag);
        if(elements_in_bag < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "gnutls_pkcs12_bag_get_count",
                        XMLSEC_ERRORS_R_CRYPTO_FAILED,
                        XMLSEC_GNUTLS_REPORT_ERROR(bag_type));
            goto done;
        }
        for(ii = 0; ii < elements_in_bag; ++ii) {
            bag_type = gnutls_pkcs12_bag_get_type(bag, ii);
            if(bag_type < 0) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            NULL,
                            "gnutls_pkcs12_bag_get_type",
                            XMLSEC_ERRORS_R_CRYPTO_FAILED,
                            XMLSEC_GNUTLS_REPORT_ERROR(bag_type));
                goto done;
            }

            err = gnutls_pkcs12_bag_get_data(bag, ii, &datum);
            if(err != GNUTLS_E_SUCCESS) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            NULL,
                            "gnutls_pkcs12_bag_get_data",
                            XMLSEC_ERRORS_R_CRYPTO_FAILED,
                            XMLSEC_GNUTLS_REPORT_ERROR(err));
                goto done;
            }

            switch(bag_type) {
            case GNUTLS_BAG_PKCS8_ENCRYPTED_KEY:
            case GNUTLS_BAG_PKCS8_KEY:
                /* we want only the first private key */
                if((*priv_key) == NULL) {
                    err = gnutls_x509_privkey_init(priv_key);
                    if(err != GNUTLS_E_SUCCESS) {
                        xmlSecError(XMLSEC_ERRORS_HERE,
                                    NULL,
                                    "gnutls_x509_privkey_init",
                                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                                    XMLSEC_GNUTLS_REPORT_ERROR(err));
                        goto done;
                    }

                    err = gnutls_x509_privkey_import_pkcs8((*priv_key),
                                &datum, GNUTLS_X509_FMT_DER,
                                pwd,
                                (bag_type == GNUTLS_BAG_PKCS8_KEY) ? GNUTLS_PKCS_PLAIN : 0);
                    if(err != GNUTLS_E_SUCCESS) {
                        xmlSecError(XMLSEC_ERRORS_HERE,
                                    NULL,
                                    "gnutls_x509_privkey_import_pkcs8",
                                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                                    XMLSEC_GNUTLS_REPORT_ERROR(err));
                        goto done;
                    }
                }
                break;
            case GNUTLS_BAG_CERTIFICATE:
                err = gnutls_x509_crt_init(&cert);
                if(err != GNUTLS_E_SUCCESS) {
                    xmlSecError(XMLSEC_ERRORS_HERE,
                                NULL,
                                "gnutls_x509_crt_init",
                                XMLSEC_ERRORS_R_CRYPTO_FAILED,
                                XMLSEC_GNUTLS_REPORT_ERROR(err));
                    goto done;
                }

                err = gnutls_x509_crt_import(cert, &datum, GNUTLS_X509_FMT_DER);
                if(err != GNUTLS_E_SUCCESS) {
                    xmlSecError(XMLSEC_ERRORS_HERE,
                                NULL,
                                "gnutls_x509_crt_import",
                                XMLSEC_ERRORS_R_CRYPTO_FAILED,
                                XMLSEC_GNUTLS_REPORT_ERROR(err));
                    goto done;
                }

                ret = xmlSecPtrListAdd(certsList, cert);
                if(ret < 0) {
                    xmlSecError(XMLSEC_ERRORS_HERE,
                                NULL,
                                "xmlSecPtrListAdd(certsList)",
                                XMLSEC_ERRORS_R_XMLSEC_FAILED,
                                XMLSEC_ERRORS_NO_MESSAGE);
                    goto done;
                }
                cert = NULL; /* owned by certsList now */
                break;
            default:
                /* ignore unknown bag element */
                break;
            }
        }

        /* done with bag */
        gnutls_pkcs12_bag_deinit(bag);
        bag = NULL;
    }

    /* check we have private key */
    if((*priv_key) == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    NULL,
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "Private key was not found in pkcs12 object");
        goto done;
    }

    /* success!!! */
    res = 0;

done:
    if(cert != NULL) {
        gnutls_x509_crt_deinit(cert);
    }
    if(bag != NULL) {
        gnutls_pkcs12_bag_deinit(bag);
    }
    if(pkcs12 != NULL) {
        gnutls_pkcs12_deinit(pkcs12);
    }
    return(res);
}

xmlSecKeyDataPtr
xmlSecGnuTLSCreateKeyDataAndAdoptPrivKey(gnutls_x509_privkey_t priv_key) {
    xmlSecKeyDataPtr res = NULL;
    int key_alg;
    int ret;

    xmlSecAssert2(priv_key != NULL, NULL);

    /* create key value data */
    key_alg = gnutls_x509_privkey_get_pk_algorithm(priv_key);
    if(key_alg < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gnutls_x509_privkey_get_pk_algorithm",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_GNUTLS_REPORT_ERROR(key_alg));
        return (NULL);
    }
    switch(key_alg) {
#ifndef XMLSEC_NO_RSA
    case GNUTLS_PK_RSA:
        res = xmlSecKeyDataCreate(xmlSecGnuTLSKeyDataRsaId);
        if(res == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecKeyDataCreate",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "xmlSecGnuTLSKeyDataRsaId");
            return(NULL);
        }

        ret = xmlSecGnuTLSKeyDataRsaAdoptPrivateKey(res, priv_key);
        if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecGnuTLSKeyDataRsaAdoptPrivateKey",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "xmlSecGnuTLSKeyDataRsaId");
            xmlSecKeyDataDestroy(res);
            return(NULL);
        }
        break;
#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_DSA
    case GNUTLS_PK_DSA:
        res = xmlSecKeyDataCreate(xmlSecGnuTLSKeyDataDsaId);
        if(res == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecKeyDataCreate",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "xmlSecGnuTLSKeyDataDsaId");
            return(NULL);
        }

        ret = xmlSecGnuTLSKeyDataDsaAdoptPrivateKey(res, priv_key);
        if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecGnuTLSKeyDataDsaAdoptPrivateKey",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "xmlSecGnuTLSKeyDataDsaId");
            xmlSecKeyDataDestroy(res);
            return(NULL);
        }
        break;
#endif /* XMLSEC_NO_DSA */
    default:
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gnutls_x509_privkey_get_pk_algorithm",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    "Unsupported algorithm %d", (int)key_alg);
        return(NULL);
    }

    /* done */
    return(res);
}



#endif /* XMLSEC_NO_X509 */
