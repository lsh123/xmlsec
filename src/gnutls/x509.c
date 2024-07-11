
/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * X509 certificates implementation for GnuTLS.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:x509
 * @Short_description: X509 certificates implementation for GnuTLS.
 * @Stability: Stable
 *
 * X509 certificates implementation for GnuTLS.
 */

#include "globals.h"

#ifndef XMLSEC_NO_X509

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/base64.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/x509.h>
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>

#include <xmlsec/gnutls/crypto.h>
#include <xmlsec/gnutls/x509.h>

#include "private.h"
#include "../cast_helpers.h"
#include "../keysdata_helpers.h"

/*************************************************************************
 *
 * X509 utility functions
 *
 ************************************************************************/
static int              xmlSecGnuTLSKVerifyAndAdoptX509KeyData  (xmlSecKeyPtr key,
                                                                 xmlSecKeyDataPtr data,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);

/*************************************************************************
 *
 * Internal GnuTLS X509 data CTX
 *
 ************************************************************************/
typedef struct _xmlSecGnuTLSX509DataCtx                         xmlSecGnuTLSX509DataCtx,
                                                                *xmlSecGnuTLSX509DataCtxPtr;
struct _xmlSecGnuTLSX509DataCtx {
    gnutls_x509_crt_t   keyCert;    /* OWNED BY certsList */
    xmlSecPtrList       certsList;
    xmlSecPtrList       crlsList;
};


/**************************************************************************
 *
 * &lt;dsig:X509Data/&gt; processing (http://www.w3.org/TR/xmldsig-core/#sec-X509Data)
 *
 *************************************************************************/
XMLSEC_KEY_DATA_DECLARE(GnuTLSX509Data, xmlSecGnuTLSX509DataCtx)
#define xmlSecGnuTLSX509DataSize XMLSEC_KEY_DATA_SIZE(GnuTLSX509Data)

static int              xmlSecGnuTLSKeyDataX509Initialize      (xmlSecKeyDataPtr data);
static int              xmlSecGnuTLSKeyDataX509Duplicate       (xmlSecKeyDataPtr dst,
                                                                 xmlSecKeyDataPtr src);
static void             xmlSecGnuTLSKeyDataX509Finalize        (xmlSecKeyDataPtr data);
static int              xmlSecGnuTLSKeyDataX509XmlRead         (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecGnuTLSKeyDataX509XmlWrite        (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
static xmlSecKeyDataType xmlSecGnuTLSKeyDataX509GetType        (xmlSecKeyDataPtr data);
static const xmlChar*   xmlSecGnuTLSKeyDataX509GetIdentifier   (xmlSecKeyDataPtr data);

static void             xmlSecGnuTLSKeyDataX509DebugDump       (xmlSecKeyDataPtr data,
                                                                 FILE* output);
static void             xmlSecGnuTLSKeyDataX509DebugXmlDump    (xmlSecKeyDataPtr data,
                                                                 FILE* output);


typedef struct _xmlSecGnuTLSKeyDataX509Context {
    xmlSecSize crtPos;
    xmlSecSize crtSize;
    xmlSecSize crlPos;
    xmlSecSize crlSize;
} xmlSecGnuTLSKeyDataX509Context;

static int              xmlSecGnuTLSKeyDataX509Read             (xmlSecKeyDataPtr data,
                                                                 xmlSecKeyX509DataValuePtr x509Value,
                                                                 xmlSecKeysMngrPtr keysMngr,
                                                                 unsigned int flags);
static int              xmlSecGnuTLSKeyDataX509Write            (xmlSecKeyDataPtr data,
                                                                  xmlSecKeyX509DataValuePtr x509Value,
                                                                  int content,
                                                                  void* context);

static int              xmlSecGnuTLSX509CertSKIWrite            (gnutls_x509_crt_t cert,
                                                                 xmlSecBufferPtr buf);

static xmlSecKeyDataKlass xmlSecGnuTLSKeyDataX509Klass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecGnuTLSX509DataSize,

    /* data */
    xmlSecNameX509Data,
    xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageKeyInfoNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                                /* xmlSecKeyDataUsage usage; */
    xmlSecHrefX509Data,                         /* const xmlChar* href; */
    xmlSecNodeX509Data,                         /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                               /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecGnuTLSKeyDataX509Initialize,         /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecGnuTLSKeyDataX509Duplicate,          /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecGnuTLSKeyDataX509Finalize,           /* xmlSecKeyDataFinalizeMethod finalize; */
    NULL,                                       /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecGnuTLSKeyDataX509GetType,            /* xmlSecKeyDataGetTypeMethod getType; */
    NULL,                                       /* xmlSecKeyDataGetSizeMethod getSize; */
    xmlSecGnuTLSKeyDataX509GetIdentifier,      /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecGnuTLSKeyDataX509XmlRead,            /* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecGnuTLSKeyDataX509XmlWrite,           /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                                       /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecGnuTLSKeyDataX509DebugDump,          /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecGnuTLSKeyDataX509DebugXmlDump,       /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSKeyDataX509GetKlass:
 *
 * The GnuTLS X509 key data klass (http://www.w3.org/TR/xmldsig-core/#sec-X509Data).
 *
 * Returns: the X509 data klass.
 */
xmlSecKeyDataId
xmlSecGnuTLSKeyDataX509GetKlass(void) {
    return(&xmlSecGnuTLSKeyDataX509Klass);
}

/**
 * xmlSecGnuTLSKeyDataX509GetKeyCert:
 * @data:               the pointer to X509 key data.
 *
 * Gets the certificate from which the key was extracted.
 *
 * Returns: the key's certificate or NULL if key data was not used for key
 * extraction or an error occurs.
 */
gnutls_x509_crt_t
xmlSecGnuTLSKeyDataX509GetKeyCert(xmlSecKeyDataPtr data) {
    xmlSecGnuTLSX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataX509Id), NULL);

    ctx = xmlSecGnuTLSX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);

    return(ctx->keyCert);
}

xmlSecPtrListPtr
xmlSecGnuTLSKeyDataX509GetCerts(xmlSecKeyDataPtr data) {
    xmlSecGnuTLSX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataX509Id), NULL);

    ctx = xmlSecGnuTLSX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);

    return(&(ctx->certsList));
}

xmlSecPtrListPtr
xmlSecGnuTLSKeyDataX509GetCrls(xmlSecKeyDataPtr data) {
    xmlSecGnuTLSX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataX509Id), NULL);

    ctx = xmlSecGnuTLSX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);

    return(&(ctx->crlsList));
}


static int
xmlSecGnuTLSKeyDataX509AddCertInternal(xmlSecGnuTLSX509DataCtxPtr ctx, gnutls_x509_crt_t cert, int keyCert) {
    gnutls_x509_crt_t cert2;
    xmlSecSize ii, size;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(cert != NULL, -1);

    /* we don't want duplicate certs */
    size = xmlSecPtrListGetSize(&(ctx->certsList));
    for(ii = 0; ii < size; ++ii) {
        cert2 = xmlSecPtrListGetItem(&(ctx->certsList), ii);
        if(cert2 == NULL) {
            continue;
        }
        if((cert == cert2) || (gnutls_x509_crt_equals(cert, cert2) != 0)) {
            ret = xmlSecPtrListRemove(&(ctx->certsList), ii);
            if(ret < 0) {
                xmlSecInternalError("xmlSecPtrListRemove()", NULL);
                return(-1);
            }
            break;
        }
    }

    /* ensure that key cert is the first one */
    if(keyCert != 1) {
        ret = xmlSecPtrListInsert(&(ctx->certsList), cert, 0);
        if(ret < 0) {
            xmlSecInternalError("xmlSecPtrListInsert(0)", NULL);
            return(-1);
        }
    } else {
        ret = xmlSecPtrListAdd(&(ctx->certsList), cert);
        if(ret < 0) {
            xmlSecInternalError("xmlSecPtrListAdd", NULL);
            return(-1);
        }
    }

    /* done */
    return(0);
}

/**
 * xmlSecGnuTLSKeyDataX509AdoptKeyCert:
 * @data:               the pointer to X509 key data.
 * @cert:               the pointer to GnuTLS X509 certificate.
 *
 * Adds certificate to the X509 key data and sets the it as the key's
 * certificate in @data. On success, the @data owns the cert.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecGnuTLSKeyDataX509AdoptKeyCert(xmlSecKeyDataPtr data, gnutls_x509_crt_t cert) {
    xmlSecGnuTLSX509DataCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataX509Id), -1);
    xmlSecAssert2(cert != NULL, -1);

    ctx = xmlSecGnuTLSX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    /* check if for some reasons same cert is used */
    if((ctx->keyCert != NULL) && ((cert == ctx->keyCert) || (gnutls_x509_crt_equals(cert, ctx->keyCert) != 0))) {
        gnutls_x509_crt_deinit(cert);  /* caller expects data to own the cert on success. */
        return(0);
    }
    xmlSecAssert2(ctx->keyCert == NULL, -1);

    ret = xmlSecGnuTLSKeyDataX509AddCertInternal(ctx, cert, 1); /* key cert */
    if(ret < 0) {
        xmlSecInternalError("xmlSecGnuTLSKeyDataX509AddCertInternal", xmlSecKeyDataGetName(data));
        return(-1);
    }

    /* cert is now owned by data, we can't fail or there will be a double free */
    ctx->keyCert = cert;
    return(0);
}

/**
 * xmlSecGnuTLSKeyDataX509AdoptCert:
 * @data:               the pointer to X509 key data.
 * @cert:               the pointer to GnuTLS X509 certificate.
 *
 * Adds certificate to the X509 key data.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecGnuTLSKeyDataX509AdoptCert(xmlSecKeyDataPtr data, gnutls_x509_crt_t cert) {
    xmlSecGnuTLSX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataX509Id), -1);
    xmlSecAssert2(cert != NULL, -1);

    ctx = xmlSecGnuTLSX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    /* pkcs12 files sometime have key cert twice: as the key cert and as the cert in the chain */
    if((ctx->keyCert != NULL) && ((cert == ctx->keyCert) || (gnutls_x509_crt_equals(cert, ctx->keyCert) != 0))) {
        gnutls_x509_crt_deinit(cert); /* caller expects data to own the cert on success. */
        return(0);
    }
    return(xmlSecGnuTLSKeyDataX509AddCertInternal(ctx, cert, 0)); /* not a key cert */
}

/**
 * xmlSecGnuTLSKeyDataX509GetCert:
 * @data:               the pointer to X509 key data.
 * @pos:                the desired certificate position.
 *
 * Gets a certificate from X509 key data.
 *
 * Returns: the pointer to certificate or NULL if @pos is larger than the
 * number of certificates in @data or an error occurs.
 */
gnutls_x509_crt_t
xmlSecGnuTLSKeyDataX509GetCert(xmlSecKeyDataPtr data, xmlSecSize pos) {
    xmlSecGnuTLSX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataX509Id), NULL);

    ctx = xmlSecGnuTLSX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);

    /* to ensure that key cert is always first we put it at the first position
     * in xmlSecGnuTLSKeyDataX509AddCertInternal */
    return(xmlSecPtrListGetItem(&(ctx->certsList), pos));
}

/**
 * xmlSecGnuTLSKeyDataX509GetCertsSize:
 * @data:               the pointer to X509 key data.
 *
 * Gets the number of certificates in @data.
 *
 * Returns: te number of certificates in @data.
 */
xmlSecSize
xmlSecGnuTLSKeyDataX509GetCertsSize(xmlSecKeyDataPtr data) {
    xmlSecGnuTLSX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataX509Id), 0);

    ctx = xmlSecGnuTLSX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);

    return(xmlSecPtrListGetSize(&(ctx->certsList)));
}

/**
 * xmlSecGnuTLSKeyDataX509AdoptCrl:
 * @data:               the pointer to X509 key data.
 * @crl:                the pointer to GnuTLS X509 crl.
 *
 * Adds crl to the X509 key data.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecGnuTLSKeyDataX509AdoptCrl(xmlSecKeyDataPtr data, gnutls_x509_crl_t crl) {
    xmlSecGnuTLSX509DataCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataX509Id), -1);
    xmlSecAssert2(crl != NULL, -1);

    ctx = xmlSecGnuTLSX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecPtrListAdd(&(ctx->crlsList), crl);
    if(ret < 0) {
        xmlSecInternalError("xmlSecPtrListAdd",
                            xmlSecKeyDataGetName(data));
        return(-1);
    }

    return(0);
}

/**
 * xmlSecGnuTLSKeyDataX509GetCrl:
 * @data:               the pointer to X509 key data.
 * @pos:                the desired crl position.
 *
 * Gets a crl from X509 key data.
 *
 * Returns: the pointer to crl or NULL if @pos is larger than the
 * number of crls in @data or an error occurs.
 */
gnutls_x509_crl_t
xmlSecGnuTLSKeyDataX509GetCrl(xmlSecKeyDataPtr data, xmlSecSize pos) {
    xmlSecGnuTLSX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataX509Id), NULL);

    ctx = xmlSecGnuTLSX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);

    return(xmlSecPtrListGetItem(&(ctx->crlsList), pos));
}

/**
 * xmlSecGnuTLSKeyDataX509GetCrlsSize:
 * @data:               the pointer to X509 key data.
 *
 * Gets the number of crls in @data.
 *
 * Returns: te number of crls in @data.
 */
xmlSecSize
xmlSecGnuTLSKeyDataX509GetCrlsSize(xmlSecKeyDataPtr data) {
    xmlSecGnuTLSX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataX509Id), 0);

    ctx = xmlSecGnuTLSX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);

    return(xmlSecPtrListGetSize(&(ctx->crlsList)));
}

static int
xmlSecGnuTLSKeyDataX509Initialize(xmlSecKeyDataPtr data) {
    xmlSecGnuTLSX509DataCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataX509Id), -1);

    ctx = xmlSecGnuTLSX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecGnuTLSX509DataCtx));

    ret = xmlSecPtrListInitialize(&(ctx->certsList), xmlSecGnuTLSX509CrtListId);
    if(ret < 0) {
        xmlSecInternalError("xmlSecPtrListInitialize(certsList)", NULL);
        return(-1);
    }

    ret = xmlSecPtrListInitialize(&(ctx->crlsList), xmlSecGnuTLSX509CrlListId);
    if(ret < 0) {
        xmlSecInternalError("xmlSecPtrListInitialize(crlsList)", NULL);
        return(-1);
    }

    return(0);
}

static int
xmlSecGnuTLSKeyDataX509Duplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecGnuTLSX509DataCtxPtr ctxSrc;
    xmlSecGnuTLSX509DataCtxPtr ctxDst;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecGnuTLSKeyDataX509Id), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecGnuTLSKeyDataX509Id), -1);

    ctxSrc = xmlSecGnuTLSX509DataGetCtx(src);
    xmlSecAssert2(ctxSrc != NULL, -1);
    ctxDst = xmlSecGnuTLSX509DataGetCtx(dst);
    xmlSecAssert2(ctxDst != NULL, -1);

    /* copy certsList if exists */
    xmlSecPtrListEmpty(&(ctxDst->certsList));
    ret = xmlSecPtrListCopy(&(ctxDst->certsList), &(ctxSrc->certsList));
    if(ret < 0) {
        xmlSecInternalError("xmlSecPtrListCopy(certsList)", NULL);
        return(-1);
    }

    /* copy crlsList if exists */
    xmlSecPtrListEmpty(&(ctxDst->crlsList));
    ret = xmlSecPtrListCopy(&(ctxDst->crlsList), &(ctxSrc->crlsList));
    if(ret < 0) {
        xmlSecInternalError("xmlSecPtrListCopy(crlsList)", NULL);
        return(-1);
    }

    /* keyCert: should be in the same position in certsList after copy */
    if(ctxSrc->keyCert != NULL) {
        xmlSecSize ii, size;

        size = xmlSecPtrListGetSize(&(ctxDst->certsList));
        xmlSecAssert2(size == xmlSecPtrListGetSize(&(ctxDst->certsList)), -1);
        for(ii = 0; ii < size; ++ii) {
            gnutls_x509_crt_t cert = xmlSecPtrListGetItem(&(ctxSrc->certsList), ii);
            if(cert == ctxSrc->keyCert) {
                ctxDst->keyCert = xmlSecPtrListGetItem(&(ctxDst->certsList), ii);
                break;
            }
        }
        /* just to double check */
        xmlSecAssert2(ctxDst->keyCert != NULL, -1);
        xmlSecAssert2(gnutls_x509_crt_equals(ctxSrc->keyCert, ctxDst->keyCert) != 0, -1);
    }

    /* done */
    return(0);
}

static void
xmlSecGnuTLSKeyDataX509Finalize(xmlSecKeyDataPtr data) {
    xmlSecGnuTLSX509DataCtxPtr ctx;

    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataX509Id));

    ctx = xmlSecGnuTLSX509DataGetCtx(data);
    xmlSecAssert(ctx != NULL);

    xmlSecPtrListFinalize(&(ctx->crlsList));
    xmlSecPtrListFinalize(&(ctx->certsList));

    memset(ctx, 0, sizeof(xmlSecGnuTLSX509DataCtx));
}

static int
xmlSecGnuTLSKeyDataX509XmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataPtr data;
    int ret;

    xmlSecAssert2(id == xmlSecGnuTLSKeyDataX509Id, -1);
    xmlSecAssert2(key != NULL, -1);

    data = xmlSecKeyDataCreate(xmlSecGnuTLSKeyDataX509Id);
    if(data == NULL) {
        xmlSecInternalError("xmlSecKeyDataCreate(xmlSecGnuTLSKeyDataX509Id)", xmlSecKeyDataKlassGetName(id));
        return(-1);
    }

    ret = xmlSecKeyDataX509XmlRead(key, data, node, keyInfoCtx, xmlSecGnuTLSKeyDataX509Read);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyDataX509XmlRead", xmlSecKeyDataKlassGetName(id));
        xmlSecKeyDataDestroy(data);
        return(-1);
    }

    /* did we find the key already? */
    if(xmlSecKeyGetValue(key) != NULL) {
        xmlSecKeyDataDestroy(data);
        return(0);
    }

    ret = xmlSecGnuTLSKVerifyAndAdoptX509KeyData(key, data, keyInfoCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGnuTLSKVerifyAndAdoptX509KeyData", xmlSecKeyDataKlassGetName(id));
        xmlSecKeyDataDestroy(data);
        return(-1);
    } else if(ret != 1) {
        /* no errors but key was not found and data was not adopted */
        xmlSecKeyDataDestroy(data);
        return(0);
    }
    data = NULL; /* owned by data now */

    /* success */
    return(0);
}

static int
xmlSecGnuTLSKeyDataX509XmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataPtr data;
    xmlSecGnuTLSKeyDataX509Context context;
    int ret;

    xmlSecAssert2(id == xmlSecGnuTLSKeyDataX509Id, -1);
    xmlSecAssert2(key != NULL, -1);

    /* get x509 data */
    data = xmlSecKeyGetData(key, id);
    if(data == NULL) {
        /* no x509 data in the key */
        return(0);
    }

    /* setup context */
    context.crtPos = context.crlPos = 0;
    context.crtSize = xmlSecGnuTLSKeyDataX509GetCertsSize(data);
    context.crlSize = xmlSecGnuTLSKeyDataX509GetCrlsSize(data);

    ret = xmlSecKeyDataX509XmlWrite(data, node, keyInfoCtx,
        xmlSecBase64GetDefaultLineSize(), 1, /* add line breaks */
        xmlSecGnuTLSKeyDataX509Write, &context);
    if(ret < 0) {
        xmlSecInternalError3("xmlSecKeyDataX509XmlWrite",
            xmlSecKeyDataKlassGetName(id),
            "crtSize=" XMLSEC_SIZE_FMT "; crlSize=" XMLSEC_SIZE_FMT,
            context.crtSize, context.crlSize);
        return(-1);
    }

    /* success */
    return(0);
}


static xmlSecKeyDataType
xmlSecGnuTLSKeyDataX509GetType(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataX509Id), xmlSecKeyDataTypeUnknown);

    /* TODO: return verified/not verified status */
    return(xmlSecKeyDataTypeUnknown);
}

static const xmlChar*
xmlSecGnuTLSKeyDataX509GetIdentifier(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataX509Id), NULL);

    /* TODO */
    return(NULL);
}

static void
xmlSecGnuTLSKeyDataX509DebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecSize size, pos;

    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataX509Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== X509 Data:\n");

    /* key cert */
    {
        gnutls_x509_crt_t cert;

        cert = xmlSecGnuTLSKeyDataX509GetKeyCert(data);
        if(cert != NULL) {
            fprintf(output, "==== Key Certificate:\n");
            xmlSecGnuTLSX509CertDebugDump(cert, output);
        }
    }

    /* other certs */
    size = xmlSecGnuTLSKeyDataX509GetCertsSize(data);
    for(pos = 0; pos < size; ++pos) {
        gnutls_x509_crt_t cert;

        cert = xmlSecGnuTLSKeyDataX509GetCert(data, pos);
        if(cert == NULL) {
            xmlSecInternalError2("xmlSecGnuTLSKeyDataX509GetCert",
                                 xmlSecKeyDataGetName(data),
                                 "pos=" XMLSEC_SIZE_FMT, pos);
            return;
        }
        fprintf(output, "==== Certificate:\n");
        xmlSecGnuTLSX509CertDebugDump(cert, output);
    }

    /* crls */
    size = xmlSecGnuTLSKeyDataX509GetCrlsSize(data);
    for(pos = 0; pos < size; ++pos) {
        gnutls_x509_crl_t crl;

        crl = xmlSecGnuTLSKeyDataX509GetCrl(data, pos);
        if(crl == NULL) {
            xmlSecInternalError2("xmlSecGnuTLSKeyDataX509GetCrl",
                                 xmlSecKeyDataGetName(data),
                                 "pos=" XMLSEC_SIZE_FMT, pos);
            return;
        }
        fprintf(output, "==== Crl:\n");
        xmlSecGnuTLSX509CrlDebugDump(crl, output);
    }
}

static void
xmlSecGnuTLSKeyDataX509DebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecSize size, pos;

    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataX509Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "<X509Data>\n");

    /* key cert */
    {
        gnutls_x509_crt_t cert;

        cert = xmlSecGnuTLSKeyDataX509GetKeyCert(data);
        if(cert != NULL) {
            fprintf(output, "<KeyCertificate>\n");
            xmlSecGnuTLSX509CertDebugXmlDump(cert, output);
            fprintf(output, "</KeyCertificate>\n");
        }
    }

    /* other certs */
    size = xmlSecGnuTLSKeyDataX509GetCertsSize(data);
    for(pos = 0; pos < size; ++pos) {
        gnutls_x509_crt_t cert;

        cert = xmlSecGnuTLSKeyDataX509GetCert(data, pos);
        if(cert == NULL) {
            xmlSecInternalError2("xmlSecGnuTLSKeyDataX509GetCert",
                                 xmlSecKeyDataGetName(data),
                                 "pos=" XMLSEC_SIZE_FMT, pos);
            return;
        }
        fprintf(output, "<Certificate>\n");
        xmlSecGnuTLSX509CertDebugXmlDump(cert, output);
        fprintf(output, "</Certificate>\n");
    }

    /* other crls */
    size = xmlSecGnuTLSKeyDataX509GetCrlsSize(data);
    for(pos = 0; pos < size; ++pos) {
        gnutls_x509_crl_t crl;

        crl = xmlSecGnuTLSKeyDataX509GetCrl(data, pos);
        if(crl == NULL) {
            xmlSecInternalError2("xmlSecGnuTLSKeyDataX509GetCrl",
                                 xmlSecKeyDataGetName(data),
                                 "pos=" XMLSEC_SIZE_FMT, pos);
            return;
        }
        fprintf(output, "<CRL>\n");
        xmlSecGnuTLSX509CrlDebugXmlDump(crl, output);
        fprintf(output, "</CRL>\n");
    }

    /* we don't print out crls */
    fprintf(output, "</X509Data>\n");
}

/* xmlSecKeyDataX509Read: 0 on success and a negative value otherwise */
static int
xmlSecGnuTLSKeyDataX509Read(xmlSecKeyDataPtr data, xmlSecKeyX509DataValuePtr x509Value,
                             xmlSecKeysMngrPtr keysMngr, unsigned int flags) {
    xmlSecKeyDataStorePtr x509Store;
    gnutls_x509_crt_t cert = NULL;
    gnutls_x509_crl_t crl = NULL;
    int ret;
    int res = -1;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataX509Id), -1);
    xmlSecAssert2(x509Value != NULL, -1);
    xmlSecAssert2(keysMngr != NULL, -1);

    x509Store = xmlSecKeysMngrGetDataStore(keysMngr, xmlSecGnuTLSX509StoreId);
    if(x509Store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetDataStore", xmlSecKeyDataGetName(data));
        goto done;
    }

    if(xmlSecBufferGetSize(&(x509Value->cert)) > 0) {
        cert = xmlSecGnuTLSX509CertRead(xmlSecBufferGetData(&(x509Value->cert)),
            xmlSecBufferGetSize(&(x509Value->cert)), xmlSecKeyDataFormatCertDer);
        if(cert == NULL) {
            xmlSecInternalError("xmlSecGnuTLSX509CertRead", xmlSecKeyDataGetName(data));
            goto done;
        }
    }

    if(xmlSecBufferGetSize(&(x509Value->crl)) > 0) {
        crl = xmlSecGnuTLSX509CrlRead(xmlSecBufferGetData(&(x509Value->crl)),
            xmlSecBufferGetSize(&(x509Value->crl)), xmlSecKeyDataFormatCertDer);
        if(crl == NULL) {
            xmlSecInternalError("xmlSecGnuTLSX509CrlRead", xmlSecKeyDataGetName(data));
            goto done;
        }
    }

    /* if there is no cert in the X509Data node then try to find one */
    if(cert == NULL) {
        gnutls_x509_crt_t storeCert = NULL;
        int stopOnUnknownCert = 0;

        /* determine what to do */
        if((flags & XMLSEC_KEYINFO_FLAGS_X509DATA_STOP_ON_UNKNOWN_CERT) != 0) {
            stopOnUnknownCert = 1;
        }
        storeCert = xmlSecGnuTLSX509StoreFindCertByValue(x509Store, x509Value);
        if((storeCert == NULL) && (stopOnUnknownCert != 0)) {
            xmlSecOtherError(XMLSEC_ERRORS_R_CERT_NOT_FOUND, xmlSecKeyDataGetName(data), "cert lookup");
            goto done;
        }
        /* if we found cert in a store, then duplicate it for key data */
        if(storeCert != NULL) {
            cert = xmlSecGnuTLSX509CertDup(storeCert);
            if(cert == NULL) {
                xmlSecInternalError("xmlSecGnuTLSX509CertDup", xmlSecKeyDataGetName(data));
                goto done;
            }
        }
    }

    /* if we found a cert or a crl, then add it to the data */
    if(cert != NULL) {
        ret = xmlSecGnuTLSKeyDataX509AdoptCert(data, cert);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGnuTLSKeyDataX509AdoptCert", xmlSecKeyDataGetName(data));
            goto done;
        }
        cert = NULL; /* owned by data now */
    }
    if(crl != NULL) {
        ret = xmlSecGnuTLSKeyDataX509AdoptCrl(data, crl);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGnuTLSKeyDataX509AdoptCrl", xmlSecKeyDataGetName(data));
            goto done;
        }
        crl = NULL; /* owned by data now */
    }

    /* success */
    res = 0;

done:
    /* cleanup */
    if(cert != NULL) {
        gnutls_x509_crt_deinit(cert);
    }
    if(crl != NULL) {
        gnutls_x509_crl_deinit(crl);
    }
    return(res);
}

/* xmlSecKeyDataX509Write: returns 1 on success, 0 if no more certs/crls are available,
 * or a negative value if an error occurs.
 */
static int
xmlSecGnuTLSKeyDataX509Write(xmlSecKeyDataPtr data,  xmlSecKeyX509DataValuePtr x509Value,
                            int content, void* context) {
    xmlSecGnuTLSKeyDataX509Context* ctx;
    int ret;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataX509Id), -1);
    xmlSecAssert2(x509Value != NULL, -1);
    xmlSecAssert2(context != NULL, -1);

    ctx = (xmlSecGnuTLSKeyDataX509Context*)context;
    if(ctx->crtPos < ctx->crtSize) {
        /* write cert */
        gnutls_x509_crt_t cert = xmlSecGnuTLSKeyDataX509GetCert(data, ctx->crtPos);
        if(cert == NULL) {
            xmlSecInternalError2("xmlSecGnuTLSKeyDataX509GetCert",
                xmlSecKeyDataGetName(data),
                "pos=" XMLSEC_SIZE_FMT, ctx->crtPos);
            return(-1);
        }
        if (XMLSEC_X509DATA_HAS_EMPTY_NODE(content, XMLSEC_X509DATA_CERTIFICATE_NODE)) {
            ret = xmlSecGnuTLSX509CertDerWrite(cert, &(x509Value->cert));
            if(ret < 0) {
                xmlSecInternalError2("xmlSecGnuTLSX509CertDerWrite",
                    xmlSecKeyDataGetName(data),
                    "pos=" XMLSEC_SIZE_FMT, ctx->crtPos);
                return(-1);
            }
        }
        if (XMLSEC_X509DATA_HAS_EMPTY_NODE(content, XMLSEC_X509DATA_SKI_NODE)) {
            ret = xmlSecGnuTLSX509CertSKIWrite(cert, &(x509Value->ski));
            if(ret < 0) {
                xmlSecInternalError2("xmlSecGnuTLSX509SKIWrite",
                    xmlSecKeyDataGetName(data),
                    "pos=" XMLSEC_SIZE_FMT, ctx->crtPos);
                return(-1);
            }
        }
        if (XMLSEC_X509DATA_HAS_EMPTY_NODE(content, XMLSEC_X509DATA_SUBJECTNAME_NODE)) {
            xmlSecAssert2(x509Value->subject == NULL, -1);

            x509Value->subject = xmlSecGnuTLSX509CertGetSubjectDN(cert);
            if(x509Value->subject == NULL) {
                xmlSecInternalError2("xmlSecGnuTLSX509CertGetSubjectDN",
                    xmlSecKeyDataGetName(data),
                    "pos=" XMLSEC_SIZE_FMT, ctx->crtPos);
                return(-1);
            }
        }
        if (XMLSEC_X509DATA_HAS_EMPTY_NODE(content, XMLSEC_X509DATA_ISSUERSERIAL_NODE)) {
            xmlSecAssert2(x509Value->issuerName == NULL, -1);
            xmlSecAssert2(x509Value->issuerSerial == NULL, -1);

            x509Value->issuerName = xmlSecGnuTLSX509CertGetIssuerDN(cert);
            if(x509Value->issuerName == NULL) {
                xmlSecInternalError2("xmlSecGnuTLSX509CertGetIssuerDN",
                    xmlSecKeyDataGetName(data),
                    "pos=" XMLSEC_SIZE_FMT, ctx->crtPos);
                return(-1);
            }
            x509Value->issuerSerial = xmlSecGnuTLSX509CertGetIssuerSerial(cert);
            if(x509Value->issuerSerial == NULL) {
                xmlSecInternalError2("xmlSecGnuTLSX509CertGetIssuerSerial",
                    xmlSecKeyDataGetName(data),
                    "pos=" XMLSEC_SIZE_FMT, ctx->crtPos);
                return(-1);
            }
        }
        if((XMLSEC_X509DATA_HAS_EMPTY_NODE(content, XMLSEC_X509DATA_DIGEST_NODE)) && (x509Value->digestAlgorithm != NULL)) {
            ret = xmlSecGnuTLSX509DigestWrite(cert, x509Value->digestAlgorithm, &(x509Value->digest));
            if(ret < 0) {
                xmlSecInternalError2("xmlSecGnuTLSX509DigestWrite",
                    xmlSecKeyDataGetName(data),
                    "pos=" XMLSEC_SIZE_FMT, ctx->crtPos);
                return(-1);
            }
        }
        ++ctx->crtPos;
    } else if(ctx->crlPos < ctx->crlSize) {
        /* write crl */
        gnutls_x509_crl_t crl = xmlSecGnuTLSKeyDataX509GetCrl(data, ctx->crlPos);
        if(crl == NULL) {
            xmlSecInternalError2("xmlSecGnuTLSKeyDataX509GetCrl",
                xmlSecKeyDataGetName(data),
                "pos=" XMLSEC_SIZE_FMT, ctx->crlPos);
            return(-1);
        }

        if((content & XMLSEC_X509DATA_CRL_NODE) != 0) {
            ret = xmlSecGnuTLSX509CrlDerWrite(crl, &(x509Value->crl));
            if(ret < 0) {
                xmlSecInternalError2("xmlSecGnuTLSX509CrlDerWrite",
                    xmlSecKeyDataGetName(data),
                    "pos=" XMLSEC_SIZE_FMT, ctx->crlPos);
                return(-1);
            }
        }
        ++ctx->crlPos;
    } else {
        /* no more certs or crls */
        return(0);
    }

    /* success */
    return(1);
}

static int
xmlSecGnuTLSX509CertSKIWrite(gnutls_x509_crt_t cert, xmlSecBufferPtr buf) {
    size_t bufSizeT = 0;
    xmlSecSize bufSize;
    xmlSecByte * bufData;
    unsigned int critical = 0;
    int ret;
    int err;

    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);

    /* get size */
    err = gnutls_x509_crt_get_subject_key_id(cert, NULL, &bufSizeT, &critical);
    if((err != GNUTLS_E_SHORT_MEMORY_BUFFER) || (bufSizeT <= 0)) {
        xmlSecGnuTLSError("gnutls_x509_crt_get_subject_key_id", err, NULL);
        return(-1);
    }
    XMLSEC_SAFE_CAST_SIZE_T_TO_SIZE(bufSizeT, bufSize, return(-1), NULL);

    /* allocate buffer */
    ret = xmlSecBufferSetSize(buf, bufSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
            "bufSize=" XMLSEC_SIZE_FMT, bufSize);
        return(-1);
    }
    bufData = xmlSecBufferGetData(buf);
    xmlSecAssert2(bufData != NULL, -1);

    /* write it out */
    err = gnutls_x509_crt_get_subject_key_id(cert, bufData, &bufSizeT, &critical);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_x509_crt_get_subject_key_id", err, NULL);
        return(-1);
    }

    /* success */
    return(0);
}

static int
xmlSecGnuTLSKVerifyAndAdoptX509KeyData(xmlSecKeyPtr key, xmlSecKeyDataPtr data,  xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecGnuTLSX509DataCtxPtr ctx;
    xmlSecKeyDataStorePtr x509Store;
    gnutls_x509_crt_t cert;
    gnutls_x509_crt_t keyCert;
    xmlSecKeyDataPtr keyValue;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataX509Id), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(keyInfoCtx->keysMngr != NULL, -1);

    ctx = xmlSecGnuTLSX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyCert == NULL, -1);

    if( (xmlSecPtrListGetSize(&(ctx->certsList)) <= 0) || (xmlSecKeyGetValue(key) != NULL)) {
        /* no certs or key was already found -> nothing to do (this shouldn't really happen) */
        return(0);
    }

    /* lets find a cert we can verify */
    x509Store = xmlSecKeysMngrGetDataStore(keyInfoCtx->keysMngr, xmlSecGnuTLSX509StoreId);
    if(x509Store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetDataStore", xmlSecKeyDataGetName(data));
        return(-1);
    }
    cert = xmlSecGnuTLSX509StoreVerify(x509Store, &(ctx->certsList), &(ctx->crlsList), keyInfoCtx);
    if(cert == NULL) {
        /* check if we want to fail if cert is not found */
        if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_STOP_ON_INVALID_CERT) != 0) {
            xmlSecOtherError(XMLSEC_ERRORS_R_CERT_NOT_FOUND, xmlSecKeyDataGetName(data), NULL);
            return(-1);
        }
        return(0);
    }

    /* set cert into the x509 data, we don't know if the cert is already in KeyData or not
     * so assume we need to add it again.
     */
    keyCert = xmlSecGnuTLSX509CertDup(cert);
    if(keyCert == NULL) {
        xmlSecInternalError("xmlSecGnuTLSX509CertDup", xmlSecKeyDataGetName(data));
        return(-1);
    }
    ret = xmlSecGnuTLSKeyDataX509AdoptKeyCert(data, keyCert);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGnuTLSKeyDataX509AdoptKeyCert", xmlSecKeyDataGetName(data));
        gnutls_x509_crt_deinit(keyCert);
        return(-1);
    }
    cert = keyCert = NULL; /* we should be using ctx->keyCert for everything */

    /* extract key from cert and verify that the key matches our expectations */
    keyValue = xmlSecGnuTLSX509CertGetKey(ctx->keyCert);
    if(keyValue == NULL) {
        xmlSecInternalError("xmlSecGnuTLSX509CertGetKey", xmlSecKeyDataGetName(data));
        return(-1);
    }
    if(xmlSecKeyReqMatchKeyValue(&(keyInfoCtx->keyReq), keyValue) != 1) {
        xmlSecInternalError("xmlSecKeyReqMatchKeyValue", xmlSecKeyDataGetName(data));
        xmlSecKeyDataDestroy(keyValue);
        return(-1);
    }
    ret = xmlSecKeySetValue(key, keyValue);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeySetValue", xmlSecKeyDataGetName(data));
        xmlSecKeyDataDestroy(keyValue);
        return(-1);
    }
    keyValue = NULL; /* owned by key now */

    /* copy cert not before / not after times from the cert */
    key->notValidBefore = gnutls_x509_crt_get_activation_time(ctx->keyCert);
    if(key->notValidBefore == (time_t)-1) {
        xmlSecGnuTLSError("gnutls_x509_crt_get_activation_time", GNUTLS_E_SUCCESS, xmlSecKeyDataGetName(data));
        return(-1);
    }
    key->notValidAfter = gnutls_x509_crt_get_expiration_time(ctx->keyCert);
    if(key->notValidAfter == (time_t)-1) {
        xmlSecGnuTLSError("gnutls_x509_crt_get_expiration_time", GNUTLS_E_SUCCESS, xmlSecKeyDataGetName(data));
        return(-1);
    }

    /* THIS MUST BE THE LAST THING WE DO: add data to the key
     * if we do it sooner and fail later then both the caller and the key will free data
     * which would lead to double free */
    ret = xmlSecKeyAdoptData(key, data);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyAdoptData", xmlSecKeyDataGetName(data));
        return(-1);
    }

    /* success: cert found and data was adopted */
    return(1);
}

/**
 * xmlSecGnuTLSX509CertGetKey:
 * @cert:               the certificate.
 *
 * Extracts public key from the @cert.
 *
 * Returns: public key value or NULL if an error occurs.
 */
xmlSecKeyDataPtr
xmlSecGnuTLSX509CertGetKey(gnutls_x509_crt_t cert) {
    xmlSecKeyDataPtr data;
    gnutls_pubkey_t pubkey;
    int err;

    xmlSecAssert2(cert != NULL, NULL);

    err = gnutls_pubkey_init(&pubkey);
    if (err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_pubkey_init", err, NULL);
        return(NULL);
    }

    err = gnutls_pubkey_import_x509(pubkey, cert, 0);
    if (err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_pubkey_import_x509", err, NULL);
        gnutls_pubkey_deinit(pubkey);
        return(NULL);
    }

    data = xmlSecGnuTLSAsymKeyDataCreate(pubkey, NULL);
    if(data == NULL) {
        xmlSecInternalError("xmlSecGnuTLSAsymKeyDataCreate", NULL);
        gnutls_pubkey_deinit(pubkey);
        return(NULL);
    }
    pubkey = NULL; /* owned by data */

    /* done */
    return(data);
}


/**************************************************************************
 *
 * Raw X509 Certificate processing
 *
 *
 *************************************************************************/
static int              xmlSecGnuTLSKeyDataRawX509CertBinRead  (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 const xmlSecByte* buf,
                                                                 xmlSecSize bufSize,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);

static xmlSecKeyDataKlass xmlSecGnuTLSKeyDataRawX509CertKlass = {
    sizeof(xmlSecKeyDataKlass),
    sizeof(xmlSecKeyData),

    /* data */
    xmlSecNameRawX509Cert,
    xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageRetrievalMethodNodeBin,
                                                /* xmlSecKeyDataUsage usage; */
    xmlSecHrefRawX509Cert,                      /* const xmlChar* href; */
    NULL,                                       /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                               /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    NULL,                                       /* xmlSecKeyDataInitializeMethod initialize; */
    NULL,                                       /* xmlSecKeyDataDuplicateMethod duplicate; */
    NULL,                                       /* xmlSecKeyDataFinalizeMethod finalize; */
    NULL,                                       /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    NULL,                                       /* xmlSecKeyDataGetTypeMethod getType; */
    NULL,                                       /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                                       /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    NULL,                                       /* xmlSecKeyDataXmlReadMethod xmlRead; */
    NULL,                                       /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    xmlSecGnuTLSKeyDataRawX509CertBinRead,     /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    NULL,                                       /* xmlSecKeyDataDebugDumpMethod debugDump; */
    NULL,                                       /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSKeyDataRawX509CertGetKlass:
 *
 * The raw X509 certificates key data klass.
 *
 * Returns: raw X509 certificates key data klass.
 */
xmlSecKeyDataId
xmlSecGnuTLSKeyDataRawX509CertGetKlass(void) {
    return(&xmlSecGnuTLSKeyDataRawX509CertKlass);
}

static int
xmlSecGnuTLSKeyDataRawX509CertBinRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                    const xmlSecByte* buf, xmlSecSize bufSize,
                                    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataPtr data;
    gnutls_x509_crt_t cert;
    int ret;

    xmlSecAssert2(id == xmlSecGnuTLSKeyDataRawX509CertId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    cert = xmlSecGnuTLSX509CertRead(buf, bufSize, xmlSecKeyDataFormatCertDer);
    if(cert == NULL) {
        xmlSecInternalError("xmlSecGnuTLSX509CertRead", NULL);
        return(-1);
    }

    data = xmlSecKeyDataCreate(xmlSecGnuTLSKeyDataX509Id);
    if(data == NULL) {
        xmlSecInternalError("xmlSecKeyDataCreate(xmlSecGnuTLSKeyDataX509Id)", xmlSecKeyDataKlassGetName(id));
        gnutls_x509_crt_deinit(cert);
        return(-1);
    }

    ret = xmlSecGnuTLSKeyDataX509AdoptCert(data, cert);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGnuTLSKeyDataX509AdoptCert", xmlSecKeyDataKlassGetName(id));
        gnutls_x509_crt_deinit(cert);
        xmlSecKeyDataDestroy(data);
        return(-1);
    }
    cert = NULL; /* owned by data now */

    ret = xmlSecGnuTLSKVerifyAndAdoptX509KeyData(key, data, keyInfoCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGnuTLSKVerifyAndAdoptX509KeyData", xmlSecKeyDataKlassGetName(id));
        xmlSecKeyDataDestroy(data);
        return(-1);
    } else if(ret != 1) {
        /* no errors but key was not found and data was not adopted */
        xmlSecKeyDataDestroy(data);
        return(0);
    }
    data = NULL; /* owned by data now */

    /* success */
    return(0);
}

#endif /* XMLSEC_NO_X509 */
