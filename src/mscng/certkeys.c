/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2018 Miklos Vajna <vmiklos@vmiklos.hu>. All Rights Reserved.
 */
#include "globals.h"

#include <string.h>

#include <windows.h>
#include <bcrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/bn.h>

#include <xmlsec/mscng/crypto.h>

typedef struct _xmlSecMSCngKeyDataCtx xmlSecMSCngKeyDataCtx,
                                      *xmlSecMSCngKeyDataCtxPtr;

struct _xmlSecMSCngKeyDataCtx {
    PCCERT_CONTEXT cert;
    BCRYPT_KEY_HANDLE privkey;
    BCRYPT_KEY_HANDLE pubkey;
};

#define xmlSecMSCngKeyDataSize       \
    (sizeof(xmlSecKeyData) + sizeof(xmlSecMSCngKeyDataCtx))
#define xmlSecMSCngKeyDataGetCtx(data) \
    ((xmlSecMSCngKeyDataCtxPtr)(((xmlSecByte*)(data)) + sizeof(xmlSecKeyData)))

/**
 * xmlSecMSCngKeyDataAdoptCert:
 * @data:               the pointer to MSCng pccert data.
 * @cert:               the pointer to PCCERT key.
 *
 * Sets the value of key data.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
static int
xmlSecMSCngKeyDataAdoptCert(xmlSecKeyDataPtr data, PCCERT_CONTEXT cert, xmlSecKeyDataType type) {
    xmlSecMSCngKeyDataCtxPtr ctx;
    BCRYPT_KEY_HANDLE hKey;
    int ret;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCngKeyDataSize), -1);
    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(cert->pCertInfo != NULL, -1);
    xmlSecAssert2((type & (xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate)) != 0, -1);

    ctx = xmlSecMSCngKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pubkey == NULL, -1);
    xmlSecAssert2(ctx->cert == NULL, -1);

    /* acquire the CNG key handle from the certificate */
    if((type & xmlSecKeyDataTypePrivate) != 0) {
        xmlSecNotImplementedError(NULL);

        return(-1);
    }

    if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING,
            &cert->pCertInfo->SubjectPublicKeyInfo,
            0,
            NULL,
            &hKey)) {
        xmlSecMSCngLastError("CryptImportPublicKeyInfoEx2", NULL);
        return(-1);
    }
    ctx->pubkey = hKey;
    ctx->cert = cert;

    return(0);
}

/**
 * xmlSecMSCngCertAdopt:
 * @pCert:              the pointer to cert.
 * @type:               the expected key type.
 *
 * Creates key data value from the cert.
 *
 * Returns: pointer to newly created xmlsec key or NULL if an error occurs.
 */
xmlSecKeyDataPtr
xmlSecMSCngCertAdopt(PCCERT_CONTEXT pCert, xmlSecKeyDataType type) {
    xmlSecKeyDataPtr data = NULL;
    int ret;

    xmlSecAssert2(pCert != NULL, NULL);
    xmlSecAssert2(pCert->pCertInfo != NULL, NULL);
    xmlSecAssert2(pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId != NULL, NULL);

#ifndef XMLSEC_NO_ECDSA
    if(!strcmp(pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, szOID_ECC_PUBLIC_KEY)) {
        data = xmlSecKeyDataCreate(xmlSecMSCngKeyDataEcdsaId);
        if(data == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(KeyDataEcdsaId)", NULL);
            return(NULL);
        }
    }
#endif /* XMLSEC_NO_ECDSA */

    if(data == NULL) {
        xmlSecInvalidStringTypeError("PCCERT_CONTEXT key type",
            pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId,
            "unsupported keytype",
            NULL);
        return(NULL);
    }

    ret = xmlSecMSCngKeyDataAdoptCert(data, pCert, type);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataAdoptCert", NULL);
        xmlSecKeyDataDestroy(data);
        return(NULL);
    }

    return(data);
}

static int
xmlSecMSCngKeyDataInitialize(xmlSecKeyDataPtr data) {
    xmlSecMSCngKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCngKeyDataSize), -1);

    ctx = xmlSecMSCngKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecMSCngKeyDataCtx));

    return(0);
}

static void
xmlSecMSCngKeyDataFinalize(xmlSecKeyDataPtr data) {
    xmlSecMSCngKeyDataCtxPtr ctx;

    xmlSecAssert(xmlSecKeyDataIsValid(data));
    xmlSecAssert(xmlSecKeyDataCheckSize(data, xmlSecMSCngKeyDataSize));

    ctx = xmlSecMSCngKeyDataGetCtx(data);
    xmlSecAssert(ctx != NULL);

    if (ctx->pubkey != 0) {
        if(!BCryptDestroyKey(ctx->pubkey)) {
            xmlSecMSCngLastError("BCryptDestroyKey", NULL);
        }
    }

    if (ctx->cert != NULL) {
        CertFreeCertificateContext(ctx->cert);
    }

    memset(ctx, 0, sizeof(xmlSecMSCngKeyDataCtx));
}

#ifndef XMLSEC_NO_ECDSA
static int
xmlSecMSCngKeyDataEcdsaDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecMSCngKeyDataEcdsaId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecMSCngKeyDataEcdsaId), -1);

    xmlSecNotImplementedError(NULL);

    return(-1);
}

static xmlSecKeyDataType
xmlSecMSCngKeyDataEcdsaGetType(xmlSecKeyDataPtr data) {
    xmlSecMSCngKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataEcdsaId), xmlSecKeyDataTypeUnknown);

    ctx = xmlSecMSCngKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, xmlSecKeyDataTypeUnknown);

    if (ctx->privkey != 0) {
        return(xmlSecKeyDataTypePrivate | xmlSecKeyDataTypePublic);
    }

    return(xmlSecKeyDataTypePublic);
}

static xmlSecSize
xmlSecMSCngKeyDataEcdsaGetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataEcdsaId), 0);

    xmlSecNotImplementedError(NULL);

    return(0);
}


static void
xmlSecMSCngKeyDataEcdsaDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataEcdsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== rsa key: size = %d\n",
            xmlSecMSCngKeyDataEcdsaGetSize(data));
}

static void xmlSecMSCngKeyDataEcdsaDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataEcdsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "<ECDSAKeyValue size=\"%d\" />\n",
            xmlSecMSCngKeyDataEcdsaGetSize(data));
}

static xmlSecKeyDataKlass xmlSecMSCngKeyDataEcdsaKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecMSCngKeyDataSize,

    /* data */
    xmlSecNameECDSAKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                                /* xmlSecKeyDataUsage usage; */
    xmlSecHrefECDSAKeyValue,                    /* const xmlChar* href; */
    xmlSecNodeECDSAKeyValue,                    /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                               /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecMSCngKeyDataInitialize,               /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecMSCngKeyDataEcdsaDuplicate,           /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecMSCngKeyDataFinalize,                 /* xmlSecKeyDataFinalizeMethod finalize; */
    NULL,                                       /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecMSCngKeyDataEcdsaGetType,             /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecMSCngKeyDataEcdsaGetSize,             /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                                       /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    NULL,                                       /* xmlSecKeyDataXmlReadMethod xmlRead; */
    NULL,                                       /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                                       /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecMSCngKeyDataEcdsaDebugDump,           /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecMSCngKeyDataEcdsaDebugXmlDump,        /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecMSCngKeyDataEcdsaGetKlass:
 *
 * The MSCng ECDSA CertKey data klass.
 *
 * Returns: pointer to MSCng ECDSA key data klass.
 */
xmlSecKeyDataId
xmlSecMSCngKeyDataEcdsaGetKlass(void) {
    return(&xmlSecMSCngKeyDataEcdsaKlass);
}
#endif /* XMLSEC_NO_ECDSA */
