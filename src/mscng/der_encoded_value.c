/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * <dsig11:DEREncodedKeyValue /> processing for Microsoft Cryptography API:
 * Next Generation (CNG).
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2018 Miklos Vajna. All Rights Reserved.
 */
/**
 * SECTION:crypto
 */

#include "globals.h"

#include <xmlsec/xmlsec.h>
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keys.h>
#include <xmlsec/private.h>
#include <xmlsec/xmltree.h>

#include <xmlsec/mscng/certkeys.h>
#include <xmlsec/mscng/crypto.h>

#include "../cast_helpers.h"
#include "private.h"


/**************************************************************************
 *
 * <dsig11:DEREncodedKeyValue /> processing
 *
 *************************************************************************/
static int                      xmlSecMSCngKeyDataDEREncodedKeyValueXmlRead(xmlSecKeyDataId id,
    xmlSecKeyPtr key,
    xmlNodePtr node,
    xmlSecKeyInfoCtxPtr keyInfoCtx);
static int                      xmlSecMSCngKeyDataDEREncodedKeyValueXmlWrite(xmlSecKeyDataId id,
    xmlSecKeyPtr key,
    xmlNodePtr node,
    xmlSecKeyInfoCtxPtr keyInfoCtx);
static int                      xmlSecMSCngBuildSubjectPublicKeyInfoDer(BCRYPT_KEY_HANDLE hKey,
    LPVOID* ppDer,
    DWORD* pcbDer);



static xmlSecKeyDataKlass xmlSecMSCngKeyDataDEREncodedKeyValueKlass = {
    sizeof(xmlSecKeyDataKlass),
    sizeof(xmlSecKeyData),

    /* data */
    xmlSecNameDEREncodedKeyValue,
    xmlSecKeyDataUsageKeyInfoNode | xmlSecKeyDataUsageRetrievalMethodNodeXml, /* xmlSecKeyDataUsage usage; */
    NULL,                                       /* const xmlChar* href; */
    xmlSecNodeDEREncodedKeyValue,               /* const xmlChar* dataNodeName; */
    xmlSecDSig11Ns,                             /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    NULL,                                       /* xmlSecKeyDataInitializeMethod initialize; */
    NULL,                                       /* xmlSecKeyDataDuplicateMethod duplicate; */
    NULL,                                       /* xmlSecKeyDataFinalizeMethod finalize; */
    NULL,                                       /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    NULL,                                       /* xmlSecKeyDataGetTypeMethod getType; */
    NULL,                                       /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                                       /* DEPRECATED xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecMSCngKeyDataDEREncodedKeyValueXmlRead,     /* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecMSCngKeyDataDEREncodedKeyValueXmlWrite,    /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                                       /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    NULL,                                       /* xmlSecKeyDataDebugDumpMethod debugDump; */
    NULL,                                       /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecMSCngKeyDataDEREncodedKeyValueGetKlass:
 * The public key algorithm and value are DER-encoded in accordance with the value that would be used
 * in the Subject Public Key Info field of an X.509 certificate, per section 4.1.2.7 of [RFC5280].
 * The DER-encoded value is then base64-encoded.
 *
 * https://www.w3.org/TR/xmldsig-core1/#sec-DEREncodedKeyValue
 *
 *      <!-- targetNamespace="http://www.w3.org/2009/xmldsig11#" -->
 *      <element name="DEREncodedKeyValue" type="dsig11:DEREncodedKeyValueType" />
 *      <complexType name="DEREncodedKeyValueType">
 *          <simpleContent>
 *              <extension base="base64Binary">
 *                  <attribute name="Id" type="ID" use="optional"/>
 *              </extension>
 *          </simpleContent>
 *      </complexType>
 *
 * Returns: the &lt;dsig11:DEREncodedKeyValue/&gt;element processing key data klass.
 */
xmlSecKeyDataId
xmlSecMSCngKeyDataDEREncodedKeyValueGetKlass(void) {
    return(&xmlSecMSCngKeyDataDEREncodedKeyValueKlass);
}

static int
xmlSecMSCngKeyDataDEREncodedKeyValueXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecBuffer buffer;
    const xmlSecByte* data;
    xmlSecSize dataSize;
    DWORD dataLen;
    LPVOID keyInfo = NULL;
    DWORD keyInfoLen = 0;
    BCRYPT_KEY_HANDLE hPubkey = 0;
    xmlSecKeyDataPtr keyData = NULL;
    xmlNodePtr cur;
    BOOL status;
    int res = -1;
    int ret;

    xmlSecAssert2(id == xmlSecMSCngKeyDataDEREncodedKeyValueId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(node->doc != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(keyInfoCtx->mode == xmlSecKeyInfoModeRead, -1);

    ret = xmlSecBufferInitialize(&buffer, 256);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", xmlSecKeyDataKlassGetName(id));
        return(-1);
    }

    /* no children are expected */
    cur = xmlSecGetNextElementNode(node->children);
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur, xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* read base64 node content */
    ret = xmlSecBufferBase64NodeContentRead(&buffer, node);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferBase64NodeContentRead", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    data = xmlSecBufferGetData(&buffer);
    dataSize = xmlSecBufferGetSize(&buffer);
    if((data == NULL) || (dataSize <= 0)) {
        /* this is not an error if we are reading a doc to be encrypted or signed */
        res = 0;
        goto done;
    }

    /* read pubkey */
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(dataSize, dataLen, goto done, xmlSecKeyDataKlassGetName(id));
    status = CryptDecodeObjectEx(
        X509_ASN_ENCODING,
        X509_PUBLIC_KEY_INFO,
        data,
        dataLen,
        CRYPT_DECODE_ALLOC_FLAG,
        NULL,
        &keyInfo,
        &keyInfoLen
    );
    if((status != TRUE) || (keyInfo == NULL) || (keyInfoLen <= 0)) {
        xmlSecMSCngNtError("CryptDecodeObjectEx", xmlSecKeyDataKlassGetName(id), STATUS_SUCCESS);
        goto done;
    }

    ret = xmlSecMSCngKeyDataCertGetPubkey((PCERT_PUBLIC_KEY_INFO)keyInfo, &hPubkey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataCertGetPubkey", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* add to key */
    keyData = xmlSecMSCngKeyDataFromAlgorithm(((PCERT_PUBLIC_KEY_INFO)keyInfo)->Algorithm.pszObjId);
    if(keyData == NULL) {
        xmlSecInternalError("xmlSecMSCngKeyDataFromAlgorithm", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = xmlSecMSCngKeyDataAdoptKey(keyData, hPubkey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataAdoptKey", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    hPubkey = 0; /* owned by key data now */

    ret = xmlSecKeySetValue(key, keyData);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeySetValue", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    keyData = NULL; /* owned by key now */

    /* success! */
    res = 0;

done:
    if(keyData != NULL) {
        xmlSecKeyDataDestroy(keyData);
    }
    if(hPubkey != 0) {
        BCryptDestroyKey(hPubkey);
    }
    if(keyInfo != NULL) {
        LocalFree(keyInfo);
    }
    xmlSecBufferFinalize(&buffer);
    return(res);
}

#ifndef XMLSEC_NO_DSA
/* Builds the correct SubjectPublicKeyInfo DER for a DSA BCrypt public key.
 * CryptExportPublicKeyInfoFromBCryptKeyHandle misinterprets V2 (>1024-bit) DSA
 * blobs, reading all fields at V1 offsets and producing garbled P/Q/G/Y values.
 * This helper exports the BCrypt blob directly, extracts the correct fields, and
 * re-encodes them. On success returns 0; caller must LocalFree(*ppDer). */
static int
xmlSecMSCngDsaBuildSubjectPublicKeyInfoDer(BCRYPT_KEY_HANDLE hKey,
                                           LPVOID* ppDer, DWORD* pcbDer) {
    BYTE* blobData = NULL;
    DWORD blobLen = 0;
    const BYTE* pBE = NULL;
    const BYTE* qBE = NULL;
    const BYTE* gBE = NULL;
    const BYTE* yBE = NULL;
    BCRYPT_DSA_KEY_BLOB* hdr;
    DWORD pSize = 0, qSize = 0, gSize = 0, ySize = 0;
    BYTE* pLE = NULL, * qLE = NULL, * gLE = NULL, * yLE = NULL;
    CERT_DSS_PARAMETERS dssParams;
    CRYPT_UINT_BLOB yBlob;
    BYTE* encodedParams = NULL;
    DWORD encodedParamsLen = 0;
    BYTE* encodedY = NULL;
    DWORD encodedYLen = 0;
    CERT_PUBLIC_KEY_INFO spki;
    NTSTATUS status;
    DWORD ii;
    int ret = -1;

    xmlSecAssert2(hKey != 0, -1);
    xmlSecAssert2(ppDer != NULL, -1);
    xmlSecAssert2(pcbDer != NULL, -1);

    *ppDer = NULL;
    *pcbDer = 0;

    /* Export DSA public key to BCrypt blob */
    status = BCryptExportKey(hKey, NULL, BCRYPT_DSA_PUBLIC_BLOB, NULL, 0, &blobLen, 0);
    if((status != STATUS_SUCCESS) || (blobLen < sizeof(BCRYPT_DSA_KEY_BLOB))) {
        xmlSecMSCngNtError("BCryptExportKey(size)", NULL, status);
        goto done;
    }
    blobData = (BYTE*)LocalAlloc(LMEM_ZEROINIT, blobLen);
    if(blobData == NULL) {
        xmlSecMSCngLastError("LocalAlloc", NULL);
        goto done;
    }
    status = BCryptExportKey(hKey, NULL, BCRYPT_DSA_PUBLIC_BLOB, blobData, blobLen, &blobLen, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptExportKey", NULL, status);
        goto done;
    }

    /* Locate P, Q, G, Y within the blob (BCrypt stores all values big-endian) */
    hdr = (BCRYPT_DSA_KEY_BLOB*)blobData;
    if(hdr->dwMagic == BCRYPT_DSA_PUBLIC_MAGIC) {
        /* V1: header + p[cbKey] + g[cbKey] + y[cbKey], q fixed 20 bytes in header */
        BYTE* d = blobData + sizeof(BCRYPT_DSA_KEY_BLOB);
        pBE = d;       pSize = hdr->cbKey; d += pSize;
        qBE = hdr->q;  qSize = sizeof(hdr->q);
        gBE = d;       gSize = hdr->cbKey; d += gSize;
        yBE = d;       ySize = hdr->cbKey;
    }
#if XMLSEC_MSCNG_HAVE_DSA_V2
    else if(hdr->dwMagic == BCRYPT_DSA_PUBLIC_MAGIC_V2) {
        /* V2: header + seed[cbSeedLength] + q[cbGroupSize] + p[cbKey] + g[cbKey] + y[cbKey] */
        BCRYPT_DSA_KEY_BLOB_V2* h2 = (BCRYPT_DSA_KEY_BLOB_V2*)blobData;
        BYTE* d = blobData + sizeof(BCRYPT_DSA_KEY_BLOB_V2);
        d    += h2->cbSeedLength;               /* skip seed placeholder */
        qBE = d;  qSize = h2->cbGroupSize; d += qSize;
        pBE = d;  pSize = h2->cbKey;       d += pSize;
        gBE = d;  gSize = h2->cbKey;       d += gSize;
        yBE = d;  ySize = h2->cbKey;
    }
#endif /* XMLSEC_MSCNG_HAVE_DSA_V2 */
    else {
        xmlSecNotImplementedError2("Unexpected DSA blob magic: 0x%08lX",
            (unsigned long)hdr->dwMagic);
        goto done;
    }

    /* Reverse each big-endian BCrypt value to little-endian for CryptEncodeObjectEx
     * (CRYPT_UINT_BLOB values are expected in little-endian / LSB-first order). */
    pLE = (BYTE*)LocalAlloc(LMEM_ZEROINIT, pSize);
    qLE = (BYTE*)LocalAlloc(LMEM_ZEROINIT, qSize);
    gLE = (BYTE*)LocalAlloc(LMEM_ZEROINIT, gSize);
    yLE = (BYTE*)LocalAlloc(LMEM_ZEROINIT, ySize);
    if(!pLE || !qLE || !gLE || !yLE) {
        xmlSecMSCngLastError("LocalAlloc", NULL);
        goto done;
    }
    for(ii = 0; ii < pSize; ii++) pLE[ii] = pBE[pSize - 1 - ii];
    for(ii = 0; ii < qSize; ii++) qLE[ii] = qBE[qSize - 1 - ii];
    for(ii = 0; ii < gSize; ii++) gLE[ii] = gBE[gSize - 1 - ii];
    for(ii = 0; ii < ySize; ii++) yLE[ii] = yBE[ySize - 1 - ii];

    /* Encode DSS domain parameters: SEQUENCE { INTEGER p, INTEGER q, INTEGER g } */
    memset(&dssParams, 0, sizeof(dssParams));
    dssParams.p.cbData = pSize; dssParams.p.pbData = pLE;
    dssParams.q.cbData = qSize; dssParams.q.pbData = qLE;
    dssParams.g.cbData = gSize; dssParams.g.pbData = gLE;
    if(!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_DSS_PARAMETERS, &dssParams,
            CRYPT_ENCODE_ALLOC_FLAG, NULL, (PVOID*)&encodedParams, &encodedParamsLen)) {
        xmlSecMSCngLastError("CryptEncodeObjectEx(X509_DSS_PARAMETERS)", NULL);
        goto done;
    }

    /* Encode public key value Y as DER INTEGER */
    memset(&yBlob, 0, sizeof(yBlob));
    yBlob.cbData = ySize; yBlob.pbData = yLE;
    if(!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_DSS_PUBLICKEY, &yBlob,
            CRYPT_ENCODE_ALLOC_FLAG, NULL, (PVOID*)&encodedY, &encodedYLen)) {
        xmlSecMSCngLastError("CryptEncodeObjectEx(X509_DSS_PUBLICKEY)", NULL);
        goto done;
    }

    /* Build SubjectPublicKeyInfo and encode as DER */
    memset(&spki, 0, sizeof(spki));
    spki.Algorithm.pszObjId          = (LPSTR)szOID_X957_DSA;
    spki.Algorithm.Parameters.pbData = encodedParams;
    spki.Algorithm.Parameters.cbData = encodedParamsLen;
    spki.PublicKey.pbData             = encodedY;
    spki.PublicKey.cbData             = encodedYLen;
    spki.PublicKey.cUnusedBits        = 0;
    if(!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, &spki,
            CRYPT_ENCODE_ALLOC_FLAG, NULL, ppDer, pcbDer)) {
        xmlSecMSCngLastError("CryptEncodeObjectEx(X509_PUBLIC_KEY_INFO)", NULL);
        goto done;
    }

    ret = 0;
done:
    if(pLE != NULL) LocalFree(pLE);
    if(qLE != NULL) LocalFree(qLE);
    if(gLE != NULL) LocalFree(gLE);
    if(yLE != NULL) LocalFree(yLE);
    if(encodedParams != NULL) LocalFree(encodedParams);
    if(encodedY != NULL) LocalFree(encodedY);
    if(blobData != NULL) LocalFree(blobData);
    return(ret);
}
#endif /* XMLSEC_NO_DSA */

static int
xmlSecMSCngBuildSubjectPublicKeyInfoDer(BCRYPT_KEY_HANDLE hKey, LPVOID* ppDer, DWORD* pcbDer) {
    PUCHAR pInfo = NULL;
    DWORD cbInfo = 0;
    BOOL status;

    xmlSecAssert2(hKey != 0, -1);
    xmlSecAssert2(ppDer != NULL, -1);
    xmlSecAssert2(pcbDer != NULL, -1);

    *ppDer = NULL;
    *pcbDer = 0;

#ifndef XMLSEC_NO_DSA
    {
        WCHAR algName[64] = {0};
        ULONG algNameLen = 0;
        NTSTATUS ntstatus;

        ntstatus = BCryptGetProperty(hKey, BCRYPT_ALGORITHM_NAME,
            (PUCHAR)algName, sizeof(algName) - sizeof(WCHAR), &algNameLen, 0);
        if((ntstatus == STATUS_SUCCESS) &&
                (wcsncmp(algName, BCRYPT_DSA_ALGORITHM, wcslen(BCRYPT_DSA_ALGORITHM)) == 0)) {
            return xmlSecMSCngDsaBuildSubjectPublicKeyInfoDer(hKey, ppDer, pcbDer);
        }
    }
#endif /* XMLSEC_NO_DSA */

    status = CryptExportPublicKeyInfoFromBCryptKeyHandle(
        hKey,
        X509_ASN_ENCODING,
        NULL,
        0,
        NULL,
        NULL,
        &cbInfo
    );
    if((status != TRUE) || (cbInfo <= 0)) {
        xmlSecMSCngNtError("CryptExportPublicKeyInfoFromBCryptKeyHandle", NULL, STATUS_SUCCESS);
        goto done;
    }

    pInfo = (PUCHAR)xmlMalloc(cbInfo);
    if(pInfo == NULL) {
        xmlSecMallocError(cbInfo, NULL);
        goto done;
    }

    status = CryptExportPublicKeyInfoFromBCryptKeyHandle(
        hKey,
        X509_ASN_ENCODING,
        NULL,
        0,
        NULL,
        (PCERT_PUBLIC_KEY_INFO)pInfo,
        &cbInfo
    );
    if((status != TRUE) || (cbInfo <= 0)) {
        xmlSecMSCngNtError("CryptExportPublicKeyInfoFromBCryptKeyHandle", NULL, STATUS_SUCCESS);
        goto done;
    }

    status = CryptEncodeObjectEx(
        X509_ASN_ENCODING,
        X509_PUBLIC_KEY_INFO,
        pInfo,
        CRYPT_ENCODE_ALLOC_FLAG,
        NULL,
        ppDer,
        pcbDer
    );
    if((status != TRUE) || (*ppDer == NULL) || (*pcbDer <= 0)) {
        xmlSecMSCngNtError("CryptEncodeObjectEx", NULL, STATUS_SUCCESS);
        goto done;
    }

    xmlFree(pInfo);
    return(0);

done:
    if(pInfo != NULL) {
        xmlFree(pInfo);
    }
    if(*ppDer != NULL) {
        LocalFree(*ppDer);
        *ppDer = NULL;
    }
    *pcbDer = 0;
    return(-1);
}

static int
xmlSecMSCngKeyDataDEREncodedKeyValueXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataPtr keyData;
    BCRYPT_KEY_HANDLE hPubkey;
    LPVOID keyDer = NULL;
    DWORD keyDerLen = 0;
    xmlChar* content = NULL;
    int res = -1;
    int ret;

    xmlSecAssert2(id == xmlSecMSCngKeyDataDEREncodedKeyValueId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(keyInfoCtx->mode == xmlSecKeyInfoModeWrite, -1);

    /* get pubkey */
    keyData = xmlSecKeyGetValue(key);
    if(keyData == NULL) {
        xmlSecInternalError("xmlSecKeyGetValue", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    hPubkey = xmlSecMSCngKeyDataGetPubKey(keyData);
    if(hPubkey == 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataGetPubKey", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* build DER encoded subject public key info */
    ret = xmlSecMSCngBuildSubjectPublicKeyInfoDer(hPubkey, &keyDer, &keyDerLen);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngBuildSubjectPublicKeyInfoDer", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* write to XML */
    content = xmlSecBase64Encode(keyDer, keyDerLen, xmlSecBase64GetDefaultLineSize());
    if(content == NULL) {
        xmlSecInternalError("xmlSecBase64Encode", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    xmlNodeAddContent(node, content);

    /* success */
    res = 0;

done:
    if(keyDer != NULL) {
        LocalFree(keyDer);
    }
    if(content != NULL) {
        xmlFree(content);
    }
    return(res);
}