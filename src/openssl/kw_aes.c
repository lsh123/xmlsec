/**
 *
 * XMLSec library
 *
 * AES Algorithm support
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef XMLSEC_NO_AES
#ifndef XMLSEC_OPENSSL_096
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/aes.h>
#include <openssl/rand.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>

#include "../kw_aes_des.h"


/*********************************************************************
 *
 * AES KW transforms
 *
 * key (xmlSecBuffer) is located after xmlSecTransform structure
 *
 ********************************************************************/
#define xmlSecOpenSSLKWAesGetKey(transform) \
    ((xmlSecBufferPtr)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)))
#define xmlSecOpenSSLKWAesSize  \
    (sizeof(xmlSecTransform) + sizeof(xmlSecBuffer))

static int      xmlSecOpenSSLKWAesInitialize                    (xmlSecTransformPtr transform);
static void     xmlSecOpenSSLKWAesFinalize                      (xmlSecTransformPtr transform);
static int      xmlSecOpenSSLKWAesSetKeyReq                     (xmlSecTransformPtr transform,
                                                                 xmlSecKeyReqPtr keyReq);
static int      xmlSecOpenSSLKWAesSetKey                        (xmlSecTransformPtr transform,
                                                                 xmlSecKeyPtr key);
static int      xmlSecOpenSSLKWAesExecute                       (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);
static xmlSecSize       xmlSecOpenSSLKWAesGetKeySize                    (xmlSecTransformPtr transform);
static int      xmlSecOpenSSLKWAesEncode                        (const xmlSecByte *key,
                                                                 xmlSecSize keySize,
                                                                 const xmlSecByte* in,
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte* out,
                                                                 xmlSecSize outSize);
static int      xmlSecOpenSSLKWAesDecode                        (const xmlSecByte *key,
                                                                 xmlSecSize keySize,
                                                                 const xmlSecByte* in,
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte* out,
                                                                 xmlSecSize outSize);

static xmlSecTransformKlass xmlSecOpenSSLKWAes128Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLKWAesSize,                     /* xmlSecSize objSize */

    xmlSecNameKWAes128,                         /* const xmlChar* name; */
    xmlSecHrefKWAes128,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecOpenSSLKWAesInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLKWAesFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLKWAesSetKeyReq,                /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLKWAesSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLKWAesExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

static xmlSecTransformKlass xmlSecOpenSSLKWAes192Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLKWAesSize,                     /* xmlSecSize objSize */

    xmlSecNameKWAes192,                         /* const xmlChar* name; */
    xmlSecHrefKWAes192,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecOpenSSLKWAesInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLKWAesFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLKWAesSetKeyReq,                /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLKWAesSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLKWAesExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

static xmlSecTransformKlass xmlSecOpenSSLKWAes256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLKWAesSize,                     /* xmlSecSize objSize */

    xmlSecNameKWAes256,                         /* const xmlChar* name; */
    xmlSecHrefKWAes256,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecOpenSSLKWAesInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLKWAesFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLKWAesSetKeyReq,                /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLKWAesSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLKWAesExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

#define xmlSecOpenSSLKWAesCheckId(transform) \
    (xmlSecTransformCheckId((transform), xmlSecOpenSSLTransformKWAes128Id) || \
     xmlSecTransformCheckId((transform), xmlSecOpenSSLTransformKWAes192Id) || \
     xmlSecTransformCheckId((transform), xmlSecOpenSSLTransformKWAes256Id))

/**
 * xmlSecOpenSSLTransformKWAes128GetKlass:
 *
 * The AES-128 kew wrapper transform klass.
 *
 * Returns: AES-128 kew wrapper transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformKWAes128GetKlass(void) {
    return(&xmlSecOpenSSLKWAes128Klass);
}

/**
 * xmlSecOpenSSLTransformKWAes192GetKlass:
 *
 * The AES-192 kew wrapper transform klass.
 *
 * Returns: AES-192 kew wrapper transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformKWAes192GetKlass(void) {
    return(&xmlSecOpenSSLKWAes192Klass);
}

/**
 * xmlSecOpenSSLTransformKWAes256GetKlass:
 *
 * The AES-256 kew wrapper transform klass.
 *
 * Returns: AES-256 kew wrapper transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformKWAes256GetKlass(void) {
    return(&xmlSecOpenSSLKWAes256Klass);
}


static int 
xmlSecOpenSSLAesBlockEncryptCallback(const xmlSecByte * in, xmlSecByte * out, void * key) {
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(key != NULL, -1);

    AES_encrypt(in, out, (AES_KEY*)key);
    return(0);
}

static int
xmlSecOpenSSLAesBlockDecryptCallback(const xmlSecByte * in, xmlSecByte * out, void * key) {
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(key != NULL, -1);

    AES_decrypt(in, out, (AES_KEY*)key);
    return(0);
}

static int
xmlSecOpenSSLKWAesInitialize(xmlSecTransformPtr transform) {
    int ret;

    xmlSecAssert2(xmlSecOpenSSLKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWAesSize), -1);

    ret = xmlSecBufferInitialize(xmlSecOpenSSLKWAesGetKey(transform), 0);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                    "xmlSecOpenSSLKWAesGetKey",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    return(0);
}

static void
xmlSecOpenSSLKWAesFinalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecOpenSSLKWAesCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWAesSize));

    if(xmlSecOpenSSLKWAesGetKey(transform) != NULL) {
        xmlSecBufferFinalize(xmlSecOpenSSLKWAesGetKey(transform));
    }
}

static int
xmlSecOpenSSLKWAesSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecAssert2(xmlSecOpenSSLKWAesCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWAesSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    keyReq->keyId        = xmlSecOpenSSLKeyDataAesId;
    keyReq->keyType  = xmlSecKeyDataTypeSymmetric;
    if(transform->operation == xmlSecTransformOperationEncrypt) {
        keyReq->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
        keyReq->keyUsage = xmlSecKeyUsageDecrypt;
    }
    keyReq->keyBitsSize = 8 * xmlSecOpenSSLKWAesGetKeySize(transform);

    return(0);
}

static int
xmlSecOpenSSLKWAesSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecBufferPtr buffer;
    xmlSecSize keySize;
    xmlSecSize expectedKeySize;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLKWAesCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWAesSize), -1);
    xmlSecAssert2(xmlSecOpenSSLKWAesGetKey(transform) != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecOpenSSLKeyDataAesId), -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(key));
    xmlSecAssert2(buffer != NULL, -1);

    keySize = xmlSecBufferGetSize(buffer);
    expectedKeySize = xmlSecOpenSSLKWAesGetKeySize(transform);
    if(keySize < expectedKeySize) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                    NULL,
                    XMLSEC_ERRORS_R_INVALID_KEY_DATA_SIZE,
                    "key=%d;expected=%d",
                    keySize, expectedKeySize);
        return(-1);
    }

    ret = xmlSecBufferSetData(xmlSecOpenSSLKWAesGetKey(transform),
                            xmlSecBufferGetData(buffer),
                            expectedKeySize);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                    "xmlSecBufferSetData",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "expected-size=%d", expectedKeySize);
        return(-1);
    }

    return(0);
}

static int
xmlSecOpenSSLKWAesExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecBufferPtr in, out, key;
    xmlSecSize inSize, outSize, keySize, expectedKeySize;
    AES_KEY aesKey;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLKWAesCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWAesSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    key = xmlSecOpenSSLKWAesGetKey(transform);
    xmlSecAssert2(key != NULL, -1);

    keySize = xmlSecBufferGetSize(key);
    expectedKeySize = xmlSecOpenSSLKWAesGetKeySize(transform);
    xmlSecAssert2(keySize == expectedKeySize, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);
    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);
    xmlSecAssert2(outSize == 0, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
        /* just do nothing */
    } else  if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        if((inSize % 8) != 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                        NULL,
                        XMLSEC_ERRORS_R_INVALID_SIZE,
                        "size=%d(not 8 bytes aligned)", inSize);
            return(-1);
        }

        if(transform->operation == xmlSecTransformOperationEncrypt) {
            /* the encoded key might be 8 bytes longer plus 8 bytes just in case */
            outSize = inSize + XMLSEC_KW_AES_MAGIC_BLOCK_SIZE +
                               XMLSEC_KW_AES_BLOCK_SIZE;
        } else {
            outSize = inSize + XMLSEC_KW_AES_BLOCK_SIZE;
        }

        ret = xmlSecBufferSetMaxSize(out, outSize);
        if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                        "xmlSecBufferSetMaxSize",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "outSize=%d", outSize);
            return(-1);
        }

        if(transform->operation == xmlSecTransformOperationEncrypt) {
            /* prepare key */
            ret = AES_set_encrypt_key(xmlSecBufferGetData(key), 8 * keySize, &aesKey);
            if(ret != 0) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            NULL,
                            "AES_set_decrypt_key",
                            XMLSEC_ERRORS_R_CRYPTO_FAILED,
                            XMLSEC_ERRORS_NO_MESSAGE);
                return(-1);
            }

            ret = xmlSecKWAesEncode(xmlSecOpenSSLAesBlockEncryptCallback, &aesKey,
                                    xmlSecBufferGetData(in), inSize,
                                    xmlSecBufferGetData(out), outSize);
            if(ret < 0) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                            "xmlSecKWAesEncode",
                            XMLSEC_ERRORS_R_XMLSEC_FAILED,
                            XMLSEC_ERRORS_NO_MESSAGE);
                return(-1);
            }
            outSize = ret;
        } else {
            /* prepare key */
            ret = AES_set_decrypt_key(xmlSecBufferGetData(key), 8 * keySize, &aesKey);
            if(ret != 0) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            NULL,
                            "AES_set_decrypt_key",
                            XMLSEC_ERRORS_R_CRYPTO_FAILED,
                            XMLSEC_ERRORS_NO_MESSAGE);
                return(-1);
            }

            ret = xmlSecKWAesDecode(xmlSecOpenSSLAesBlockDecryptCallback, &aesKey,
                                    xmlSecBufferGetData(in), inSize,
                                    xmlSecBufferGetData(out), outSize);
            if(ret < 0) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                            "xmlSecKWAesEncode",
                            XMLSEC_ERRORS_R_XMLSEC_FAILED,
                            XMLSEC_ERRORS_NO_MESSAGE);
                return(-1);
            }
            outSize = ret;
        }

        ret = xmlSecBufferSetSize(out, outSize);
        if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                        "xmlSecBufferSetSize",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "outSize=%d", outSize);
            return(-1);
        }

        ret = xmlSecBufferRemoveHead(in, inSize);
        if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                        "xmlSecBufferRemoveHead",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "inSize%d", inSize);
            return(-1);
        }

        transform->status = xmlSecTransformStatusFinished;
    } else if(transform->status == xmlSecTransformStatusFinished) {
        /* the only way we can get here is if there is no input */
        xmlSecAssert2(xmlSecBufferGetSize(&(transform->inBuf)) == 0, -1);
    } else {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                    NULL,
                    XMLSEC_ERRORS_R_INVALID_STATUS,
                    "status=%d", transform->status);
        return(-1);
    }
    return(0);
}

static xmlSecSize
xmlSecOpenSSLKWAesGetKeySize(xmlSecTransformPtr transform) {
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWAes128Id)) {
        return(XMLSEC_KW_AES128_KEY_SIZE);
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWAes192Id)) {
        return(XMLSEC_KW_AES192_KEY_SIZE);
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWAes256Id)) {
        return(XMLSEC_KW_AES256_KEY_SIZE);
    }
    return(0);
}

#endif /* XMLSEC_OPENSSL_096 */
#endif /* XMLSEC_NO_AES */
