/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2018-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_mscng_crypto
 * @brief ML-KEM Key Transport transforms implementation for MSCng.
 *
 * ML-KEM (FIPS 203) key transport via the standard &lt;enc:EncryptedKey/&gt; element
 * (https://www.w3.org/TR/xmlenc-core1/#sec-EncryptedKey): the &lt;enc:EncryptionMethod/&gt;
 * references one of the ML-KEM transforms and the &lt;enc:CipherValue/&gt; holds the
 * base64 encoded FIPS 203 ciphertext; the resulting 32-byte shared secret becomes
 * the content encryption key (CEK).
 *
 *  - Encrypt (encapsulate): BCryptEncapsulate(recipient public key) -> (ct, ss);
 *    the shared secret becomes the CEK and the ciphertext is stored in the
 *    KEM key data of the transform context, to be serialized into
 *    &lt;enc:CipherValue/&gt; by the EncryptedKey write code;
 *  - Decrypt (decapsulate): BCryptDecapsulate(recipient private key, ct) -> ss (CEK).
 */

#include "globals.h"

#include <stdlib.h>
#include <string.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>
#include <xmlsec/errors.h>
#include <xmlsec/keys.h>
#include <xmlsec/private.h>
#include <xmlsec/strings.h>
#include <xmlsec/transforms.h>

#include <xmlsec/mscng/crypto.h>
#include <xmlsec/mscng/certkeys.h>

#include "../cast_helpers.h"
#include "../keysdata_helpers.h"
#include "../transform_helpers.h"
#include "private.h"

#ifndef XMLSEC_NO_MLKEM


/******************************************************************************
 *
 * Internal MSCng ML-KEM CTX
 *
  *****************************************************************************/
typedef struct _xmlSecMSCngMLKEMCtx        xmlSecMSCngMLKEMCtx,
                                           *xmlSecMSCngMLKEMCtxPtr;
struct _xmlSecMSCngMLKEMCtx {
    BCRYPT_KEY_HANDLE pubkey;           /**< recipient public key handle (used for encapsulation) */
    BCRYPT_KEY_HANDLE privkey;          /**< recipient private key handle (used for decapsulation) */
    DWORD             ciphertextSize;   /**< size of the FIPS 203 ciphertext for this variant */
    DWORD             sharedSecretSize; /**< size of the shared secret */
};

/******************************************************************************
 *
 * ML-KEM key transport transform
 *
  *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(MSCngMLKEM, xmlSecMSCngMLKEMCtx)
#define xmlSecMSCngMLKEMSize XMLSEC_TRANSFORM_SIZE(MSCngMLKEM)

static int      xmlSecMSCngMLKEMCheckId                       (xmlSecTransformPtr transform);
static int      xmlSecMSCngMLKEMInitialize                    (xmlSecTransformPtr transform);
static void     xmlSecMSCngMLKEMFinalize                      (xmlSecTransformPtr transform);
static int      xmlSecMSCngMLKEMSetKeyReq                     (xmlSecTransformPtr transform,
                                                               xmlSecKeyReqPtr keyReq);
static int      xmlSecMSCngMLKEMSetKey                        (xmlSecTransformPtr transform,
                                                               xmlSecKeyPtr key);
static int      xmlSecMSCngMLKEMExecute                       (xmlSecTransformPtr transform,
                                                               int last,
                                                               xmlSecTransformCtxPtr transformCtx);
static int      xmlSecMSCngMLKEMEncapsulate                   (xmlSecMSCngMLKEMCtxPtr ctx,
                                                               xmlSecBufferPtr cipherTextOut,
                                                               xmlSecBufferPtr sharedSecretOut);
static int      xmlSecMSCngMLKEMDecapsulate                   (xmlSecMSCngMLKEMCtxPtr ctx,
                                                               xmlSecBufferPtr cipherTextIn,
                                                               xmlSecBufferPtr sharedSecretOut);
static int      xmlSecMSCngMLKEMProcess                       (xmlSecTransformPtr transform,
                                                               xmlSecTransformCtxPtr transformCtx);

#define XMLSEC_MSCNG_ML_KEM_KLASS_EX(name)                                                            \
static xmlSecTransformKlass xmlSecMSCng ## name ## Klass = {                                          \
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */                            \
    xmlSecMSCngMLKEMSize,                       /* xmlSecSize objSize */                              \
    xmlSecName ## name,                         /* const xmlChar* name; */                            \
    xmlSecHref ## name,                         /* const xmlChar* href; */                            \
    xmlSecTransformUsageEncryptionMethod,                                                             \
                                                /* xmlSecAlgorithmUsage usage; */                     \
    xmlSecMSCngMLKEMInitialize,               /* xmlSecTransformInitializeMethod initialize; */       \
    xmlSecMSCngMLKEMFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */           \
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */          \
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */        \
    xmlSecMSCngMLKEMSetKeyReq,                /* xmlSecTransformSetKeyReqMethod setKeyReq; */         \
    xmlSecMSCngMLKEMSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */               \
    NULL,                                       /* xmlSecTransformValidateMethod validate; */          \
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */    \
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */            \
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */              \
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */            \
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */               \
    xmlSecMSCngMLKEMExecute,                  /* xmlSecTransformExecuteMethod execute; */             \
    NULL,                                       /* void* reserved0; */                                 \
    NULL,                                       /* void* reserved1; */                                 \
};

/* ML-KEM-512 key transport: xmlSecMSCngMLKEM512Klass */
XMLSEC_MSCNG_ML_KEM_KLASS_EX(MLKEM512)

/**
 * @brief The ML-KEM-512 key transport transform klass.
 * @return ML-KEM-512 key transport transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformMLKEM512GetKlass(void) {
    return(&xmlSecMSCngMLKEM512Klass);
}

/* ML-KEM-768 key transport: xmlSecMSCngMLKEM768Klass */
XMLSEC_MSCNG_ML_KEM_KLASS_EX(MLKEM768)

/**
 * @brief The ML-KEM-768 key transport transform klass.
 * @return ML-KEM-768 key transport transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformMLKEM768GetKlass(void) {
    return(&xmlSecMSCngMLKEM768Klass);
}

/* ML-KEM-1024 key transport: xmlSecMSCngMLKEM1024Klass */
XMLSEC_MSCNG_ML_KEM_KLASS_EX(MLKEM1024)

/**
 * @brief The ML-KEM-1024 key transport transform klass.
 * @return ML-KEM-1024 key transport transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformMLKEM1024GetKlass(void) {
    return(&xmlSecMSCngMLKEM1024Klass);
}

static int
xmlSecMSCngMLKEMCheckId(xmlSecTransformPtr transform) {
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformMLKEM512Id)) {
        return(1);
    } else if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformMLKEM768Id)) {
        return(1);
    } else if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformMLKEM1024Id)) {
        return(1);
    }

    /* not found */
    return(0);
}

static int
xmlSecMSCngMLKEMInitialize(xmlSecTransformPtr transform) {
    xmlSecMSCngMLKEMCtxPtr ctx;

    xmlSecAssert2(xmlSecMSCngMLKEMCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngMLKEMSize), -1);

    ctx = xmlSecMSCngMLKEMGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecMSCngMLKEMCtx));

    return(0);
}

static void
xmlSecMSCngMLKEMFinalize(xmlSecTransformPtr transform) {
    xmlSecMSCngMLKEMCtxPtr ctx;

    xmlSecAssert(xmlSecMSCngMLKEMCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecMSCngMLKEMSize));

    ctx = xmlSecMSCngMLKEMGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    /* the key handle is borrowed from the key data, which owns it */

    memset(ctx, 0, sizeof(xmlSecMSCngMLKEMCtx));
}

static int
xmlSecMSCngMLKEMSetKeyReq(xmlSecTransformPtr transform, xmlSecKeyReqPtr keyReq) {
    xmlSecMSCngMLKEMCtxPtr ctx;

    xmlSecAssert2(xmlSecMSCngMLKEMCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) ||
                  (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngMLKEMSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecMSCngMLKEMGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keyReq->keyId = xmlSecMSCngKeyDataMLKEMId;

    /* A KEM key is used for either encapsulation (public key) or decapsulation
     * (private key). The transform operation flag is not a reliable indicator
     * of which is needed: the <enc:EncryptedKey> read phase always runs as a
     * "decrypt" operation even when a new ciphertext is being produced. So
     * accept both key types here; the actual encapsulate/decapsulate decision
     * is made in xmlSecMSCngMLKEMProcess based on the input buffer presence. */
    keyReq->keyType  = xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate;
    keyReq->keyUsage = xmlSecKeyUsageKeyEncapsulate;
    return(0);
}

static int
xmlSecMSCngMLKEMSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecMSCngMLKEMCtxPtr ctx;
    xmlSecKeyDataPtr keyValue;
    BCRYPT_KEY_HANDLE hKey = 0;
    DWORD dwSize = 0;
    DWORD cbResult = 0;
    NTSTATUS status;

    xmlSecAssert2(xmlSecMSCngMLKEMCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) ||
                  (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngMLKEMSize), -1);
    xmlSecAssert2(key != NULL, -1);

    keyValue = xmlSecKeyGetValue(key);
    xmlSecAssert2(keyValue != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(keyValue, xmlSecMSCngKeyDataMLKEMId), -1);

    ctx = xmlSecMSCngMLKEMGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    /* the key can only be set once */
    xmlSecAssert2((ctx->pubkey == 0) && (ctx->privkey == 0), -1);

    /* Capture both the public and the private key handles (whichever are
     * present in the key data). The <enc:EncryptedKey> read phase always runs
     * as a "decrypt" operation even when a new ciphertext is being produced,
     * so the transform operation flag cannot be used to pick the handle; the
     * actual encapsulate/decapsulate decision is made in
     * xmlSecMSCngMLKEMProcess based on the input buffer presence. */
    ctx->pubkey  = xmlSecMSCngKeyDataGetPubkey(keyValue);
    ctx->privkey = xmlSecMSCngKeyDataGetBCryptPrivKey(keyValue);
    if((ctx->pubkey == 0) && (ctx->privkey == 0)) {
        xmlSecInternalError("Failed to get the ML-KEM key handle", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* query the ciphertext and shared secret sizes from the key; the public
     * and private handles of the same variant report identical sizes */
    hKey = (ctx->pubkey != 0) ? ctx->pubkey : ctx->privkey;
    status = BCryptGetProperty(hKey, BCRYPT_KEM_CIPHERTEXT_LENGTH, (PUCHAR)&dwSize, sizeof(dwSize), &cbResult, 0);
    if((status != STATUS_SUCCESS) || (cbResult != sizeof(dwSize)) || (dwSize == 0)) {
        xmlSecMSCngNtError("BCryptGetProperty(ML-KEM ciphertext length)", NULL, status);
        return(-1);
    }
    ctx->ciphertextSize = dwSize;

    status = BCryptGetProperty(hKey, BCRYPT_KEM_SHARED_SECRET_LENGTH, (PUCHAR)&dwSize, sizeof(dwSize), &cbResult, 0);
    if((status != STATUS_SUCCESS) || (cbResult != sizeof(dwSize)) || (dwSize == 0)) {
        xmlSecMSCngNtError("BCryptGetProperty(ML-KEM shared secret length)", NULL, status);
        return(-1);
    }
    ctx->sharedSecretSize = dwSize;

    /* success */
    return(0);
}

/**
 * This function can be called either from xmlSecKeyDataEncryptedKeyXmlRead()
 * or from xmlSecEncCtxEncryptedKeyXmlWrite().
 */
static int
xmlSecMSCngMLKEMExecute(
    xmlSecTransformPtr transform,
    int last,
    xmlSecTransformCtxPtr transformCtx
) {
    int ret;

    xmlSecAssert2(xmlSecMSCngMLKEMCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) ||
                  (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngMLKEMSize), -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
        /* just do nothing */
    } else if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        ret = xmlSecMSCngMLKEMProcess(transform, transformCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngMLKEMProcess", xmlSecTransformGetName(transform));
            return(-1);
        }
        transform->status = xmlSecTransformStatusFinished;
    } else if(transform->status == xmlSecTransformStatusFinished) {
        /* the only way we can get here is if there is no input */
        xmlSecAssert2(xmlSecBufferGetSize(&(transform->inBuf)) == 0, -1);
    } else {
        xmlSecInvalidTransformStatusError(transform);
        return(-1);
    }
    return(0);
}

static int
xmlSecMSCngMLKEMEncapsulate(xmlSecMSCngMLKEMCtxPtr ctx, xmlSecBufferPtr cipherTextOut,
                            xmlSecBufferPtr sharedSecretOut) {
    xmlSecBuffer ssBuf;
    xmlSecByte* ctBuf;
    xmlSecByte* ssBufData;
    DWORD ctSize = 0;
    DWORD ssSize = 0;
    NTSTATUS status;
    int ret;
    int res = -1;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pubkey != 0, -1);
    xmlSecAssert2(ctx->ciphertextSize > 0, -1);
    xmlSecAssert2(ctx->sharedSecretSize > 0, -1);
    xmlSecAssert2(cipherTextOut != NULL, -1);
    xmlSecAssert2(xmlSecBufferIsSecure(cipherTextOut), -1);
    xmlSecAssert2(sharedSecretOut != NULL, -1);
    xmlSecAssert2(xmlSecBufferIsSecure(sharedSecretOut), -1);

    /* zero-initialized so that the xmlSecBufferFinalize() call below is
     * safe even on error paths where the buffer was never initialized */
    memset(&ssBuf, 0, sizeof(ssBuf));

    /* create ct buffer */
    ret = xmlSecBufferSetSize(cipherTextOut, ctx->ciphertextSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize(ct)", NULL, "size=" XMLSEC_SIZE_FMT, ctx->ciphertextSize);
        goto done;
    }
    ctBuf = xmlSecBufferGetData(cipherTextOut);
    if(ctBuf == NULL) {
        xmlSecInternalError("xmlSecBufferGetData(ct)", NULL);
        goto done;
    }

    /* create secure ss buffer */
    ret = xmlSecBufferInitialize(&ssBuf, ctx->sharedSecretSize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(ss)", NULL);
        goto done;
    }
    xmlSecBufferMakeSecure(&ssBuf);
    ssBufData = xmlSecBufferGetData(&ssBuf);
    if(ssBufData == NULL) {
        xmlSecInternalError("xmlSecBufferGetData(ss)", NULL);
        goto done;
    }

    /* perform encapsulation */
    status = BCryptEncapsulate(ctx->pubkey,
        ssBufData, ctx->sharedSecretSize, &ssSize,
        ctBuf, ctx->ciphertextSize, &ctSize, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptEncapsulate", NULL, status);
        goto done;
    }
    if(ctSize != ctx->ciphertextSize || ssSize != ctx->sharedSecretSize) {
        xmlSecInternalError3("ML-KEM encapsulation output sizes do not match the expected values", NULL,
            "ct=" XMLSEC_SIZE_FMT " expected ct=" XMLSEC_SIZE_FMT, (xmlSecSize)ctSize, (xmlSecSize)ctx->ciphertextSize);
        goto done;
    }

    /* write shared secret to sharedSecretOut so the caller can use it as the CEK */
    ret = xmlSecBufferSetData(sharedSecretOut, ssBufData, ssSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetData(ss)", NULL, "size=" XMLSEC_SIZE_FMT, (xmlSecSize)ssSize);
        goto done;
    }

    /* done */
    res = 0;

done:
    if(res < 0) {
        xmlSecBufferEmpty(cipherTextOut);
    }
    xmlSecBufferFinalize(&ssBuf);
    return(res);
}

static int
xmlSecMSCngMLKEMDecapsulate(xmlSecMSCngMLKEMCtxPtr ctx, xmlSecBufferPtr cipherTextIn,
                            xmlSecBufferPtr sharedSecretOut) {
    xmlSecBuffer ssBuf;
    xmlSecByte* ctBuf;
    xmlSecByte* ssBufData;
    xmlSecSize inSize;
    DWORD ssSize = 0;
    NTSTATUS status;
    int ret;
    int res = -1;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->privkey != 0, -1);
    xmlSecAssert2(ctx->ciphertextSize > 0, -1);
    xmlSecAssert2(ctx->sharedSecretSize > 0, -1);
    xmlSecAssert2(cipherTextIn != NULL, -1);
    xmlSecAssert2(sharedSecretOut != NULL, -1);

    /* zero-initialized so that the xmlSecBufferFinalize() call below is
     * safe even on error paths where the buffer was never initialized */
    memset(&ssBuf, 0, sizeof(ssBuf));

    inSize = xmlSecBufferGetSize(cipherTextIn);
    if(inSize != ctx->ciphertextSize) {
        xmlSecInvalidSizeError("Input ciphertext", inSize, ctx->ciphertextSize, NULL);
        return(-1);
    }
    ctBuf = xmlSecBufferGetData(cipherTextIn);
    if(ctBuf == NULL) {
        xmlSecInternalError("xmlSecBufferGetData(ct)", NULL);
        return(-1);
    }

    /* create secure ss buffer */
    ret = xmlSecBufferInitialize(&ssBuf, ctx->sharedSecretSize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(ss)", NULL);
        goto done;
    }
    xmlSecBufferMakeSecure(&ssBuf);
    ssBufData = xmlSecBufferGetData(&ssBuf);
    if(ssBufData == NULL) {
        xmlSecInternalError("xmlSecBufferGetData(ss)", NULL);
        goto done;
    }

    /* perform decapsulation */
    status = BCryptDecapsulate(ctx->privkey,
        ctBuf, (ULONG)inSize,
        ssBufData, ctx->sharedSecretSize, &ssSize, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptDecapsulate", NULL, status);
        goto done;
    }
    if(ssSize != ctx->sharedSecretSize) {
        xmlSecInternalError3("ML-KEM decapsulation output size does not match the expected value", NULL,
            "ss=" XMLSEC_SIZE_FMT " expected ss=" XMLSEC_SIZE_FMT, (xmlSecSize)ssSize, (xmlSecSize)ctx->sharedSecretSize);
        goto done;
    }

    /* write ss to output buffer: this becomes the CEK for content decryption */
    ret = xmlSecBufferSetData(sharedSecretOut, ssBufData, ssSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetData(ss)", NULL, "size=" XMLSEC_SIZE_FMT, (xmlSecSize)ssSize);
        goto done;
    }

    /* done */
    res = 0;

done:
    xmlSecBufferFinalize(&ssBuf);
    return(res);
}

/**
 * This function can be called either from xmlSecKeyDataEncryptedKeyXmlRead()
 * or from xmlSecEncCtxEncryptedKeyXmlWrite().
 * - When we read the key, we either encapsulate the key using the KEM and produce
 * a ciphertext and shared secret, or decapsulate the key from the ciphertext.
 * - When we write the key, we simply write the existing ciphertext.
 */
static int
xmlSecMSCngMLKEMProcess(xmlSecTransformPtr transform, xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCngMLKEMCtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecSize inSize;
    xmlSecKeyDataPtr kemKeyData;
    xmlSecBufferPtr ciphertext;
    int ret;

    xmlSecAssert2(xmlSecMSCngMLKEMCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) ||
                  (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngMLKEMSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecMSCngMLKEMGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2((ctx->pubkey != 0) || (ctx->privkey != 0), -1);
    xmlSecAssert2(ctx->ciphertextSize > 0, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);
    inSize = xmlSecBufferGetSize(in);
    xmlSecAssert2(xmlSecBufferGetSize(out) == 0, -1);

    kemKeyData = xmlSecTransformCtxExtraKeyDataGet(transformCtx, xmlSecKeyDataKEMId);
    if(kemKeyData != NULL) {
        /* we are writing the ciphertext */
        ciphertext = xmlSecKeyDataKEMGetCiphertext(kemKeyData);
        if(ciphertext == NULL) {
            xmlSecInternalError("xmlSecKeyDataKEMGetCiphertext", NULL);
            return(-1);
        }
        if(xmlSecBufferGetSize(ciphertext) != ctx->ciphertextSize) {
            xmlSecInvalidSizeError("KEM ciphertext", xmlSecBufferGetSize(ciphertext), ctx->ciphertextSize, NULL);
            return(-1);
        }

        ret = xmlSecBufferSetData(out, xmlSecBufferGetData(ciphertext), xmlSecBufferGetSize(ciphertext));
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferSetData(out)", NULL);
            return(-1);
        }
    } else {
        /* we are reading the key: encapsulate or decapsulate shared secret into output buffer,
         * so it must be marked secure before the first allocation */
        xmlSecBufferMakeSecure(out);

        /* we ignore transform->operation flag and decide to do encapsulation or decapsulation based
         * on the input buffer presence */
        if(inSize == 0) {
            /* encapsulation takes no input and produces a fresh ciphertext; the
             * ciphertext is stored in the KEM key data of the transform context
             * and serialized into <enc:CipherValue/> by the EncryptedKey write code */
            kemKeyData = xmlSecTransformCtxExtraKeyDataEnsure(transformCtx, xmlSecKeyDataKEMId);
            if(kemKeyData == NULL) {
                xmlSecInternalError("xmlSecTransformCtxExtraKeyDataEnsure(xmlSecKeyDataKEMId)", NULL);
                return(-1);
            }
            ciphertext = xmlSecKeyDataKEMGetCiphertext(kemKeyData);
            if(ciphertext == NULL) {
                xmlSecInternalError("xmlSecKeyDataKEMGetCiphertext", NULL);
                return(-1);
            }
            xmlSecBufferEmpty(ciphertext);

            ret = xmlSecMSCngMLKEMEncapsulate(ctx, ciphertext, out);
            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCngMLKEMEncapsulate", xmlSecTransformGetName(transform));
                return(-1);
            }
        } else {
            /* decapsulation consumes the ciphertext from the input buffer */
            if(transform->operation == xmlSecTransformOperationEncrypt) {
                /* a key write (operation=Encrypt) must have the KEM data produced during
                 * the read phase; reaching the decapsulation path means the KeyInfo was
                 * not read (e.g. a session key was preset), so there is no KEM ciphertext
                 * to write */
                xmlSecInvalidTransformError2(transform,
                    "cannot write the KEM ciphertext: no encapsulation was performed during the read phase (operation=%u)",
                    transform->operation);
                return(-1);
            }
            ret = xmlSecMSCngMLKEMDecapsulate(ctx, in, out);
            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCngMLKEMDecapsulate", xmlSecTransformGetName(transform));
                return(-1);
            }
        }
    }

    /* the input has been consumed */
    xmlSecBufferEmpty(in);

    /*
     * Truncate the shared secret to the expected content-decryption key size
     * if the KEM output is longer (e.g. the 32-byte ML-KEM shared secret vs.
     * a 16-byte AES-128 CEK); a mismatch larger than the KEM output is
     * rejected outright.
     */
    if(transform->expectedOutputSize > 0) {
        xmlSecSize outSize = xmlSecBufferGetSize(out);
        if(transform->expectedOutputSize > outSize) {
            xmlSecInvalidSizeLessThanError("Output data", outSize, transform->expectedOutputSize, xmlSecTransformGetName(transform));
            return(-1);
        }
        if(transform->expectedOutputSize < outSize) {
            ret = xmlSecBufferSetSize(out, transform->expectedOutputSize);
            if(ret < 0) {
                xmlSecInternalError2("xmlSecBufferSetSize(out)", xmlSecTransformGetName(transform), "size=" XMLSEC_SIZE_FMT, transform->expectedOutputSize);
                return(-1);
            }
        }
    }

    /* done */
    return(0);
}

#else /* XMLSEC_NO_MLKEM */

/* ISO C forbids an empty translation unit */
typedef int make_iso_compilers_happy;

#endif /* XMLSEC_NO_MLKEM */
