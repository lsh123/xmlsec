/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * THIS IS A PRIVATE XMLSEC HEADER FILE
 * DON'T USE IT IN YOUR APPLICATION
 *
 * Implementation of AES/DES Key Transport algorithm
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_KT_AES_DES_H__
#define __XMLSEC_KT_AES_DES_H__

#ifndef XMLSEC_PRIVATE
#error "this file contains private xmlsec definitions and should not be used outside xmlsec or xmlsec-$crypto libraries"
#endif /* XMLSEC_PRIVATE */

#include <xmlsec/exports.h>
#include <xmlsec/transforms.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifndef XMLSEC_NO_DES
/******************************************************************************
 *
 * KT DES
 *
  *****************************************************************************/
#define XMLSEC_KW_DES3_KEY_LENGTH                   ((xmlSecSize)24)
#define XMLSEC_KW_DES3_IV_LENGTH                    ((xmlSecSize)8)
#define XMLSEC_KW_DES3_BLOCK_LENGTH                 ((xmlSecSize)8)
#define XMLSEC_KW_DES3_SHA_DIGEST_LENGTH            ((xmlSecSize)20)


typedef int  (*xmlSecKWDes3Sha1Method)              (xmlSecTransformPtr transform,
                                                     const xmlSecByte * in,
                                                     xmlSecSize inSize,
                                                     xmlSecByte * out,
                                                     xmlSecSize outSize,
                                                     xmlSecSize * outWritten);
typedef int  (*xmlSecKWDes3GenerateRandomMethod)    (xmlSecTransformPtr transform,
                                                     xmlSecByte * out,
                                                     xmlSecSize outSize,
                                                     xmlSecSize * outWritten);
typedef int  (*xmlSecKWDes3BlockEncryptMethod)      (xmlSecTransformPtr transform,
                                                     const xmlSecByte * iv,
                                                     xmlSecSize ivSize,
                                                     const xmlSecByte * in,
                                                     xmlSecSize inSize,
                                                     xmlSecByte * out,
                                                     xmlSecSize outSize,
                                                     xmlSecSize * outWritten);
typedef int  (*xmlSecKWDes3BlockDecryptMethod)      (xmlSecTransformPtr transform,
                                                     const xmlSecByte * iv,
                                                     xmlSecSize ivSize,
                                                     const xmlSecByte * in,
                                                     xmlSecSize inSize,
                                                     xmlSecByte * out,
                                                     xmlSecSize outSize,
                                                     xmlSecSize * outWritten);


struct _xmlSecKWDes3Klass {
    /* callbacks */
    xmlSecKWDes3GenerateRandomMethod    generateRandom;
    xmlSecKWDes3Sha1Method              sha1;
    xmlSecKWDes3BlockEncryptMethod      encrypt;
    xmlSecKWDes3BlockDecryptMethod      decrypt;

    /* for the future */
    void*                               reserved0;
    void*                               reserved1;
};
typedef const struct _xmlSecKWDes3Klass              xmlSecKWDes3Klass,
                                                    *xmlSecKWDes3Id;

#define xmlSecKWDes3CheckId(id) \
    ( \
     ((id) != NULL) && \
     ((id)->generateRandom != NULL) && \
     ((id)->sha1 != NULL) && \
     ((id)->encrypt != NULL) && \
     ((id)->decrypt != NULL) \
    )


/******************************************************************************
 *
 * Triple DES Key Wrap transform
 *
  *****************************************************************************/

typedef struct _xmlSecTransformKWDes3Ctx     xmlSecTransformKWDes3Ctx,
                                            *xmlSecTransformKWDes3CtxPtr;
struct _xmlSecTransformKWDes3Ctx {
    xmlSecKWDes3Id      kwDes3Id;
    xmlSecKeyDataId     keyId;
    xmlSecBuffer        keyBuffer;
};

XMLSEC_EXPORT int      xmlSecTransformKWDes3Initialize          (xmlSecTransformPtr transform,
                                                                 xmlSecTransformKWDes3CtxPtr ctx,
                                                                 xmlSecKWDes3Id kwDes3Id,
                                                                 xmlSecKeyDataId keyId);
XMLSEC_EXPORT void     xmlSecTransformKWDes3Finalize            (xmlSecTransformPtr transform,
                                                                 xmlSecTransformKWDes3CtxPtr ctx);
XMLSEC_EXPORT int      xmlSecTransformKWDes3SetKeyReq           (xmlSecTransformPtr transform,
                                                                 xmlSecTransformKWDes3CtxPtr ctx,
                                                                 xmlSecKeyReqPtr keyReq);
XMLSEC_EXPORT int      xmlSecTransformKWDes3SetKey              (xmlSecTransformPtr transform,
                                                                 xmlSecTransformKWDes3CtxPtr ctx,
                                                                 xmlSecKeyPtr key);
XMLSEC_EXPORT int      xmlSecTransformKWDes3Execute             (xmlSecTransformPtr transform,
                                                                 xmlSecTransformKWDes3CtxPtr ctx,
                                                                 int last);
#endif /* XMLSEC_NO_DES */

#if !defined(XMLSEC_NO_AES) || !defined(XMLSEC_NO_CAMELLIA)
/******************************************************************************
 *
 * KW RFC 3394 (AES and Camellia)
 *
  *****************************************************************************/
#define XMLSEC_KW_RFC3394_IN_SIZE_MULTIPLY              ((xmlSecSize)8)
#define XMLSEC_KW_RFC3394_MAGIC_BLOCK_SIZE              ((xmlSecSize)8)
#define XMLSEC_KW_RFC3394_BLOCK_SIZE                    ((xmlSecSize)16)

#include "keysdata_helpers.h"

typedef int  (*xmlSecKWRfc3394BlockEncryptMethod)       (xmlSecTransformPtr transform,
                                                     const xmlSecByte * in,
                                                     xmlSecSize inSize,
                                                     xmlSecByte * out,
                                                     xmlSecSize outSize,
                                                     xmlSecSize * outWritten);
typedef int  (*xmlSecKWRfc3394BlockDecryptMethod)       (xmlSecTransformPtr transform,
                                                     const xmlSecByte * in,
                                                     xmlSecSize inSize,
                                                     xmlSecByte * out,
                                                     xmlSecSize outSize,
                                                     xmlSecSize * outWritten);


struct _xmlSecKWRfc3394Klass {
    /* callbacks */
    xmlSecKWRfc3394BlockEncryptMethod       encrypt;
    xmlSecKWRfc3394BlockDecryptMethod       decrypt;

    /* for the future */
    void*                               reserved0;
    void*                               reserved1;
};
typedef const struct _xmlSecKWRfc3394Klass          xmlSecKWRfc3394Klass,
                                                    *xmlSecKWRfc3394Id;

/******************************************************************************
 *
 * RFC 3394 KW transforms context (AES and Camellia)
 *
  *****************************************************************************/
typedef struct _xmlSecTransformKWRfc3394Ctx xmlSecTransformKWRfc3394Ctx,
                                           *xmlSecTransformKWRfc3394CtxPtr;
struct _xmlSecTransformKWRfc3394Ctx {
    xmlSecKWRfc3394Id       kwRfc3394Id;
    xmlSecKeyDataId     keyId;
    xmlSecBuffer        keyBuffer;
    xmlSecSize          keyExpectedSize;
};


XMLSEC_EXPORT int       xmlSecTransformKWRfc3394Initialize  (xmlSecTransformPtr transform,
                                                        xmlSecTransformKWRfc3394CtxPtr ctx,
                                                        xmlSecKWRfc3394Id kwRfc3394Id,
                                                        xmlSecKeyDataId keyId,
                                                        xmlSecSize keyExpectedSize);
XMLSEC_EXPORT void      xmlSecTransformKWRfc3394Finalize    (xmlSecTransformPtr transform,
                                                        xmlSecTransformKWRfc3394CtxPtr ctx);
XMLSEC_EXPORT int       xmlSecTransformKWRfc3394SetKeyReq   (xmlSecTransformPtr transform,
                                                        xmlSecTransformKWRfc3394CtxPtr ctx,
                                                        xmlSecKeyReqPtr keyReq);
XMLSEC_EXPORT int       xmlSecTransformKWRfc3394SetKey      (xmlSecTransformPtr transform,
                                                        xmlSecTransformKWRfc3394CtxPtr ctx,
                                                        xmlSecKeyPtr key);
XMLSEC_EXPORT int       xmlSecTransformKWRfc3394Execute     (xmlSecTransformPtr transform,
                                                        xmlSecTransformKWRfc3394CtxPtr ctx,
                                                        int last);

#endif /* !XMLSEC_NO_AES || !XMLSEC_NO_CAMELLIA */


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_KT_AES_DES_H__ */
