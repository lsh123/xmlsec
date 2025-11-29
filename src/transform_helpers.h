/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Internal header only used during the compilation,
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_TRANSFORMS_HELPERS_H__
#define __XMLSEC_TRANSFORMS_HELPERS_H__


#ifndef XMLSEC_PRIVATE
#error "transform_helpers.h file contains private xmlsec definitions and should not be used outside xmlsec or xmlsec-$crypto libraries"
#endif /* XMLSEC_PRIVATE */

#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>


/**************************** Common Key Agreement params ********************************/
struct _xmlSecTransformKeyAgreementParams {
    xmlSecTransformPtr  kdfTransform;
    xmlSecKeyInfoCtx    kdfKeyInfoCtx;

    xmlSecTransformPtr  memBufTransform;

    xmlSecKeyPtr        keyOriginator;
    xmlSecKeyPtr        keyRecipient;
};
typedef struct _xmlSecTransformKeyAgreementParams xmlSecTransformKeyAgreementParams, *xmlSecTransformKeyAgreementParamsPtr;

XMLSEC_EXPORT int   xmlSecTransformKeyAgreementParamsInitialize    (xmlSecTransformKeyAgreementParamsPtr params);
XMLSEC_EXPORT void  xmlSecTransformKeyAgreementParamsFinalize      (xmlSecTransformKeyAgreementParamsPtr params);
XMLSEC_EXPORT int   xmlSecTransformKeyAgreementParamsRead          (xmlSecTransformKeyAgreementParamsPtr params,
                                                                    xmlNodePtr node,
                                                                    xmlSecTransformPtr kaTransform,
                                                                    xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT int   xmlSecTransformKeyAgreementParamsWrite         (xmlSecTransformKeyAgreementParamsPtr params,
                                                                    xmlNodePtr node,
                                                                    xmlSecTransformPtr kaTransform,
                                                                    xmlSecTransformCtxPtr transformCtx);


/**************************** ConcatKDF ********************************/
#ifndef XMLSEC_NO_CONCATKDF

struct _xmlSecTransformConcatKdfParams {
    xmlChar* digestMethod;
    xmlSecBuffer bufAlgorithmID;
    xmlSecBuffer bufPartyUInfo;
    xmlSecBuffer bufPartyVInfo;
    xmlSecBuffer bufSuppPubInfo;
    xmlSecBuffer bufSuppPrivInfo;
};
typedef struct _xmlSecTransformConcatKdfParams   xmlSecTransformConcatKdfParams, *xmlSecTransformConcatKdfParamsPtr;

XMLSEC_EXPORT int   xmlSecTransformConcatKdfParamsInitialize    (xmlSecTransformConcatKdfParamsPtr params);
XMLSEC_EXPORT void  xmlSecTransformConcatKdfParamsFinalize      (xmlSecTransformConcatKdfParamsPtr params);
XMLSEC_EXPORT int   xmlSecTransformConcatKdfParamsRead          (xmlSecTransformConcatKdfParamsPtr params,
                                                                 xmlNodePtr node);
XMLSEC_EXPORT int   xmlSecTransformConcatKdfParamsGetFixedInfo  (xmlSecTransformConcatKdfParamsPtr params,
                                                                 xmlSecBufferPtr bufFixedInfo);

#endif /* XMLSEC_NO_CONCATKDF */


/********************************** HMAC *******************************/
#ifndef XMLSEC_NO_HMAC

/* max HMAC output size in bytes */
#define XMLSEC_TRANSFORM_HMAC_MAX_OUTPUT_SIZE       128U

#define XMLSEC_TRANSFORM_HMAC_BITS_TO_BYTES(bits)   (((bits) + 7) / 8)

XMLSEC_EXPORT int xmlSecTransformHmacReadOutputBitsSize (xmlNodePtr node,
                                                         xmlSecSize defaultSize,
                                                         xmlSecSize* res);
XMLSEC_EXPORT int xmlSecTransformHmacWriteOutput        (const xmlSecByte * hmac,
                                                         xmlSecSize hmacSizeInBits,
                                                         xmlSecSize hmacMaxSizeInBytes,
                                                         xmlSecBufferPtr out);
XMLSEC_EXPORT int xmlSecTransformHmacVerify             (const xmlSecByte* data,
                                                         xmlSecSize dataSize,
                                                         const xmlSecByte * hmac,
                                                         xmlSecSize hmacSizeInBits,
                                                         xmlSecSize hmacMaxSizeInBytes);

#endif /* XMLSEC_NO_HMAC */


/**************************** PBKDF2 ********************************/
#ifndef XMLSEC_NO_PBKDF2

struct _xmlSecTransformPbkdf2Params {
    xmlSecBuffer salt;
    xmlSecSize iterationCount;
    xmlSecSize keyLength;
    xmlChar* prfAlgorithmHref;
};
typedef struct _xmlSecTransformPbkdf2Params   xmlSecTransformPbkdf2Params, *xmlSecTransformPbkdf2ParamsPtr;

XMLSEC_EXPORT int   xmlSecTransformPbkdf2ParamsInitialize    (xmlSecTransformPbkdf2ParamsPtr params);
XMLSEC_EXPORT void  xmlSecTransformPbkdf2ParamsFinalize      (xmlSecTransformPbkdf2ParamsPtr params);
XMLSEC_EXPORT int   xmlSecTransformPbkdf2ParamsRead          (xmlSecTransformPbkdf2ParamsPtr params,
                                                              xmlNodePtr node);

#endif /* XMLSEC_NO_PBKDF2 */


/********************************** RSA *******************************/
#ifndef XMLSEC_NO_RSA

/* All OAEP params in one place */
struct _xmlSecTransformRsaOaepParams {
    xmlSecBuffer oaepParams;
    xmlChar *    digestAlgorithm;
    xmlChar *    mgf1DigestAlgorithm;
};
typedef struct _xmlSecTransformRsaOaepParams            xmlSecTransformRsaOaepParams,
                                                        *xmlSecTransformRsaOaepParamsPtr;

XMLSEC_EXPORT int  xmlSecTransformRsaOaepParamsInitialize   (xmlSecTransformRsaOaepParamsPtr oaepParams);
XMLSEC_EXPORT void xmlSecTransformRsaOaepParamsFinalize     (xmlSecTransformRsaOaepParamsPtr oaepParams);
XMLSEC_EXPORT int  xmlSecTransformRsaOaepParamsRead         (xmlSecTransformRsaOaepParamsPtr oaepParams,
                                                             xmlNodePtr node);

#endif /* XMLSEC_NO_RSA */

#endif /* __XMLSEC_TRANSFORMS_HELPERS_H__ */
