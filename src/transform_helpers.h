/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Internal header only used during the compilation,
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_TRASNFORMS_HELPERS_H__
#define __XMLSEC_TRASNFORMS_HELPERS_H__


#ifndef XMLSEC_PRIVATE
#error "private.h file contains private xmlsec definitions and should not be used outside xmlsec or xmlsec-$crypto libraries"
#endif /* XMLSEC_PRIVATE */

#include <xmlsec/buffer.h>
#include <xmlsec/transforms.h>


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


/**************************** ECDH ********************************/
#ifndef XMLSEC_NO_EC

struct _xmlSecTransformEcdhParams {
    xmlSecTransformPtr  kdfTransform;
    xmlSecKeyInfoCtx    kdfKeyInfoCtx;

    xmlSecTransformPtr  memBufTransform;

    xmlSecKeyPtr        keyOriginator;
    xmlSecKeyPtr        keyRecipient;
};
typedef struct _xmlSecTransformEcdhParams xmlSecTransformEcdhParams, *xmlSecTransformEcdhParamsPtr;

XMLSEC_EXPORT int   xmlSecTransformEcdhParamsInitialize    (xmlSecTransformEcdhParamsPtr params);
XMLSEC_EXPORT void  xmlSecTransformEcdhParamsFinalize      (xmlSecTransformEcdhParamsPtr params);
XMLSEC_EXPORT int   xmlSecTransformEcdhParamsRead          (xmlSecTransformEcdhParamsPtr params,
                                                            xmlNodePtr node,
                                                            xmlSecTransformPtr ecdhTransform,
                                                            xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT int   xmlSecTransformEcdhParamsWrite         (xmlSecTransformEcdhParamsPtr params,
                                                            xmlNodePtr node,
                                                            xmlSecTransformPtr ecdhTransform,
                                                            xmlSecTransformCtxPtr transformCtx);
#endif /* XMLSEC_NO_EC */

/********************************** HMAC *******************************/
#ifndef XMLSEC_NO_HMAC

/* max HMAC output size in bytes */
#define XMLSEC_TRASNFORM_HMAC_MAX_OUTPUT_SIZE       128U

#define XMLSEC_TRASNFORM_HMAC_BITS_TO_BYTES(bits)   (((bits) + 7) / 8)

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

#endif /* __XMLSEC_TRASNFORMS_HELPERS_H__ */
