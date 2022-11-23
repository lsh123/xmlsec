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

#include <xmlsec/transforms.h>

#ifndef XMLSEC_NO_HMAC

/* max HMAC output size in bytes */
#define XMLSEC_TRASNFORM_HMAC_MAX_OUTPUT_SIZE       128U

XMLSEC_EXPORT int xmlSecTransformHmacReadOutputBitsSize    (xmlNodePtr node,
                                                         xmlSecSize defaultSize,
                                                         xmlSecSize* res);

#endif /* XMLSEC_NO_HMAC */

#ifndef XMLSEC_NO_RSA

/* All OAEP params in one place */
struct _xmlSecTransformRsaOaepParams {
    xmlSecBuffer oaepParams;
    xmlChar *    digestAlgorithm;
    xmlChar *    mgfAlgorithm;
};
typedef struct _xmlSecTransformRsaOaepParams            xmlSecTransformRsaOaepParams,
                                                        *xmlSecTransformRsaOaepParamsPtr;

XMLSEC_EXPORT int  xmlSecTransformRsaOaepParamsInitialize   (xmlSecTransformRsaOaepParamsPtr oaepParams);
XMLSEC_EXPORT void xmlSecTransformRsaOaepParamsFinalize     (xmlSecTransformRsaOaepParamsPtr oaepParams);
XMLSEC_EXPORT int  xmlSecTransformRsaOaepParamsRead         (xmlSecTransformRsaOaepParamsPtr oaepParams,
                                                             xmlNodePtr node);


/* DEPRECATED, TO REMOVE */
XMLSEC_EXPORT int xmlSecTransformRsaOaepReadParams        (xmlNodePtr node,
                                                         xmlSecBufferPtr params,
                                                         xmlChar** algorithm);
#endif /* XMLSEC_NO_RSA */

#endif /* __XMLSEC_TRASNFORMS_HELPERS_H__ */
