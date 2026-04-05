/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_BASE64_H__
#define __XMLSEC_BASE64_H__

/**
 * @brief Base64 encoding/decoding functions and transform implementation.
 * @defgroup xmlsec_core_base64 Base64 Encode/Decode
 * @ingroup xmlsec_core
 *
 * @{
 */

#include <libxml/tree.h>

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/transforms.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


/**
 * @brief The default maximum base64 encoded line size.
 */
#define XMLSEC_BASE64_LINESIZE                          64

XMLSEC_EXPORT int               xmlSecBase64GetDefaultLineSize  (void);
XMLSEC_EXPORT void              xmlSecBase64SetDefaultLineSize  (int columns);

/**
 * @brief Base64 Context
 */
typedef struct _xmlSecBase64Ctx                                 xmlSecBase64Ctx,
                                                                *xmlSecBase64CtxPtr;

XMLSEC_EXPORT xmlSecBase64CtxPtr xmlSecBase64CtxCreate          (int encode,
                                                                 int columns);
XMLSEC_EXPORT void              xmlSecBase64CtxDestroy          (xmlSecBase64CtxPtr ctx);
XMLSEC_EXPORT int               xmlSecBase64CtxInitialize       (xmlSecBase64CtxPtr ctx,
                                                                 int encode,
                                                                 int columns);
XMLSEC_EXPORT void              xmlSecBase64CtxFinalize         (xmlSecBase64CtxPtr ctx);
XMLSEC_EXPORT int               xmlSecBase64CtxUpdate_ex        (xmlSecBase64CtxPtr ctx,
                                                                 const xmlSecByte* in,
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte* out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize* outWritten);
XMLSEC_EXPORT int                xmlSecBase64CtxFinal_ex        (xmlSecBase64CtxPtr ctx,
                                                                 xmlSecByte* out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize* outWritten);

/* Standalone routines to do base64 encode/decode "at once" */
XMLSEC_EXPORT xmlChar*           xmlSecBase64Encode             (const xmlSecByte* in,
                                                                 xmlSecSize inSize,
                                                                 int columns);
XMLSEC_EXPORT int                xmlSecBase64Decode_ex          (const xmlChar* str,
                                                                 xmlSecByte* out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize* outWritten);
XMLSEC_EXPORT int                xmlSecBase64DecodeInPlace      (xmlChar* str,
                                                                 xmlSecSize* outWritten);

#ifdef __cplusplus
}
#endif /* __cplusplus */

/** @} */  /* xmlsec_core_base64 */

#endif /* __XMLSEC_BASE64_H__ */
