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
#ifndef __XMLSEC_KEYSDATA_HELPERS_H__
#define __XMLSEC_KEYSDATA_HELPERS_H__

#include <xmlsec/keysdata.h>

/**************************************************************************
 *
 * xmlSecKeyDataBinary
 *
 * xmlSecKeyData + xmlSecBuffer (key)
 *
 *************************************************************************/

/**
 * xmlSecKeyDataiBinary:
 * @keyData:            the key data (#xmlSecKeyData).
 * @buffer:             the key's binary (#xmlSecBuffer).
 *
 * The binary key data (e.g. HMAC key).
 */
typedef struct _xmlSecKeyDataBinary {
    xmlSecKeyData  keyData;
    xmlSecBuffer   buffer;
} xmlSecKeyDataBinary;

/**
 * xmlSecKeyDataBinarySize:
 *
 * The binary key data object size.
 */
#define xmlSecKeyDataBinarySize (sizeof(xmlSecKeyDataBinary))

XMLSEC_EXPORT int               xmlSecKeyDataBinaryValueInitialize      (xmlSecKeyDataPtr data);
XMLSEC_EXPORT int               xmlSecKeyDataBinaryValueDuplicate       (xmlSecKeyDataPtr dst,
                                                                        xmlSecKeyDataPtr src);
XMLSEC_EXPORT void              xmlSecKeyDataBinaryValueFinalize        (xmlSecKeyDataPtr data);
XMLSEC_EXPORT int               xmlSecKeyDataBinaryValueXmlRead         (xmlSecKeyDataId id,
                                                                         xmlSecKeyPtr key,
                                                                         xmlNodePtr node,
                                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_EXPORT int               xmlSecKeyDataBinaryValueXmlWrite        (xmlSecKeyDataId id,
                                                                         xmlSecKeyPtr key,
                                                                         xmlNodePtr node,
                                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_EXPORT int               xmlSecKeyDataBinaryValueBinRead         (xmlSecKeyDataId id,
                                                                         xmlSecKeyPtr key,
                                                                         const xmlSecByte* buf,
                                                                         xmlSecSize bufSize,
                                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_EXPORT int               xmlSecKeyDataBinaryValueBinWrite        (xmlSecKeyDataId id,
                                                                         xmlSecKeyPtr key,
                                                                         xmlSecByte** buf,
                                                                         xmlSecSize* bufSize,
                                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_EXPORT void              xmlSecKeyDataBinaryValueDebugDump       (xmlSecKeyDataPtr data,
                                                                        FILE* output);
XMLSEC_EXPORT void              xmlSecKeyDataBinaryValueDebugXmlDump    (xmlSecKeyDataPtr data,
                                                                         FILE* output);

XMLSEC_EXPORT xmlSecSize        xmlSecKeyDataBinaryValueGetSize         (xmlSecKeyDataPtr data);
XMLSEC_EXPORT xmlSecBufferPtr   xmlSecKeyDataBinaryValueGetBuffer       (xmlSecKeyDataPtr data);
XMLSEC_EXPORT int               xmlSecKeyDataBinaryValueSetBuffer       (xmlSecKeyDataPtr data,
                                                                         const xmlSecByte* buf,
                                                                         xmlSecSize bufSize);



/**************************************************************************
 *
 * Helper functions to read/write RSA/DSA keys
 *
 *************************************************************************/
#if !defined(XMLSEC_NO_DSA)
typedef struct _xmlSecKeyDataDsa {
    xmlSecBuffer p;
    xmlSecBuffer q;
    xmlSecBuffer g;
    xmlSecBuffer x;
    xmlSecBuffer y;
} xmlSecKeyDataDsa, *xmlSecKeyDataDsaPtr;

/**
 * xmlSecKeyDataDsaRead:
 * @id:                 the key data data.
 * @dsaData:            the pointer to input @xmlSecKeyDataDsa.
 *
 * Creates xmlSecKeyData from @dsaData
 *
 * Returns: the poitner to xmlSecKeyData or NULL if an error occurs.
 */
typedef xmlSecKeyDataPtr       (*xmlSecKeyDataDsaRead)                  (xmlSecKeyDataId id,
                                                                         xmlSecKeyDataDsaPtr dsaData);

/**
 * xmlSecKeyDataDsaWrite:
 * @id:                 the key data data.
 * @data:               the pointer to input @xmlSecKeyData.
 * @dsaData:            the pointer to input @xmlSecKeyDataDsa.
 * @writePrivateKey:    the flag indicating if private key component should be output or not.
 *
 * Writes @xmlSecKeyData to @xmlSecKeyDataDsa.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
typedef int                    (*xmlSecKeyDataDsaWrite)                 (xmlSecKeyDataId id,
                                                                         xmlSecKeyDataPtr data,
                                                                         xmlSecKeyDataDsaPtr dsaData,
                                                                         int writePrivateKey);

XMLSEC_EXPORT int               xmlSecKeyDataDsaXmlRead                 (xmlSecKeyDataId id,
                                                                         xmlSecKeyPtr key,
                                                                         xmlNodePtr node,
                                                                         xmlSecKeyInfoCtxPtr keyInfoCtx,
                                                                         xmlSecKeyDataDsaRead readFunc);
XMLSEC_EXPORT int               xmlSecKeyDataDsaXmlWrite                (xmlSecKeyDataId id,
                                                                         xmlSecKeyPtr key,
                                                                         xmlNodePtr node,
                                                                         xmlSecKeyInfoCtxPtr keyInfoCtx,
                                                                         int base64LineSize,
                                                                         int addLineBreaks,
                                                                         xmlSecKeyDataDsaWrite writeFunc);
#endif /* !defined(XMLSEC_NO_DSA) */

#if !defined(XMLSEC_NO_RSA)
typedef struct _xmlSecKeyDataRsa {
    xmlSecBuffer   modulus;
    xmlSecBuffer   publicExponent;
    xmlSecBuffer   privateExponent;
} xmlSecKeyDataRsa, *xmlSecKeyDataRsaPtr;

/**
 * xmlSecKeyDataRsaRead:
 * @id:                 the key data data.
 * @dsaData:            the pointer to input @xmlSecKeyDataRsa.
 *
 * Creates xmlSecKeyData from @dsaData
 *
 * Returns: the poitner to xmlSecKeyData or NULL if an error occurs.
 */
typedef xmlSecKeyDataPtr       (*xmlSecKeyDataRsaRead)                  (xmlSecKeyDataId id,
                                                                         xmlSecKeyDataRsaPtr rsaData);

/**
 * xmlSecKeyDataRsaWrite:
 * @id:                 the key data data.
 * @data:               the pointer to input @xmlSecKeyData.
 * @dsaData:            the pointer to input @xmlSecKeyDataRsa.
 * @writePrivateKey:    the flag indicating if private key component should be output or not.
 *
 * Writes @xmlSecKeyData to @xmlSecKeyDataRsa.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
typedef int                    (*xmlSecKeyDataRsaWrite)                 (xmlSecKeyDataId id,
                                                                         xmlSecKeyDataPtr data,
                                                                         xmlSecKeyDataRsaPtr rsaData,
                                                                         int writePrivateKey);

XMLSEC_EXPORT int               xmlSecKeyDataRsaXmlRead                 (xmlSecKeyDataId id,
                                                                         xmlSecKeyPtr key,
                                                                         xmlNodePtr node,
                                                                         xmlSecKeyInfoCtxPtr keyInfoCtx,
                                                                         xmlSecKeyDataRsaRead readFunc);
XMLSEC_EXPORT int               xmlSecKeyDataRsaXmlWrite                (xmlSecKeyDataId id,
                                                                         xmlSecKeyPtr key,
                                                                         xmlNodePtr node,
                                                                         xmlSecKeyInfoCtxPtr keyInfoCtx,
                                                                         int base64LineSize,
                                                                         int addLineBreaks,
                                                                         xmlSecKeyDataRsaWrite writeFunc);
#endif /* !defined(XMLSEC_NO_RSA) */

#endif /* __XMLSEC_KEYSDATA_HELPERS_H__ */
