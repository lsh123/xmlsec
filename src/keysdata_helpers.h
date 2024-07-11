/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Internal header only used during the compilation,
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_KEYSDATA_HELPERS_H__
#define __XMLSEC_KEYSDATA_HELPERS_H__


#ifndef XMLSEC_PRIVATE
#error "keysdata_helpers.h file contains private xmlsec definitions and should not be used outside xmlsec or xmlsec-$crypto libraries"
#endif /* XMLSEC_PRIVATE */

#include <xmlsec/keysdata.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/x509.h>

/**************************************************************************
 *
 * xmlSecKeyDataBinary (for HMAC, AES, DES, ...)
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


#if !defined(XMLSEC_NO_EC)

/* TODO: do we even need pub_x and pub_y? */
typedef struct _xmlSecKeyValueEc {
    xmlChar* curve;
    xmlSecBuffer pubkey;
    xmlSecBuffer pub_x;
    xmlSecBuffer pub_y;
} xmlSecKeyValueEc, *xmlSecKeyValueEcPtr;

/**
 * xmlSecKeyDataEcRead:
 * @id:                 the key data data.
 * @ecValue:            the pointer to input @xmlSecKeyValueEc.
 *
 * Creates xmlSecKeyData from @ecValue
 *
 * Returns: the poitner to xmlSecKeyData or NULL if an error occurs.
 */
typedef xmlSecKeyDataPtr       (*xmlSecKeyDataEcRead)                   (xmlSecKeyDataId id,
                                                                         xmlSecKeyValueEcPtr ecValue);

/**
 * xmlSecKeyDataEcWrite:
 * @id:                 the key data data.
 * @data:               the pointer to input @xmlSecKeyData.
 * @c:                  the pointer to input @xmlSecKeyValueEc.
 *
 * Writes @xmlSecKeyData to @xmlSecKeyValueEc.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
typedef int                    (*xmlSecKeyDataEcWrite)                  (xmlSecKeyDataId id,
                                                                         xmlSecKeyDataPtr data,
                                                                         xmlSecKeyValueEcPtr ecValue);


XMLSEC_EXPORT int               xmlSecKeyDataEcPublicKeySplitComponents (xmlSecKeyValueEcPtr ecValue);
XMLSEC_EXPORT int               xmlSecKeyDataEcPublicKeyCombineComponents (xmlSecKeyValueEcPtr ecValue);


XMLSEC_EXPORT int               xmlSecKeyDataEcXmlRead                  (xmlSecKeyDataId id,
                                                                         xmlSecKeyPtr key,
                                                                         xmlNodePtr node,
                                                                         xmlSecKeyInfoCtxPtr keyInfoCtx,
                                                                         xmlSecKeyDataEcRead readFunc);
XMLSEC_EXPORT int               xmlSecKeyDataEcXmlWrite                 (xmlSecKeyDataId id,
                                                                         xmlSecKeyPtr key,
                                                                         xmlNodePtr node,
                                                                         xmlSecKeyInfoCtxPtr keyInfoCtx,
                                                                         int base64LineSize,
                                                                         int addLineBreaks,
                                                                         xmlSecKeyDataEcWrite writeFunc);

#endif /* !defined(XMLSEC_NO_EC) */

#if !defined(XMLSEC_NO_RSA)
/**************************************************************************
 *
 * Helper functions to read/write RSA keys
 *
 *************************************************************************/
typedef struct _xmlSecKeyValueRsa {
    xmlSecBuffer   modulus;
    xmlSecBuffer   publicExponent;
    xmlSecBuffer   privateExponent;
} xmlSecKeyValueRsa, *xmlSecKeyValueRsaPtr;

/**
 * xmlSecKeyDataRsaRead:
 * @id:                 the key data data.
 * @dsaValue:            the pointer to input @xmlSecKeyValueRsa.
 *
 * Creates xmlSecKeyData from @dsaValue
 *
 * Returns: the poitner to xmlSecKeyData or NULL if an error occurs.
 */
typedef xmlSecKeyDataPtr       (*xmlSecKeyDataRsaRead)                  (xmlSecKeyDataId id,
                                                                         xmlSecKeyValueRsaPtr rsaValue);

/**
 * xmlSecKeyDataRsaWrite:
 * @id:                 the key data data.
 * @data:               the pointer to input @xmlSecKeyData.
 * @dsaValue:            the pointer to input @xmlSecKeyValueRsa.
 * @writePrivateKey:    the flag indicating if private key component should be output or not.
 *
 * Writes @xmlSecKeyData to @xmlSecKeyValueRsa.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
typedef int                    (*xmlSecKeyDataRsaWrite)                 (xmlSecKeyDataId id,
                                                                         xmlSecKeyDataPtr data,
                                                                         xmlSecKeyValueRsaPtr rsaValue,
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

#if !defined(XMLSEC_NO_DH)
/**************************************************************************
 *
 * Helper functions to read/write DH keys
 *
 *************************************************************************/
typedef struct _xmlSecKeyValueDh {
    xmlSecBuffer p;
    xmlSecBuffer q;
    xmlSecBuffer generator;
    xmlSecBuffer public;
    xmlSecBuffer seed;
    xmlSecBuffer pgenCounter;
} xmlSecKeyValueDh, *xmlSecKeyValueDhPtr;

/**
 * xmlSecKeyDataDhRead:
 * @id:                 the key data data.
 * @dhValue:            the pointer to input @xmlSecKeyValueDh.
 *
 * Creates xmlSecKeyData from @dhValue
 *
 * Returns: the poitner to xmlSecKeyData or NULL if an error occurs.
 */
typedef xmlSecKeyDataPtr       (*xmlSecKeyDataDhRead)                  (xmlSecKeyDataId id,
                                                                         xmlSecKeyValueDhPtr dhValue);

/**
 * xmlSecKeyDataDhWrite:
 * @id:                 the key data data.
 * @data:               the pointer to input @xmlSecKeyData.
 * @dhValue:            the pointer to input @xmlSecKeyValueDh.
 * @writePrivateKey:    the flag indicating if private key component should be output or not.
 *
 * Writes @xmlSecKeyData to @xmlSecKeyValueDh.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
typedef int                    (*xmlSecKeyDataDhWrite)                  (xmlSecKeyDataId id,
                                                                         xmlSecKeyDataPtr data,
                                                                         xmlSecKeyValueDhPtr dhValue,
                                                                         int writePrivateKey);

XMLSEC_EXPORT int               xmlSecKeyDataDhXmlRead                  (xmlSecKeyDataId id,
                                                                         xmlSecKeyPtr key,
                                                                         xmlNodePtr node,
                                                                         xmlSecKeyInfoCtxPtr keyInfoCtx,
                                                                         xmlSecKeyDataDhRead readFunc);
XMLSEC_EXPORT int               xmlSecKeyDataDhXmlWrite                 (xmlSecKeyDataId id,
                                                                         xmlSecKeyPtr key,
                                                                         xmlNodePtr node,
                                                                         xmlSecKeyInfoCtxPtr keyInfoCtx,
                                                                         int base64LineSize,
                                                                         int addLineBreaks,
                                                                         xmlSecKeyDataDhWrite writeFunc);
#endif /* !defined(XMLSEC_NO_DH) */


#if !defined(XMLSEC_NO_DSA)
/**************************************************************************
 *
 * Helper functions to read/write DSA keys
 *
 *************************************************************************/
typedef struct _xmlSecKeyValueDsa {
    xmlSecBuffer p;
    xmlSecBuffer q;
    xmlSecBuffer g;
    xmlSecBuffer x;
    xmlSecBuffer y;
} xmlSecKeyValueDsa, *xmlSecKeyValueDsaPtr;

/**
 * xmlSecKeyDataDsaRead:
 * @id:                 the key data data.
 * @dsaValue:            the pointer to input @xmlSecKeyValueDsa.
 *
 * Creates xmlSecKeyData from @dsaValue
 *
 * Returns: the poitner to xmlSecKeyData or NULL if an error occurs.
 */
typedef xmlSecKeyDataPtr       (*xmlSecKeyDataDsaRead)                  (xmlSecKeyDataId id,
                                                                         xmlSecKeyValueDsaPtr dsaValue);

/**
 * xmlSecKeyDataDsaWrite:
 * @id:                 the key data data.
 * @data:               the pointer to input @xmlSecKeyData.
 * @dsaValue:            the pointer to input @xmlSecKeyValueDsa.
 * @writePrivateKey:    the flag indicating if private key component should be output or not.
 *
 * Writes @xmlSecKeyData to @xmlSecKeyValueDsa.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
typedef int                    (*xmlSecKeyDataDsaWrite)                 (xmlSecKeyDataId id,
                                                                         xmlSecKeyDataPtr data,
                                                                         xmlSecKeyValueDsaPtr dsaValue,
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

#if !defined(XMLSEC_NO_X509)
/**************************************************************************
 *
 * Helper functions to read/write X509 Keys
 *
 *************************************************************************/


/**
 * xmlSecKeyDataX509Read:
 * @data:               the pointer to X509 key data
 * @x509Value:          the pointer to input @xmlSecKeyX509DataValue.
 * @keysMngr:           the pointer to @xmlSecKeysMngr.
 * @flags:              the flags for certs processing.
 *
 *
 * Returns: 0 on success and a negative value otherwise.
 */
typedef int                    (*xmlSecKeyDataX509Read)                 (xmlSecKeyDataPtr data,
                                                                         xmlSecKeyX509DataValuePtr x509Value,
                                                                         xmlSecKeysMngrPtr keysMngr,
                                                                         unsigned int flags);

/**
 * xmlSecKeyDataX509Write:
 * @data:               the pointer to result @xmlSecKeyData.
 * @x509Value:          the pointer to result @xmlSecKeyX509DataValue.
 * @content:            the bitmask of what should be output to @x509Value.
 * @context:            the writer function context.
 *
 * If available, writes the next X509 object (cert or crl) into @x509Value.
 *
 * Returns: 1 on success, 0 if no more certs/crls are available, or a negative
 * value if an error occurs.
 */
typedef int                    (*xmlSecKeyDataX509Write)                (xmlSecKeyDataPtr data,
                                                                         xmlSecKeyX509DataValuePtr x509Value,
                                                                         int content,
                                                                         void* context);

XMLSEC_EXPORT int               xmlSecKeyDataX509XmlRead                (xmlSecKeyPtr key,
                                                                         xmlSecKeyDataPtr data,
                                                                         xmlNodePtr node,
                                                                         xmlSecKeyInfoCtxPtr keyInfoCtx,
                                                                         xmlSecKeyDataX509Read readFunc);
XMLSEC_EXPORT int               xmlSecKeyDataX509XmlWrite               (xmlSecKeyDataPtr data,
                                                                         xmlNodePtr node,
                                                                         xmlSecKeyInfoCtxPtr keyInfoCtx,
                                                                         int base64LineSize,
                                                                         int addLineBreaks,
                                                                         xmlSecKeyDataX509Write writeFunc,
                                                                         void* writeFuncContext);
#endif /* !defined(XMLSEC_NO_X509) */

#endif /* __XMLSEC_KEYSDATA_HELPERS_H__ */
