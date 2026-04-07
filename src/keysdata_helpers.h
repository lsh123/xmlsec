/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @brief Internal helper functions for key data implementations.
 */
#ifndef __XMLSEC_KEYSDATA_HELPERS_H__
#define __XMLSEC_KEYSDATA_HELPERS_H__


#ifndef XMLSEC_PRIVATE
#error "keysdata_helpers.h file contains private xmlsec definitions and should not be used outside xmlsec or xmlsec-$crypto libraries"
#endif /* XMLSEC_PRIVATE */

#include <xmlsec/keysdata.h>
#include <xmlsec/keysmngr.h>


XMLSEC_EXPORT void          xmlSecKeyDataDebugDumpImpl(xmlSecKeyDataPtr data, FILE* output);
XMLSEC_EXPORT void          xmlSecKeyDataDebugXmlDumpImpl(xmlSecKeyDataPtr data, FILE* output);

/******************************************************************************
 *
 * xmlSecKeyDataBinary (for HMAC, AES, DES, ...)
 *
 * xmlSecKeyData + xmlSecBuffer (key)
 *
  *****************************************************************************/

/******************************************************************************
 *
 * Binary key sizes (in bytes)
 *
  *****************************************************************************/
#define XMLSEC_BINARY_KEY_BYTES_SIZE_128            ((xmlSecSize)16)
#define XMLSEC_BINARY_KEY_BYTES_SIZE_192            ((xmlSecSize)24)
#define XMLSEC_BINARY_KEY_BYTES_SIZE_256            ((xmlSecSize)32)

/**
 * @brief The binary key data (e.g. HMAC key).
 */
typedef struct _xmlSecKeyDataBinary {
    xmlSecKeyData  keyData;  /**< the key data (xmlSecKeyData). */
    xmlSecBuffer   buffer;  /**< the key's binary (xmlSecBuffer). */
} xmlSecKeyDataBinary;

/**
 * @brief The binary key data object size.
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
 * @brief Creates xmlSecKeyData from #ecValue.
 * @param id the key data data.
 * @param ecValue the pointer to input xmlSecKeyValueEc.
 * @return the poitner to xmlSecKeyData or NULL if an error occurs.
 */
typedef xmlSecKeyDataPtr       (*xmlSecKeyDataEcRead)                   (xmlSecKeyDataId id,
                                                                         xmlSecKeyValueEcPtr ecValue);

/**
 * @brief Writes xmlSecKeyData to xmlSecKeyValueEc.
 * @param id the key data data.
 * @param data the pointer to input xmlSecKeyData.
 * @param c the pointer to input xmlSecKeyValueEc.
 * @return 0 on success or a negative value if an error occurs.
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
/******************************************************************************
 *
 * Helper functions to read/write RSA keys
 *
  *****************************************************************************/
typedef struct _xmlSecKeyValueRsa {
    xmlSecBuffer   modulus;
    xmlSecBuffer   publicExponent;
    xmlSecBuffer   privateExponent;
} xmlSecKeyValueRsa, *xmlSecKeyValueRsaPtr;

/**
 * @brief Creates xmlSecKeyData from #rsaValue.
 * @param id the key data data.
 * @param dsaValue the pointer to input xmlSecKeyValueRsa.
 * @return the poitner to xmlSecKeyData or NULL if an error occurs.
 */
typedef xmlSecKeyDataPtr       (*xmlSecKeyDataRsaRead)                  (xmlSecKeyDataId id,
                                                                         xmlSecKeyValueRsaPtr rsaValue);

/**
 * @brief Writes xmlSecKeyData to xmlSecKeyValueRsa.
 * @param id the key data data.
 * @param data the pointer to input xmlSecKeyData.
 * @param dsaValue the pointer to input xmlSecKeyValueRsa.
 * @param writePrivateKey the flag indicating if private key component should be output or not.
 * @return 0 on success or a negative value if an error occurs.
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
/******************************************************************************
 *
 * Helper functions to read/write DH keys
 *
  *****************************************************************************/
typedef struct _xmlSecKeyValueDh {
    xmlSecBuffer p;
    xmlSecBuffer q;
    xmlSecBuffer generator;
    xmlSecBuffer public;
    xmlSecBuffer seed;
    xmlSecBuffer pgenCounter;
} xmlSecKeyValueDh, *xmlSecKeyValueDhPtr;

/**
 * @brief Creates xmlSecKeyData from #dhValue.
 * @param id the key data data.
 * @param dhValue the pointer to input xmlSecKeyValueDh.
 * @return the poitner to xmlSecKeyData or NULL if an error occurs.
 */
typedef xmlSecKeyDataPtr       (*xmlSecKeyDataDhRead)                  (xmlSecKeyDataId id,
                                                                         xmlSecKeyValueDhPtr dhValue);

/**
 * @brief Writes xmlSecKeyData to xmlSecKeyValueDh.
 * @param id the key data data.
 * @param data the pointer to input xmlSecKeyData.
 * @param dhValue the pointer to input xmlSecKeyValueDh.
 * @param writePrivateKey the flag indicating if private key component should be output or not.
 * @return 0 on success or a negative value if an error occurs.
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
/******************************************************************************
 *
 * Helper functions to read/write DSA keys
 *
  *****************************************************************************/
typedef struct _xmlSecKeyValueDsa {
    xmlSecBuffer p;
    xmlSecBuffer q;
    xmlSecBuffer g;
    xmlSecBuffer x;
    xmlSecBuffer y;
} xmlSecKeyValueDsa, *xmlSecKeyValueDsaPtr;

/**
 * @brief Creates xmlSecKeyData from #dsaValue.
 * @param id the key data data.
 * @param dsaValue the pointer to input xmlSecKeyValueDsa.
 * @return the poitner to xmlSecKeyData or NULL if an error occurs.
 */
typedef xmlSecKeyDataPtr       (*xmlSecKeyDataDsaRead)                  (xmlSecKeyDataId id,
                                                                         xmlSecKeyValueDsaPtr dsaValue);

/**
 * @brief Writes xmlSecKeyData to xmlSecKeyValueDsa.
 * @param id the key data data.
 * @param data the pointer to input xmlSecKeyData.
 * @param dsaValue the pointer to input xmlSecKeyValueDsa.
 * @param writePrivateKey the flag indicating if private key component should be output or not.
 * @return 0 on success or a negative value if an error occurs.
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


#endif /* __XMLSEC_KEYSDATA_HELPERS_H__ */
