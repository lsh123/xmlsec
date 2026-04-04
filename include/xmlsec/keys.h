/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Keys.
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_KEYS_H__
#define __XMLSEC_KEYS_H__

/**
 * @defgroup xmlsec_core_keys Keys
 * @ingroup xmlsec_core
 * @brief Key objects and key management.
 * @{
 */

#include <time.h>

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/list.h>
#include <xmlsec/keysdata.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief The key usage.
 */
typedef unsigned int                    xmlSecKeyUsage;

/**
 * @brief Key for signing.
 */
#define xmlSecKeyUsageSign              0x00000001

/**
 * @brief Key for signature verification.
 */
#define xmlSecKeyUsageVerify            0x00000002

/**
 * @brief An encryption key.
 */
#define xmlSecKeyUsageEncrypt           0x00000004

/**
 * @brief A decryption key.
 */
#define xmlSecKeyUsageDecrypt           0x00000008

/**
 * @brief Deprecated. The key is used for key exchange.
 */
#define xmlSecKeyUsageKeyExchange       0x00000010

/**
 * @brief The key is used for key derivation.
 */
#define xmlSecKeyUsageKeyDerive         0x00000020

/**
 * @brief The key is used for key agreement.
 */
#define xmlSecKeyUsageKeyAgreement      0x00000040

/**
 * @brief Key can be used in any way.
 */
#define xmlSecKeyUsageAny               0xFFFFFFFF


/******************************************************************************
 *
 * xmlSecKeyUseWith
 *
  *****************************************************************************/
typedef struct _xmlSecKeyUseWith                xmlSecKeyUseWith, *xmlSecKeyUseWithPtr;
XMLSEC_EXPORT int       xmlSecKeyUseWithInitialize              (xmlSecKeyUseWithPtr keyUseWith);
XMLSEC_EXPORT void      xmlSecKeyUseWithFinalize                (xmlSecKeyUseWithPtr keyUseWith);
XMLSEC_EXPORT void      xmlSecKeyUseWithReset                   (xmlSecKeyUseWithPtr keyUseWith);
XMLSEC_EXPORT int       xmlSecKeyUseWithCopy                    (xmlSecKeyUseWithPtr dst,
                                                                 xmlSecKeyUseWithPtr src);
XMLSEC_EXPORT xmlSecKeyUseWithPtr xmlSecKeyUseWithCreate        (const xmlChar* application,
                                                                 const xmlChar* identifier);
XMLSEC_EXPORT xmlSecKeyUseWithPtr xmlSecKeyUseWithDuplicate     (xmlSecKeyUseWithPtr keyUseWith);
XMLSEC_EXPORT void      xmlSecKeyUseWithDestroy                 (xmlSecKeyUseWithPtr keyUseWith);
XMLSEC_EXPORT int       xmlSecKeyUseWithSet                     (xmlSecKeyUseWithPtr keyUseWith,
                                                                 const xmlChar* application,
                                                                 const xmlChar* identifier);
XMLSEC_EXPORT void      xmlSecKeyUseWithDebugDump               (xmlSecKeyUseWithPtr keyUseWith,
                                                                 FILE* output);
XMLSEC_EXPORT void      xmlSecKeyUseWithDebugXmlDump            (xmlSecKeyUseWithPtr keyUseWith,
                                                                 FILE* output);

/**
 * @brief Information about application and user of the key.
 */
struct _xmlSecKeyUseWith {
    xmlChar*                    application;  /**< the application. */
    xmlChar*                    identifier;  /**< the identifier. */

    void*                       reserved1;  /**< reserved for future use. */
    void*                       reserved2;  /**< reserved for future use. */
};

/**
 * @brief The keys list klass.
 */
#define xmlSecKeyUseWithPtrListId       xmlSecKeyUseWithPtrListGetKlass()
XMLSEC_EXPORT xmlSecPtrListId   xmlSecKeyUseWithPtrListGetKlass (void);

/******************************************************************************
 *
 * xmlSecKeyReq - what key are we looking for?
 *
  *****************************************************************************/
typedef struct _xmlSecKeyReq                    xmlSecKeyReq, *xmlSecKeyReqPtr;

/**
 * @brief The key requirements information.
 */
struct _xmlSecKeyReq {
    xmlSecKeyDataId             keyId;  /**< the desired key value klass. */
    xmlSecKeyDataType           keyType;  /**< the desired key type. */
    xmlSecKeyUsage              keyUsage;  /**< the desired key usage. */
    xmlSecSize                  keyBitsSize;  /**< the desired key size (in bits!). */
    xmlSecPtrList               keyUseWithList;  /**< the desired key use with application/identifier information. */

    void*                       reserved1;  /**< reserved for future use. */
    void*                       reserved2;  /**< reserved for future use. */
};

XMLSEC_EXPORT int       xmlSecKeyReqInitialize                  (xmlSecKeyReqPtr keyReq);
XMLSEC_EXPORT void      xmlSecKeyReqFinalize                    (xmlSecKeyReqPtr keyReq);
XMLSEC_EXPORT void      xmlSecKeyReqReset                       (xmlSecKeyReqPtr keyReq);
XMLSEC_EXPORT int       xmlSecKeyReqCopy                        (xmlSecKeyReqPtr dst,
                                                                 xmlSecKeyReqPtr src);
XMLSEC_EXPORT int       xmlSecKeyReqMatchKey                    (xmlSecKeyReqPtr keyReq,
                                                                 xmlSecKeyPtr key);
XMLSEC_EXPORT int       xmlSecKeyReqMatchKeyValue               (xmlSecKeyReqPtr keyReq,
                                                                 xmlSecKeyDataPtr value);
XMLSEC_EXPORT void      xmlSecKeyReqDebugDump                   (xmlSecKeyReqPtr keyReq,
                                                                 FILE* output);
XMLSEC_EXPORT void      xmlSecKeyReqDebugXmlDump                (xmlSecKeyReqPtr keyReq,
                                                                 FILE* output);

/**
 * @brief The key.
 */
struct _xmlSecKey {
    xmlChar*                            name;  /**< the key name. */
    xmlSecKeyDataPtr                    value;  /**< the key value. */
    xmlSecPtrListPtr                    dataList;  /**< the key data list. */
    xmlSecKeyUsage                      usage;  /**< the key usage. */
    time_t                              notValidBefore;  /**< the start key validity interval. */
    time_t                              notValidAfter;  /**< the end key validity interval. */
};

XMLSEC_EXPORT xmlSecKeyPtr      xmlSecKeyCreate         (void);
XMLSEC_EXPORT void              xmlSecKeyDestroy        (xmlSecKeyPtr key);
XMLSEC_EXPORT void              xmlSecKeyEmpty          (xmlSecKeyPtr key);
XMLSEC_EXPORT xmlSecKeyPtr      xmlSecKeyDuplicate      (xmlSecKeyPtr key);
XMLSEC_EXPORT int               xmlSecKeyCopy           (xmlSecKeyPtr keyDst,
                                                         xmlSecKeyPtr keySrc);
XMLSEC_EXPORT int               xmlSecKeySwap           (xmlSecKeyPtr key1,
                                                         xmlSecKeyPtr key2);
XMLSEC_EXPORT const xmlChar*    xmlSecKeyGetName        (xmlSecKeyPtr key);
XMLSEC_EXPORT int               xmlSecKeySetName        (xmlSecKeyPtr key,
                                                         const xmlChar* name);
XMLSEC_EXPORT int               xmlSecKeySetNameEx      (xmlSecKeyPtr key,
                                                         const xmlChar* name,
                                                         xmlSecSize nameSize);
XMLSEC_EXPORT xmlSecKeyDataType xmlSecKeyGetType        (xmlSecKeyPtr key);

XMLSEC_EXPORT xmlSecKeyDataPtr  xmlSecKeyGetValue       (xmlSecKeyPtr key);
XMLSEC_EXPORT int               xmlSecKeySetValue       (xmlSecKeyPtr key,
                                                         xmlSecKeyDataPtr value);

XMLSEC_EXPORT xmlSecSize         xmlSecKeyGetSize       (xmlSecKeyPtr key);


XMLSEC_EXPORT xmlSecKeyDataPtr  xmlSecKeyGetData        (xmlSecKeyPtr key,
                                                         xmlSecKeyDataId dataId);
XMLSEC_EXPORT xmlSecKeyDataPtr  xmlSecKeyEnsureData     (xmlSecKeyPtr key,
                                                         xmlSecKeyDataId dataId);
XMLSEC_EXPORT int               xmlSecKeyAdoptData      (xmlSecKeyPtr key,
                                                         xmlSecKeyDataPtr data);

XMLSEC_EXPORT void              xmlSecKeyDebugDump      (xmlSecKeyPtr key,
                                                         FILE *output);
XMLSEC_EXPORT void              xmlSecKeyDebugXmlDump   (xmlSecKeyPtr key,
                                                         FILE *output);
XMLSEC_EXPORT xmlSecKeyPtr      xmlSecKeyGenerate       (xmlSecKeyDataId dataId,
                                                         xmlSecSize sizeBits,
                                                         xmlSecKeyDataType type);
XMLSEC_EXPORT xmlSecKeyPtr      xmlSecKeyGenerateByName (const xmlChar* name,
                                                         xmlSecSize sizeBits,
                                                         xmlSecKeyDataType type);


XMLSEC_EXPORT int               xmlSecKeyMatch          (xmlSecKeyPtr key,
                                                         const xmlChar *name,
                                                         xmlSecKeyReqPtr keyReq);

XMLSEC_EXPORT xmlSecKeyPtr      xmlSecKeyReadBuffer     (xmlSecKeyDataId dataId,
                                                         xmlSecBuffer* buffer);
XMLSEC_EXPORT xmlSecKeyPtr      xmlSecKeyReadBinaryFile (xmlSecKeyDataId dataId,
                                                         const char* filename);
XMLSEC_EXPORT xmlSecKeyPtr      xmlSecKeyReadMemory     (xmlSecKeyDataId dataId,
                                                         const xmlSecByte* data,
                                                         xmlSecSize dataSize);


/**
 * @brief Macro. Returns 1 if @p key is valid.
 * @details Macro. Returns 1 if @p key is not NULL and @p key->id is not NULL
 * or 0 otherwise.
 * @param key the pointer to key.
 */
#define xmlSecKeyIsValid(key) \
        ((( key ) != NULL) && \
         (( key )->value != NULL) && \
         ((( key )->value->id) != NULL))
/**
 * @brief Macro. Returns 1 if @p key's id equals @p keyId.
 * @details Macro. Returns 1 if @p key is valid and @p key's id is equal to @p keyId.
 * @param key the pointer to key.
 * @param keyId the key Id.
 */
#define xmlSecKeyCheckId(key, keyId) \
        (xmlSecKeyIsValid(( key )) && \
        ((( key )->value->id) == ( keyId )))


/******************************************************************************
 *
 * Keys list
 *
  *****************************************************************************/
/**
 * @brief The keys list klass.
 */
#define xmlSecKeyPtrListId      xmlSecKeyPtrListGetKlass()
XMLSEC_EXPORT xmlSecPtrListId   xmlSecKeyPtrListGetKlass                (void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

/** @} */ /** xmlsec_core_keys */

#endif /* __XMLSEC_KEYS_H__ */
