/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_KEYINFO_H__
#define __XMLSEC_KEYINFO_H__

/**
 * @defgroup xmlsec_core_keyinfo KeyInfo Processing
 * @ingroup xmlsec_core
 * @brief &lt;dsig:KeyInfo&gt; node processing.
 * @{
 */

#include <time.h>

#include <libxml/tree.h>

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/list.h>
#include <xmlsec/keysdata.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/******************************************************************************
 *
 * High-level functions
 *
  *****************************************************************************/
XMLSEC_EXPORT int               xmlSecKeyInfoNodeRead           (xmlNodePtr keyInfoNode,
                                                                 xmlSecKeyPtr key,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_EXPORT int               xmlSecKeyInfoNodeWrite          (xmlNodePtr keyInfoNode,
                                                                 xmlSecKeyPtr key,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);

/**
 * @brief The KeyInfo context operation mode.
 * @details The xmlSecKeyInfoCtx operation mode (read or write).
 */
typedef enum {
    xmlSecKeyInfoModeRead = 0,  /**< read <dsig:KeyInfo /> element. */
    xmlSecKeyInfoModeWrite  /**< write <dsig:KeyInfo /> element. */
} xmlSecKeyInfoMode;

/**
 * @brief Continue reading KeyInfo after key is found.
 * @details If flag is set then we will continue reading <dsig:KeyInfo />
 * element even when key is already found.
 */
#define XMLSEC_KEYINFO_FLAGS_DONT_STOP_ON_KEY_FOUND             0x00000001

/**
 * @brief Abort on unknown KeyInfo child element.
 * @details If flag is set then we abort if an unknown <dsig:KeyInfo />
 * child is found.
 */
#define XMLSEC_KEYINFO_FLAGS_STOP_ON_UNKNOWN_CHILD              0x00000002

/**
 * @brief Abort on unknown KeyName content.
 * @details If flags is set then we abort if an unknown key name
 * (content of <dsig:KeyName /> element) is found.
 */
#define XMLSEC_KEYINFO_FLAGS_KEYNAME_STOP_ON_UNKNOWN            0x00000004

/**
 * @brief Abort on unknown KeyValue child element.
 * @details If flags is set then we abort if an unknown <dsig:KeyValue />
 * child is found.
 */
#define XMLSEC_KEYINFO_FLAGS_KEYVALUE_STOP_ON_UNKNOWN_CHILD     0x00000008

/**
 * @brief Abort on unknown RetrievalMethod href.
 * @details If flag is set then we abort if an unknown href attribute
 * of <dsig:RetrievalMethod /> element is found.
 */
#define XMLSEC_KEYINFO_FLAGS_RETRMETHOD_STOP_ON_UNKNOWN_HREF    0x00000010

/**
 * @brief Abort when href doesn't match actual key data type.
 * @details If flag is set then we abort if an href attribute <dsig:RetrievalMethod />
 * element does not match the real key data type.
 */
#define XMLSEC_KEYINFO_FLAGS_RETRMETHOD_STOP_ON_MISMATCH_HREF   0x00000020

/**
 * @brief Abort on unknown X509Data child element.
 * @details If flags is set then we abort if an unknown <dsig:X509Data />
 * child is found.
 */
#define XMLSEC_KEYINFO_FLAGS_X509DATA_STOP_ON_UNKNOWN_CHILD     0x00000100

/**
 * @brief Load certificates/CRLs without verification.
 * @details If flag is set then we'll load certificates or CRLs from <dsig:X509Data />
 * element without verification.
 */
#define XMLSEC_KEYINFO_FLAGS_X509DATA_DONT_VERIFY_CERTS         0x00000200

/**
 * @brief Stop on unresolved X509 certificate reference.
 * @details If flag is set then we'll stop when we could not resolve reference
 * to certificate from <dsig:X509IssuerSerial />, <dsig:X509SKI /> or
 * <dsig:X509SubjectName /> elements.
 */
#define XMLSEC_KEYINFO_FLAGS_X509DATA_STOP_ON_UNKNOWN_CERT      0x00000400

/**
 * @brief Stop when X509Data returns no verified certificate.
 * @details If the flag is set then we'll stop when <dsig:X509Data /> element
 * processing does not return a verified certificate.
 */
#define XMLSEC_KEYINFO_FLAGS_X509DATA_STOP_ON_INVALID_CERT      0x00000800

/**
 * @brief Stop when EncryptedKey element processing fails.
 * @details If the flag is set then we'll stop when <enc:EncryptedKey /> element
 * processing fails.
 */
#define XMLSEC_KEYINFO_FLAGS_ENCKEY_DONT_STOP_ON_FAILED_DECRYPTION 0x00001000

/**
 * @brief Stop when an empty node is found.
 * @details If the flag is set then we'll stop when we found an empty node.
 * Otherwise we just ignore it.
 */
#define XMLSEC_KEYINFO_FLAGS_STOP_ON_EMPTY_NODE                 0x00002000

/**
 * @brief Skip strict checking of certificates and CRLs.
 * @details If the flag is set then we'll skip strict checking of certs and CRLs
 */
#define XMLSEC_KEYINFO_FLAGS_X509DATA_SKIP_STRICT_CHECKS        0x00004000


/**
 * @brief Try any key matching requirements, not just referenced keys.
 * @details If the flag is set then we'll try to find any key that matches requirements
 * (e.g. *any* RSA public key). In the default strict key search mode, only keys
 * referenced in &lt;dsig:KeyInfo/&gt; (e.g. by KeyName value) are used.
 */
#define XMLSEC_KEYINFO_FLAGS_LAX_KEY_SEARCH                     0x00008000

/**
 * @brief Skip time checks of certificates and CRLs.
 * @details If the flag is set then we'll skip time checks of certs and CRLs
 */
#define XMLSEC_KEYINFO_FLAGS_X509DATA_SKIP_TIME_CHECKS          0x00010000

/**
 * @brief The <dsig:KeyInfo /> reading or writing context.
 */
struct _xmlSecKeyInfoCtx {
    void*                               userData;  /**< the pointer to user data (xmlsec and xmlsec-crypto never touch this). */
    unsigned int                        flags;  /**< the bit mask for flags that control processin. */
    unsigned int                        flags2;  /**< reserved for future. */
    xmlSecKeysMngrPtr                   keysMngr;  /**< the pointer to current keys manager. */
    xmlSecKeyInfoMode                   mode;  /**< do we read or write <dsig:KeyInfo /> element. */
    xmlSecPtrList                       enabledKeyData;  /**< the list of enabled #xmlSecKeyDataId (if list is empty then all data ids are enabled). */
    int                                 base64LineSize;  /**< the max columns size for base64 encoding. */

    /* RetrievalMethod */
    xmlSecTransformCtx                  retrievalMethodCtx;  /**< the transforms context for <dsig:RetrievalMethod /> element processing. */
    int                                 maxRetrievalMethodLevel;  /**< the max recursion level when processing &lt;dsig:RetrievalMethod/&gt; element; default level is 1 (see also #curRetrievalMethodLevel). */

    /* KeyInfoReference */
    xmlSecTransformCtx                  keyInfoReferenceCtx;  /**< the transforms context for&lt;dsig11:KeyInfoReference/&gt; element processing. */
    int                                 maxKeyInfoReferenceLevel;  /**< the max recursion level when processing &lt;dsig11:KeyInfoReference/&gt; element; default level is 1 (see also #curKeyInfoReferenceLevel). */

#ifndef XMLSEC_NO_XMLENC
    /* EncryptedKey or DerivedKey */
    xmlSecEncCtxPtr                     encCtx;  /**< the encryption context for <dsig:EncryptedKey /> element processing. */
    int                                 maxEncryptedKeyLevel;  /**< the max recursion level when processing &lt;enc:EncryptedKey/&gt; element; default level is 1 (see #curEncryptedKeyLevel). */
#endif /* XMLSEC_NO_XMLENC */

#ifndef XMLSEC_NO_X509
    /* x509 certificates */
    time_t                              certsVerificationTime;  /**< the time to use for X509 certificates verification ("not valid before" and "not valid after" checks); if #certsVerificationTime is equal to 0 (default) then we verify certificates against the system's clock "now". */
    int                                 certsVerificationDepth;  /**< the max certifications chain length (default is 9). */
#endif /* XMLSEC_NO_X509 */

    /* DEPRECATED: PGP */
    void*                               deprecated0;  /**< DEPRECATED: reserved for PGP. */

    /* internal data */
    int                                 curRetrievalMethodLevel;  /**< the current&lt;dsig:RetrievalMethod/&gt; element processing level (see #maxRetrievalMethodLevel). */
    int                                 curKeyInfoReferenceLevel;  /**< the current&lt;dsig11:KeyInfoReference/&gt; element processing level (see #maxKeyInfoReferenceLevel). */
    int                                 curEncryptedKeyLevel;  /**< the current&lt;enc:EncryptedKey/&gt; or&lt;enc11:DerivedKey/&gt; element processing level (see #maxEncryptedKeyLevel). */
    xmlSecTransformOperation            operation;  /**< the transform operation for this key info. */
    xmlSecKeyReq                        keyReq;  /**< the current key requirements. */

    /* for the future */
    void*                               reserved0;  /**< reserved for the future. */
    void*                               reserved1;  /**< reserved for the future. */
};

XMLSEC_EXPORT xmlSecKeyInfoCtxPtr       xmlSecKeyInfoCtxCreate          (xmlSecKeysMngrPtr keysMngr);
XMLSEC_EXPORT void                      xmlSecKeyInfoCtxDestroy         (xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_EXPORT int                       xmlSecKeyInfoCtxInitialize      (xmlSecKeyInfoCtxPtr keyInfoCtx,
                                                                         xmlSecKeysMngrPtr keysMngr);
XMLSEC_EXPORT void                      xmlSecKeyInfoCtxFinalize        (xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_EXPORT void                      xmlSecKeyInfoCtxReset           (xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_EXPORT int                       xmlSecKeyInfoCtxCopyUserPref    (xmlSecKeyInfoCtxPtr dst,
                                                                         xmlSecKeyInfoCtxPtr src);
XMLSEC_EXPORT int                       xmlSecKeyInfoCtxCreateEncCtx    (xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_EXPORT void                      xmlSecKeyInfoCtxDebugDump       (xmlSecKeyInfoCtxPtr keyInfoCtx,
                                                                         FILE* output);
XMLSEC_EXPORT void                      xmlSecKeyInfoCtxDebugXmlDump    (xmlSecKeyInfoCtxPtr keyInfoCtx,
                                                                         FILE* output);
/**
 * @brief The dsig:KeyName processing class.
 */
#define xmlSecKeyDataNameId             xmlSecKeyDataNameGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId           xmlSecKeyDataNameGetKlass       (void);

/**
 * @brief The dsig:KeyValue processing class.
 */
#define xmlSecKeyDataValueId            xmlSecKeyDataValueGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId           xmlSecKeyDataValueGetKlass      (void);

/**
 * @brief The dsig:RetrievalMethod processing class.
 */
#define xmlSecKeyDataRetrievalMethodId  xmlSecKeyDataRetrievalMethodGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId           xmlSecKeyDataRetrievalMethodGetKlass(void);

/**
 * @brief The dsig11:KeyInfoReference processing class.
 */
#define xmlSecKeyDataKeyInfoReferenceId xmlSecKeyDataKeyInfoReferenceGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId           xmlSecKeyDataKeyInfoReferenceGetKlass(void);

#ifndef XMLSEC_NO_XMLENC
/**
 * @brief The enc:EncryptedKey element processing class.
 */
#define xmlSecKeyDataEncryptedKeyId     xmlSecKeyDataEncryptedKeyGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId           xmlSecKeyDataEncryptedKeyGetKlass(void);

/**
 * @brief The enc:AgreementMethod processing class.
 */
#define xmlSecKeyDataAgreementMethodId  xmlSecKeyDataAgreementMethodGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId           xmlSecKeyDataAgreementMethodGetKlass(void);

/**
 * @brief The enc11:DerivedKey processing class.
 */
#define xmlSecKeyDataDerivedKeyId       xmlSecKeyDataDerivedKeyGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId           xmlSecKeyDataDerivedKeyGetKlass(void);


#endif /* XMLSEC_NO_XMLENC */

#ifdef __cplusplus
}
#endif /* __cplusplus */

/** @} */ /** xmlsec_core_keyinfo */

#endif /* __XMLSEC_KEYINFO_H__ */
