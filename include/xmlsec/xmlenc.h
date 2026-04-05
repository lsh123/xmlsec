/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * "XML Encryption" implementation
 *  http://www.w3.org/TR/xmlenc-core
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_XMLENC_H__
#define __XMLSEC_XMLENC_H__

/**
 * @defgroup xmlsec_core_xmlenc XML Encryption
 * @ingroup xmlsec_core
 * @brief XML Encryption (XMLEnc) implementation.
 * @{
 */

#ifndef XMLSEC_NO_XMLENC

#include <stdio.h>

#include <libxml/tree.h>
#include <libxml/parser.h>

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief The xmlSecEncCtx mode.
 */
typedef enum {
    xmlEncCtxModeEncryptedData = 0,  /**< the &lt;enc:EncryptedData/&gt; element procesing. */
    xmlEncCtxModeEncryptedKey  /**< the &lt;enc:EncryptedKey/&gt; element processing. */
} xmlEncCtxMode;


/**
 * @brief XML Encryption processing failure reason.
 * @details XML Encryption processing failure reason. The application should use
 * the returned value from the encrypt/decrypt functions first.
 */
typedef enum {
    xmlSecEncFailureReasonUnknown = 0,  /**< the failure reason is unknown. */
    xmlSecEncFailureReasonKeyNotFound,  /**< the key not found. */
} xmlSecEncFailureReason;

/**
 * @brief If set, the replaced node will be returned in replacedNodeList.
 * @details If this flag is set, then the replaced node will be returned in the replacedNodeList
 */
#define XMLSEC_ENC_RETURN_REPLACED_NODE                 0x00000001

/**
 * @brief XML Encryption context.
 */
struct _xmlSecEncCtx {
    /* these data user can set before performing the operation */
    void*                       userData;  /**< the pointer to user data (xmlsec and xmlsec-crypto libraries never touches this). */
    unsigned int                flags;  /**< the XML Encryption processing flags. */
    unsigned int                flags2;  /**< the XML Encryption processing flags. */
    xmlEncCtxMode               mode;  /**< the mode. */
    xmlSecKeyInfoCtx            keyInfoReadCtx;  /**< the reading key context. */
    xmlSecKeyInfoCtx            keyInfoWriteCtx;  /**< the writing key context (not used for signature verification). */
    xmlSecTransformCtx          transformCtx;  /**< the transforms processing context. */
    xmlSecTransformId           defEncMethodId;  /**< the default encryption method (used if &lt;enc:EncryptionMethod/&gt; node is not present). */

    /* these data are returned */
    xmlSecKeyPtr                encKey;  /**< the signature key; application may set #encKey before calling encryption/decryption functions. */
    xmlSecTransformOperation    operation;  /**< the operation: encrypt or decrypt. */
    xmlSecBufferPtr             result;  /**< the pointer to signature (not valid for signature verification). */
    int                         resultBase64Encoded;  /**< the flag: if set then result in #result is base64 encoded. */
    int                         resultReplaced;  /**< the flag: if set then resulted &lt;enc:EncryptedData/&gt; or &lt;enc:EncryptedKey/&gt; node is added to the document. */
    xmlSecTransformPtr          encMethod;  /**< the pointer to encryption transform. */
    xmlSecEncFailureReason      failureReason;  /**< the detailed failure reason. */

    /* attributes from EncryptedData or EncryptedKey */
    xmlChar*                    id;  /**< the ID attribute of &lt;enc:EncryptedData/&gt; or &lt;enc:EncryptedKey/&gt; node. */
    xmlChar*                    type;  /**< the Type attribute of &lt;enc:EncryptedData/&gt; or &lt;enc:EncryptedKey/&gt; node. */
    xmlChar*                    mimeType;  /**< the MimeType attribute of &lt;enc:EncryptedData/&gt; or &lt;enc:EncryptedKey/&gt; node. */
    xmlChar*                    encoding;  /**< the Encoding attributeof &lt;enc:EncryptedData/&gt; or &lt;enc:EncryptedKey/&gt; node. */
    xmlChar*                    recipient;  /**< the Recipient attribute of &lt;enc:EncryptedKey/&gt; node.. */
    xmlChar*                    carriedKeyName;  /**< the CarriedKeyName attribute of &lt;enc:EncryptedKey/&gt; node. */

    /* these are internal data, nobody should change that except us */
    xmlNodePtr                  encDataNode;  /**< the pointer to &lt;enc:EncryptedData/&gt; or &lt;enc:EncryptedKey/&gt; node. */
    xmlNodePtr                  encMethodNode;  /**< the pointer to &lt;enc:EncryptionMethod/&gt; node. */
    xmlNodePtr                  keyInfoNode;  /**< the pointer to &lt;enc:KeyInfo/&gt; node. */
    xmlNodePtr                  cipherValueNode;  /**< the pointer to &lt;enc:CipherValue/&gt; node. */

    xmlNodePtr                  replacedNodeList;  /**< the first node of the list of replaced nodes depending on the nodeReplacementMode */
    void*                       reserved1;  /**< reserved for the future. */
};

XMLSEC_EXPORT xmlSecEncCtxPtr   xmlSecEncCtxCreate              (xmlSecKeysMngrPtr keysMngr);
XMLSEC_EXPORT void              xmlSecEncCtxDestroy             (xmlSecEncCtxPtr encCtx);
XMLSEC_EXPORT int               xmlSecEncCtxInitialize          (xmlSecEncCtxPtr encCtx,
                                                                 xmlSecKeysMngrPtr keysMngr);
XMLSEC_EXPORT void              xmlSecEncCtxFinalize            (xmlSecEncCtxPtr encCtx);
XMLSEC_EXPORT int               xmlSecEncCtxCopyUserPref        (xmlSecEncCtxPtr dst,
                                                                 xmlSecEncCtxPtr src);
XMLSEC_EXPORT void              xmlSecEncCtxReset               (xmlSecEncCtxPtr encCtx);
XMLSEC_EXPORT int               xmlSecEncCtxBinaryEncrypt       (xmlSecEncCtxPtr encCtx,
                                                                 xmlNodePtr tmpl,
                                                                 const xmlSecByte* data,
                                                                 xmlSecSize dataSize);
XMLSEC_EXPORT int               xmlSecEncCtxXmlEncrypt          (xmlSecEncCtxPtr encCtx,
                                                                 xmlNodePtr tmpl,
                                                                 xmlNodePtr node);
XMLSEC_EXPORT int               xmlSecEncCtxUriEncrypt          (xmlSecEncCtxPtr encCtx,
                                                                 xmlNodePtr tmpl,
                                                                 const xmlChar *uri);
XMLSEC_EXPORT int               xmlSecEncCtxDecrypt             (xmlSecEncCtxPtr encCtx,
                                                                 xmlNodePtr node);
XMLSEC_EXPORT xmlSecBufferPtr   xmlSecEncCtxDecryptToBuffer     (xmlSecEncCtxPtr encCtx,
                                                                 xmlNodePtr node);
XMLSEC_EXPORT void              xmlSecEncCtxDebugDump           (xmlSecEncCtxPtr encCtx,
                                                                 FILE* output);
XMLSEC_EXPORT void              xmlSecEncCtxDebugXmlDump        (xmlSecEncCtxPtr encCtx,
                                                                 FILE* output);

XMLSEC_EXPORT xmlSecKeyPtr      xmlSecEncCtxDerivedKeyGenerate  (xmlSecEncCtxPtr encCtx,
                                                                 xmlSecKeyDataId keyId,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);


XMLSEC_EXPORT xmlSecKeyPtr      xmlSecEncCtxAgreementMethodGenerate(xmlSecEncCtxPtr encCtx,
                                                                 xmlSecKeyDataId keyId,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);

XMLSEC_EXPORT int               xmlSecEncCtxAgreementMethodXmlWrite(xmlSecEncCtxPtr encCtx,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);

XMLSEC_EXPORT const char*       xmlSecEncCtxGetFailureReasonString(xmlSecEncFailureReason failureReason);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* XMLSEC_NO_XMLENC */

/** @} */ /** xmlsec_core_xmlenc */

#endif /* __XMLSEC_XMLENC_H__ */
