/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * "XML Encryption" implementation
 *  http://www.w3.org/TR/xmlenc-core
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_XMLENC_H__
#define __XMLSEC_XMLENC_H__

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
 * xmlEncCtxMode:
 * @xmlEncCtxModeEncryptedData: the &lt;enc:EncryptedData/&gt; element procesing.
 * @xmlEncCtxModeEncryptedKey:  the &lt;enc:EncryptedKey/&gt; element processing.
 *
 * The #xmlSecEncCtx mode.
 */
typedef enum {
    xmlEncCtxModeEncryptedData = 0,
    xmlEncCtxModeEncryptedKey
} xmlEncCtxMode;


/**
 * xmlSecEncFailureReason:
 * @xmlSecEncFailureReasonUnknown:            the failure reason is unknown.
 * @xmlSecEncFailureReasonKeyNotFound:        the key not found.
 *
 * XML Encryption processing failure reason. The application should use
 * the returned value from the encrypt/decrypt functions first.
 */
typedef enum {
    xmlSecEncFailureReasonUnknown = 0,
    xmlSecEncFailureReasonKeyNotFound,
} xmlSecEncFailureReason;

/**
 * XMLSEC_ENC_RETURN_REPLACED_NODE:
 *
 * If this flag is set, then the replaced node will be returned in the replacedNodeList
 */
#define XMLSEC_ENC_RETURN_REPLACED_NODE                 0x00000001

/**
 * xmlSecEncCtx:
 * @userData:                   the pointer to user data (xmlsec and xmlsec-crypto libraries
 *                              never touches this).
 * @flags:                      the XML Encryption processing flags.
 * @flags2:                     the XML Encryption processing flags.
 * @mode:                       the mode.
 * @keyInfoReadCtx:             the reading key context.
 * @keyInfoWriteCtx:            the writing key context (not used for signature verification).
 * @transformCtx:               the transforms processing context.
 * @defEncMethodId:             the default encryption method (used if
 *                              &lt;enc:EncryptionMethod/&gt; node is not present).
 * @encKey:                     the signature key; application may set #encKey
 *                              before calling encryption/decryption functions.
 * @operation:                  the operation: encrypt or decrypt.
 * @result:                     the pointer to signature (not valid for signature verification).
 * @resultBase64Encoded:        the flag: if set then result in #result is base64 encoded.
 * @resultReplaced:             the flag: if set then resulted &lt;enc:EncryptedData/&gt;
 *                              or &lt;enc:EncryptedKey/&gt; node is added to the document.
 * @encMethod:                  the pointer to encryption transform.
 * @replacedNodeList: the first node of the list of replaced nodes depending on the nodeReplacementMode
 * @id:                         the ID attribute of &lt;enc:EncryptedData/&gt;
 *                              or &lt;enc:EncryptedKey/&gt; node.
 * @type:                       the Type attribute of &lt;enc:EncryptedData/&gt;
 *                              or &lt;enc:EncryptedKey/&gt; node.
 * @mimeType:                   the MimeType attribute of &lt;enc:EncryptedData/&gt;
 *                              or &lt;enc:EncryptedKey/&gt; node.
 * @encoding:                   the Encoding attributeof &lt;enc:EncryptedData/&gt;
 *                              or &lt;enc:EncryptedKey/&gt; node.
 * @recipient:                  the Recipient attribute of &lt;enc:EncryptedKey/&gt; node..
 * @carriedKeyName:             the CarriedKeyName attribute of &lt;enc:EncryptedKey/&gt; node.
 * @encDataNode:                the pointer to &lt;enc:EncryptedData/&gt;
 *                              or &lt;enc:EncryptedKey/&gt; node.
 * @encMethodNode:              the pointer to &lt;enc:EncryptionMethod/&gt; node.
 * @failureReason:              the detailed failure reason.
 * @keyInfoNode:                the pointer to &lt;enc:KeyInfo/&gt; node.
 * @cipherValueNode:            the pointer to &lt;enc:CipherValue/&gt; node.
 * @reserved1:                  reserved for the future.
 *
 * XML Encryption context.
 */
struct _xmlSecEncCtx {
    /* these data user can set before performing the operation */
    void*                       userData;
    unsigned int                flags;
    unsigned int                flags2;
    xmlEncCtxMode               mode;
    xmlSecKeyInfoCtx            keyInfoReadCtx;
    xmlSecKeyInfoCtx            keyInfoWriteCtx;
    xmlSecTransformCtx          transformCtx;
    xmlSecTransformId           defEncMethodId;

    /* these data are returned */
    xmlSecKeyPtr                encKey;
    xmlSecTransformOperation    operation;
    xmlSecBufferPtr             result;
    int                         resultBase64Encoded;
    int                         resultReplaced;
    xmlSecTransformPtr          encMethod;
    xmlSecEncFailureReason      failureReason;

    /* attributes from EncryptedData or EncryptedKey */
    xmlChar*                    id;
    xmlChar*                    type;
    xmlChar*                    mimeType;
    xmlChar*                    encoding;
    xmlChar*                    recipient;
    xmlChar*                    carriedKeyName;

    /* these are internal data, nobody should change that except us */
    xmlNodePtr                  encDataNode;
    xmlNodePtr                  encMethodNode;
    xmlNodePtr                  keyInfoNode;
    xmlNodePtr                  cipherValueNode;

    xmlNodePtr                  replacedNodeList; /* the pointer to the replaced node */
    void*                       reserved1;        /* reserved for future */
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

#endif /* __XMLSEC_XMLENC_H__ */
