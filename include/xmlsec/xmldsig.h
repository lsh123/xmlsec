/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * "XML Digital Signature" implementation
 *  http://www.w3.org/TR/xmldsig-core/
 *  http://www.w3.org/Signature/Overview.html
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_XMLDSIG_H__
#define __XMLSEC_XMLDSIG_H__

/**
 * @defgroup xmlsec_core_xmldsig XML Digital Signatures
 * @ingroup xmlsec_core
 * @brief XML Digital Signature (XMLDSig) implementation.
 * @{
 */

#ifndef XMLSEC_NO_XMLDSIG

#include <libxml/tree.h>
#include <libxml/parser.h>

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/list.h>
#include <xmlsec/buffer.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _xmlSecDSigReferenceCtx          xmlSecDSigReferenceCtx,
                                                *xmlSecDSigReferenceCtxPtr;

/**
 * @brief XML Digital signature processing status.
 */
typedef enum {
    xmlSecDSigStatusUnknown = 0,  /**< the status is unknown. */
    xmlSecDSigStatusSucceeded,  /**< the processing succeeded. */
    xmlSecDSigStatusInvalid  /**< the processing failed. */
} xmlSecDSigStatus;

/**
 * @brief XML Digital signature processing failure reason.
 * @details XML Digital signature processing failure reason. The application should use
 * #xmlSecDSigStatus to find out the operation status first.
 */
typedef enum {
    xmlSecDSigFailureReasonUnknown = 0,  /**< the failure reason is unknown. */
    xmlSecDSigFailureReasonReference,  /**< the reference processing failure (e.g. digest doesn't match). */
    xmlSecDSigFailureReasonSignature,  /**< the signature processing failure (e.g. signature doesn't match). */
    xmlSecDSigFailureReasonKeyNotFound,  /**< the key not found. */
} xmlSecDSigFailureReason;


/******************************************************************************
 *
 * xmlSecDSigCtx
 *
  *****************************************************************************/

/**
 * @brief If set, dsig:Manifests nodes will not be processed.
 * @details If this flag is set then &lt;dsig:Manifests/&gt; nodes will not be processed.
 */
#define XMLSEC_DSIG_FLAGS_IGNORE_MANIFESTS                      0x00000001

/**
 * @brief If set, pre-digest buffer for SignedInfo References is stored in xmlSecDSigCtx.
 * @details If this flag is set then pre-digest buffer for &lt;dsig:Reference/&gt; child
 * of &lt;dsig:KeyInfo/&gt; element will be stored in xmlSecDSigCtx.
 */
#define XMLSEC_DSIG_FLAGS_STORE_SIGNEDINFO_REFERENCES           0x00000002

/**
 * @brief If set, pre-digest buffer for Manifest References is stored in xmlSecDSigCtx.
 * @details If this flag is set then pre-digest buffer for &lt;dsig:Reference/&gt; child
 * of &lt;dsig:Manifest/&gt; element will be stored in xmlSecDSigCtx.
 */
#define XMLSEC_DSIG_FLAGS_STORE_MANIFEST_REFERENCES             0x00000004

/**
 * @brief If set, pre-signature buffer for SignedInfo is stored in xmlSecDSigCtx.
 * @details If this flag is set then pre-signature buffer for &lt;dsig:SignedInfo/&gt;
 * element processing will be stored in xmlSecDSigCtx.
 */
#define XMLSEC_DSIG_FLAGS_STORE_SIGNATURE                       0x00000008

/**
 * @brief If set, resolve URI ID references without XPointers (Visa3D hack).
 * @details If this flag is set then URI ID references are resolved directly
 * without using XPointers. This allows one to sign/verify Visa3D
 * documents that don't follow XML, XPointer and XML DSig specifications.
 */
#define XMLSEC_DSIG_FLAGS_USE_VISA3D_HACK                       0x00000010


/**
 * @brief If set, use ASN1 encoded ECDSA signature values.
 * @details If this flag is set then ASN1 encoded ECDSA signature values will be
 * used (see https://github.com/lsh123/xmlsec/issues/995).
 */
#define XMLSEC_DSIG_FLAGS_USE_ASN1_SIGNATURE_VALUES             0x00000020

/**
 * @brief XML DSig processing context.
 */
struct _xmlSecDSigCtx {
    /* these data user can set before performing the operation */
    void*                       userData;  /**< the pointer to user data (xmlsec and xmlsec-crypto libraries never touches this). */
    unsigned int                flags;  /**< the XML Digital Signature processing flags. */
    unsigned int                flags2;  /**< the XML Digital Signature processing flags. */
    xmlSecKeyInfoCtx            keyInfoReadCtx;  /**< the reading key context. */
    xmlSecKeyInfoCtx            keyInfoWriteCtx;  /**< the writing key context (not used for signature verification). */
    xmlSecTransformCtx          transformCtx;  /**< the &lt;dsig:SignedInfo/&gt; node processing context. */
    xmlSecTransformUriType      enabledReferenceUris;  /**< the URI types allowed for &lt;dsig:Reference/&gt; node. */
    xmlSecPtrListPtr            enabledReferenceTransforms;  /**< the list of transforms allowed in &lt;dsig:Reference/&gt; node. */
    xmlSecTransformCtxPreExecuteCallback referencePreExecuteCallback;  /**< the callback for &lt;dsig:Reference/&gt; node processing. */
    xmlSecTransformId           defSignMethodId;  /**< the default signing method klass. */
    xmlSecTransformId           defC14NMethodId;  /**< the default c14n method klass. */
    xmlSecTransformId           defDigestMethodId;  /**< the default digest method klass. */

    /* these data are returned */
    xmlSecKeyPtr                signKey;  /**< the signature key; application may set #signKey before calling #xmlSecDSigCtxSign or #xmlSecDSigCtxVerify functions. */
    xmlSecTransformOperation    operation;  /**< the operation: sign or verify. */
    xmlSecBufferPtr             result;  /**< the pointer to signature (not valid for signature verification). */
    xmlSecDSigStatus            status;  /**< the &lt;dsig:Signature/&gt; processing status. */
    xmlSecDSigFailureReason     failureReason;  /**< the detailed failure reason (if known); the application should check @p status first. */
    xmlSecTransformPtr          signMethod;  /**< the pointer to signature transform. */
    xmlSecTransformPtr          c14nMethod;  /**< the pointer to c14n transform. */
    xmlSecTransformPtr          preSignMemBufMethod;  /**< the pointer to binary buffer right before signature (valid only if #XMLSEC_DSIG_FLAGS_STORE_SIGNATURE flag is set). */
    xmlNodePtr                  signValueNode;  /**< the pointer to &lt;dsig:SignatureValue/&gt; node. */
    xmlChar*                    id;  /**< the pointer to Id attribute of &lt;dsig:Signature/&gt; node. */
    xmlSecPtrList               signedInfoReferences;  /**< the list of references in &lt;dsig:SignedInfo/&gt; node. */
    xmlSecPtrList               manifestReferences;  /**< the list of references in &lt;dsig:Manifest/&gt; nodes. */

    /* reserved for future */
    void*                       reserved0;  /**< reserved for the future. */
    void*                       reserved1;  /**< reserved for the future. */
};

/* constructor/destructor */
XMLSEC_EXPORT xmlSecDSigCtxPtr  xmlSecDSigCtxCreate             (xmlSecKeysMngrPtr keysMngr);
XMLSEC_EXPORT void              xmlSecDSigCtxDestroy            (xmlSecDSigCtxPtr dsigCtx);
XMLSEC_EXPORT int               xmlSecDSigCtxInitialize         (xmlSecDSigCtxPtr dsigCtx,
                                                                 xmlSecKeysMngrPtr keysMngr);
XMLSEC_EXPORT void              xmlSecDSigCtxFinalize           (xmlSecDSigCtxPtr dsigCtx);
XMLSEC_EXPORT int               xmlSecDSigCtxSign               (xmlSecDSigCtxPtr dsigCtx,
                                                                 xmlNodePtr tmpl);
XMLSEC_EXPORT int               xmlSecDSigCtxVerify             (xmlSecDSigCtxPtr dsigCtx,
                                                                 xmlNodePtr node);
XMLSEC_EXPORT int               xmlSecDSigCtxEnableReferenceTransform(xmlSecDSigCtxPtr dsigCtx,
                                                                xmlSecTransformId transformId);
XMLSEC_EXPORT int               xmlSecDSigCtxEnableSignatureTransform(xmlSecDSigCtxPtr dsigCtx,
                                                                xmlSecTransformId transformId);
XMLSEC_EXPORT xmlSecBufferPtr   xmlSecDSigCtxGetPreSignBuffer   (xmlSecDSigCtxPtr dsigCtx);
XMLSEC_EXPORT void              xmlSecDSigCtxDebugDump          (xmlSecDSigCtxPtr dsigCtx,
                                                                 FILE* output);
XMLSEC_EXPORT void              xmlSecDSigCtxDebugXmlDump       (xmlSecDSigCtxPtr dsigCtx,
                                                                 FILE* output);


XMLSEC_EXPORT const char*       xmlSecDSigCtxGetStatusString    (xmlSecDSigStatus status);
XMLSEC_EXPORT const char*       xmlSecDSigCtxGetFailureReasonString(xmlSecDSigFailureReason failureReason);


/******************************************************************************
 *
 * xmlSecDSigReferenceCtx
 *
  *****************************************************************************/
/**
 * @brief The possible dsig:Reference node locations (SignedInfo or Manifest).
 * @details The possible &lt;dsig:Reference/&gt; node locations: in the &lt;dsig:SignedInfo/&gt;
 * node or in the &lt;dsig:Manifest/&gt; node.
 */
typedef enum  {
    xmlSecDSigReferenceOriginSignedInfo,  /**< reference in &lt;dsig:SignedInfo/&gt; node. */
    xmlSecDSigReferenceOriginManifest  /**< reference &lt;dsig:Manifest/&gt; node. */
} xmlSecDSigReferenceOrigin;

/**
 * @brief The dsig:Reference processing context.
 */
struct _xmlSecDSigReferenceCtx {
    void*                       userData;  /**< the pointer to user data (xmlsec and xmlsec-crypto libraries never touches this). */
    xmlSecDSigCtxPtr            dsigCtx;  /**< the pointer to "parent" &lt;dsig:Signature/&gt; processing context. */
    xmlSecDSigReferenceOrigin   origin;  /**< the signature origin (&lt;dsig:SignedInfo/&gt; or &lt;dsig:Manifest/&gt;). */
    xmlSecTransformCtx          transformCtx;  /**< the reference processing transforms context. */
    xmlSecTransformPtr          digestMethod;  /**< the pointer to digest transform. */

    xmlSecBufferPtr             result;  /**< the pointer to digest result. */
    xmlSecDSigStatus            status;  /**< the reference processing status. */
    xmlSecTransformPtr          preDigestMemBufMethod;  /**< the pointer to binary buffer right before digest (valid only if either #XMLSEC_DSIG_FLAGS_STORE_SIGNEDINFO_REFERENCES or #XMLSEC_DSIG_FLAGS_STORE_MANIFEST_REFERENCES flags are set). */
    xmlChar*                    id;  /**< the &lt;dsig:Reference/&gt; node ID attribute. */
    xmlChar*                    uri;  /**< the &lt;dsig:Reference/&gt; node URI attribute. */
    xmlChar*                    type;  /**< the &lt;dsig:Reference/&gt; node Type attribute. */

     /* reserved for future */
    void*                       reserved0;  /**< reserved for the future. */
    void*                       reserved1;  /**< reserved for the future. */
};

XMLSEC_EXPORT xmlSecDSigReferenceCtxPtr xmlSecDSigReferenceCtxCreate(xmlSecDSigCtxPtr dsigCtx,
                                                                xmlSecDSigReferenceOrigin origin);
XMLSEC_EXPORT void              xmlSecDSigReferenceCtxDestroy   (xmlSecDSigReferenceCtxPtr dsigRefCtx);
XMLSEC_EXPORT int               xmlSecDSigReferenceCtxInitialize(xmlSecDSigReferenceCtxPtr dsigRefCtx,
                                                                xmlSecDSigCtxPtr dsigCtx,
                                                                xmlSecDSigReferenceOrigin origin);
XMLSEC_EXPORT void              xmlSecDSigReferenceCtxFinalize  (xmlSecDSigReferenceCtxPtr dsigRefCtx);
XMLSEC_EXPORT int               xmlSecDSigReferenceCtxProcessNode(xmlSecDSigReferenceCtxPtr dsigRefCtx,
                                                                  xmlNodePtr node);
XMLSEC_EXPORT xmlSecBufferPtr   xmlSecDSigReferenceCtxGetPreDigestBuffer
                                                                (xmlSecDSigReferenceCtxPtr dsigRefCtx);
XMLSEC_EXPORT void              xmlSecDSigReferenceCtxDebugDump (xmlSecDSigReferenceCtxPtr dsigRefCtx,
                                                                 FILE* output);
XMLSEC_EXPORT void              xmlSecDSigReferenceCtxDebugXmlDump(xmlSecDSigReferenceCtxPtr dsigRefCtx,
                                                                 FILE* output);

/******************************************************************************
 *
 * xmlSecDSigReferenceCtxListKlass
 *
  *****************************************************************************/
/**
 * @brief The references list klass.
 */
#define xmlSecDSigReferenceCtxListId \
        xmlSecDSigReferenceCtxListGetKlass()
XMLSEC_EXPORT xmlSecPtrListId   xmlSecDSigReferenceCtxListGetKlass(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* XMLSEC_NO_XMLDSIG */

/** @} */ /** xmlsec_core_xmldsig */

#endif /* __XMLSEC_XMLDSIG_H__ */
