/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * The transforms engine
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_TRANSFORMS_H__
#define __XMLSEC_TRANSFORMS_H__

/**
 * @defgroup xmlsec_core_transforms Transforms Engine
 * @ingroup xmlsec_core
 * @brief Transforms engine — chaining, execution, and built-in transforms.
 * @{
 */

#include <stdint.h>

#include <libxml/tree.h>
#include <libxml/xpath.h>

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>
#include <xmlsec/list.h>
#include <xmlsec/nodeset.h>
#include <xmlsec/keys.h>

#ifndef XMLSEC_NO_XSLT
#include <libxslt/security.h>
#endif /* XMLSEC_NO_XSLT */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief The transform klass.
 */
typedef const struct _xmlSecTransformKlass              xmlSecTransformKlass;
/**
 * @brief Pointer to #xmlSecTransformKlass.
 */
typedef const struct _xmlSecTransformKlass              *xmlSecTransformId;

/******************************************************************************
 *
 * High-level functions
 *
  *****************************************************************************/
XMLSEC_EXPORT xmlSecPtrListPtr  xmlSecTransformIdsGet           (void);
XMLSEC_EXPORT int               xmlSecTransformIdsInit          (void);
XMLSEC_EXPORT void              xmlSecTransformIdsShutdown      (void);
XMLSEC_EXPORT int               xmlSecTransformIdsRegisterDefault(void);
XMLSEC_EXPORT int               xmlSecTransformIdsRegister      (xmlSecTransformId id);



/**
 * @brief The transform execution status.
 */
typedef enum  {
    xmlSecTransformStatusNone = 0,  /**< the status unknown. */
    xmlSecTransformStatusWorking,  /**< the transform is executed. */
    xmlSecTransformStatusFinished,  /**< the transform finished */
    xmlSecTransformStatusOk,  /**< the transform succeeded. */
    xmlSecTransformStatusFail  /**< the transform failed (an error occur). */
} xmlSecTransformStatus;

/**
 * @brief The transform operation mode.
 */
typedef enum  {
    xmlSecTransformModeNone = 0,  /**< the mode is unknown. */
    xmlSecTransformModePush,  /**< pushing data thru transform. */
    xmlSecTransformModePop  /**< popping data from transform. */
} xmlSecTransformMode;

/**
 * @brief The transform operation.
 */
typedef enum  {
    xmlSecTransformOperationNone = 0,  /**< the operation is unknown. */
    xmlSecTransformOperationEncode,  /**< the encode operation (for base64 transform). */
    xmlSecTransformOperationDecode,  /**< the decode operation (for base64 transform). */
    xmlSecTransformOperationSign,  /**< the sign or digest operation. */
    xmlSecTransformOperationVerify,  /**< the verification of signature or digest operation. */
    xmlSecTransformOperationEncrypt,  /**< the encryption operation. */
    xmlSecTransformOperationDecrypt  /**< the decryption operation. */
} xmlSecTransformOperation;

/******************************************************************************
 *
 * xmlSecTransformUriType:
 *
  *****************************************************************************/
/**
 * @brief URI transform type bit mask.
 */
typedef unsigned int                            xmlSecTransformUriType;

/**
 * @brief The URI type is unknown or not set.
 */
#define xmlSecTransformUriTypeNone              0x0000

/**
 * @brief The empty URI ("") type.
 */
#define xmlSecTransformUriTypeEmpty             0x0001

/**
 * @brief The same-document ("#...") non-empty URI type.
 * @details The same document ("#...") but not empty ("") URI type.
 */
#define xmlSecTransformUriTypeSameDocument      0x0002

/**
 * @brief The local URI ("file:///....") type.
 */
#define xmlSecTransformUriTypeLocal             0x0004

/**
 * @brief The remote URI type.
 */
#define xmlSecTransformUriTypeRemote            0x0008

/**
 * @brief Any URI type.
 */
#define xmlSecTransformUriTypeAny               0xFFFF

XMLSEC_EXPORT int                       xmlSecTransformUriTypeCheck     (xmlSecTransformUriType type,
                                                                         const xmlChar* uri);
/******************************************************************************
 *
 * xmlSecTransformDataType
 *
  *****************************************************************************/
/**
 * @brief Transform data type bit mask.
 */
typedef xmlSecByte                              xmlSecTransformDataType;

/**
 * @brief The transform data type is unknown.
 * @details The transform data type is unknown or nor data expected.
 */
#define xmlSecTransformDataTypeUnknown          0x0000

/**
 * @brief The binary transform data.
 */
#define xmlSecTransformDataTypeBin              0x0001

/**
 * @brief The xml transform data.
 */
#define xmlSecTransformDataTypeXml              0x0002

/******************************************************************************
 *
 * xmlSecTransformUsage
 *
  *****************************************************************************/
/**
 * @brief The transform usage bit mask.
 */
typedef unsigned int                            xmlSecTransformUsage;

/**
 * @brief Transforms usage is unknown or undefined.
 */
#define xmlSecTransformUsageUnknown             0x0000

/**
 * @brief Transform usable in dsig:Transform.
 * @details Transform could be used in &lt;dsig:Transform/&gt;.
 */
#define xmlSecTransformUsageDSigTransform       0x0001

/**
 * @brief Transform usable in dsig:CanonicalizationMethod.
 * @details Transform could be used in &lt;dsig:CanonicalizationMethod/&gt;.
 */
#define xmlSecTransformUsageC14NMethod          0x0002

/**
 * @brief Transform usable in dsig:DigestMethod.
 * @details Transform could be used in &lt;dsig:DigestMethod/&gt;.
 */
#define xmlSecTransformUsageDigestMethod        0x0004

/**
 * @brief Transform usable in dsig:SignatureMethod.
 * @details Transform could be used in &lt;dsig:SignatureMethod/&gt;.
 */
#define xmlSecTransformUsageSignatureMethod     0x0008

/**
 * @brief Transform usable in enc:EncryptionMethod.
 * @details Transform could be used in &lt;enc:EncryptionMethod/&gt;.
 */
#define xmlSecTransformUsageEncryptionMethod    0x0010

/**
 * @brief Transform usable in enc11:KeyDerivationMethod.
 * @details Transform could be used in &lt;enc11:KeyDerivationMethod/&gt;.
 */
#define xmlSecTransformUsageKeyDerivationMethod 0x0020

/**
 * @brief Transform usable in enc11:AgreementMethod.
 * @details Transform could be used in &lt;enc11:AgreementMethod/&gt;.
 */
#define xmlSecTransformUsageAgreementMethod 0x0040

/**
 * @brief Transform could be used for operation.
 */
#define xmlSecTransformUsageAny                 0xFFFF

/******************************************************************************
 *
 * xmlSecTransformCtx
 *
  *****************************************************************************/
/**
 * @brief Callback called before data processing to verify/modify transforms.
 * @details The callback called after creating transforms chain but before
 * starting data processing. Application can use this callback to
 * do additional transforms chain verification or modification and
 * aborting transforms execution (if necessary).
 * @param transformCtx the pointer to transform's context.
 * @return 0 on success and a negative value otherwise (in this case,
 * transforms chain will not be executed and xmlsec processing stops).
 */
typedef int             (*xmlSecTransformCtxPreExecuteCallback)         (xmlSecTransformCtxPtr transformCtx);

/**
 * @brief Resolve URI ID references without XPointers (Visa3D hack).
 * @details If this flag is set then URI ID references are resolved directly
 * without using XPointers. This allows one to sign/verify Visa3D
 * documents that don't follow XML, XPointer and XML DSig specifications.
 */
#define XMLSEC_TRANSFORMCTX_FLAGS_USE_VISA3D_HACK               0x00000001

/**
 * @brief Support ASN1 encoded ECDSA signature values.
 * @details If this flag is set then ASN1 encoded ECDSA signature values will be
 * used (see https://github.com/lsh123/xmlsec/issues/995).
 */
#define XMLSEC_TRANSFORMCTX_FLAGS_SUPPORT_ASN1_SIGNATURE_VALUES 0x00000002


/**
 * @brief The transform execution context.
 */
struct _xmlSecTransformCtx {
    /* user settings */
    void*                                       userData;  /**< the pointer to user data (xmlsec and xmlsec-crypto never touch this). */
    unsigned int                                flags;  /**< the bit mask flags to control transforms execution (reserved for the future). */
    unsigned int                                flags2;  /**< the bit mask flags to control transforms execution (reserved for the future). */
    xmlSecSize                                  binaryChunkSize;  /**< the chunk of size for binary transforms processing. */
    xmlSecTransformUriType                      enabledUris;  /**< the allowed transform data source uri types. */
    xmlSecPtrList                               enabledTransforms;  /**< the list of enabled transforms; if list is empty (default) then all registered transforms are enabled. */
    xmlSecTransformCtxPreExecuteCallback        preExecCallback;  /**< the callback called after preparing transform chain and right before actual data processing; application can use this callback to change transforms parameters, insert additional transforms in the chain or do additional validation (and abort transform execution if needed). */

    /* used by Key Agreement transforms */
    xmlSecKeyInfoCtxPtr                         parentKeyInfoCtx;  /**< the parent's key info ctx for key agreement. */

    /* results */
    xmlSecBufferPtr                             result;  /**< the pointer to transforms result buffer. */
    xmlSecTransformStatus                       status;  /**< the transforms chain processing status. */
    xmlChar*                                    uri;  /**< the data source URI without xpointer expression. */
    xmlChar*                                    xptrExpr;  /**< the xpointer expression from data source URI (if any). */
    xmlSecTransformPtr                          first;  /**< the first transform in the chain. */
    xmlSecTransformPtr                          last;  /**< the last transform in the chain. */

    /* for the future */
    void*                                       reserved0;  /**< reserved for the future. */
    void*                                       reserved1;  /**< reserved for the future. */
};

XMLSEC_EXPORT xmlSecTransformCtxPtr     xmlSecTransformCtxCreate        (void);
XMLSEC_EXPORT void                      xmlSecTransformCtxDestroy       (xmlSecTransformCtxPtr ctx);
XMLSEC_EXPORT int                       xmlSecTransformCtxInitialize    (xmlSecTransformCtxPtr ctx);
XMLSEC_EXPORT void                      xmlSecTransformCtxFinalize      (xmlSecTransformCtxPtr ctx);
XMLSEC_EXPORT void                      xmlSecTransformCtxReset         (xmlSecTransformCtxPtr ctx);
XMLSEC_EXPORT int                       xmlSecTransformCtxCopyUserPref  (xmlSecTransformCtxPtr dst,
                                                                         xmlSecTransformCtxPtr src);
XMLSEC_EXPORT int                       xmlSecTransformCtxSetUri        (xmlSecTransformCtxPtr ctx,
                                                                         const xmlChar* uri,
                                                                         xmlNodePtr hereNode);
XMLSEC_EXPORT int                       xmlSecTransformCtxAppend        (xmlSecTransformCtxPtr ctx,
                                                                         xmlSecTransformPtr transform);
XMLSEC_EXPORT int                       xmlSecTransformCtxPrepend       (xmlSecTransformCtxPtr ctx,
                                                                         xmlSecTransformPtr transform);
XMLSEC_EXPORT xmlSecTransformPtr        xmlSecTransformCtxCreateAndAppend(xmlSecTransformCtxPtr ctx,
                                                                         xmlSecTransformId id);
XMLSEC_EXPORT xmlSecTransformPtr        xmlSecTransformCtxCreateAndPrepend(xmlSecTransformCtxPtr ctx,
                                                                         xmlSecTransformId id);
XMLSEC_EXPORT xmlSecTransformPtr        xmlSecTransformCtxNodeRead      (xmlSecTransformCtxPtr ctx,
                                                                         xmlNodePtr node,
                                                                         xmlSecTransformUsage usage);
XMLSEC_EXPORT int                       xmlSecTransformCtxNodesListRead (xmlSecTransformCtxPtr ctx,
                                                                         xmlNodePtr node,
                                                                         xmlSecTransformUsage usage);
XMLSEC_EXPORT int                       xmlSecTransformCtxPrepare       (xmlSecTransformCtxPtr ctx,
                                                                         xmlSecTransformDataType inputDataType);
XMLSEC_EXPORT int                       xmlSecTransformCtxBinaryExecute (xmlSecTransformCtxPtr ctx,
                                                                         const xmlSecByte* data,
                                                                         xmlSecSize dataSize);
XMLSEC_EXPORT int                       xmlSecTransformCtxUriExecute    (xmlSecTransformCtxPtr ctx,
                                                                         const xmlChar* uri);
XMLSEC_EXPORT int                       xmlSecTransformCtxXmlExecute    (xmlSecTransformCtxPtr ctx,
                                                                         xmlSecNodeSetPtr nodes);
XMLSEC_EXPORT int                       xmlSecTransformCtxExecute       (xmlSecTransformCtxPtr ctx,
                                                                         xmlDocPtr doc);
XMLSEC_EXPORT void                      xmlSecTransformCtxDebugDump     (xmlSecTransformCtxPtr ctx,
                                                                        FILE* output);
XMLSEC_EXPORT void                      xmlSecTransformCtxDebugXmlDump  (xmlSecTransformCtxPtr ctx,
                                                                         FILE* output);


XMLSEC_EXPORT xmlSecSize                xmlSecTransformCtxGetDefaultBinaryChunkSize(void);
XMLSEC_EXPORT void                      xmlSecTransformCtxSetDefaultBinaryChunkSize(xmlSecSize binaryChunkSize);


/**
 * @brief Transform was specified in the XML file.
 * @details If this flag is set then this transform was specified in the XML file
 * (vs a transform added by the XMLSec library).
 */
#define XMLSEC_TRANSFORM_FLAGS_USER_SPECIFIED               0x00000001


/******************************************************************************
 *
 * xmlSecTransform
 *
  *****************************************************************************/
/**
 * @brief The transform structure.
 */
struct _xmlSecTransform {
    xmlSecTransformId                   id;  /**< the transform id (pointer to #xmlSecTransformId). */
    xmlSecTransformOperation            operation;  /**< the transform's operation. */
    xmlSecTransformStatus               status;  /**< the current status. */
    xmlNodePtr                          hereNode;  /**< the pointer to transform's <dsig:Transform /> node. */

    /* transforms chain */
    xmlSecTransformPtr                  next;  /**< the pointer to next transform in the chain. */
    xmlSecTransformPtr                  prev;  /**< the pointer to previous transform in the chain. */

    /* binary data */
    xmlSecBuffer                        inBuf;  /**< the input binary data buffer. */
    xmlSecBuffer                        outBuf;  /**< the output binary data buffer. */

    /* xml data */
    xmlSecNodeSetPtr                    inNodes;  /**< the input XML nodes. */
    xmlSecNodeSetPtr                    outNodes;  /**< the output XML nodes. */

    /* used for some transform (e.g. KDF) to determine the desired output size */
    xmlSecSize                          expectedOutputSize;  /**< the expected transform output size (used for key wraps). */

    /* transform flags (use uintptr_t to insure struct size stays the same) )*/
    uintptr_t                           flags;  /**< the transform flags (eg user specified vs inserted by XMLSec). */

    /* reserved for the future */
    void*                               reserved0;  /**< reserved for the future. */
};

XMLSEC_EXPORT xmlSecTransformPtr        xmlSecTransformCreate   (xmlSecTransformId id);
XMLSEC_EXPORT void                      xmlSecTransformDestroy  (xmlSecTransformPtr transform);
XMLSEC_EXPORT xmlSecTransformPtr        xmlSecTransformNodeRead (xmlNodePtr node,
                                                                 xmlSecTransformUsage usage,
                                                                 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT int                       xmlSecTransformPump     (xmlSecTransformPtr left,
                                                                 xmlSecTransformPtr right,
                                                                 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT int                       xmlSecTransformSetKey   (xmlSecTransformPtr transform,
                                                                 xmlSecKeyPtr key);
XMLSEC_EXPORT int                       xmlSecTransformSetKeyReq(xmlSecTransformPtr transform,
                                                                 xmlSecKeyReqPtr keyReq);
XMLSEC_EXPORT int                       xmlSecTransformVerify   (xmlSecTransformPtr transform,
                                                                 const xmlSecByte* data,
                                                                 xmlSecSize dataSize,
                                                                 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT int                       xmlSecTransformVerifyNodeContent(xmlSecTransformPtr transform,
                                                                 xmlNodePtr node,
                                                                 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT xmlSecTransformDataType   xmlSecTransformGetDataType(xmlSecTransformPtr transform,
                                                                 xmlSecTransformMode mode,
                                                                 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT int                       xmlSecTransformPushBin  (xmlSecTransformPtr transform,
                                                                 const xmlSecByte* data,
                                                                 xmlSecSize dataSize,
                                                                 int final,
                                                                 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT int                       xmlSecTransformPopBin   (xmlSecTransformPtr transform,
                                                                 xmlSecByte* data,
                                                                 xmlSecSize maxDataSize,
                                                                 xmlSecSize* dataSize,
                                                                 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT int                       xmlSecTransformPushXml  (xmlSecTransformPtr transform,
                                                                 xmlSecNodeSetPtr nodes,
                                                                 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT int                       xmlSecTransformPopXml   (xmlSecTransformPtr transform,
                                                                 xmlSecNodeSetPtr* nodes,
                                                                 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT int                       xmlSecTransformExecute  (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT void                      xmlSecTransformDebugDump(xmlSecTransformPtr transform,
                                                                 FILE* output);
XMLSEC_EXPORT void                      xmlSecTransformDebugXmlDump(xmlSecTransformPtr transform,
                                                                 FILE* output);
/**
 * @brief Macro. Returns transform name.
 * @param transform the pointer to transform.
 */
#define xmlSecTransformGetName(transform) \
        ((xmlSecTransformIsValid((transform))) ? \
          xmlSecTransformKlassGetName((transform)->id) : NULL)

/**
 * @brief Macro. Returns 1 if @p transform is valid.
 * @details Macro. Returns 1 if the @p transform is valid or 0 otherwise.
 * @param transform the pointer to transform.
 */
#define xmlSecTransformIsValid(transform) \
        ((( transform ) != NULL) && \
         (( transform )->id != NULL) && \
         (( transform )->id->klassSize >= sizeof(xmlSecTransformKlass)) && \
         (( transform )->id->objSize >= sizeof(xmlSecTransform)) && \
         (( transform )->id->name != NULL))

/**
 * @brief Macro. Returns 1 if @p transform has id @p i.
 * @details Macro. Returns 1 if the @p transform is valid and has specified id @p i
 * or 0 otherwise.
 * @param transform the pointer to transform.
 * @param i the transform id.
 */
#define xmlSecTransformCheckId(transform, i) \
        (xmlSecTransformIsValid(( transform )) && \
        ((((const xmlSecTransformId) (( transform )->id))) == ( i )))

/**
 * @brief Macro. Returns 1 if @p transform has at least @p size bytes.
 * @details Macro. Returns 1 if the @p transform is valid and has at least @p size
 * bytes or 0 otherwise.
 * @param transform the pointer to transform.
 * @param size the transform object size.
 */
#define xmlSecTransformCheckSize(transform, size) \
        (xmlSecTransformIsValid(( transform )) && \
        ((( transform )->id->objSize) >= ( size )))


/******************************************************************************
 *
 * Operations on transforms chain
 *
  *****************************************************************************/
XMLSEC_EXPORT int                       xmlSecTransformConnect  (xmlSecTransformPtr left,
                                                                 xmlSecTransformPtr right,
                                                                 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT void                      xmlSecTransformRemove   (xmlSecTransformPtr transform);

/******************************************************************************
 *
 * Default callbacks, most of the transforms can use them
 *
  *****************************************************************************/
XMLSEC_EXPORT xmlSecTransformDataType   xmlSecTransformDefaultGetDataType(xmlSecTransformPtr transform,
                                                                 xmlSecTransformMode mode,
                                                                 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT int                       xmlSecTransformDefaultPushBin(xmlSecTransformPtr transform,
                                                                 const xmlSecByte* data,
                                                                 xmlSecSize dataSize,
                                                                 int final,
                                                                 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT int                       xmlSecTransformDefaultPopBin(xmlSecTransformPtr transform,
                                                                 xmlSecByte* data,
                                                                 xmlSecSize maxDataSize,
                                                                 xmlSecSize* dataSize,
                                                                 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT int                       xmlSecTransformDefaultPushXml(xmlSecTransformPtr transform,
                                                                 xmlSecNodeSetPtr nodes,
                                                                 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT int                       xmlSecTransformDefaultPopXml(xmlSecTransformPtr transform,
                                                                 xmlSecNodeSetPtr* nodes,
                                                                 xmlSecTransformCtxPtr transformCtx);

/******************************************************************************
 *
 * IO buffers for transforms
 *
  *****************************************************************************/
XMLSEC_EXPORT xmlOutputBufferPtr        xmlSecTransformCreateOutputBuffer(xmlSecTransformPtr transform,
                                                                 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT xmlParserInputBufferPtr   xmlSecTransformCreateInputBuffer(xmlSecTransformPtr transform,
                                                                 xmlSecTransformCtxPtr transformCtx);

/******************************************************************************
 *
 * Transform Klass
 *
  *****************************************************************************/
/**
 * @brief The transform specific initialization method.
 * @param transform the pointer to transform object.
 * @return 0 on success or a negative value otherwise.
 */
typedef int             (*xmlSecTransformInitializeMethod)      (xmlSecTransformPtr transform);

/**
 * @brief The transform specific destroy method.
 * @param transform the pointer to transform object.
 */
typedef void            (*xmlSecTransformFinalizeMethod)        (xmlSecTransformPtr transform);

/**
 * @brief The transform specific method to query data type in a mode.
 * @details The transform specific method to query information about transform
 * data type in specified mode @p mode.
 * @param transform the pointer to transform object.
 * @param mode the mode.
 * @param transformCtx the pointer to transform context object.
 * @return transform data type.
 */
typedef xmlSecTransformDataType (*xmlSecTransformGetDataTypeMethod)(xmlSecTransformPtr transform,
                                                                 xmlSecTransformMode mode,
                                                                 xmlSecTransformCtxPtr transformCtx);

/**
 * @brief The transform specific method to read data from XML node.
 * @details The transform specific method to read the transform data from
 * the @p node.
 * @param transform the pointer to transform object.
 * @param node the pointer to &lt;dsig:Transform/&gt; node.
 * @param transformCtx the pointer to transform context object.
 * @return 0 on success or a negative value otherwise.
 */
typedef int             (*xmlSecTransformNodeReadMethod)        (xmlSecTransformPtr transform,
                                                                 xmlNodePtr node,
                                                                 xmlSecTransformCtxPtr transformCtx);

/**
 * @brief The transform specific method to write transform info to XML.
 * @details The transform specific method to write transform information to an XML node @p node.
 * @param transform the pointer to transform object.
 * @param node the pointer to &lt;dsig:Transform/&gt; node.
 * @param transformCtx the pointer to transform context object.
 * @return 0 on success or a negative value otherwise.
 */
typedef int             (*xmlSecTransformNodeWriteMethod)       (xmlSecTransformPtr transform,
                                                                 xmlNodePtr node,
                                                                 xmlSecTransformCtxPtr transformCtx);

/**
 * @brief Transform specific method to set key requirements.
 * @details Transform specific method to set transform's key requirements.
 * @param transform the pointer to transform object.
 * @param keyReq the pointer to key requirements structure.
 * @return 0 on success or a negative value otherwise.
 */
typedef int             (*xmlSecTransformSetKeyRequirementsMethod)(xmlSecTransformPtr transform,
                                                                 xmlSecKeyReqPtr keyReq);

/**
 * @brief The transform specific method to set the key.
 * @details The transform specific method to set the key for use.
 * @param transform the pointer to transform object.
 * @param key the pointer to key.
 * @return 0 on success or a negative value otherwise.
 */
typedef int             (*xmlSecTransformSetKeyMethod)          (xmlSecTransformPtr transform,
                                                                 xmlSecKeyPtr key);

/**
 * @brief The transform specific method to verify processing results.
 * @details The transform specific method to verify transform processing results
 * (used by digest and signature transforms). This method sets @p status
 * member of the xmlSecTransform structure to either #xmlSecTransformStatusOk
 * if verification succeeded or #xmlSecTransformStatusFail otherwise.
 * @param transform the pointer to transform object.
 * @param data the input buffer.
 * @param dataSize the size of input buffer @p data.
 * @param transformCtx the pointer to transform context object.
 * @return 0 on success or a negative value otherwise.
 */
typedef int             (*xmlSecTransformVerifyMethod)          (xmlSecTransformPtr transform,
                                                                 const xmlSecByte* data,
                                                                 xmlSecSize dataSize,
                                                                 xmlSecTransformCtxPtr transformCtx);
/**
 * @brief The transform specific method to push binary data down the chain.
 * @details The transform specific method to process data from @p data and push
 * result to the next transform in the chain.
 * @param transform the pointer to transform object.
 * @param data the input binary data,
 * @param dataSize the input data size.
 * @param final the flag: if set to 1 then it's the last
 *                              data chunk.
 * @param transformCtx the pointer to transform context object.
 * @return 0 on success or a negative value otherwise.
 */
typedef int             (*xmlSecTransformPushBinMethod)         (xmlSecTransformPtr transform,
                                                                 const xmlSecByte* data,
                                                                 xmlSecSize dataSize,
                                                                 int final,
                                                                 xmlSecTransformCtxPtr transformCtx);
/**
 * @brief The transform specific method to pop binary data from the chain.
 * @details The transform specific method to pop data from previous transform
 * in the chain and return result in the @p data buffer. The size of returned
 * data is placed in the @p dataSize.
 * @param transform the pointer to transform object.
 * @param data the buffer to store result data.
 * @param maxDataSize the size of the buffer @p data.
 * @param dataSize the pointer to returned data size.
 * @param transformCtx the pointer to transform context object.
 * @return 0 on success or a negative value otherwise.
 */
typedef int             (*xmlSecTransformPopBinMethod)          (xmlSecTransformPtr transform,
                                                                 xmlSecByte* data,
                                                                 xmlSecSize maxDataSize,
                                                                 xmlSecSize* dataSize,
                                                                 xmlSecTransformCtxPtr transformCtx);
/**
 * @brief The transform specific method to push XML nodes down the chain.
 * @details The transform specific method to process @p nodes and push result to the next
 * transform in the chain.
 * @param transform the pointer to transform object.
 * @param nodes the input nodes.
 * @param transformCtx the pointer to transform context object.
 * @return 0 on success or a negative value otherwise.
 */
typedef int             (*xmlSecTransformPushXmlMethod)         (xmlSecTransformPtr transform,
                                                                 xmlSecNodeSetPtr nodes,
                                                                 xmlSecTransformCtxPtr transformCtx);
/**
 * @brief The transform specific method to pop XML nodes from the chain.
 * @details The transform specific method to pop data from previous transform in the chain,
 * process the data and return result in @p nodes.
 * @param transform the pointer to transform object.
 * @param nodes the pointer to store popinter to result nodes.
 * @param transformCtx the pointer to transform context object.
 * @return 0 on success or a negative value otherwise.
 */
typedef int             (*xmlSecTransformPopXmlMethod)          (xmlSecTransformPtr transform,
                                                                 xmlSecNodeSetPtr* nodes,
                                                                 xmlSecTransformCtxPtr transformCtx);
/**
 * @brief Transform specific data processing method.
 * @details Transform specific method to process a chunk of data.
 * @param transform the pointer to transform object.
 * @param last the flag: if set to 1 then it's the last data chunk.
 * @param transformCtx the pointer to transform context object.
 * @return 0 on success or a negative value otherwise.
 */
typedef int             (*xmlSecTransformExecuteMethod)         (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);

/**
 * @brief The transform klass description structure.
 */
struct _xmlSecTransformKlass {
    /* data */
    xmlSecSize                          klassSize;  /**< the transform klass structure size. */
    xmlSecSize                          objSize;  /**< the transform object size. */
    const xmlChar*                      name;  /**< the transform's name. */
    const xmlChar*                      href;  /**< the transform's identification string (href). */
    xmlSecTransformUsage                usage;  /**< the allowed transforms usages. */

    /* methods */
    xmlSecTransformInitializeMethod     initialize;  /**< the initialization method. */
    xmlSecTransformFinalizeMethod       finalize;  /**< the finalization (destroy) function. */

    xmlSecTransformNodeReadMethod       readNode;  /**< the XML node read method. */
    xmlSecTransformNodeWriteMethod      writeNode;  /**< the XML node write method. */

    xmlSecTransformSetKeyRequirementsMethod     setKeyReq;  /**< the set key requirements method. */
    xmlSecTransformSetKeyMethod         setKey;  /**< the set key method. */
    xmlSecTransformVerifyMethod         verify;  /**< the verify method (for digest and signature transforms). */
    xmlSecTransformGetDataTypeMethod    getDataType;  /**< the input/output data type query method. */

    xmlSecTransformPushBinMethod        pushBin;  /**< the binary data "push thru chain" processing method. */
    xmlSecTransformPopBinMethod         popBin;  /**< the binary data "pop from chain" procesing method. */
    xmlSecTransformPushXmlMethod        pushXml;  /**< the XML data "push thru chain" processing method. */
    xmlSecTransformPopXmlMethod         popXml;  /**< the XML data "pop from chain" procesing method. */

    /* low level method */
    xmlSecTransformExecuteMethod        execute;  /**< the low level data processing method used  by default implementations of #pushBin, #popBin, #pushXml and #popXml. */

    /* reserved for future */
    void*                               reserved0;  /**< reserved for the future. */
    void*                               reserved1;  /**< reserved for the future. */
};

/**
 * @brief Macro. Returns transform klass name.
 * @param klass the transform's klass.
 */
#define xmlSecTransformKlassGetName(klass) \
        (((klass)) ? ((klass)->name) : NULL)

/******************************************************************************
 *
 * Transform Ids list
 *
  *****************************************************************************/
/**
 * @brief Transform klasses list klass.
 */
#define xmlSecTransformIdListId xmlSecTransformIdListGetKlass()
XMLSEC_EXPORT xmlSecPtrListId   xmlSecTransformIdListGetKlass   (void);
XMLSEC_EXPORT int               xmlSecTransformIdListFind       (xmlSecPtrListPtr list,
                                                                 xmlSecTransformId transformId);
XMLSEC_EXPORT xmlSecTransformId xmlSecTransformIdListFindByHref (xmlSecPtrListPtr list,
                                                                 const xmlChar* href,
                                                                 xmlSecTransformUsage usage);
XMLSEC_EXPORT xmlSecTransformId xmlSecTransformIdListFindByName (xmlSecPtrListPtr list,
                                                                 const xmlChar* name,
                                                                 xmlSecTransformUsage usage);
XMLSEC_EXPORT void              xmlSecTransformIdListDebugDump  (xmlSecPtrListPtr list,
                                                                 FILE* output);
XMLSEC_EXPORT void              xmlSecTransformIdListDebugXmlDump(xmlSecPtrListPtr list,
                                                                 FILE* output);


/******************************************************************************
 *
 * XML Sec Library Transform Ids
 *
  *****************************************************************************/
/**
 * @brief The "unknown" transform id (NULL).
 */
#define xmlSecTransformIdUnknown                        ((xmlSecTransformId)NULL)

/**
 * @brief The base64 encode transform klass.
 */
#define xmlSecTransformBase64Id \
        xmlSecTransformBase64GetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecTransformBase64GetKlass           (void);
XMLSEC_EXPORT void              xmlSecTransformBase64SetLineSize        (xmlSecTransformPtr transform,
                                                                         xmlSecSize lineSize);
/**
 * @brief The inclusive C14N without comments transform klass.
 * @details The regular (inclusive) C14N without comments transform klass.
 */
#define xmlSecTransformInclC14NId \
        xmlSecTransformInclC14NGetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecTransformInclC14NGetKlass         (void);

/**
 * @brief The inclusive C14N with comments transform klass.
 * @details The regular (inclusive) C14N with comments transform klass.
 */
#define xmlSecTransformInclC14NWithCommentsId \
        xmlSecTransformInclC14NWithCommentsGetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecTransformInclC14NWithCommentsGetKlass(void);

/**
 * @brief The inclusive C14N 1.1 without comments transform klass.
 * @details The regular (inclusive) C14N 1.1 without comments transform klass.
 */
#define xmlSecTransformInclC14N11Id \
        xmlSecTransformInclC14N11GetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecTransformInclC14N11GetKlass       (void);

/**
 * @brief The inclusive C14N 1.1 with comments transform klass.
 * @details The regular (inclusive) C14N 1.1 with comments transform klass.
 */
#define xmlSecTransformInclC14N11WithCommentsId \
        xmlSecTransformInclC14N11WithCommentsGetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecTransformInclC14N11WithCommentsGetKlass(void);

/**
 * @brief The exclusive C14N without comments transform.
 * @details The exclusive C14N without comments transform klass.
 */
#define xmlSecTransformExclC14NId \
        xmlSecTransformExclC14NGetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecTransformExclC14NGetKlass         (void);

/**
 * @brief The exclusive C14N with comments transform klass.
 */
#define xmlSecTransformExclC14NWithCommentsId \
        xmlSecTransformExclC14NWithCommentsGetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecTransformExclC14NWithCommentsGetKlass(void);

/**
 * @brief The "enveloped" transform klass.
 */
#define xmlSecTransformEnvelopedId \
        xmlSecTransformEnvelopedGetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecTransformEnvelopedGetKlass        (void);

/**
 * @brief The XPath transform klass.
 */
#define xmlSecTransformXPathId \
        xmlSecTransformXPathGetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecTransformXPathGetKlass            (void);

/**
 * @brief The XPath2 transform klass.
 */
#define xmlSecTransformXPath2Id \
        xmlSecTransformXPath2GetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecTransformXPath2GetKlass           (void);

/**
 * @brief The XPointer transform klass.
 */
#define xmlSecTransformXPointerId \
        xmlSecTransformXPointerGetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecTransformXPointerGetKlass         (void);
XMLSEC_EXPORT int               xmlSecTransformXPointerSetExpr          (xmlSecTransformPtr transform,
                                                                         const xmlChar* expr,
                                                                         xmlSecNodeSetType nodeSetType,
                                                                         xmlNodePtr hereNode);
/**
 * @brief The Relationship transform klass.
 */
#define xmlSecTransformRelationshipId \
        xmlSecTransformRelationshipGetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecTransformRelationshipGetKlass     (void);

#ifndef XMLSEC_NO_XSLT

/**
 * @brief The XSLT transform klass.
 */
#define xmlSecTransformXsltId \
        xmlSecTransformXsltGetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecTransformXsltGetKlass             (void);
XMLSEC_EXPORT void              xmlSecTransformXsltSetDefaultSecurityPrefs(xsltSecurityPrefsPtr sec);
#endif /* XMLSEC_NO_XSLT */

/**
 * @brief The 'remove all xml tags' transform klass.
 * @details The "remove all xml tags" transform klass (used before base64 transforms).
 */
#define xmlSecTransformRemoveXmlTagsC14NId \
        xmlSecTransformRemoveXmlTagsC14NGetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecTransformRemoveXmlTagsC14NGetKlass(void);

/**
 * @brief Selects node subtree by node id string (Visa3D hack).
 * @details Selects node subtree by given node id string. The only reason why we need this
 * is Visa3D protocol. It doesn't follow XML/XPointer/XMLDSig specs and allows
 * invalid XPointer expressions in the URI attribute. Since we couldn't evaluate
 * such expressions thru XPath/XPointer engine, we need to have this hack here.
 */
#define xmlSecTransformVisa3DHackId \
        xmlSecTransformVisa3DHackGetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecTransformVisa3DHackGetKlass       (void);
XMLSEC_EXPORT int               xmlSecTransformVisa3DHackSetID          (xmlSecTransformPtr transform,
                                                                         const xmlChar* id);



/******************************************************************************
 *
 * Helper transform functions
 *
  *****************************************************************************/

#ifndef XMLSEC_NO_HMAC
XMLSEC_EXPORT xmlSecSize        xmlSecTransformHmacGetMinOutputBitsSize(void);
XMLSEC_EXPORT void              xmlSecTransformHmacSetMinOutputBitsSize(xmlSecSize val);
#endif /* XMLSEC_NO_HMAC */

#ifdef __cplusplus
}
#endif /* __cplusplus */

/** @} */ /** xmlsec_core_transforms */

#endif /* __XMLSEC_TRANSFORMS_H__ */
