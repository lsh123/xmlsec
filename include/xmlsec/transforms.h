/** 
 * XMLSec library
 *
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_TRANSFORMS_H__
#define __XMLSEC_TRANSFORMS_H__    



#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>
#include <libxml/xpath.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/nodeset.h>


#define XMLSEC_TRANSFORM_BINARY_CHUNK			64
#define XMLSEC_TRANSFORM_BUFFER_SIZE			64	/* should be greater than XMLSEC_TRANSFORM_MIN_BLOCK_SIZE */

typedef const struct _xmlSecTransformKlass		xmlSecTransformKlass, *xmlSecTransformId;
typedef struct _xmlSecTransform 			xmlSecTransform, *xmlSecTransformPtr; 
typedef struct _xmlSecTransformCtx 			xmlSecTransformCtx, *xmlSecTransformCtxPtr; 



/******************************************************************** 
 *
 * Base64 Transform
 *
 *******************************************************************/
#define XMLSEC_BASE64_LINESIZE			64
/**
 * XMLSEC_BASE64_LINESIZE:
 *
 * The default max line size for base64 encoding
 */ 
#define xmlSecTransformBase64Id \
	xmlSecTransformBase64GetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecTransformBase64GetKlass		(void);
XMLSEC_EXPORT     void xmlSecTransformBase64SetLineSize			(xmlSecTransformPtr transform,
									 size_t lineSize);


/********************************************************************
 *
 * Memory Buffer transform 
 *
 *******************************************************************/
/**
 * xmlSecTransformMemBufId:
 * 
 * The XSLT transform id.
 */
#define xmlSecTransformMemBufId \
	xmlSecTransformMemBufGetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecTransformMemBufGetKlass		(void);
XMLSEC_EXPORT xmlSecBufferPtr	xmlSecTransformMemBufGetBuffer		(xmlSecTransformPtr transform, 
									 int removeBuffer);

/********************************************************************
 *
 * XSLT transform 
 *
 *******************************************************************/
#ifndef XMLSEC_NO_XSLT
/**
 * xmlSecTransformXsltId:
 * 
 * The XSLT transform id.
 */
#define xmlSecTransformXsltId \
	xmlSecTransformXsltGetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecTransformXsltGetKlass		(void);
#endif /* XMLSEC_NO_XSLT */

/**************************************************************************
 *
 * xmlSecTransformStatus
 *
 *************************************************************************/
/**
 * xmlSecTransformStatus:
 * @xmlSecTransformStatusNone: the status unknown.
 * @xmlSecTransformStatusOk: success.
 * @xmlSecTransformStatusFail: an error occur.
 *
 * The transform execution result.
 */
typedef enum  {
    xmlSecTransformStatusNone = 0,
    xmlSecTransformStatusWorking,
    xmlSecTransformStatusFinished,
    xmlSecTransformStatusOk,
    xmlSecTransformStatusFail
} xmlSecTransformStatus;

#define xmlSecTransformStatusIsDone(status) \
    (((status) != xmlSecTransformStatusNone) && \
     ((status) != xmlSecTransformStatusWorking))

/**************************************************************************
 *
 * xmlSecTransformCtx
 *
 *************************************************************************/
/**
 * xmlSecTransformCtx:
 *
 * The transform context.
 */
struct _xmlSecTransformCtx {
    int 	something;
};

/**************************************************************************
 *
 * xmlSecTransform
 *
 *************************************************************************/
/**
 * xmlSecTransform:
 * @id: the transform id (pointer to #xmlSecTransformId).
 * @status: the transform status (ok/fail/unknown).
 * @dontDestroy: the don't automatically destroy flag.
 * @data: the pointer to transform specific data.
 *
 * The transform structure.
 */
struct _xmlSecTransform {
    /* general data */
    xmlSecTransformId 			id; 
    xmlSecTransformStatus		status;
    int					dontDestroy;

    /* binary specific */
    int					encode;
    xmlSecTransformPtr			next;
    xmlSecTransformPtr			prev;
    
    /* xml specific */
    xmlNodePtr				hereNode;

    xmlSecBuffer			inBuf;
    xmlSecBuffer			outBuf;
        
    unsigned char			binBuf[XMLSEC_TRANSFORM_BUFFER_SIZE];
    size_t				binBufSize;
    size_t				processed;
        
    void*				reserved0;
    void*				reserved1;
    void*				reserved2;
    void*				reserved3;
    int					reserved4;
    int					reserved5;
};

XMLSEC_EXPORT xmlSecTransformPtr	xmlSecTransformCreate	(xmlSecTransformId id,
								 int dontDestroy);
XMLSEC_EXPORT void			xmlSecTransformDestroy	(xmlSecTransformPtr transform,
								 int forceDestroy);
XMLSEC_EXPORT int 			xmlSecTransformRead	(xmlSecTransformPtr transform,
								 xmlNodePtr node);
XMLSEC_EXPORT int  			xmlSecTransformSetKey	(xmlSecTransformPtr transform, 
								 xmlSecKeyPtr key);
XMLSEC_EXPORT int  			xmlSecTransformSetKeyReq(xmlSecTransformPtr transform, 
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_EXPORT int  			xmlSecTransformVerify	(xmlSecTransformPtr transform, 
								 const unsigned char* data,
								 size_t dataSize,
								 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT int  			xmlSecTransformExecute	(xmlSecTransformPtr transform, 
								 int last,
								 xmlSecTransformCtxPtr transformCtx);



XMLSEC_EXPORT int			xmlSecTransformReadBin	(xmlSecTransformPtr transform,
								 unsigned char *buf,
								 size_t size);		
XMLSEC_EXPORT int			xmlSecTransformWriteBin	(xmlSecTransformPtr transform,
								 const unsigned char *buf,
								 size_t size);		
XMLSEC_EXPORT int			xmlSecTransformFlushBin	(xmlSecTransformPtr transform);
XMLSEC_EXPORT int 			xmlSecTransformExecuteXml(xmlSecTransformPtr transform,
								  xmlDocPtr ctxDoc,
								  xmlDocPtr *doc,
								  xmlSecNodeSetPtr *nodes);
XMLSEC_EXPORT int 			xmlSecTransformExecuteC14N(xmlSecTransformPtr transform,
								 xmlDocPtr doc,
								 xmlSecNodeSetPtr nodes,
								 xmlOutputBufferPtr buffer);



XMLSEC_EXPORT void			xmlSecTransformDestroyAll(xmlSecTransformPtr transform);	
XMLSEC_EXPORT xmlSecTransformPtr	xmlSecTransformAddAfter	(xmlSecTransformPtr curTransform,
								 xmlSecTransformPtr newTransform);
XMLSEC_EXPORT xmlSecTransformPtr	xmlSecTransformAddBefore(xmlSecTransformPtr curTransform,
								 xmlSecTransformPtr newTransform);
XMLSEC_EXPORT void			xmlSecTransformRemove	(xmlSecTransformPtr transform);



XMLSEC_EXPORT int			xmlSecTransformDefault2ReadBin	(xmlSecTransformPtr transform,
								 unsigned char *buf,
								 size_t size);		
XMLSEC_EXPORT int			xmlSecTransformDefault2WriteBin	(xmlSecTransformPtr transform,
								 const unsigned char *buf,
								 size_t size);		
XMLSEC_EXPORT int			xmlSecTransformDefault2FlushBin	(xmlSecTransformPtr transform);

/**
 * xmlSecTransformIsValid:
 * @transform: the pointer to transform.
 *
 * Macro. Returns 1 if the @transform is valid or 0 otherwise.
 */
#define xmlSecTransformIsValid(transform) \
	((( transform ) != NULL) && \
	 (( transform )->id != NULL) && \
	 (( transform )->id->klassSize >= sizeof(xmlSecTransformKlass)) && \
	 (( transform )->id->objSize >= sizeof(xmlSecTransform)) && \
	 (( transform )->id->name != NULL))
 
/**
 * xmlSecTransformCheckType:
 * @transform: the pointer to transform.
 * @t: the transform type.
 *
 * Macro. Returns 1 if the @transform is valid and has specified type @t 
 * or 0 otherwise.
 */
#define xmlSecTransformCheckType(transform, t) \
 	(xmlSecTransformIsValid(( transform )) && \
	((( transform )->id->type) == ( t )))

/**
 * xmlSecTransformCheckId:
 * @transform: the pointer to transform.
 * @i: the transform id.
 *
 * Macro. Returns 1 if the @transform is valid and has specified id @i 
 * or 0 otherwise.
 */
#define xmlSecTransformCheckId(transform, i) \
 	(xmlSecTransformIsValid(( transform )) && \
	((((const xmlSecTransformId) (( transform )->id))) == ( i )))

/**
 * xmlSecTransformCheckSize:
 * @transform: the pointer to transform.
 * @size: the transform object size.
 *
 * Macro. Returns 1 if the @transform is valid and has at least @size
 * bytes or 0 otherwise.
 */
#define xmlSecTransformCheckSize(transform, size) \
 	(xmlSecTransformIsValid(( transform )) && \
	((( transform )->id->objSize) >= ( size )))

/**************************************************************************
 *
 * xmlSecTransformType
 *
 *************************************************************************/
/**
 * xmlSecTransformType:
 * @xmlSecTransformTypeBinary: input - binary; output - binary.
 * @xmlSecTransformTypeXml: input - XML; output - XML.
 * @xmlSecTransformTypeC14N: input - XML; output - binary.
 *
 * The transform input/output types.
 */
typedef enum  {
    xmlSecTransformTypeBinary,
    xmlSecTransformTypeXml,
    xmlSecTransformTypeC14N
} xmlSecTransformType;

/**************************************************************************
 *
 * xmlSecTransformUsage
 *
 *************************************************************************/
typedef unsigned int					xmlSecTransformUsage;
#define xmlSecTransformUsageUnknown			0x0000
/**
 * xmlSecTransformUsageDSigTransform:
 *
 * Transform could be used in <dsig:Transform>.
 */
#define xmlSecTransformUsageDSigTransform		0x0001
/**
 * xmlSecTransformUsageC14NMethod:
 *
 * Transform could be used in <dsig:CanonicalizationMethod>.
 */
#define xmlSecTransformUsageC14NMethod			0x0002
/**
 * xmlSecTransformUsageDigestMethod:
 *
 * Transform could be used in <dsig:DigestMethod>.
 */
#define xmlSecTransformUsageDigestMethod		0x0004
/**
 * xmlSecTransformUsageSignatureMethod:
 *
 * Transform could be used in <dsig:SignatureMethod>.
 */
#define xmlSecTransformUsageSignatureMethod		0x0008
/**
 * xmlSecTransformUsageEncryptionMethod:
 *
 * Transform could be used in <enc:EncryptionMethod>.
 */
#define xmlSecTransformUsageEncryptionMethod		0x0010
/**
 * xmlSecTransformUsageAny:
 *
 * Transform could be used for operation.
 */
#define xmlSecTransformUsageAny				0xFFFF


/************************************************************************
 *
 * Transform Klass
 *
 ************************************************************************/ 
/**
 * xmlSecTransformIdUnknown:
 *
 * The "unknown" transform id (NULL).
 */
#define xmlSecTransformIdUnknown			NULL

/**
 * xmlSecTransformInitializeMethod:
 * @transform: the transform.
 *
 * The transform specific creation method.
 *
 */
typedef int		(*xmlSecTransformInitializeMethod) 	(xmlSecTransformPtr transform);

/**
 * xmlSecTransformFinalizeMethod:
 * @transform: the pointer to the #xmlSecTransform structure.
 *
 * The transform specific destroy method.
 */
typedef void 		(*xmlSecTransformFinalizeMethod)	(xmlSecTransformPtr transform);

/**
 * xmlSecTransformNodeReadMethod:
 * @transform: the pointer to the #xmlSecTransform structure.
 * @node: the pointer to the <dsig:Transform> node.
 *
 * The transfomr specific method to read the transform data from 
 * the @transformNode.
 *
 * Returns 0 on success or a negative value otherwise.
 */
typedef int 		(*xmlSecTransformNodeReadMethod)	(xmlSecTransformPtr transform,
								 xmlNodePtr node);

/**
 * xmlSecTransformSetKeyRequirements:
 * @transform: the pointer to #xmlSecTransform structure.
 * @keyInfoCtx: the pointer to key info context.
 * 
 */
typedef int  		(*xmlSecTransformSetKeyRequirements)	(xmlSecTransformPtr transform, 
								 xmlSecKeyInfoCtxPtr keyInfoCtx);

/**
 * xmlSecTransformSetKeyMethod:
 * @transform: the pointer to binary transform.
 * @key: the pointer to key.
 *
 * The transform specific method to set key for use.
 * 
 * Returns 0 on success or a negative value otherwise.
 */
typedef int  		(*xmlSecTransformSetKeyMethod)		(xmlSecTransformPtr transform, 
								 xmlSecKeyPtr key);


typedef int  		(*xmlSecTransformVerifyMethod)		(xmlSecTransformPtr transform, 
								 const unsigned char* data,
								 size_t dataSize,
								 xmlSecTransformCtxPtr transformCtx);
typedef int  		(*xmlSecTransformExecuteMethod)		(xmlSecTransformPtr transform, 
								 int last,
								 xmlSecTransformCtxPtr transformCtx);

/**
 * xmlSecTransformReadMethod:
 * @transform: the pointer to #xmlSecTransform structure.
 * @buf: the output buffer.
 * @size: the output buffer size.
 * 
 * The transform specific method to read next chunk of binary data into @buf.
 *
 * Returns the number of bytes in the buffer or negative value
 * if an error occurs.
 */
typedef int  		(*xmlSecTransformReadMethod)		(xmlSecTransformPtr transform, 
								 unsigned char *buf, 
								 size_t size);
/**
 * xmlSecTransformWriteMethod:
 * @transform: the pointer to #xmlSecTransform structure.
 * @buf: the input data buffer.
 * @size: the input data size.
 *
 * The transform specific method to write next chunk of binary data from @buf.
 * 
 * Returns 0 if success or a negative value otherwise.
 */
typedef int  		(*xmlSecTransformWriteMethod)		(xmlSecTransformPtr transform, 
                                        			 const unsigned char *buf, 
								 size_t size);
/**
 * xmlSecTransformFlushMethod:
 * @transform: the pointer to #xmlSecTransform structure.
 *
 * The transform specific method to finalize writing. 
 *
 * Returns 0 if success or negative value otherwise.
 */
typedef int  		(*xmlSecTransformFlushMethod)		(xmlSecTransformPtr transform);

/**
 * xmlSecTransformExecuteMethod:
 * @transform: the pointer to XML transform.
 * @ctxDoc: the pointer to the document containing the transform's 
 *		<dsig:Transform> node.
 * @doc: the pointer to the pointer to current document.
 * @nodes: the pointer to the pointer to current and result nodes set.
 *
 * Transform specific execute method. Returns result nodes set in @nodes.
 *
 * Returns 0 on success or a negative value otherwise.
 */
typedef int 		(*xmlSecTransformExecuteXmlMethod)	(xmlSecTransformPtr transform,
								 xmlDocPtr ctxDoc,
								 xmlDocPtr *doc,
								 xmlSecNodeSetPtr *nodes);

/**
 * xmlSecTransformExecuteMethod:
 * @transform: the pointer to C14N transform.
 * @doc: the pointer to current document.
 * @nodes: the pointer to current nodes set.
 * @buffer: the result buffer.
 *
 * Transform specific execute method. returns result in the @buffer.
 *
 * Returns 0 on success or a negative value otherwise.
 */
typedef int 		(*xmlSecTransformExecuteC14NMethod)	(xmlSecTransformPtr transform,
								 xmlDocPtr doc,
								 xmlSecNodeSetPtr nodes,
								 xmlOutputBufferPtr buffer);

/**
 * xmlSecTransformKlass:
 * @type: the type.
 * @usage: the usage.
 * @href: the algorithm href.
 * @create: creation method.
 * @destroy: destroy method.
 * @read: xml node read method.
 * 
 * The transform id structure.
 */
struct _xmlSecTransformKlass {
    size_t				klassSize;
    size_t				objSize;

    /* general data */
    const xmlChar*			name;
    xmlSecTransformType			type;
    xmlSecTransformUsage		usage;
    const xmlChar			*href;

    /* general methods */
    xmlSecTransformInitializeMethod	initialize;
    xmlSecTransformFinalizeMethod	finalize;
    xmlSecTransformNodeReadMethod	readNode;    
    xmlSecTransformSetKeyRequirements	setKeyReq;
    xmlSecTransformSetKeyMethod		setKey;
    xmlSecTransformVerifyMethod		verify;
    xmlSecTransformExecuteMethod	execute;
    
    
    /* binary methods */
    void*				deleteLater0;

    xmlSecTransformReadMethod		readBin; 
    xmlSecTransformWriteMethod		writeBin;
    xmlSecTransformFlushMethod		flushBin;

    /* xml methods */
    xmlSecTransformExecuteXmlMethod	executeXml;

    /* c14n methods */
    xmlSecTransformExecuteC14NMethod	executeC14N;
};




#include "transforms-old.h"

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_TRANSFORMS_H__ */

