#define XMLSEC_TRANSFORM_BUFFER_SIZE			64	/* should be greater than XMLSEC_TRANSFORM_MIN_BLOCK_SIZE */

XMLSEC_EXPORT int 			xmlSecTransformOldExecuteXml(xmlSecTransformPtr transform,
								  xmlDocPtr ctxDoc,
								  xmlDocPtr *doc,
								  xmlSecNodeSetPtr *nodes);


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

