#define XMLSEC_TRANSFORM_BUFFER_SIZE			64	/* should be greater than XMLSEC_TRANSFORM_MIN_BLOCK_SIZE */

XMLSEC_EXPORT int 			xmlSecTransformOldExecuteXml(xmlSecTransformPtr transform,
								  xmlDocPtr ctxDoc,
								  xmlDocPtr *doc,
								  xmlSecNodeSetPtr *nodes);


XMLSEC_EXPORT int 			xmlSecTransformExecuteXml(xmlSecTransformPtr transform,
								  xmlDocPtr ctxDoc,
								  xmlDocPtr *doc,
								  xmlSecNodeSetPtr *nodes);
XMLSEC_EXPORT int 			xmlSecTransformExecuteC14N(xmlSecTransformPtr transform,
								 xmlDocPtr doc,
								 xmlSecNodeSetPtr nodes,
								 xmlOutputBufferPtr buffer);


XMLSEC_EXPORT void			xmlSecTransformDestroyAll(xmlSecTransformPtr transform);	






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
