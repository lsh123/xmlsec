

/**
 * xmlSecMemBuf:
 *
 * The memory buffer transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId xmlSecMemBuf;

XMLSEC_EXPORT xmlSecBufferPtr	xmlSecMemBufTransformGetBuffer		
							(xmlSecTransformPtr transform,
							 int removeBuffer);

/******************************************************************** 
 *
 * Base64 Transform
 *
 *******************************************************************/
/**
 * XMLSEC_BASE64_LINESIZE:
 *
 * The default max line size for base64 encoding
 */ 
#define XMLSEC_BASE64_LINESIZE			64
/**
 * xmlSecEncBase64Encode:
 * 
 * The base64 encode transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecEncBase64Encode;
/**
 * xmlSecEncBase64Decode:
 * 
 * The base64 decode transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecEncBase64Decode;

XMLSEC_EXPORT     void xmlSecBase64EncodeSetLineSize(xmlSecTransformPtr transform,
						 size_t lineSize);


/********************************************************************
 *
 * C14N transforms 
 *
 *******************************************************************/
/**
 * xmlSecC14NInclusive:
 * 
 * The regular (inclusive) C14N without comments transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecC14NInclusive;
/**
 * xmlSecC14NInclusiveWithComments:
 * 
 * The regular (inclusive) C14N with comments transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecC14NInclusiveWithComments;
/**
 * xmlSecC14NExclusive:
 * 
 * The exclusive C14N without comments transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecC14NExclusive;
/**
 * xmlSecC14NExclusiveWithComments:
 * 
 * The exclusive C14N with comments transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecC14NExclusiveWithComments;

XMLSEC_EXPORT int	xmlSecC14NExclAddInclNamespaces		
						(xmlNodePtr transformNode,
						 const xmlChar *prefixList);


/********************************************************************
 *
 * Enveloped transform 
 *
 *******************************************************************/
/**
 * xmlSecTransformEnveloped:
 * 
 * The "enveloped" transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecTransformEnveloped;

/********************************************************************
 *
 * XPath amd XPointer transforms
 *
 *******************************************************************/
/** 
 * xmlSecXPath2TransformType:
 * @xmlSecXPathTransformIntersect: intersect.
 * @xmlSecXPathTransformSubtract: subtract.
 * @xmlSecXPathTransformUnion:  union.
 *
 * The XPath2 transform types.
 */
typedef enum {
    xmlSecXPathTransformIntersect = 0,
    xmlSecXPathTransformSubtract,
    xmlSecXPathTransformUnion
} xmlSecXPath2TransformType;
 
/**
 * xmlSecTransformXPath:
 * 
 * The XPath transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecTransformXPath;
/**
 * xmlSecTransformXPath2:
 * 
 * The XPath2 transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecTransformXPath2;
/**
 * xmlSecTransformXPointer:
 * 
 * The XPointer transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecTransformXPointer;

XMLSEC_EXPORT int 	xmlSecTransformXPathAdd	(xmlNodePtr transformNode, 
						 const xmlChar *expression,
						 const xmlChar **namespaces);
XMLSEC_EXPORT int 	xmlSecTransformXPath2Add(xmlNodePtr transformNode, 
						 xmlSecXPath2TransformType type,
						 const xmlChar *expression,
						 const xmlChar **namespaces);
XMLSEC_EXPORT int 	xmlSecTransformXPointerAdd(xmlNodePtr transformNode, 
						 const xmlChar *expression,
						 const xmlChar **namespaces);


