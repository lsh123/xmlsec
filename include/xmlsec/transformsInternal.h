/** 
 * XMLSec library
 *
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_TRANSFORMS_INTERNAL_H__
#define __XMLSEC_TRANSFORMS_INTERNAL_H__    



#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>
#include <libxml/xpath.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/nodeset.h>

/**
 * Forward typedefs 
 */
typedef struct _xmlSecTransformState		xmlSecTransformState, 
						*xmlSecTransformStatePtr;


/**
 * xmlSecTransformResult:
 * @xmlSecTransformResultBinary: binary data.
 * @xmlSecTransformResultXml: XML document plus nodes set.
 *
 * The transform result types.
 */
typedef enum {
    xmlSecTransformResultBinary,
    xmlSecTransformResultXml
} xmlSecTransformResult;


/***************************************************************************
 *
 * Transforms State
 *
 **************************************************************************/
/**
 * xmlSecTransformState: 
 * @initDoc: the pointer to the original xml document.
 * @initNodeSet: the original nodes set.
 * @initUri: the original uri.
 * @curDoc: the pointer to the current doc.
 * @curNodeSet:	the pointer to the current nodes set.
 * @curBuf: the pointer to the current binary data.
 * @curFirstBinTransform: the pointer to the first pending binary transform.
 * @curLastBinTransform: the pointer to the last pending binary transform.
 * @curC14NTransform: the current pending c14n transform.
 * 
 * The current transforms state.
 */
struct _xmlSecTransformState {
    /* initial state */
    xmlDocPtr				initDoc;
    xmlSecNodeSetPtr			initNodeSet;
    char				*initUri;

    /* current state: xml */    
    xmlDocPtr				curDoc;	
    xmlSecNodeSetPtr			curNodeSet;
    
    /* current state: binary */
    xmlSecBufferPtr			curBuf;	
    xmlSecTransformPtr			curFirstBinTransform; 
    xmlSecTransformPtr			curLastBinTransform; 

    /*  optimization: special case for c14n transforms */
    xmlSecTransformPtr			curC14NTransform; 
};

xmlSecTransformStatePtr	xmlSecTransformStateCreate	(xmlDocPtr doc,
							 xmlSecNodeSetPtr nodeSet,
							 const char *uri);
void			xmlSecTransformStateDestroy	(xmlSecTransformStatePtr state);
int			xmlSecTransformStateUpdate	(xmlSecTransformStatePtr state,
							 xmlSecTransformPtr transform);
int			xmlSecTransformStateFinal	(xmlSecTransformStatePtr state,
							 xmlSecTransformResult type);
int			xmlSecTransformStateFinalToNode	(xmlSecTransformStatePtr state, 
							 xmlNodePtr node, 
							 int addBase64, 
							 xmlSecTransformCtxPtr transformCtx);
int			xmlSecTransformStateFinalVerifyNode(xmlSecTransformStatePtr state, 
				    			xmlSecTransformPtr transform,
							xmlNodePtr node, 
						        xmlSecTransformCtxPtr transformCtx);





int			xmlSecTransformsNodeRead	(xmlSecTransformStatePtr state, 
							 xmlNodePtr transformsNode);
xmlSecTransformPtr	xmlSecTransformNodeRead		(xmlNodePtr transformNode, 
							 xmlSecTransformUsage usage,
							 int dontDestroy);
int			xmlSecTransformNodeWrite	(xmlNodePtr transformNode,
							 xmlSecTransformId id);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_TRANSFORMS_INTERNAL_H__ */

