/** 
 * XMLSec library
 *
 * XPath transform
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_XPATH_H__
#define __XMLSEC_XPATH_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>

XMLSEC_EXPORT void 	xmlSecXPathHereFunction		(xmlXPathParserContextPtr ctxt, 
							 int nargs);
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_XPATH_H__ */

