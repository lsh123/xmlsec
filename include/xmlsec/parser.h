/** 
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * XML Parser transform and utility functions.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_PARSER_H__
#define __XMLSEC_PARSER_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/transforms.h>


XMLSEC_EXPORT xmlDocPtr		xmlSecParseFile		(const char *filename);
XMLSEC_EXPORT xmlDocPtr		xmlSecParseMemory	(const unsigned char *buffer, 
							 xmlSecSize size,
							 int recovery);
XMLSEC_EXPORT xmlDocPtr		xmlSecParseMemoryExt	(const unsigned char *prefix, 
							 xmlSecSize prefixSize,
							 const unsigned char *buffer, 
							 xmlSecSize bufferSize, 
							 const unsigned char *postfix, 
							 xmlSecSize postfixSize);


/**
 * xmlSecTransformXmlParserId:
 * 
 * The XML Parser transform klass.
 */
#define xmlSecTransformXmlParserId \
	xmlSecTransformXmlParserGetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecTransformXmlParserGetKlass	(void);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_PARSER_H__ */

