/** 
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Memory buffer.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_BUFFER_H__
#define __XMLSEC_BUFFER_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>
#include <xmlsec/xmlsec.h>

typedef struct _xmlSecBuffer					xmlSecBuffer, 
								*xmlSecBufferPtr;


/** 
 * xmlSecAllocMode:
 * @xmlSecAllocModeExact: 	the memory allocation mode that minimizes total 
 *				allocated memory size.
 * @xmlSecAllocModeDouble:	the memory allocation mode that tries to minimize
 *				the number of malloc calls.
 *
 * The memory allocation mode (used by @xmlSecBuffer and @xmlSecList).
 */
typedef enum {
    xmlSecAllocModeExact = 0,
    xmlSecAllocModeDouble
} xmlSecAllocMode;

/*****************************************************************************
 *
 * xmlSecBuffer
 *
 ****************************************************************************/

/** 
 * xmlSecBuffer:
 * @data: the pointer to buffer data.
 * @size: the current data size.
 * @maxSize: the max data size (allocated buffer size).
 * @allocMode: the buffer memory allocation mode.
 *
 * Binary data buffer.
 */
struct _xmlSecBuffer {
    unsigned char* 	data;
    size_t 		size;
    size_t		maxSize;
    xmlSecAllocMode 	allocMode;
};

XMLSEC_EXPORT void		xmlSecBufferSetDefaultAllocMode	(xmlSecAllocMode defAllocMode,
								 size_t defInitialSize);

XMLSEC_EXPORT xmlSecBufferPtr	xmlSecBufferCreate		(size_t size);
XMLSEC_EXPORT void		xmlSecBufferDestroy		(xmlSecBufferPtr buf);
XMLSEC_EXPORT int		xmlSecBufferInitialize		(xmlSecBufferPtr buf,
								 size_t size);
XMLSEC_EXPORT void		xmlSecBufferFinalize		(xmlSecBufferPtr buf);
XMLSEC_EXPORT unsigned char*	xmlSecBufferGetData		(xmlSecBufferPtr buf);
XMLSEC_EXPORT int		xmlSecBufferSetData		(xmlSecBufferPtr buf,
								 const unsigned char* data,
								 size_t size);
XMLSEC_EXPORT size_t		xmlSecBufferGetSize		(xmlSecBufferPtr buf);
XMLSEC_EXPORT int		xmlSecBufferSetSize		(xmlSecBufferPtr buf,
								 size_t size);
XMLSEC_EXPORT size_t		xmlSecBufferGetMaxSize		(xmlSecBufferPtr buf);
XMLSEC_EXPORT int		xmlSecBufferSetMaxSize		(xmlSecBufferPtr buf,
								 size_t size);
XMLSEC_EXPORT void		xmlSecBufferEmpty		(xmlSecBufferPtr buf);
XMLSEC_EXPORT int		xmlSecBufferAppend		(xmlSecBufferPtr buf,
								 const unsigned char* data,
								 size_t size);
XMLSEC_EXPORT int		xmlSecBufferPrepend		(xmlSecBufferPtr buf,
								 const unsigned char* data,
								 size_t size);
XMLSEC_EXPORT int		xmlSecBufferRemoveHead		(xmlSecBufferPtr buf,
								 size_t size);
XMLSEC_EXPORT int		xmlSecBufferRemoveTail		(xmlSecBufferPtr buf,
								 size_t size);
XMLSEC_EXPORT int		xmlSecBufferBase64NodeContentRead(xmlSecBufferPtr buf,
								 xmlNodePtr node);
XMLSEC_EXPORT int		xmlSecBufferBase64NodeContentWrite(xmlSecBufferPtr buf,
								 xmlNodePtr node,
								 int columns);

XMLSEC_EXPORT xmlOutputBufferPtr xmlSecBufferCreateOutputBuffer	(xmlSecBufferPtr buf);
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_BUFFER_H__ */

