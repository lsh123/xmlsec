/** 
 *
 * XMLSec library
 * 
 * AES Algorithm support
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef XMLSEC_NO_AES
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/ciphers.h>
#include <xmlsec/buffered.h> 
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>

#define XMLSEC_AES_BLOCK_SIZE			16
#define XMLSEC_AES128_KEY_SIZE			16
#define XMLSEC_AES192_KEY_SIZE			24
#define XMLSEC_AES256_KEY_SIZE			32
#define XMLSEC_AES_IV_SIZE			16


/**************************************************************************
 *
 * <xmlsec:AESKeyValue> processing
 *
 *************************************************************************/
static xmlSecKeyDataPtr	xmlSecOpenSSLKeyDataAesValueCreate	(xmlSecKeyDataId id);
static xmlSecKeyDataPtr	xmlSecOpenSSLKeyDataAesValueDuplicate	(xmlSecKeyDataPtr data);
static void		xmlSecOpenSSLKeyDataAesValueDestroy	(xmlSecKeyDataPtr data);
static int		xmlSecOpenSSLKeyDataAesValueXmlRead	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataAesValueXmlWrite	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataAesValueBinRead	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 const unsigned char* buf,
								 size_t bufSize,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataAesValueBinWrite	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 unsigned char** buf,
								 size_t* bufSize,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataAesValueGenerate	(xmlSecKeyDataPtr data,
								 size_t sizeBits);

static xmlSecKeyDataType xmlSecOpenSSLKeyDataAesValueGetType	(xmlSecKeyDataPtr data);
static size_t		xmlSecOpenSSLKeyDataAesValueGetSize	(xmlSecKeyDataPtr data);
static void		xmlSecOpenSSLKeyDataAesValueDebugDump	(xmlSecKeyDataPtr data,
								 FILE* output);
static void		xmlSecOpenSSLKeyDataAesValueDebugXmlDump(xmlSecKeyDataPtr data,
								 FILE* output);

static const struct _xmlSecKeyDataKlass xmlSecOpenSSLKeyDataAesValueKlass = {
    /* data */
    xmlSecNameAESKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml, 
						/* xmlSecKeyDataUsage usage; */
    xmlSecHrefAESKeyValue,			/* const xmlChar* href; */
    xmlSecNodeAESKeyValue,			/* const xmlChar* dataNodeName; */
    xmlSecNs,					/* const xmlChar* dataNodeNs; */
    
    /* constructors/destructor */
    xmlSecOpenSSLKeyDataAesValueCreate,		/* xmlSecKeyDataCreateMethod create; */
    xmlSecOpenSSLKeyDataAesValueDuplicate,	/* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecOpenSSLKeyDataAesValueDestroy,	/* xmlSecKeyDataDestroyMethod destroy; */
    xmlSecOpenSSLKeyDataAesValueGenerate,	/* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecOpenSSLKeyDataAesValueGetType, 	/* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecOpenSSLKeyDataAesValueGetSize,	/* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,					/* xmlSecKeyDataGetIdentifier getIdentifier; */    
    
    /* read/write */
    xmlSecOpenSSLKeyDataAesValueXmlRead,	/* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecOpenSSLKeyDataAesValueXmlWrite,	/* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    xmlSecOpenSSLKeyDataAesValueBinRead,	/* xmlSecKeyDataBinReadMethod binRead; */
    xmlSecOpenSSLKeyDataAesValueBinWrite,	/* xmlSecKeyDataBinWriteMethod binWrite; */


    /* debug */
    xmlSecOpenSSLKeyDataAesValueDebugDump,	/* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecOpenSSLKeyDataAesValueDebugXmlDump, 	/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */
};

xmlSecKeyDataId 
xmlSecOpenSSLKeyDataAesValueGetKlass(void) {
    return(&xmlSecOpenSSLKeyDataAesValueKlass);
}

int
xmlSecOpenSSLKeyDataAesValueSet(xmlSecKeyDataPtr data, const unsigned char* buf, size_t bufSize) {
    xmlBufferPtr buffer;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecKeyDataAesValueId), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);
    
    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);
    
    /* erase current content with zeros */    
    xmlBufferEmpty(buffer);
    
    xmlBufferAdd(buffer, buf, bufSize);
    return(0);    
}

static xmlSecKeyDataPtr	
xmlSecOpenSSLKeyDataAesValueCreate(xmlSecKeyDataId id) {
    xmlSecAssert2(id == xmlSecKeyDataAesValueId, NULL);
    
    return(xmlSecKeyDataBinaryValueCreate(id));
}

static xmlSecKeyDataPtr	
xmlSecOpenSSLKeyDataAesValueDuplicate(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecKeyDataAesValueId), NULL);
    
    return(xmlSecKeyDataBinaryValueDuplicate(data));
}

static void
xmlSecOpenSSLKeyDataAesValueDestroy(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecKeyDataAesValueId));
    
    xmlSecKeyDataBinaryValueDestroy(data);
}

static int
xmlSecOpenSSLKeyDataAesValueXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecKeyDataAesValueId, -1);
    
    return(xmlSecKeyDataBinaryValueXmlRead(id, key, node, keyInfoCtx));
}

static int 
xmlSecOpenSSLKeyDataAesValueXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecKeyDataAesValueId, -1);
    
    return(xmlSecKeyDataBinaryValueXmlWrite(id, key, node, keyInfoCtx));
}

static int
xmlSecOpenSSLKeyDataAesValueBinRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    const unsigned char* buf, size_t bufSize,
				    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecKeyDataAesValueId, -1);
    
    return(xmlSecKeyDataBinaryValueBinRead(id, key, buf, bufSize, keyInfoCtx));
}

static int
xmlSecOpenSSLKeyDataAesValueBinWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    unsigned char** buf, size_t* bufSize,
				    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecKeyDataAesValueId, -1);
    
    return(xmlSecKeyDataBinaryValueBinWrite(id, key, buf, bufSize, keyInfoCtx));
}

static int
xmlSecOpenSSLKeyDataAesValueGenerate(xmlSecKeyDataPtr data, size_t sizeBits) {
    xmlBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecKeyDataAesValueId), -1);
    xmlSecAssert2(sizeBits > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);
    
    return(xmlSecOpenSSLGenerateRandom(buffer, (sizeBits + 7) / 8));
}

static xmlSecKeyDataType
xmlSecOpenSSLKeyDataAesValueGetType(xmlSecKeyDataPtr data) {
    xmlBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecKeyDataAesValueId), xmlSecKeyDataTypeUnknown);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, xmlSecKeyDataTypeUnknown);

    return((xmlBufferLength(buffer) > 0) ? xmlSecKeyDataTypeSymmetric : xmlSecKeyDataTypeUnknown);
}

static size_t 
xmlSecOpenSSLKeyDataAesValueGetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecKeyDataAesValueId), 0);
    
    return(xmlSecKeyDataBinaryValueGetSize(data));
}

static void 
xmlSecOpenSSLKeyDataAesValueDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecKeyDataAesValueId));
    
    xmlSecKeyDataBinaryValueDebugDump(data, output);    
}

static void
xmlSecOpenSSLKeyDataAesValueDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecKeyDataAesValueId));
    
    xmlSecKeyDataBinaryValueDebugXmlDump(data, output);    
}

#include "aes-old.c"

#endif /* XMLSEC_NO_AES */

