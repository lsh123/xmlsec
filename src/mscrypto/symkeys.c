/** 
 *
 * XMLSec library
 * 
 * DES Algorithm support
 * 
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2003 Cordys R&D BV, All rights reserved.
 */
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <windows.h>
#include <wincrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/mscrypto/crypto.h>

/*****************************************************************************
 * 
 * Symmetic (binary) keys - just a wrapper for xmlSecKeyDataBinary
 *
 ****************************************************************************/
static int	xmlSecMSCryptoSymKeyDataInitialize	(xmlSecKeyDataPtr data);
static int	xmlSecMSCryptoSymKeyDataDuplicate	(xmlSecKeyDataPtr dst,
							 xmlSecKeyDataPtr src);
static void	xmlSecMSCryptoSymKeyDataFinalize	(xmlSecKeyDataPtr data);
static int	xmlSecMSCryptoSymKeyDataXmlRead		(xmlSecKeyDataId id,
							 xmlSecKeyPtr key,
							 xmlNodePtr node,
							 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int	xmlSecMSCryptoSymKeyDataXmlWrite	(xmlSecKeyDataId id,
							 xmlSecKeyPtr key,
							 xmlNodePtr node,
							 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int	xmlSecMSCryptoSymKeyDataBinRead		(xmlSecKeyDataId id,
							 xmlSecKeyPtr key,
							 const unsigned char* buf,
							 size_t bufSize,
							 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int	xmlSecMSCryptoSymKeyDataBinWrite	(xmlSecKeyDataId id,
							 xmlSecKeyPtr key,
							 unsigned char** buf,
							 size_t* bufSize,
							 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int	xmlSecMSCryptoSymKeyDataGenerate	(xmlSecKeyDataPtr data,
							 size_t sizeBits,
							 xmlSecKeyDataType type);

static xmlSecKeyDataType xmlSecMSCryptoSymKeyDataGetType(xmlSecKeyDataPtr data);
static size_t	xmlSecMSCryptoSymKeyDataGetSize		(xmlSecKeyDataPtr data);
static void	xmlSecMSCryptoSymKeyDataDebugDump	(xmlSecKeyDataPtr data,
							 FILE* output);
static void	xmlSecMSCryptoSymKeyDataDebugXmlDump	(xmlSecKeyDataPtr data,
							 FILE* output);
static int	xmlSecMSCryptoSymKeyDataKlassCheck	(xmlSecKeyDataKlass* klass);

#ifndef XMLSEC_NO_AES
/**************************************************************************
 *
 * <xmlsec:AESKeyValue> processing
 *
 *************************************************************************/
static xmlSecKeyDataKlass xmlSecMSCryptoKeyDataAesKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecKeyDataBinarySize,

    /* data */
    xmlSecNameAESKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml, 
						/* xmlSecKeyDataUsage usage; */
    xmlSecHrefAESKeyValue,			/* const xmlChar* href; */
    xmlSecNodeAESKeyValue,			/* const xmlChar* dataNodeName; */
    xmlSecNs,					/* const xmlChar* dataNodeNs; */
    
    /* constructors/destructor */
    xmlSecMSCryptoSymKeyDataInitialize,		/* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecMSCryptoSymKeyDataDuplicate,		/* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecMSCryptoSymKeyDataFinalize,		/* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecMSCryptoSymKeyDataGenerate,		/* xmlSecKeyDataGenerateMethod generate; */
    
    /* get info */
    xmlSecMSCryptoSymKeyDataGetType, 		/* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecMSCryptoSymKeyDataGetSize,		/* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,					/* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecMSCryptoSymKeyDataXmlRead,		/* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecMSCryptoSymKeyDataXmlWrite,		/* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    xmlSecMSCryptoSymKeyDataBinRead,		/* xmlSecKeyDataBinReadMethod binRead; */
    xmlSecMSCryptoSymKeyDataBinWrite,		/* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecMSCryptoSymKeyDataDebugDump,		/* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecMSCryptoSymKeyDataDebugXmlDump, 	/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/** 
 * xmlSecMSCryptoKeyDataAesGetKlass:
 * 
 * The AES key data klass.
 *
 * Returns AES key data klass.
 */
xmlSecKeyDataId 
xmlSecMSCryptoKeyDataAesGetKlass(void) {
    return(&xmlSecMSCryptoKeyDataAesKlass);
}

/**
 * xmlSecMSCryptoKeyDataAesSet:
 * @data:		the pointer to AES key data.
 * @buf:		the pointer to key value.
 * @bufSize:		the key value size (in bytes).
 *
 * Sets the value of AES key data.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCryptoKeyDataAesSet(xmlSecKeyDataPtr data, const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataAesId), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);
    
    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);
    
    return(xmlSecBufferSetData(buffer, buf, bufSize));
}
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_DES
/**************************************************************************
 *
 * <xmlsec:DESKeyValue> processing
 *
 *************************************************************************/
static xmlSecKeyDataKlass xmlSecMSCryptoKeyDataDesKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecKeyDataBinarySize,

    /* data */
    xmlSecNameDESKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml, 
									/* xmlSecKeyDataUsage usage; */
    xmlSecHrefDESKeyValue,			/* const xmlChar* href; */
    xmlSecNodeDESKeyValue,			/* const xmlChar* dataNodeName; */
    xmlSecNs,					/* const xmlChar* dataNodeNs; */
    
    /* constructors/destructor */
    xmlSecMSCryptoSymKeyDataInitialize,		/* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecMSCryptoSymKeyDataDuplicate,		/* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecMSCryptoSymKeyDataFinalize,		/* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecMSCryptoSymKeyDataGenerate,		/* xmlSecKeyDataGenerateMethod generate; */
    
    /* get info */
    xmlSecMSCryptoSymKeyDataGetType, 		/* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecMSCryptoSymKeyDataGetSize,		/* xmlSecKeyDataGetSizeMethod getSize; */
	NULL,					/* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecMSCryptoSymKeyDataXmlRead,		/* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecMSCryptoSymKeyDataXmlWrite,		/* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    xmlSecMSCryptoSymKeyDataBinRead,		/* xmlSecKeyDataBinReadMethod binRead; */
    xmlSecMSCryptoSymKeyDataBinWrite,		/* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecMSCryptoSymKeyDataDebugDump,		/* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecMSCryptoSymKeyDataDebugXmlDump, 	/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/** 
 * xmlSecMSCryptoKeyDataDesGetKlass:
 * 
 * The DES key data klass.
 *
 * Returns DES key data klass.
 */
xmlSecKeyDataId 
xmlSecMSCryptoKeyDataDesGetKlass(void) {
    return(&xmlSecMSCryptoKeyDataDesKlass);
}
#endif /* XMLSEC_NO_DES */

/*
 * GENERIC HELPER FUNCTIONS 
 */

#define xmlSecMSCryptoSymKeyDataCheckId(data) \
    (xmlSecKeyDataIsValid((data)) && \
     xmlSecMSCryptoSymKeyDataKlassCheck((data)->id))

static int
xmlSecMSCryptoSymKeyDataInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecMSCryptoSymKeyDataCheckId(data), -1);
    
    return(xmlSecKeyDataBinaryValueInitialize(data));
}

static int
xmlSecMSCryptoSymKeyDataDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecMSCryptoSymKeyDataCheckId(dst), -1);
    xmlSecAssert2(xmlSecMSCryptoSymKeyDataCheckId(src), -1);
    xmlSecAssert2(dst->id == src->id, -1);
        
    return(xmlSecKeyDataBinaryValueDuplicate(dst, src));
}

static void
xmlSecMSCryptoSymKeyDataFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecMSCryptoSymKeyDataCheckId(data));
    
    xmlSecKeyDataBinaryValueFinalize(data);
}

static int
xmlSecMSCryptoSymKeyDataXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
			       xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecMSCryptoSymKeyDataKlassCheck(id), -1);
    
    return(xmlSecKeyDataBinaryValueXmlRead(id, key, node, keyInfoCtx));
}

static int 
xmlSecMSCryptoSymKeyDataXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecMSCryptoSymKeyDataKlassCheck(id), -1);
    
    return(xmlSecKeyDataBinaryValueXmlWrite(id, key, node, keyInfoCtx));
}

static int
xmlSecMSCryptoSymKeyDataBinRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
				const unsigned char* buf, size_t bufSize,
				xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecMSCryptoSymKeyDataKlassCheck(id), -1);
    
    return(xmlSecKeyDataBinaryValueBinRead(id, key, buf, bufSize, keyInfoCtx));
}

static int
xmlSecMSCryptoSymKeyDataBinWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
				 unsigned char** buf, size_t* bufSize,
				 xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecMSCryptoSymKeyDataKlassCheck(id), -1);
    
    return(xmlSecKeyDataBinaryValueBinWrite(id, key, buf, bufSize, keyInfoCtx));
}

static int
xmlSecMSCryptoSymKeyDataGenerate(xmlSecKeyDataPtr data, size_t sizeBits, xmlSecKeyDataType type ATTRIBUTE_UNUSED) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecMSCryptoSymKeyDataCheckId(data), -1);
    xmlSecAssert2(sizeBits > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);
    
    return(xmlSecMSCryptoGenerateRandom(buffer, (sizeBits + 7) / 8));
}

static xmlSecKeyDataType
xmlSecMSCryptoSymKeyDataGetType(xmlSecKeyDataPtr data) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecMSCryptoSymKeyDataCheckId(data), xmlSecKeyDataTypeUnknown);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, xmlSecKeyDataTypeUnknown);

    return((xmlSecBufferGetSize(buffer) > 0) ? xmlSecKeyDataTypeSymmetric : xmlSecKeyDataTypeUnknown);
}

static size_t 
xmlSecMSCryptoSymKeyDataGetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecMSCryptoSymKeyDataCheckId(data), 0);
    
    return(xmlSecKeyDataBinaryValueGetSize(data));
}

static void 
xmlSecMSCryptoSymKeyDataDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecMSCryptoSymKeyDataCheckId(data));
    
    xmlSecKeyDataBinaryValueDebugDump(data, output);    
}

static void
xmlSecMSCryptoSymKeyDataDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecMSCryptoSymKeyDataCheckId(data));
    
    xmlSecKeyDataBinaryValueDebugXmlDump(data, output);    
}

static int 
xmlSecMSCryptoSymKeyDataKlassCheck(xmlSecKeyDataKlass* klass) {    
#ifndef XMLSEC_NO_DES
    if(klass == xmlSecMSCryptoKeyDataDesId) {
	return(1);
    }
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_AES
    if(klass == xmlSecMSCryptoKeyDataAesId) {
		return(1);
    }
#endif /* XMLSEC_NO_AES */

    return(0);
}
