/** 
 *
 * XMLSec library
 * 
 * DES Algorithm support
 * 
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/gnutls/crypto.h>

/*****************************************************************************
 * 
 * Symmetic (binary) keys - just a wrapper for xmlSecKeyDataBinary
 *
 ****************************************************************************/
static int	xmlSecGnuTLSSymKeyDataInitialize	(xmlSecKeyDataPtr data);
static int	xmlSecGnuTLSSymKeyDataDuplicate		(xmlSecKeyDataPtr dst,
							 xmlSecKeyDataPtr src);
static void	xmlSecGnuTLSSymKeyDataFinalize		(xmlSecKeyDataPtr data);
static int	xmlSecGnuTLSSymKeyDataXmlRead		(xmlSecKeyDataId id,
							 xmlSecKeyPtr key,
							 xmlNodePtr node,
							 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int	xmlSecGnuTLSSymKeyDataXmlWrite		(xmlSecKeyDataId id,
							 xmlSecKeyPtr key,
							 xmlNodePtr node,
							 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int	xmlSecGnuTLSSymKeyDataBinRead		(xmlSecKeyDataId id,
							 xmlSecKeyPtr key,
							 const xmlSecByte* buf,
							 xmlSecSize bufSize,
							 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int	xmlSecGnuTLSSymKeyDataBinWrite		(xmlSecKeyDataId id,
							 xmlSecKeyPtr key,
							 xmlSecByte** buf,
							 xmlSecSize* bufSize,
							 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int	xmlSecGnuTLSSymKeyDataGenerate		(xmlSecKeyDataPtr data,
							 xmlSecSize sizeBits,
							 xmlSecKeyDataType type);

static xmlSecKeyDataType xmlSecGnuTLSSymKeyDataGetType	(xmlSecKeyDataPtr data);
static xmlSecSize	 xmlSecGnuTLSSymKeyDataGetSize	(xmlSecKeyDataPtr data);
static void	xmlSecGnuTLSSymKeyDataDebugDump		(xmlSecKeyDataPtr data,
							 FILE* output);
static void	xmlSecGnuTLSSymKeyDataDebugXmlDump	(xmlSecKeyDataPtr data,
							 FILE* output);
static int	xmlSecGnuTLSSymKeyDataKlassCheck	(xmlSecKeyDataKlass* klass);

#define xmlSecGnuTLSSymKeyDataCheckId(data) \
    (xmlSecKeyDataIsValid((data)) && \
     xmlSecGnuTLSSymKeyDataKlassCheck((data)->id))

static int
xmlSecGnuTLSSymKeyDataInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecGnuTLSSymKeyDataCheckId(data), -1);
    
    return(xmlSecKeyDataBinaryValueInitialize(data));
}

static int
xmlSecGnuTLSSymKeyDataDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecGnuTLSSymKeyDataCheckId(dst), -1);
    xmlSecAssert2(xmlSecGnuTLSSymKeyDataCheckId(src), -1);
    xmlSecAssert2(dst->id == src->id, -1);
        
    return(xmlSecKeyDataBinaryValueDuplicate(dst, src));
}

static void
xmlSecGnuTLSSymKeyDataFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecGnuTLSSymKeyDataCheckId(data));
    
    xmlSecKeyDataBinaryValueFinalize(data);
}

static int
xmlSecGnuTLSSymKeyDataXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
			       xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecGnuTLSSymKeyDataKlassCheck(id), -1);
    
    return(xmlSecKeyDataBinaryValueXmlRead(id, key, node, keyInfoCtx));
}

static int 
xmlSecGnuTLSSymKeyDataXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecGnuTLSSymKeyDataKlassCheck(id), -1);
    
    return(xmlSecKeyDataBinaryValueXmlWrite(id, key, node, keyInfoCtx));
}

static int
xmlSecGnuTLSSymKeyDataBinRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    const xmlSecByte* buf, xmlSecSize bufSize,
				    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecGnuTLSSymKeyDataKlassCheck(id), -1);
    
    return(xmlSecKeyDataBinaryValueBinRead(id, key, buf, bufSize, keyInfoCtx));
}

static int
xmlSecGnuTLSSymKeyDataBinWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    xmlSecByte** buf, xmlSecSize* bufSize,
				    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecGnuTLSSymKeyDataKlassCheck(id), -1);
    
    return(xmlSecKeyDataBinaryValueBinWrite(id, key, buf, bufSize, keyInfoCtx));
}

static int
xmlSecGnuTLSSymKeyDataGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits, xmlSecKeyDataType type ATTRIBUTE_UNUSED) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecGnuTLSSymKeyDataCheckId(data), -1);
    xmlSecAssert2(sizeBits > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);
    
    return(xmlSecGnuTLSGenerateRandom(buffer, (sizeBits + 7) / 8));
}

static xmlSecKeyDataType
xmlSecGnuTLSSymKeyDataGetType(xmlSecKeyDataPtr data) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecGnuTLSSymKeyDataCheckId(data), xmlSecKeyDataTypeUnknown);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, xmlSecKeyDataTypeUnknown);

    return((xmlSecBufferGetSize(buffer) > 0) ? xmlSecKeyDataTypeSymmetric : xmlSecKeyDataTypeUnknown);
}

static xmlSecSize 
xmlSecGnuTLSSymKeyDataGetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecGnuTLSSymKeyDataCheckId(data), 0);
    
    return(xmlSecKeyDataBinaryValueGetSize(data));
}

static void 
xmlSecGnuTLSSymKeyDataDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecGnuTLSSymKeyDataCheckId(data));
    
    xmlSecKeyDataBinaryValueDebugDump(data, output);    
}

static void
xmlSecGnuTLSSymKeyDataDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecGnuTLSSymKeyDataCheckId(data));
    
    xmlSecKeyDataBinaryValueDebugXmlDump(data, output);    
}

static int 
xmlSecGnuTLSSymKeyDataKlassCheck(xmlSecKeyDataKlass* klass) {    
#ifndef XMLSEC_NO_DES
    if(klass == xmlSecGnuTLSKeyDataDesId) {
	return(1);
    }
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_AES
    if(klass == xmlSecGnuTLSKeyDataAesId) {
	return(1);
    }
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_HMAC
    if(klass == xmlSecGnuTLSKeyDataHmacId) {
	return(1);
    }
#endif /* XMLSEC_NO_HMAC */

    return(0);
}

#ifndef XMLSEC_NO_AES
/**************************************************************************
 *
 * <xmlsec:AESKeyValue> processing
 *
 *************************************************************************/
static xmlSecKeyDataKlass xmlSecGnuTLSKeyDataAesKlass = {
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
    xmlSecGnuTLSSymKeyDataInitialize,		/* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecGnuTLSSymKeyDataDuplicate,		/* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecGnuTLSSymKeyDataFinalize,		/* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecGnuTLSSymKeyDataGenerate,		/* xmlSecKeyDataGenerateMethod generate; */
    
    /* get info */
    xmlSecGnuTLSSymKeyDataGetType, 		/* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecGnuTLSSymKeyDataGetSize,		/* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,					/* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecGnuTLSSymKeyDataXmlRead,		/* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecGnuTLSSymKeyDataXmlWrite,		/* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    xmlSecGnuTLSSymKeyDataBinRead,		/* xmlSecKeyDataBinReadMethod binRead; */
    xmlSecGnuTLSSymKeyDataBinWrite,		/* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecGnuTLSSymKeyDataDebugDump,		/* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecGnuTLSSymKeyDataDebugXmlDump, 	/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/** 
 * xmlSecGnuTLSKeyDataAesGetKlass:
 * 
 * The AES key data klass.
 *
 * Returns AES key data klass.
 */
xmlSecKeyDataId 
xmlSecGnuTLSKeyDataAesGetKlass(void) {
    return(&xmlSecGnuTLSKeyDataAesKlass);
}

/**
 * xmlSecGnuTLSKeyDataAesSet:
 * @data:		the pointer to AES key data.
 * @buf:		the pointer to key value.
 * @bufSize:		the key value size (in bytes).
 *
 * Sets the value of AES key data.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int
xmlSecGnuTLSKeyDataAesSet(xmlSecKeyDataPtr data, const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataAesId), -1);
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
static xmlSecKeyDataKlass xmlSecGnuTLSKeyDataDesKlass = {
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
    xmlSecGnuTLSSymKeyDataInitialize,		/* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecGnuTLSSymKeyDataDuplicate,		/* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecGnuTLSSymKeyDataFinalize,		/* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecGnuTLSSymKeyDataGenerate,		/* xmlSecKeyDataGenerateMethod generate; */
    
    /* get info */
    xmlSecGnuTLSSymKeyDataGetType, 		/* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecGnuTLSSymKeyDataGetSize,		/* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,					/* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecGnuTLSSymKeyDataXmlRead,		/* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecGnuTLSSymKeyDataXmlWrite,		/* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    xmlSecGnuTLSSymKeyDataBinRead,		/* xmlSecKeyDataBinReadMethod binRead; */
    xmlSecGnuTLSSymKeyDataBinWrite,		/* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecGnuTLSSymKeyDataDebugDump,		/* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecGnuTLSSymKeyDataDebugXmlDump, 	/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/** 
 * xmlSecGnuTLSKeyDataDesGetKlass:
 * 
 * The DES key data klass.
 *
 * Returns DES key data klass.
 */
xmlSecKeyDataId 
xmlSecGnuTLSKeyDataDesGetKlass(void) {
    return(&xmlSecGnuTLSKeyDataDesKlass);
}

/**
 * xmlSecGnuTLSKeyDataDesSet:
 * @data:		the pointer to DES key data.
 * @buf:		the pointer to key value.
 * @bufSize:		the key value size (in bytes).
 *
 * Sets the value of DES key data.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int
xmlSecGnuTLSKeyDataDesSet(xmlSecKeyDataPtr data, const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataDesId), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);
    
    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);
    
    return(xmlSecBufferSetData(buffer, buf, bufSize));
}

#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_HMAC
/**************************************************************************
 *
 * <xmlsec:HMACKeyValue> processing
 *
 *************************************************************************/
static xmlSecKeyDataKlass xmlSecGnuTLSKeyDataHmacKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecKeyDataBinarySize,

    /* data */
    xmlSecNameHMACKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml, 
						/* xmlSecKeyDataUsage usage; */
    xmlSecHrefHMACKeyValue,			/* const xmlChar* href; */
    xmlSecNodeHMACKeyValue,			/* const xmlChar* dataNodeName; */
    xmlSecNs,					/* const xmlChar* dataNodeNs; */
    
    /* constructors/destructor */
    xmlSecGnuTLSSymKeyDataInitialize,		/* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecGnuTLSSymKeyDataDuplicate,		/* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecGnuTLSSymKeyDataFinalize,		/* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecGnuTLSSymKeyDataGenerate,		/* xmlSecKeyDataGenerateMethod generate; */
    
    /* get info */
    xmlSecGnuTLSSymKeyDataGetType, 		/* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecGnuTLSSymKeyDataGetSize,		/* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,					/* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecGnuTLSSymKeyDataXmlRead,		/* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecGnuTLSSymKeyDataXmlWrite,		/* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    xmlSecGnuTLSSymKeyDataBinRead,		/* xmlSecKeyDataBinReadMethod binRead; */
    xmlSecGnuTLSSymKeyDataBinWrite,		/* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecGnuTLSSymKeyDataDebugDump,		/* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecGnuTLSSymKeyDataDebugXmlDump, 	/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/** 
 * xmlSecGnuTLSKeyDataHmacGetKlass:
 * 
 * The HMAC key data klass.
 *
 * Returns HMAC key data klass.
 */
xmlSecKeyDataId 
xmlSecGnuTLSKeyDataHmacGetKlass(void) {
    return(&xmlSecGnuTLSKeyDataHmacKlass);
}

/**
 * xmlSecGnuTLSKeyDataHmacSet:
 * @data:		the pointer to HMAC key data.
 * @buf:		the pointer to key value.
 * @bufSize:		the key value size (in bytes).
 *
 * Sets the value of HMAC key data.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int
xmlSecGnuTLSKeyDataHmacSet(xmlSecKeyDataPtr data, const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataHmacId), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);
    
    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);
    
    return(xmlSecBufferSetData(buffer, buf, bufSize));
}

#endif /* XMLSEC_NO_HMAC */

