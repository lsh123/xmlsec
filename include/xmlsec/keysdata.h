/** 
 * XMLSec library
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_KEYSDATA_H__
#define __XMLSEC_KEYSDATA_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>

/**
 * Forward declarations
 */
typedef const struct _xmlSecKeyDataKlass 	xmlSecKeyDataKlass, *xmlSecKeyDataId; 
typedef struct _xmlSecKeyData 			xmlSecKeyData, *xmlSecKeyDataPtr; 

typedef const struct _xmlSecKeyDataStoreKlass 	xmlSecKeyDataStoreKlass, *xmlSecKeyDataStoreId; 
typedef struct _xmlSecKeyDataStore		xmlSecKeyDataStore, *xmlSecKeyDataStorePtr; 

typedef struct _xmlSecKeyInfoCtx  		xmlSecKeyInfoCtx, *xmlSecKeyInfoCtxPtr; 


/**
 * TODO: do we need these?
 */
typedef struct _xmlSecKeyDataList 		xmlSecKeyDataList, *xmlSecKeyDataListPtr; 
typedef struct _xmlSecKey 			xmlSecKey, *xmlSecKeyPtr; 
typedef struct _xmlSecKeysMngr  		xmlSecKeysMngr, *xmlSecKeysMngrPtr; 


/**************************************************************************
 *
 * xmlSecKeyDataUsage
 *
 *************************************************************************/
typedef unsigned int				xmlSecKeyDataUsage;

#define xmlSecKeyDataUsageUnknown			0x00000
#define xmlSecKeyDataUsageKeyInfoNodeRead		0x00001
#define xmlSecKeyDataUsageKeyInfoNodeWrite		0x00002
#define xmlSecKeyDataUsageKeyValueNodeRead		0x00004
#define xmlSecKeyDataUsageKeyValueNodeWrite		0x00008
#define xmlSecKeyDataUsageRetrievalMethodNodeXml	0x00010
#define xmlSecKeyDataUsageRetrievalMethodNodeBin	0x00020
#define xmlSecKeyDataUsageAny				0xFFFFF
#define xmlSecKeyDataUsageKeyInfoNode			\
	(xmlSecKeyDataUsageKeyInfoNodeRead | xmlSecKeyDataUsageKeyInfoNodeWrite)
#define xmlSecKeyDataUsageKeyValueNode			\
	(xmlSecKeyDataUsageKeyValueNodeRead | xmlSecKeyDataUsageKeyValueNodeWrite)
#define xmlSecKeyDataUsageRetrievalMethodNode		\
	(xmlSecKeyDataUsageRetrievalMethodNodeXml | xmlSecKeyDataUsageRetrievalMethodNodeBin)


/**************************************************************************
 *
 * xmlSecKeyDataType
 *
 *************************************************************************/
typedef unsigned int				xmlSecKeyDataType;

#define xmlSecKeyDataTypeUnknown			0x0000
#define xmlSecKeyDataTypeNone				xmlSecKeyDataTypeUnknown
#define xmlSecKeyDataTypePublic				0x0001
#define xmlSecKeyDataTypePrivate			0x0002
#define xmlSecKeyDataTypeSymmetric			0x0004
#define xmlSecKeyDataTypeSession			0x0008
#define xmlSecKeyDataTypePermanent			0x0010
#define xmlSecKeyDataTypeAny				0xFFFF

/**************************************************************************
 *
 * Global xmlSecKeyDataIds methods
 *
 *************************************************************************/
XMLSEC_EXPORT	int		xmlSecKeyDataIdsInit		(void);
XMLSEC_EXPORT	int 		xmlSecKeyDataIdsRegisterDefault	(void);
XMLSEC_EXPORT	int 		xmlSecKeyDataIdsRegister	(xmlSecKeyDataId id);
XMLSEC_EXPORT	void 		xmlSecKeyDataIdsClear		(void);
XMLSEC_EXPORT	size_t 		xmlSecKeyDataIdsGetSize		(void);
XMLSEC_EXPORT	xmlSecKeyDataId	xmlSecKeyDataIdsGetId		(size_t pos);
XMLSEC_EXPORT	xmlSecKeyDataId	xmlSecKeyDataIdsFindByNode	(const xmlChar* nodeName,
								 const xmlChar* nodeNs,
								 xmlSecKeyDataUsage usage);
XMLSEC_EXPORT	xmlSecKeyDataId	xmlSecKeyDataIdsFindByHref	(const xmlChar* href,
								 xmlSecKeyDataUsage usage);
XMLSEC_EXPORT	xmlSecKeyDataId	xmlSecKeyDataIdsFindByName	(const xmlChar* name,
								 xmlSecKeyDataUsage usage);


/**************************************************************************
 *
 * xmlSecKeyData
 *
 *************************************************************************/
/**
 * xmlSecKeyData:
 * @id: the data id (#xmlSecKeyDataId).
 *
 * The data.
 */
struct _xmlSecKeyData {
    xmlSecKeyDataId			id;
    void				*reserved0;
    void				*reserved1;
    void				*reserved2;
    void				*reserved3;
};

XMLSEC_EXPORT xmlSecKeyDataPtr	xmlSecKeyDataCreate		(xmlSecKeyDataId id);
XMLSEC_EXPORT xmlSecKeyDataPtr	xmlSecKeyDataDuplicate		(xmlSecKeyDataPtr data);
XMLSEC_EXPORT void		xmlSecKeyDataDestroy		(xmlSecKeyDataPtr data);
XMLSEC_EXPORT int		xmlSecKeyDataGenerate		(xmlSecKeyDataPtr data,
								 size_t sizeBits,
								 xmlSecKeyDataType type);
XMLSEC_EXPORT xmlSecKeyDataType	xmlSecKeyDataGetType		(xmlSecKeyDataPtr data);
XMLSEC_EXPORT size_t		xmlSecKeyDataGetSize		(xmlSecKeyDataPtr data);
XMLSEC_EXPORT const xmlChar*	xmlSecKeyDataGetIdentifier	(xmlSecKeyDataPtr data);
XMLSEC_EXPORT void		xmlSecKeyDataDebugDump		(xmlSecKeyDataPtr data,
								 FILE *output);
XMLSEC_EXPORT void		xmlSecKeyDataDebugXmlDump	(xmlSecKeyDataPtr data,
								 FILE *output);
XMLSEC_EXPORT int		xmlSecKeyDataXmlRead		(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr dataNode,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_EXPORT int		xmlSecKeyDataXmlWrite		(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr dataNode,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_EXPORT int		xmlSecKeyDataBinRead		(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 const unsigned char* buf,
								 size_t bufSize,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_EXPORT int		xmlSecKeyDataBinWrite		(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 unsigned char** buf,
								 size_t* bufSize,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);

#define xmlSecKeyDataGetName(data) \
	((xmlSecKeyDataIsValid((data))) ? \
	  xmlSecKeyDataKlassGetName((data)->id) : NULL)

/**
 * xmlSecKeyDataIsValid:
 * @data: the pointer to data.
 *
 * Macro. Returns 1 if @data is not NULL and @data->id is not NULL
 * or 0 otherwise.
 */ 
#define xmlSecKeyDataIsValid(data) \
	((( data ) != NULL) && \
	 (( data )->id != NULL) && \
	 (( data )->id->klassSize >= sizeof(xmlSecKeyDataKlass)) && \
	 (( data )->id->objSize >= sizeof(xmlSecKeyData)) && \
	 (( data )->id->name != NULL))
/**
 * xmlSecKeyDataCheckId:
 * @data: the pointer to data.
 * @dataId: the data Id.
 *
 * Macro. Returns 1 if @data is valid and @data's id is equal to @dataId.
 */
#define xmlSecKeyDataCheckId(data, dataId) \
 	(xmlSecKeyDataIsValid(( data )) && \
	((( data )->id) == ( dataId )))

/**
 * xmlSecKeyDataCheckUsage:
 * @data: the pointer to data.
 * @usg: the data usage.
 *
 * Macro. Returns 1 if @data is valid and could be used for @usg.
 */
#define xmlSecKeyDataCheckUsage(data, usg) \
 	(xmlSecKeyDataIsValid(( data )) && \
	(((( data )->id->usage) & ( usg )) != 0))

/**
 * xmlSecKeyDataCheckSize:
 * @data: the pointer to data.
 * @size: the expected size.
 *
 * Macro. Returns 1 if @data is valid and @data's object has at least @size bytes.
 */
#define xmlSecKeyDataCheckSize(data, size) \
 	(xmlSecKeyDataIsValid(( data )) && \
	 (( data )->id->objSize >= size))

/**************************************************************************
 *
 * xmlSecKeyDataKlass
 *
 *************************************************************************/
/**
 * xmlSecKeyDataIdUnknown:
 *
 * The "unknown" id.
 */
#define xmlSecKeyDataIdUnknown 			NULL

/** 
 * xmlSecKeyDataInitMethod:
 * @data: the data.
 *
 * KeyData specific creation method.
 *
 * Returns the pointer to newly created #xmlSecKeyData structure
 * or NULL if an error occurs.
 */
typedef int			(*xmlSecKeyDataInitMethod)	(xmlSecKeyDataPtr data);

/** 
 * xmlSecKeyDataDuplicateMethod:
 * @data: the data.
 *
 * KeyData specific duplication method.
 *
 * Returns the pointer to newly created #xmlSecKeyData structure
 * or NULL if an error occurs.
 */
typedef int			(*xmlSecKeyDataDuplicateMethod)	(xmlSecKeyDataPtr dst,
								 xmlSecKeyDataPtr src);

/** 
 * xmlSecKeyDataFinalizeMethod:
 * @data: the data.
 *
 * KeyData specific destroy method.
 */
typedef void			(*xmlSecKeyDataFinalizeMethod)	(xmlSecKeyDataPtr data);

/** 
 * xmlSecKeyDataXmlReadMethod:
 * @id: the data id.
 * @key: the key.
 * @node: the pointer to data's value XML node.
 * @keyInfoCtx: the <dsig:KeyInfo> node reading context
 *
 * KeyData specific reading from XML node method.
 * 
 * Returns 0 on success or a negative value if an error occurs.
 */
typedef int			(*xmlSecKeyDataXmlReadMethod)	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
/** 
 * xmlSecKeyDataWriteXmlMethod:
 * @id: the data id.
 * @key: the key.
 * @node: the pointer to data's value XML node.
 * @keyInfoCtx: the <dsig:KeyInfo> node reading context
 *
 * KeyData specific writing to XML node method.
 * 
 * Returns 0 on success or a negative value if an error occurs.
 */
typedef int			(*xmlSecKeyDataXmlWriteMethod)	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
/** 
 * xmlSecKeyDataBinReadMethod:
 * @id: the data id.
 * @key: the key.
 * @buf: the input buffer.
 * @bufSize: the buffer size.
 * @keyInfoCtx: the <dsig:KeyInfo> node reading context
 *
 * KeyData specific reading from binary buffer method.
 * 
 * Returns 0 on success or a negative value if an error occurs.
 */
typedef int			(*xmlSecKeyDataBinReadMethod)	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 const unsigned char* buf,
								 size_t bufSize,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
/** 
 * xmlSecKeyDataWriteBinMethod:
 * @id: the data id.
 * @key: the key.
 * @buf: the output buffer.
 * @bufSize: the buffer size.
 * @keyInfoCtx: the <dsig:KeyInfo> node reading context
 *
 * KeyData specific writing to a binary buffer method.
 * 
 * Returns 0 on success or a negative value if an error occurs.
 */
typedef int			(*xmlSecKeyDataBinWriteMethod)	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 unsigned char** buf,
								 size_t* bufSize,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);

/** 
 * xmlSecKeyDataGenerateMethod:
 * @data: the data.
 * @sizeBits: the key data specific size.
 *
 * KeyData specific new key generation method.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
typedef int			(*xmlSecKeyDataGenerateMethod)	(xmlSecKeyDataPtr data,
								 size_t sizeBits,
								 xmlSecKeyDataType type);

/** 
 * xmlSecKeyDataGetTypeMethod:
 * @data: the data.
 *
 * KeyData specific method to get the key type.
 *
 * Returns the key type.
 */
typedef xmlSecKeyDataType	(*xmlSecKeyDataGetTypeMethod)	(xmlSecKeyDataPtr data);

/** 
 * xmlSecKeyDataGetSizeMethod:
 * @data: the data.
 *
 * KeyData specific method to get the key size.
 *
 * Returns the key size in bits.
 */
typedef size_t			(*xmlSecKeyDataGetSizeMethod)	(xmlSecKeyDataPtr data);

/** 
 * xmlSecKeyDataGetIdentifierMethod:
 * @data: the data.
 *
 * KeyData specific method to get the data identifier string (for example,
 * X509 data identifier is the subject of the verified cert).
 *
 * Returns the identifier string or NULL if an error occurs.
 */
typedef const xmlChar*		(*xmlSecKeyDataGetIdentifierMethod) (xmlSecKeyDataPtr data);

/** 
 * xmlSecKeyDataDebugDumpMethod:
 * @data: the data.
 * @output: the FILE to print debug info (should be open for writing).
 *
 * KeyData specific method for printing debug info.
 */
typedef void			(*xmlSecKeyDataDebugDumpMethod)	(xmlSecKeyDataPtr data,
								 FILE* output);

/**
 * xmlSecKeyDataKlass:
 * @id: the data id (#xmlSecKeyDataId).
 *
 * The data id.
 */
struct _xmlSecKeyDataKlass {
    size_t				klassSize;
    size_t				objSize;

    /* data */
    const xmlChar*			name;    
    xmlSecKeyDataUsage			usage;
    const xmlChar*			href;
    const xmlChar*			dataNodeName;
    const xmlChar*			dataNodeNs;
    
    /* constructors/destructor */
    xmlSecKeyDataInitMethod		initialize;
    xmlSecKeyDataDuplicateMethod	duplicate;
    xmlSecKeyDataFinalizeMethod		finalize;
    xmlSecKeyDataGenerateMethod		generate;
    
    /* get info */
    xmlSecKeyDataGetTypeMethod		getType;
    xmlSecKeyDataGetSizeMethod		getSize;
    xmlSecKeyDataGetIdentifierMethod	getIdentifier;

    /* read/write */
    xmlSecKeyDataXmlReadMethod		xmlRead;
    xmlSecKeyDataXmlWriteMethod		xmlWrite;
    xmlSecKeyDataBinReadMethod		binRead;
    xmlSecKeyDataBinWriteMethod		binWrite;

    /* debug */
    xmlSecKeyDataDebugDumpMethod	debugDump;
    xmlSecKeyDataDebugDumpMethod	debugXmlDump;
};

#define xmlSecKeyDataKlassGetName(klass) \
	(((klass)) ? ((klass)->name) : NULL)

/***********************************************************************
 *
 * Key Data list
 *
 **********************************************************************/
#define xmlSecKeyDataPtrListId	xmlSecKeyDataPtrListGetKlass()
XMLSEC_EXPORT xmlSecPtrListId	xmlSecKeyDataPtrListGetKlass		(void);


/**************************************************************************
 *
 * xmlSecKeyDataBinary
 * 
 * key (xmlSecBuffer) is located after xmlSecKeyData structure
 *
 *************************************************************************/
#define xmlSecKeyDataBinarySize	\
    (sizeof(xmlSecKeyData) + sizeof(xmlSecBuffer))
 
XMLSEC_EXPORT int		xmlSecKeyDataBinaryValueInitialize	(xmlSecKeyDataPtr data);
XMLSEC_EXPORT int		xmlSecKeyDataBinaryValueDuplicate	(xmlSecKeyDataPtr dst,
									xmlSecKeyDataPtr src);
XMLSEC_EXPORT void		xmlSecKeyDataBinaryValueFinalize	(xmlSecKeyDataPtr data);
XMLSEC_EXPORT int		xmlSecKeyDataBinaryValueXmlRead		(xmlSecKeyDataId id,
								         xmlSecKeyPtr key,
									 xmlNodePtr node,
								         xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_EXPORT int		xmlSecKeyDataBinaryValueXmlWrite	(xmlSecKeyDataId id,
									 xmlSecKeyPtr key,
									 xmlNodePtr node,
									 xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_EXPORT int		xmlSecKeyDataBinaryValueBinRead		(xmlSecKeyDataId id,
									 xmlSecKeyPtr key,
									 const unsigned char* buf,
									 size_t bufSize,
									 xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_EXPORT int		xmlSecKeyDataBinaryValueBinWrite	(xmlSecKeyDataId id,
									 xmlSecKeyPtr key,
									 unsigned char** buf,
									 size_t* bufSize,
									 xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_EXPORT void		xmlSecKeyDataBinaryValueDebugDump	(xmlSecKeyDataPtr data,
									FILE* output);
XMLSEC_EXPORT void		xmlSecKeyDataBinaryValueDebugXmlDump	(xmlSecKeyDataPtr data,
									 FILE* output);

XMLSEC_EXPORT size_t		xmlSecKeyDataBinaryValueGetSize		(xmlSecKeyDataPtr data);
XMLSEC_EXPORT xmlSecBufferPtr	xmlSecKeyDataBinaryValueGetBuffer	(xmlSecKeyDataPtr data);
XMLSEC_EXPORT int		xmlSecKeyDataBinaryValueSetBuffer	(xmlSecKeyDataPtr data,
									 const unsigned char* buf,
									 size_t bufSize);

/**************************************************************************
 *
 * xmlSecKeyDataStore
 *
 *************************************************************************/
/**
 * xmlSecKeyDataStore:
 * @id: the store id (#xmlSecKeyDataStoreId).
 *
 * The store.
 */
struct _xmlSecKeyDataStore {
    xmlSecKeyDataStoreId		id;
    void*				reserved0;
    void*				reserved1;
    void*				reserved2;
    void*				reserved4;
};

XMLSEC_EXPORT xmlSecKeyDataStorePtr xmlSecKeyDataStoreCreate	(xmlSecKeyDataStoreId id);
XMLSEC_EXPORT void		xmlSecKeyDataStoreDestroy	(xmlSecKeyDataStorePtr store);
XMLSEC_EXPORT int		xmlSecKeyDataStoreFind		(xmlSecKeyDataStorePtr store,
								 xmlSecKeyPtr key,
								 const xmlChar** params,
								 size_t paramsSize,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
#define xmlSecKeyDataStoreGetName(store) \
    ((xmlSecKeyDataStoreIsValid((store))) ? \
      xmlSecKeyDataStoreKlassGetName((store)->id) : NULL)

/**
 * xmlSecKeyDataStoreIsValid:
 * @store: the pointer to store.
 *
 * Macro. Returns 1 if @store is not NULL and @store->id is not NULL
 * or 0 otherwise.
 */ 
#define xmlSecKeyDataStoreIsValid(store) \
	((( store ) != NULL) && ((( store )->id) != NULL))
/**
 * xmlSecKeyDataStoreCheckId:
 * @store: the pointer to store.
 * @storeId: the store Id.
 *
 * Macro. Returns 1 if @store is valid and @store's id is equal to @storeId.
 */
#define xmlSecKeyDataStoreCheckId(store, storeId) \
 	(xmlSecKeyDataStoreIsValid(( store )) && \
	((( store )->id) == ( storeId )))

/**************************************************************************
 *
 * xmlSecKeyDataStoreKlass
 *
 *************************************************************************/
/**
 * xmlSecKeyDataStoreIdUnknown:
 *
 * The "unknown" id.
 */
#define xmlSecKeyDataStoreIdUnknown 			NULL

/** 
 * xmlSecKeyDataStoreInitializeMethod:
 * @data: the data store.
 *
 * KeyDataStore specific creation method.
 *
 * Returns the pointer to newly created #xmlSecKeyDataStore structure
 * or NULL if an error occurs.
 */
typedef int			(*xmlSecKeyDataStoreInitializeMethod)	(xmlSecKeyDataStorePtr store);

/** 
 * xmlSecKeyDataStoreFinalizeMethod:
 * @data: the data store.
 *
 * KeyDataStore specific destroy method.
 */
typedef void			(*xmlSecKeyDataStoreFinalizeMethod)	(xmlSecKeyDataStorePtr store);

/** 
 * xmlSecKeyDataStoreFindMethod:
 * @data: the data store.
 * @key: the destination key.
 * @params: the params strings array.
 * @paramsSize: the params strings array @params.
 * @keyInfoCtx: the pointer to key info context.
 *
 * KeyDataStore specific find method.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
typedef int			(*xmlSecKeyDataStoreFindMethod)	(xmlSecKeyDataStorePtr store,
								 xmlSecKeyPtr key,
								 const xmlChar** params,
								 size_t paramsSize,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);

/**
 * xmlSecKeyDataStoreIdKlass:
 * @id: the data id (#xmlSecKeyDataStoreId).
 *
 * The data id.
 */
struct _xmlSecKeyDataStoreKlass {
    size_t				klassSize;
    size_t				objSize;

    /* data */
    const xmlChar*			name;    
        
    /* constructors/destructor */
    xmlSecKeyDataStoreInitializeMethod	initialize;
    xmlSecKeyDataStoreFinalizeMethod	finalize;
    xmlSecKeyDataStoreFindMethod	find;
};
#define xmlSecKeyDataStoreKlassGetName(klass) \
	(((klass)) ? ((klass)->name) : NULL)

/***********************************************************************
 *
 * Key Data Store list
 *
 **********************************************************************/
#define xmlSecKeyDataStorePtrListId	xmlSecKeyDataStorePtrListGetKlass()
XMLSEC_EXPORT xmlSecPtrListId	xmlSecKeyDataStorePtrListGetKlass	(void);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_KEYSDATA_H__ */
