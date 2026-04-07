/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_KEYSDATA_H__
#define __XMLSEC_KEYSDATA_H__

/**
 * @defgroup xmlsec_core_keysdata Key Data
 * @ingroup xmlsec_core
 * @brief Key data containers and key-data processing.
 * @{
 */

#include <libxml/tree.h>

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>
#include <xmlsec/list.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/******************************************************************************
 *
 * Forward declarations
 *
  *****************************************************************************/
/**
 * @brief The key data klass.
 */
typedef const struct _xmlSecKeyDataKlass                xmlSecKeyDataKlass;
/**
 * @brief Pointer to #xmlSecKeyDataKlass.
 */
typedef const struct _xmlSecKeyDataKlass                *xmlSecKeyDataId;
/**
 * @brief The key data store klass.
 */
typedef const struct _xmlSecKeyDataStoreKlass           xmlSecKeyDataStoreKlass;
/**
 * @brief Pointer to #xmlSecKeyDataStoreKlass.
 */
typedef const struct _xmlSecKeyDataStoreKlass           *xmlSecKeyDataStoreId;
/**
 * @brief The key data list.
 */
typedef struct _xmlSecKeyDataList                       xmlSecKeyDataList;
/**
 * @brief Pointer to #xmlSecKeyDataList.
 */
typedef struct _xmlSecKeyDataList                       *xmlSecKeyDataListPtr;

/**
 * @brief The X.509 key data value.
 */
typedef struct _xmlSecKeyX509DataValue                  xmlSecKeyX509DataValue;

/**
 * @brief Pointer to xmlSecKeyX509DataValue.
 */
typedef struct _xmlSecKeyX509DataValue                  *xmlSecKeyX509DataValuePtr;

/******************************************************************************
 *
 * xmlSecKeyDataUsage
 *
  *****************************************************************************/
/**
 * @brief The key data usage bitmask.
 * @details The bits mask that determines possible keys data usage.
 */
typedef unsigned int                                    xmlSecKeyDataUsage;

/**
 * @brief The key data usage is unknown.
 */
#define xmlSecKeyDataUsageUnknown                       0x00000

/**
 * @brief The key data can be read from a KeyInfo child.
 * @details The key data could be read from a &lt;dsig:KeyInfo/&gt; child.
 */
#define xmlSecKeyDataUsageKeyInfoNodeRead               0x00001

/**
 * @brief The key data can be written to a KeyInfo child.
 * @details The key data could be written to a <dsig:KeyInfo /> child.
 */
#define xmlSecKeyDataUsageKeyInfoNodeWrite              0x00002

/**
 * @brief The key data can be read from a KeyValue child.
 * @details The key data could be read from a <dsig:KeyValue /> child.
 */
#define xmlSecKeyDataUsageKeyValueNodeRead              0x00004

/**
 * @brief The key data can be written to a KeyValue child.
 * @details The key data could be written to a <dsig:KeyValue /> child.
 */
#define xmlSecKeyDataUsageKeyValueNodeWrite             0x00008

/**
 * @brief The key data can be retrieved via RetrievalMethod in XML format.
 * @details The key data could be retrieved using <dsig:RetrievalMethod /> node
 * in XML format.
 */
#define xmlSecKeyDataUsageRetrievalMethodNodeXml        0x00010

/**
 * @brief The key data can be retrieved via RetrievalMethod in binary format.
 * @details The key data could be retrieved using <dsig:RetrievalMethod /> node
 * in binary format.
 */
#define xmlSecKeyDataUsageRetrievalMethodNodeBin        0x00020

/**
 * @brief The key data could be read from a file.
 */
#define xmlSecKeyDataUsageReadFromFile                   0x00040

/**
 * @brief Any key data usage.
 */
#define xmlSecKeyDataUsageAny                            0xFFFFF

/**
 * @brief The key data can be read and written from/to a KeyInfo child.
 * @details The key data could be read and written from/to a <dsig:KeyInfo /> child.
 */
#define xmlSecKeyDataUsageKeyInfoNode                   \
        (xmlSecKeyDataUsageKeyInfoNodeRead | xmlSecKeyDataUsageKeyInfoNodeWrite)

/**
 * @brief The key data can be read and written from/to a KeyValue child.
 * @details The key data could be read and written from/to a <dsig:KeyValue /> child.
 */
#define xmlSecKeyDataUsageKeyValueNode                  \
        (xmlSecKeyDataUsageKeyValueNodeRead | xmlSecKeyDataUsageKeyValueNodeWrite)

/**
 * @brief The key data can be retrieved via RetrievalMethod in any format.
 * @details The key data could be retrieved using <dsig:RetrievalMethod /> node
 * in any format.
 */
#define xmlSecKeyDataUsageRetrievalMethodNode           \
        (xmlSecKeyDataUsageRetrievalMethodNodeXml | xmlSecKeyDataUsageRetrievalMethodNodeBin)

/******************************************************************************
 *
 * xmlSecKeyDataType
 *
  *****************************************************************************/
/**
 * @brief The key data type.
 * @details The key data type (public/private, session/permanent, etc.).
 */
typedef unsigned int                            xmlSecKeyDataType;

/**
 * @brief The key data type is unknown (same as none).
 * @details The key data type is unknown (same as #xmlSecKeyDataTypeNone).
 */
#define xmlSecKeyDataTypeUnknown                        0x0000

/**
 * @brief The key data type is unknown (same as unknown).
 * @details The key data type is unknown (same as #xmlSecKeyDataTypeUnknown).
 */
#define xmlSecKeyDataTypeNone                           xmlSecKeyDataTypeUnknown

/**
 * @brief The key data contain a public key.
 */
#define xmlSecKeyDataTypePublic                         0x0001

/**
 * @brief The key data contain a private key.
 */
#define xmlSecKeyDataTypePrivate                        0x0002

/**
 * @brief The key data contain a symmetric key.
 */
#define xmlSecKeyDataTypeSymmetric                      0x0004

/**
 * @brief The key data contains a session (one-time) key.
 * @details The key data contain session key (one time key, not stored in keys manager).
 */
#define xmlSecKeyDataTypeSession                        0x0008

/**
 * @brief The key data contains a permanent key.
 * @details The key data contain permanent key (stored in keys manager).
 */
#define xmlSecKeyDataTypePermanent                      0x0010

/**
 * @brief The key data is trusted.
 */
#define xmlSecKeyDataTypeTrusted                        0x0100

/**
 * @brief Any key data.
 */
#define xmlSecKeyDataTypeAny                            0xFFFF

/******************************************************************************
 *
 * xmlSecKeyDataFormat
 *
  *****************************************************************************/
/**
 * @brief The key data format (binary, der, pem, etc.).
 */
typedef enum {
    xmlSecKeyDataFormatUnknown = 0,  /**< the key data format is unknown. */
    xmlSecKeyDataFormatBinary,  /**< the binary key data. */
    xmlSecKeyDataFormatPem,  /**< the PEM key data (cert or public/private key). */
    xmlSecKeyDataFormatDer,  /**< the DER key data (cert or public/private key). */
    xmlSecKeyDataFormatPkcs8Pem,  /**< the PKCS8 PEM private key. */
    xmlSecKeyDataFormatPkcs8Der,  /**< the PKCS8 DER private key. */
    xmlSecKeyDataFormatPkcs12,  /**< the PKCS12 format (bag of keys and certs) */
    xmlSecKeyDataFormatCertPem,  /**< the PEM cert. */
    xmlSecKeyDataFormatCertDer,  /**< the DER cert. */
    xmlSecKeyDataFormatEngine,  /**< the crypto engine (e.g. OpenSSL ENGINE). */
    xmlSecKeyDataFormatStore  /**< the crypto store (e.g. OpenSSL ossl_store). */
} xmlSecKeyDataFormat;

/******************************************************************************
 *
 * Global xmlSecKeyDataIds methods
 *
  *****************************************************************************/
XMLSEC_EXPORT xmlSecPtrListPtr  xmlSecKeyDataIdsGet             (void);
XMLSEC_EXPORT xmlSecPtrListPtr  xmlSecKeyDataIdsGetEnabled      (void);
XMLSEC_EXPORT int               xmlSecKeyDataIdsInit            (void);
XMLSEC_EXPORT void              xmlSecKeyDataIdsShutdown        (void);
XMLSEC_EXPORT int               xmlSecKeyDataIdsRegisterDefault (void);
XMLSEC_EXPORT int               xmlSecKeyDataIdsRegister        (xmlSecKeyDataId id);
XMLSEC_EXPORT int               xmlSecKeyDataIdsRegisterDisabled(xmlSecKeyDataId id);

/******************************************************************************
 *
 * xmlSecKeyData
 *
  *****************************************************************************/
/**
 * @brief The key data (key value, x509 data, pgp data, etc.).
 * @details The key data: key value (crypto material), x509 data, pgp data, etc.
 */
struct _xmlSecKeyData {
    xmlSecKeyDataId                     id;  /**< the data id (#xmlSecKeyDataId). */
    void*                               reserved0;  /**< reserved for the future. */
    void*                               reserved1;  /**< reserved for the future. */
};

XMLSEC_EXPORT xmlSecKeyDataPtr  xmlSecKeyDataCreate             (xmlSecKeyDataId id);
XMLSEC_EXPORT xmlSecKeyDataPtr  xmlSecKeyDataDuplicate          (xmlSecKeyDataPtr data);
XMLSEC_EXPORT void              xmlSecKeyDataDestroy            (xmlSecKeyDataPtr data);
XMLSEC_EXPORT int               xmlSecKeyDataGenerate           (xmlSecKeyDataPtr data,
                                                                 xmlSecSize sizeBits,
                                                                 xmlSecKeyDataType type);
XMLSEC_EXPORT xmlSecKeyDataType xmlSecKeyDataGetType            (xmlSecKeyDataPtr data);
XMLSEC_EXPORT xmlSecSize        xmlSecKeyDataGetSize            (xmlSecKeyDataPtr data);

XMLSEC_EXPORT void              xmlSecKeyDataDebugDump          (xmlSecKeyDataPtr data,
                                                                 FILE *output);
XMLSEC_EXPORT void              xmlSecKeyDataDebugXmlDump       (xmlSecKeyDataPtr data,
                                                                 FILE *output);

XMLSEC_EXPORT int               xmlSecKeyDataXmlRead            (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_EXPORT int               xmlSecKeyDataXmlWrite           (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);

XMLSEC_EXPORT int               xmlSecKeyDataBinRead            (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 const xmlSecByte* buf,
                                                                 xmlSecSize bufSize,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_EXPORT int               xmlSecKeyDataBinWrite           (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlSecByte** buf,
                                                                 xmlSecSize* bufSize,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);


/**
 * @brief Macro. Returns the key data name.
 * @param data the pointer to key data.
 */
#define xmlSecKeyDataGetName(data) \
        ((xmlSecKeyDataIsValid((data))) ? \
          xmlSecKeyDataKlassGetName((data)->id) : NULL)

/**
 * @brief Macro. Returns 1 if @p data is valid.
 * @details Macro. Returns 1 if @p data is not NULL and @p data->id is not NULL
 * or 0 otherwise.
 * @param data the pointer to data.
 */
#define xmlSecKeyDataIsValid(data) \
        ((( data ) != NULL) && \
         (( data )->id != NULL) && \
         (( data )->id->klassSize >= sizeof(xmlSecKeyDataKlass)) && \
         (( data )->id->objSize >= sizeof(xmlSecKeyData)) && \
         (( data )->id->name != NULL))

/**
 * @brief Macro. Returns 1 if @p data's id equals @p dataId.
 * @details Macro. Returns 1 if @p data is valid and @p data's id is equal to @p dataId.
 * @param data the pointer to data.
 * @param dataId the data Id.
 */
#define xmlSecKeyDataCheckId(data, dataId) \
        (xmlSecKeyDataIsValid(( data )) && \
        ((( data )->id) == ( dataId )))

/**
 * @brief Macro. Returns 1 if @p data can be used for @p usg.
 * @details Macro. Returns 1 if @p data is valid and could be used for @p usg.
 * @param data the pointer to data.
 * @param usg the data usage.
 */
#define xmlSecKeyDataCheckUsage(data, usg) \
        (xmlSecKeyDataIsValid(( data )) && \
        (((( data )->id->usage) & ( usg )) != 0))

/**
 * @brief Macro. Returns 1 if @p data's object has at least @p size bytes.
 * @details Macro. Returns 1 if @p data is valid and @p data's object has at least @p size bytes.
 * @param data the pointer to data.
 * @param size the expected size.
 */
#define xmlSecKeyDataCheckSize(data, size) \
        (xmlSecKeyDataIsValid(( data )) && \
         (( data )->id->objSize >= size))

/******************************************************************************
 *
 * xmlSecKeyDataKlass
 *
  *****************************************************************************/
/**
 * @brief The "unknown" id.
 */
#define xmlSecKeyDataIdUnknown                  ((xmlSecKeyDataId)NULL)

/**
 * @brief Key data specific initialization method.
 * @param data the pointer to key data.
 * @return 0 on success or a negative value if an error occurs.
 */
typedef int                     (*xmlSecKeyDataInitMethod)      (xmlSecKeyDataPtr data);

/**
 * @brief Key data specific duplication (copy) method.
 * @param dst the pointer to destination key data.
 * @param src the pointer to source key data.
 * @return 0 on success or a negative value if an error occurs.
 */
typedef int                     (*xmlSecKeyDataDuplicateMethod) (xmlSecKeyDataPtr dst,
                                                                 xmlSecKeyDataPtr src);

/**
 * @brief Key data specific finalization method.
 * @details Key data specific finalization method. All the objects and resources allocated
 * by the key data object must be freed inside this method.
 * @param data the data.
 */
typedef void                    (*xmlSecKeyDataFinalizeMethod)  (xmlSecKeyDataPtr data);

/**
 * @brief Key data specific method for reading XML node.
 * @param id the data id.
 * @param key the key.
 * @param node the pointer to data's value XML node.
 * @param keyInfoCtx the &lt;dsig:KeyInfo/&gt; node processing context.
 * @return 0 on success or a negative value if an error occurs.
 */
typedef int                     (*xmlSecKeyDataXmlReadMethod)   (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
/**
 * @brief Key data specific method for writing XML node.
 * @param id the data id.
 * @param key the key.
 * @param node the pointer to data's value XML node.
 * @param keyInfoCtx the &lt;dsig:KeyInfo/&gt; node processing context.
 * @return 0 on success or a negative value if an error occurs.
 */
typedef int                     (*xmlSecKeyDataXmlWriteMethod)  (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
/**
 * @brief Key data specific method to read a binary buffer.
 * @details Key data specific method for reading binary buffer.
 * @param id the data id.
 * @param key the key.
 * @param buf the input buffer.
 * @param bufSize the buffer size.
 * @param keyInfoCtx the &lt;dsig:KeyInfo/&gt; node processing context.
 * @return 0 on success or a negative value if an error occurs.
 */
typedef int                     (*xmlSecKeyDataBinReadMethod)   (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 const xmlSecByte* buf,
                                                                 xmlSecSize bufSize,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
/**
 * @brief Key data specific method to write a binary buffer.
 * @details Key data specific method for reading binary buffer.
 * @param id the data id.
 * @param key the key.
 * @param buf the output buffer.
 * @param bufSize the buffer size.
 * @param keyInfoCtx the &lt;dsig:KeyInfo/&gt; node processing context.
 * @return 0 on success or a negative value if an error occurs.
 */
typedef int                     (*xmlSecKeyDataBinWriteMethod)  (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlSecByte** buf,
                                                                 xmlSecSize* bufSize,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);

/**
 * @brief Key data specific key generation method.
 * @details Key data specific method for generating new key data.
 * @param data the pointer to key data.
 * @param sizeBits the key data specific size.
 * @param type the required key type (session/permanent, etc.)
 * @return 0 on success or a negative value if an error occurs.
 */
typedef int                     (*xmlSecKeyDataGenerateMethod)  (xmlSecKeyDataPtr data,
                                                                 xmlSecSize sizeBits,
                                                                 xmlSecKeyDataType type);

/**
 * @brief Key data specific method to get the key type.
 * @param data the data.
 * @return the key type.
 */
typedef xmlSecKeyDataType       (*xmlSecKeyDataGetTypeMethod)   (xmlSecKeyDataPtr data);

/**
 * @brief Key data specific method to get the key size.
 * @param data the pointer to key data.
 * @return the key size in bits.
 */
typedef xmlSecSize              (*xmlSecKeyDataGetSizeMethod)   (xmlSecKeyDataPtr data);

/**
 * @brief Key data specific method for printing debug info.
 * @param data the data.
 * @param output the FILE to print debug info (should be open for writing).
 */
typedef void                    (*xmlSecKeyDataDebugDumpMethod) (xmlSecKeyDataPtr data,
                                                                 FILE* output);

/**
 * @brief The data id (klass).
 */
struct _xmlSecKeyDataKlass {
    xmlSecSize                          klassSize;  /**< the klass size. */
    xmlSecSize                          objSize;  /**< the object size. */

    /* data */
    const xmlChar*                      name;  /**< the object name. */
    xmlSecKeyDataUsage                  usage;  /**< the allowed data usage. */
    const xmlChar*                      href;  /**< the identification string (href). */
    const xmlChar*                      dataNodeName;  /**< the data's XML node name. */
    const xmlChar*                      dataNodeNs;  /**< the data's XML node namespace. */

    /* constructors/destructor */
    xmlSecKeyDataInitMethod             initialize;  /**< the initialization method. */
    xmlSecKeyDataDuplicateMethod        duplicate;  /**< the duplicate (copy) method. */
    xmlSecKeyDataFinalizeMethod         finalize;  /**< the finalization (destroy) method. */
    xmlSecKeyDataGenerateMethod         generate;  /**< the new data generation method. */

    /* get info */
    xmlSecKeyDataGetTypeMethod          getType;  /**< the method to access data's type information. */
    xmlSecKeyDataGetSizeMethod          getSize;  /**< the method to access data's size. */
    void*                               deprecated0;  /**< DEPRECAED: the method to access data's string identifier. */

    /* read/write */
    xmlSecKeyDataXmlReadMethod          xmlRead;  /**< the method for reading data from XML node. */
    xmlSecKeyDataXmlWriteMethod         xmlWrite;  /**< the method for writing data to XML node. */
    xmlSecKeyDataBinReadMethod          binRead;  /**< the method for reading data from a binary buffer. */
    xmlSecKeyDataBinWriteMethod         binWrite;  /**< the method for writing data to binary buffer. */

    /* debug */
    xmlSecKeyDataDebugDumpMethod        debugDump;  /**< the method for printing debug data information. */
    xmlSecKeyDataDebugDumpMethod        debugXmlDump;  /**< the method for printing debug data information in XML format. */

    /* for the future */
    void*                               reserved0;  /**< reserved for the future. */
    void*                               reserved1;  /**< reserved for the future. */
};

/**
 * @brief Macro. Returns data klass name.
 * @param klass the data klass.
 */
#define xmlSecKeyDataKlassGetName(klass) \
        (((klass)) ? ((klass)->name) : NULL)



/******************************************************************************
 *
 * Helper functions for binary key data (HMAC, AES, DES, ...).
 *
  *****************************************************************************/
XMLSEC_EXPORT xmlSecSize        xmlSecKeyDataBinaryValueGetSize         (xmlSecKeyDataPtr data);
XMLSEC_EXPORT xmlSecBufferPtr   xmlSecKeyDataBinaryValueGetBuffer       (xmlSecKeyDataPtr data);
XMLSEC_EXPORT int               xmlSecKeyDataBinaryValueSetBuffer       (xmlSecKeyDataPtr data,
                                                                         const xmlSecByte* buf,
                                                                         xmlSecSize bufSize);

/******************************************************************************
 *
 * Key Data list
 *
  *****************************************************************************/
/**
 * @brief The key data klasses list klass id.
 */
#define xmlSecKeyDataListId     xmlSecKeyDataListGetKlass()
XMLSEC_EXPORT xmlSecPtrListId   xmlSecKeyDataListGetKlass       (void);

/******************************************************************************
 *
 * Key Data Ids list
 *
  *****************************************************************************/
/**
 * @brief The key data list klass id.
 */
#define xmlSecKeyDataIdListId   xmlSecKeyDataIdListGetKlass()
XMLSEC_EXPORT xmlSecPtrListId   xmlSecKeyDataIdListGetKlass     (void);
XMLSEC_EXPORT int               xmlSecKeyDataIdListFind         (xmlSecPtrListPtr list,
                                                                 xmlSecKeyDataId dataId);
XMLSEC_EXPORT xmlSecKeyDataId   xmlSecKeyDataIdListFindByNode   (xmlSecPtrListPtr list,
                                                                 const xmlChar* nodeName,
                                                                 const xmlChar* nodeNs,
                                                                 xmlSecKeyDataUsage usage);
XMLSEC_EXPORT xmlSecKeyDataId   xmlSecKeyDataIdListFindByHref   (xmlSecPtrListPtr list,
                                                                 const xmlChar* href,
                                                                 xmlSecKeyDataUsage usage);
XMLSEC_EXPORT xmlSecKeyDataId   xmlSecKeyDataIdListFindByName   (xmlSecPtrListPtr list,
                                                                 const xmlChar* name,
                                                                 xmlSecKeyDataUsage usage);
XMLSEC_EXPORT void              xmlSecKeyDataIdListDebugDump    (xmlSecPtrListPtr list,
                                                                 FILE* output);
XMLSEC_EXPORT void              xmlSecKeyDataIdListDebugXmlDump (xmlSecPtrListPtr list,
                                                                 FILE* output);


/******************************************************************************
 *
 * xmlSecKeyDataStore
 *
  *****************************************************************************/
/**
 * @brief The key data store (holds common data for key processing).
 * @details The key data store. Key data store holds common key data specific information
 * required for key data processing. For example, X509 data store may hold
 * information about trusted (root) certificates.
 */
struct _xmlSecKeyDataStore {
    xmlSecKeyDataStoreId                id;  /**< the store id (#xmlSecKeyDataStoreId). */

    /* for the future */
    void*                               reserved0;  /**< reserved for the future. */
    void*                               reserved1;  /**< reserved for the future. */
};

XMLSEC_EXPORT xmlSecKeyDataStorePtr xmlSecKeyDataStoreCreate    (xmlSecKeyDataStoreId id);
XMLSEC_EXPORT void              xmlSecKeyDataStoreDestroy       (xmlSecKeyDataStorePtr store);

/**
 * @brief Macro. Returns key data store name.
 * @param store the pointer to store.
 */
#define xmlSecKeyDataStoreGetName(store) \
    ((xmlSecKeyDataStoreIsValid((store))) ? \
      xmlSecKeyDataStoreKlassGetName((store)->id) : NULL)

/**
 * @brief Macro. Returns 1 if @p store is valid.
 * @details Macro. Returns 1 if @p store is not NULL and @p store->id is not NULL
 * or 0 otherwise.
 * @param store the pointer to store.
 */
#define xmlSecKeyDataStoreIsValid(store) \
        ((( store ) != NULL) && ((( store )->id) != NULL))
/**
 * @brief Macro. Returns 1 if @p store's id equals @p storeId.
 * @details Macro. Returns 1 if @p store is valid and @p store's id is equal to @p storeId.
 * @param store the pointer to store.
 * @param storeId the store Id.
 */
#define xmlSecKeyDataStoreCheckId(store, storeId) \
        (xmlSecKeyDataStoreIsValid(( store )) && \
        ((( store )->id) == ( storeId )))

/**
 * @brief Macro. Returns 1 if @p store's object has at least @p size bytes.
 * @details Macro. Returns 1 if @p data is valid and @p stores's object has at least @p size bytes.
 * @param store the pointer to store.
 * @param size the expected size.
 */
#define xmlSecKeyDataStoreCheckSize(store, size) \
        (xmlSecKeyDataStoreIsValid(( store )) && \
         (( store )->id->objSize >= size))


/******************************************************************************
 *
 * xmlSecKeyDataStoreKlass
 *
  *****************************************************************************/
/**
 * @brief The "unknown" id.
 */
#define xmlSecKeyDataStoreIdUnknown                     NULL

/**
 * @brief Key data store specific initialization method.
 * @param store the data store.
 * @return 0 on success or a negative value if an error occurs.
 */
typedef int                     (*xmlSecKeyDataStoreInitializeMethod)   (xmlSecKeyDataStorePtr store);

/**
 * @brief Key data store specific finalization method.
 * @details Key data store specific finalization (destroy) method.
 * @param store the data store.
 */
typedef void                    (*xmlSecKeyDataStoreFinalizeMethod)     (xmlSecKeyDataStorePtr store);

/**
 * @brief The data store id (klass).
 */
struct _xmlSecKeyDataStoreKlass {
    xmlSecSize                          klassSize;  /**< the data store klass size. */
    xmlSecSize                          objSize;  /**< the data store obj size. */

    /* data */
    const xmlChar*                      name;  /**< the store's name. */

    /* constructors/destructor */
    xmlSecKeyDataStoreInitializeMethod  initialize;  /**< the store's initialization method. */
    xmlSecKeyDataStoreFinalizeMethod    finalize;  /**< the store's finalization (destroy) method. */

    /* for the future */
    void*                               reserved0;  /**< reserved for the future. */
    void*                               reserved1;  /**< reserved for the future. */
};

/**
 * @brief Macro. Returns store klass name.
 * @param klass the pointer to store klass.
 */
#define xmlSecKeyDataStoreKlassGetName(klass) \
        (((klass)) ? ((klass)->name) : NULL)

/******************************************************************************
 *
 * Key Data Store list
 *
  *****************************************************************************/
/**
 * @brief The data store list id (klass).
 */
#define xmlSecKeyDataStorePtrListId     xmlSecKeyDataStorePtrListGetKlass()
XMLSEC_EXPORT xmlSecPtrListId   xmlSecKeyDataStorePtrListGetKlass       (void);

XMLSEC_EXPORT void xmlSecImportSetPersistKey                            (void);
XMLSEC_EXPORT int xmlSecImportGetPersistKey                             (void);


/******************************************************************************
 *
 * DEPRECATED
 *
  *****************************************************************************/
XMLSEC_EXPORT XMLSEC_DEPRECATED const xmlChar*    xmlSecKeyDataGetIdentifier      (xmlSecKeyDataPtr data);


#ifdef __cplusplus
}
#endif /* __cplusplus */

/** @} */ /** xmlsec_core_keysdata */

#endif /* __XMLSEC_KEYSDATA_H__ */
