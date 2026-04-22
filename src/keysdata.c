/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_core_keysdata
 * @brief Crypto key data object functions.
 */
#include "globals.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/base64.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>
#include <xmlsec/x509.h>

#include "cast_helpers.h"
#include "keysdata_helpers.h"

/******************************************************************************
 *
 * Global xmlSecKeyDataIds list functions
 *
  *****************************************************************************/
static xmlSecPtrList xmlSecAllKeyDataIds;
static xmlSecPtrList xmlSecEnabledKeyDataIds;
static int xmlSecImportPersistKey = 0;

/**
 * @brief Gets global registered key data klasses list.
 *
 * @return the pointer to list of all registered key data klasses.
 */
xmlSecPtrListPtr
xmlSecKeyDataIdsGet(void) {
    return(&xmlSecAllKeyDataIds);
}

/**
 * @brief Gets global enabled key data klasses list.
 *
 * @return the pointer to list of all enabled key data klasses.
 */
xmlSecPtrListPtr
xmlSecKeyDataIdsGetEnabled(void) {
    return(&xmlSecEnabledKeyDataIds);
}


/**
 * @brief Initializes the key data klasses.
 * @details Initializes the key data klasses. This function is called from the
 * #xmlSecInit function and the application should not call it directly.
 *
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecKeyDataIdsInit(void) {
    int ret;

    ret = xmlSecPtrListInitialize(&xmlSecAllKeyDataIds, xmlSecKeyDataIdListId);
    if(ret < 0) {
        xmlSecInternalError("xmlSecPtrListInitialize(xmlSecKeyDataIdListId)", NULL);
        return(-1);
    }

    ret = xmlSecPtrListInitialize(&xmlSecEnabledKeyDataIds, xmlSecKeyDataIdListId);
    if(ret < 0) {
        xmlSecInternalError("xmlSecPtrListInitialize(xmlSecKeyDataIdListId)", NULL);
        return(-1);
    }

    ret = xmlSecKeyDataIdsRegisterDefault();
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyDataIdsRegisterDefault", NULL);
        return(-1);
    }

    return(0);
}

/**
 * @brief Shuts down the key data klasses.
 * @details Shuts down the keys data klasses. This function is called from the
 * #xmlSecShutdown function and the application should not call it directly.
 */
void
xmlSecKeyDataIdsShutdown(void) {
    xmlSecPtrListFinalize(&xmlSecAllKeyDataIds);
    xmlSecPtrListFinalize(&xmlSecEnabledKeyDataIds);
}

/**
 * @brief Registers a key data klass in the global list (enabled).
 * @details Registers @p id in the global list of key data klasses and enable this key data.
 * @param id the key data klass.
 *
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecKeyDataIdsRegister(xmlSecKeyDataId id) {
    int ret;

    xmlSecAssert2(id != xmlSecKeyDataIdUnknown, -1);

    ret = xmlSecPtrListAdd(&xmlSecAllKeyDataIds, (xmlSecPtr)id);
    if(ret < 0) {
        xmlSecInternalError("xmlSecPtrListAdd(&xmlSecAllKeyDataIds)", xmlSecKeyDataKlassGetName(id));
        return(-1);
    }

    ret = xmlSecPtrListAdd(&xmlSecEnabledKeyDataIds, (xmlSecPtr)id);
    if(ret < 0) {
        xmlSecInternalError("xmlSecPtrListAdd(&xmlSecEnabledKeyDataIds)", xmlSecKeyDataKlassGetName(id));
        return(-1);
    }

    return(0);
}

/**
 * @brief Registers a key data klass in the global list (disabled).
 * @details Registers @p id in the global list of key data klasses and but DO NOT enable this key data.
 * @param id the key data klass.
 *
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecKeyDataIdsRegisterDisabled(xmlSecKeyDataId id) {
    int ret;

    xmlSecAssert2(id != xmlSecKeyDataIdUnknown, -1);

    ret = xmlSecPtrListAdd(&xmlSecAllKeyDataIds, (xmlSecPtr)id);
    if(ret < 0) {
        xmlSecInternalError("xmlSecPtrListAdd(&xmlSecAllKeyDataIds)", xmlSecKeyDataKlassGetName(id));
        return(-1);
    }

    return(0);
}

/**
 * @brief Registers default key data klasses.
 * @details Registers default (implemented by XML Security Library)
 * key data klasses: &lt;dsig:KeyName/&gt; element processing klass,
 * &lt;dsig:KeyValue/&gt; element processing klass, ...
 *
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecKeyDataIdsRegisterDefault(void) {
    if(xmlSecKeyDataIdsRegister(xmlSecKeyDataNameId) < 0) {
        xmlSecInternalError("xmlSecKeyDataIdsRegister(xmlSecKeyDataNameId)", NULL);
        return(-1);
    }

    if(xmlSecKeyDataIdsRegister(xmlSecKeyDataRetrievalMethodId) < 0) {
        xmlSecInternalError("xmlSecKeyDataIdsRegister(xmlSecKeyDataRetrievalMethodId", NULL);
        return(-1);
    }

    if(xmlSecKeyDataIdsRegister(xmlSecKeyDataKeyInfoReferenceId) < 0) {
        xmlSecInternalError("xmlSecKeyDataIdsRegister(xmlSecKeyDataKeyInfoReferenceId", NULL);
        return(-1);
    }

#ifndef XMLSEC_NO_XMLENC
    if(xmlSecKeyDataIdsRegister(xmlSecKeyDataEncryptedKeyId) < 0) {
        xmlSecInternalError("xmlSecKeyDataIdsRegister(xmlSecKeyDataEncryptedKeyId)", NULL);
        return(-1);
    }
    if(xmlSecKeyDataIdsRegister(xmlSecKeyDataAgreementMethodId) < 0) {
        xmlSecInternalError("xmlSecKeyDataIdsRegister(xmlSecKeyDataAgreementMethodId)", NULL);
        return(-1);
    }
    if(xmlSecKeyDataIdsRegister(xmlSecKeyDataDerivedKeyId) < 0) {
        xmlSecInternalError("xmlSecKeyDataIdsRegister(xmlSecKeyDataDerivedKeyId)", NULL);
        return(-1);
    }
    /* EXPERIMENTAL and should NOT be used in production */
 #ifndef XMLSEC_NO_MLKEM
    if(xmlSecKeyDataIdsRegisterDisabled(xmlSecKeyDataEncapsulationMechanismId) < 0) {
        xmlSecInternalError("xmlSecKeyDataIdsRegister(xmlSecKeyDataEncapsulationMechanismId)", NULL);
        return(-1);
    }
#endif /* XMLSEC_NO_MLKEM */

#endif /* XMLSEC_NO_XMLENC */

    /* KeyValue key data should not be used in production w/o understanding of the security risks */
    if(xmlSecKeyDataIdsRegisterDisabled(xmlSecKeyDataValueId) < 0) {
        xmlSecInternalError("xmlSecKeyDataIdsRegister(xmlSecKeyDataValueId)", NULL);
        return(-1);
    }

    return(0);
}

/******************************************************************************
 *
 * xmlSecKeyData functions
 *
  *****************************************************************************/
/**
 * @brief Allocates and initializes new key data of the specified type.
 * @details Allocates and initializes new key data of the specified type @p id.
 * Caller is responsible for destroying returned object with
 * #xmlSecKeyDataDestroy function.
 * @param id the data id.
 *
 * @return the pointer to newly allocated key data structure
 * or NULL if an error occurs.
 */
xmlSecKeyDataPtr
xmlSecKeyDataCreate(xmlSecKeyDataId id)  {
    xmlSecKeyDataPtr data;
    int ret;

    xmlSecAssert2(id != NULL, NULL);
    xmlSecAssert2(id->klassSize >= sizeof(xmlSecKeyDataKlass), NULL);
    xmlSecAssert2(id->objSize >= sizeof(xmlSecKeyData), NULL);
    xmlSecAssert2(id->name != NULL, NULL);

    /* Allocate a new xmlSecKeyData and fill the fields. */
    data = (xmlSecKeyDataPtr)xmlMalloc(id->objSize);
    if(data == NULL) {
        xmlSecMallocError(id->objSize,
                          xmlSecKeyDataKlassGetName(id));
        return(NULL);
    }
    memset(data, 0, id->objSize);
    data->id = id;

    if(id->initialize != NULL) {
        ret = (id->initialize)(data);
        if(ret < 0) {
            xmlSecInternalError("id->initialize",
                                xmlSecKeyDataKlassGetName(id));
            xmlSecKeyDataDestroy(data);
            return(NULL);
        }
    }

    return(data);
}

/**
 * @brief Creates a duplicate of the given key data.
 * @details Creates a duplicate of the given @p data. Caller is responsible for
 * destroying returned object with #xmlSecKeyDataDestroy function.
 * @param data the pointer to the key data.
 *
 * @return the pointer to newly allocated key data structure
 * or NULL if an error occurs.
 */
xmlSecKeyDataPtr
xmlSecKeyDataDuplicate(xmlSecKeyDataPtr data) {
    xmlSecKeyDataPtr newData;
    int ret;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), NULL);
    xmlSecAssert2(data->id->duplicate != NULL, NULL);

    newData = xmlSecKeyDataCreate(data->id);
    if(newData == NULL) {
        xmlSecInternalError("xmlSecKeyDataCreate",
                            xmlSecKeyDataGetName(data));
        return(NULL);
    }

    ret = (data->id->duplicate)(newData, data);
    if(ret < 0) {
        xmlSecInternalError("id->duplicate",
                            xmlSecKeyDataGetName(data));
        xmlSecKeyDataDestroy(newData);
        return(NULL);
    }

    return(newData);
}

/**
 * @brief Destroys the data and frees all allocated memory.
 * @param data the pointer to the key data.
 */
void
xmlSecKeyDataDestroy(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataIsValid(data));
    xmlSecAssert(data->id->objSize > 0);

    if(data->id->finalize != NULL) {
        (data->id->finalize)(data);
    }
    memset(data, 0, data->id->objSize);
    xmlFree(data);
}


/**
 * @brief Reads key data from an XML node into a key.
 * @details Reads the key data of klass @p id from XML @p node and adds them to @p key.
 * @param id the data klass.
 * @param key the destination key.
 * @param node the pointer to an XML node.
 * @param keyInfoCtx the pointer to &lt;dsig:KeyInfo/&gt; element processing context.
 *
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecKeyDataXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id != NULL, -1);
    xmlSecAssert2(id->xmlRead != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    return((id->xmlRead)(id, key, node, keyInfoCtx));
}

/**
 * @brief Writes key data from a key into an XML node.
 * @details Writes the key data of klass @p id from @p key to an XML @p node.
 * @param id the data klass.
 * @param key the source key.
 * @param node the pointer to an XML node.
 * @param keyInfoCtx the pointer to &lt;dsig:KeyInfo/&gt; element processing context.
 *
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecKeyDataXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id != NULL, -1);
    xmlSecAssert2(id->xmlWrite != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    return((id->xmlWrite)(id, key, node, keyInfoCtx));
}

/**
 * @brief Reads key data from a binary buffer into a key.
 * @details Reads the key data of klass @p id from binary buffer @p buf to @p key.
 * @param id the data klass.
 * @param key the destination key.
 * @param buf the input binary buffer.
 * @param bufSize the input buffer size.
 * @param keyInfoCtx the &lt;dsig:KeyInfo/&gt; node processing context.
 *
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecKeyDataBinRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
                    const xmlSecByte* buf, xmlSecSize bufSize,
                    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id != NULL, -1);
    xmlSecAssert2(id->binRead != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);

    return((id->binRead)(id, key, buf, bufSize, keyInfoCtx));
}

/**
 * @brief Writes key data from a key into a binary buffer.
 * @details Writes the key data of klass @p id from the @p key to a binary buffer @p buf.
 * @param id the data klass.
 * @param key the source key.
 * @param buf the output binary buffer.
 * @param bufSize the output buffer size.
 * @param keyInfoCtx the &lt;dsig:KeyInfo/&gt; node processing context.
 *
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecKeyDataBinWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                    xmlSecByte** buf, xmlSecSize* bufSize,
                    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id != NULL, -1);
    xmlSecAssert2(id->binWrite != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);

    return((id->binWrite)(id, key, buf, bufSize, keyInfoCtx));
}

/**
 * @brief Generates new key data of given size and type.
 * @param data the pointer to key data.
 * @param sizeBits the desired key data size (in bits).
 * @param type the desired key data type.
 *
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecKeyDataGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits,
                      xmlSecKeyDataType type) {
    int ret;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(data->id->generate != NULL, -1);

    /* write data */
    ret = data->id->generate(data, sizeBits, type);
    if(ret < 0) {
        xmlSecInternalError2("id->generate", xmlSecKeyDataGetName(data),
            "size=" XMLSEC_SIZE_FMT, sizeBits);
        return(-1);
    }
    return(0);
}

/**
 * @brief Gets key data type.
 * @param data the pointer to key data.
 *
 * @return key data type.
 */
xmlSecKeyDataType
xmlSecKeyDataGetType(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataIsValid(data), xmlSecKeyDataTypeUnknown);
    return(data->id->getType != NULL ? data->id->getType(data) : xmlSecKeyDataTypeUnknown);
}

/**
 * @brief Gets key data size (in bits).
 * @param data the pointer to key data.
 *
 * @return key data size (in bits).
 */
xmlSecSize
xmlSecKeyDataGetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataIsValid(data), 0);
    return(data->id->getSize != NULL ? data->id->getSize(data) : 0);
}

/**
 * @brief DEPRECATED. Gets key data identifier string.
 * @param data the pointer to key data.
 *
 * @return key data id string.
 */
const xmlChar*
xmlSecKeyDataGetIdentifier(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataIsValid(data), NULL);
    xmlSecNotImplementedError("Key data identifier method is deprecated");
    return(NULL);
}

/**
 * @brief Prints key data debug info.
 * @param data the pointer to key data.
 * @param output the pointer to output FILE.
 */
void
xmlSecKeyDataDebugDump(xmlSecKeyDataPtr data, FILE *output) {
    xmlSecAssert(xmlSecKeyDataIsValid(data));
    xmlSecAssert(data->id->debugDump != NULL);
    xmlSecAssert(output != NULL);

    data->id->debugDump(data, output);
}

/**
 * @brief Prints key data debug info in XML format.
 * @param data the pointer to key data.
 * @param output the pointer to output FILE.
 */
void
xmlSecKeyDataDebugXmlDump(xmlSecKeyDataPtr data, FILE *output) {
    xmlSecAssert(xmlSecKeyDataIsValid(data));
    xmlSecAssert(data->id->debugXmlDump != NULL);
    xmlSecAssert(output != NULL);

    data->id->debugXmlDump(data, output);
}

/******************************************************************************
 *
 * Keys Data list
 *
  *****************************************************************************/
static xmlSecPtrListKlass xmlSecKeyDataListKlass = {
    BAD_CAST "key-data-list",
    (xmlSecPtrDuplicateItemMethod)xmlSecKeyDataDuplicate,       /* xmlSecPtrDuplicateItemMethod duplicateItem; */
    (xmlSecPtrDestroyItemMethod)xmlSecKeyDataDestroy,           /* xmlSecPtrDestroyItemMethod destroyItem; */
    (xmlSecPtrDebugDumpItemMethod)xmlSecKeyDataDebugDump,       /* xmlSecPtrDebugDumpItemMethod debugDumpItem; */
    (xmlSecPtrDebugDumpItemMethod)xmlSecKeyDataDebugXmlDump,    /* xmlSecPtrDebugDumpItemMethod debugXmlDumpItem; */
};

/**
 * @brief The key data list klass.
 *
 * @return pointer to the key data list klass.
 */
xmlSecPtrListId
xmlSecKeyDataListGetKlass(void) {
    return(&xmlSecKeyDataListKlass);
}


/******************************************************************************
 *
 * Keys Data Ids list
 *
  *****************************************************************************/
static xmlSecPtrListKlass xmlSecKeyDataIdListKlass = {
    BAD_CAST "key-data-ids-list",
    NULL,                                                       /* xmlSecPtrDuplicateItemMethod duplicateItem; */
    NULL,                                                       /* xmlSecPtrDestroyItemMethod destroyItem; */
    NULL,                                                       /* xmlSecPtrDebugDumpItemMethod debugDumpItem; */
    NULL,                                                       /* xmlSecPtrDebugDumpItemMethod debugXmlDumpItem; */
};

/**
 * @brief The key data id list klass.
 *
 * @return pointer to the key data id list klass.
 */
xmlSecPtrListId
xmlSecKeyDataIdListGetKlass(void) {
    return(&xmlSecKeyDataIdListKlass);
}

/**
 * @brief Lookups @p dataId in @p list.
 * @param list the pointer to key data ids list.
 * @param dataId the key data klass.
 *
 * @return 1 if @p dataId is found in the @p list, 0 if not and a negative
 * value if an error occurs.
 */
int
xmlSecKeyDataIdListFind(xmlSecPtrListPtr list, xmlSecKeyDataId dataId) {
    xmlSecSize i, size;

    xmlSecAssert2(xmlSecPtrListCheckId(list, xmlSecKeyDataIdListId), 0);
    xmlSecAssert2(dataId != NULL, 0);

    size = xmlSecPtrListGetSize(list);
    for(i = 0; i < size; ++i) {
        if((xmlSecKeyDataId)xmlSecPtrListGetItem(list, i) == dataId) {
            return(1);
        }
    }
    return(0);
}

/**
 * @brief Looks up a key data klass by XML node name, namespace, and usage.
 * @details Lookups data klass in the list with given @p nodeName, @p nodeNs and
 * @p usage in the @p list.
 * @param list the pointer to key data ids list.
 * @param nodeName the desired key data klass XML node name.
 * @param nodeNs the desired key data klass XML node namespace.
 * @param usage the desired key data usage.
 *
 * @return key data klass is found and NULL otherwise.
 */
xmlSecKeyDataId
xmlSecKeyDataIdListFindByNode(xmlSecPtrListPtr list, const xmlChar* nodeName,
                            const xmlChar* nodeNs, xmlSecKeyDataUsage usage) {
    xmlSecKeyDataId dataId;
    xmlSecSize i, size;

    xmlSecAssert2(xmlSecPtrListCheckId(list, xmlSecKeyDataIdListId), xmlSecKeyDataIdUnknown);
    xmlSecAssert2(nodeName != NULL, xmlSecKeyDataIdUnknown);

    size = xmlSecPtrListGetSize(list);
    for(i = 0; i < size; ++i) {
        dataId = (xmlSecKeyDataId)xmlSecPtrListGetItem(list, i);
        xmlSecAssert2(dataId != xmlSecKeyDataIdUnknown, xmlSecKeyDataIdUnknown);

        if(((usage & dataId->usage) != 0) &&
           xmlStrEqual(nodeName, dataId->dataNodeName) &&
           xmlStrEqual(nodeNs, dataId->dataNodeNs)) {

           return(dataId);
        }
    }
    return(xmlSecKeyDataIdUnknown);
}

/**
 * @brief Looks up a key data klass by href and usage.
 * @details Lookups data klass in the list with given @p href and @p usage in @p list.
 * @param list the pointer to key data ids list.
 * @param href the desired key data klass href.
 * @param usage the desired key data usage.
 *
 * @return key data klass is found and NULL otherwise.
 */
xmlSecKeyDataId
xmlSecKeyDataIdListFindByHref(xmlSecPtrListPtr list, const xmlChar* href,
                            xmlSecKeyDataUsage usage) {
    xmlSecKeyDataId dataId;
    xmlSecSize i, size;

    xmlSecAssert2(xmlSecPtrListCheckId(list, xmlSecKeyDataIdListId), xmlSecKeyDataIdUnknown);
    xmlSecAssert2(href != NULL, xmlSecKeyDataIdUnknown);

    size = xmlSecPtrListGetSize(list);
    for(i = 0; i < size; ++i) {
        dataId = (xmlSecKeyDataId)xmlSecPtrListGetItem(list, i);
        xmlSecAssert2(dataId != xmlSecKeyDataIdUnknown, xmlSecKeyDataIdUnknown);

        if(((usage & dataId->usage) != 0) && (dataId->href != NULL) &&
           xmlStrEqual(href, dataId->href)) {

           return(dataId);
        }
    }
    return(xmlSecKeyDataIdUnknown);
}

/**
 * @brief Looks up a key data klass by name and usage.
 * @details Lookups data klass in the list with given @p name and @p usage in @p list.
 * @param list the pointer to key data ids list.
 * @param name the desired key data klass name.
 * @param usage the desired key data usage.
 *
 * @return key data klass is found and NULL otherwise.
 */
xmlSecKeyDataId
xmlSecKeyDataIdListFindByName(xmlSecPtrListPtr list, const xmlChar* name,
                            xmlSecKeyDataUsage usage) {
    xmlSecKeyDataId dataId;
    xmlSecSize i, size;

    xmlSecAssert2(xmlSecPtrListCheckId(list, xmlSecKeyDataIdListId), xmlSecKeyDataIdUnknown);
    xmlSecAssert2(name != NULL, xmlSecKeyDataIdUnknown);

    size = xmlSecPtrListGetSize(list);
    for(i = 0; i < size; ++i) {
        dataId = (xmlSecKeyDataId)xmlSecPtrListGetItem(list, i);
        xmlSecAssert2(dataId != xmlSecKeyDataIdUnknown, xmlSecKeyDataIdUnknown);

        if(((usage & dataId->usage) != 0) && (dataId->name != NULL) &&
           xmlStrEqual(name, BAD_CAST dataId->name)) {

           return(dataId);
        }
    }
    return(xmlSecKeyDataIdUnknown);
}

/**
 * @brief Prints key data ID list debug information.
 * @details Prints binary key data debug information to @p output.
 * @param list the pointer to key data ids list.
 * @param output the pointer to output FILE.
 */
void
xmlSecKeyDataIdListDebugDump(xmlSecPtrListPtr list, FILE* output) {
    xmlSecKeyDataId dataId;
    xmlSecSize i, size;

    xmlSecAssert(xmlSecPtrListCheckId(list, xmlSecKeyDataIdListId));
    xmlSecAssert(output != NULL);

    size = xmlSecPtrListGetSize(list);
    for(i = 0; i < size; ++i) {
        dataId = (xmlSecKeyDataId)xmlSecPtrListGetItem(list, i);
        xmlSecAssert(dataId != NULL);
        xmlSecAssert(dataId->name != NULL);

        if(i > 0) {
            fprintf(output, ",\"%s\"", dataId->name);
        } else {
            fprintf(output, "\"%s\"", dataId->name);
        }
    }
    fprintf(output, "\n");
}

/**
 * @brief Prints key data ID list debug information in XML format.
 * @details Prints binary key data debug information to @p output in XML format.
 * @param list the pointer to key data ids list.
 * @param output the pointer to output FILE.
 */
void
xmlSecKeyDataIdListDebugXmlDump(xmlSecPtrListPtr list, FILE* output) {
    xmlSecKeyDataId dataId;
    xmlSecSize i, size;

    xmlSecAssert(xmlSecPtrListCheckId(list, xmlSecKeyDataIdListId));
    xmlSecAssert(output != NULL);

    fprintf(output, "<KeyDataIdsList>\n");
    size = xmlSecPtrListGetSize(list);
    for(i = 0; i < size; ++i) {
        dataId = (xmlSecKeyDataId)xmlSecPtrListGetItem(list, i);
        xmlSecAssert(dataId != NULL);
        xmlSecAssert(dataId->name != NULL);

        fprintf(output, "<DataId name=\"");
        xmlSecPrintXmlString(output, dataId->name);
        fprintf(output, "\"/>");
    }
    fprintf(output, "</KeyDataIdsList>\n");
}

/******************************************************************************
 *
 * xmlSecKeyDataStore functions
 *
  *****************************************************************************/
/**
 * @brief Creates a new key data store of the specified klass.
 * @details Creates new key data store of the specified klass @p id. Caller is responsible
 * for freeing returned object with #xmlSecKeyDataStoreDestroy function.
 * @param id the store id.
 *
 * @return the pointer to newly allocated key data store structure
 * or NULL if an error occurs.
 */
xmlSecKeyDataStorePtr
xmlSecKeyDataStoreCreate(xmlSecKeyDataStoreId id)  {
    xmlSecKeyDataStorePtr store;
    int ret;

    xmlSecAssert2(id != NULL, NULL);
    xmlSecAssert2(id->objSize > 0, NULL);

    /* Allocate a new xmlSecKeyDataStore and fill the fields. */
    store = (xmlSecKeyDataStorePtr)xmlMalloc(id->objSize);
    if(store == NULL) {
        xmlSecMallocError(id->objSize,
                          xmlSecKeyDataStoreKlassGetName(id));
        return(NULL);
    }
    memset(store, 0, id->objSize);
    store->id = id;

    if(id->initialize != NULL) {
        ret = (id->initialize)(store);
        if(ret < 0) {
            xmlSecInternalError("id->initialize",
                                xmlSecKeyDataStoreKlassGetName(id));
            xmlSecKeyDataStoreDestroy(store);
            return(NULL);
        }
    }

    return(store);
}

/**
 * @brief Destroys a key data store.
 * @details Destroys the key data store created with #xmlSecKeyDataStoreCreate
 * function.
 * @param store the pointer to the key data store..
 */
void
xmlSecKeyDataStoreDestroy(xmlSecKeyDataStorePtr store) {
    xmlSecAssert(xmlSecKeyDataStoreIsValid(store));
    xmlSecAssert(store->id->objSize > 0);

    if(store->id->finalize != NULL) {
        (store->id->finalize)(store);
    }
    memset(store, 0, store->id->objSize);
    xmlFree(store);
}

/******************************************************************************
 *
 * Keys Data Store list
 *
  *****************************************************************************/
static xmlSecPtrListKlass xmlSecKeyDataStorePtrListKlass = {
    BAD_CAST "keys-data-store-list",
    NULL,                                                       /* xmlSecPtrDuplicateItemMethod duplicateItem; */
    (xmlSecPtrDestroyItemMethod)xmlSecKeyDataStoreDestroy,      /* xmlSecPtrDestroyItemMethod destroyItem; */
    NULL,                                                       /* xmlSecPtrDebugDumpItemMethod debugDumpItem; */
    NULL,                                                       /* xmlSecPtrDebugDumpItemMethod debugXmlDumpItem; */
};

/**
 * @brief Key data stores list.
 *
 * @return key data stores list klass.
 */
xmlSecPtrListId
xmlSecKeyDataStorePtrListGetKlass(void) {
    return(&xmlSecKeyDataStorePtrListKlass);
}

/**
 * @brief Sets global flag to import keys to persistent storage.
 * @details Sets global flag to import keys to persistent storage (MSCrypto and MSCNG).
 * Also see PKCS12_NO_PERSIST_KEY.
 *
 */
void xmlSecImportSetPersistKey(void) {
    xmlSecImportPersistKey = 1;
}

/**
 * @brief Gets global flag for importing keys to persistent storage.
 * @details Gets global flag to import keys to persistent storage (MSCrypto and MSCNG).
 * Also see PKCS12_NO_PERSIST_KEY.
 *
 * @return 1 if keys should be imported into persistent storage and 0 otherwise.
 */
int xmlSecImportGetPersistKey(void) {
    return xmlSecImportPersistKey;
}
