/** 
 * XMLSec library
 *
 * Keys
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <string.h>
 
#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysInternal.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/x509.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/errors.h>



/***************************************************************************
 *
 * xmlSecKey
 *
 **************************************************************************/
xmlSecKeyPtr
xmlSecKeyCreate(xmlSecKeyValuePtr value, const xmlChar* name)  {
    xmlSecKeyPtr key;

    /*
     * Allocate a new xmlSecKey and fill the fields.
     */
    key = (xmlSecKeyPtr) xmlMalloc(sizeof(xmlSecKey));
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecKey)=%d", 
		    sizeof(xmlSecKey));
	return(NULL);
    }
    memset(key, 0, sizeof(xmlSecKey));

    /* dup value */    
    if(value != NULL) {
	key->value = xmlSecKeyValueDuplicate(value, 0);
	if(key->value == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyValueDuplicate");
	    xmlSecKeyDestroy(key);
	    return(NULL);	
	}
    }
    /* dup name */    
    if(name != NULL) {
	key->name = xmlStrdup(name);
	if(key->name == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "xmlStrdup(\"%s\")", name);
	    xmlSecKeyDestroy(key);
	    return(NULL);	
	}
    }
    
    return(key);    
}

void
xmlSecKeyDestroy(xmlSecKeyPtr key) {
    xmlSecAssert(key != NULL);

    if(key->value != NULL) {
	xmlSecKeyValueDestroy(key->value);
    }
    if(key->name != NULL) {
	xmlFree(key->name);
    }
    if(key->x509Data != NULL) {
	xmlSecKeyDataDestroy(key->x509Data);
    }
    if(key->pgpData != NULL) {
	xmlSecKeyDataDestroy(key->pgpData);
    }
    
    memset(key, 0, sizeof(xmlSecKey));
    xmlFree(key);    
}

xmlSecKeyPtr
xmlSecKeyDuplicate(xmlSecKeyPtr key) {
    xmlSecKeyPtr newKey = NULL;
    
    xmlSecAssert2(key != NULL, NULL);
    
    newKey = xmlSecKeyCreate(key->value, key->name);
    if(newKey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyCreate");
	return(NULL);	
    }
    /* dup x509 */    
    if(key->x509Data != NULL) {
	newKey->x509Data = xmlSecKeyDataDuplicate(key->x509Data);
	if(newKey->x509Data == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyDataDuplicate(x509Data)");
	    xmlSecKeyDestroy(newKey);
	    return(NULL);	
	}
    }

    /* dup pgp */    
    if(key->pgpData != NULL) {
	newKey->pgpData = xmlSecKeyDataDuplicate(key->pgpData);
	if(newKey->pgpData == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyDataDuplicate(pgpData)");
	    xmlSecKeyDestroy(newKey);
	    return(NULL);	
	}
    }
    
    return(newKey);
}

/**
 * xmlSecKeyCheck:
 * @key: the pointer to the #xmlSecKey structure.
 * @name: the pointer to key name (may be NULL).
 * @id: the key id (may be "any").
 * @type: the key type to write (public/private).
 * 
 * Checks whether the @key matches the given criteria
 * (key name is equal to @name, key id is equal to @id,
 * key type is @type).
 *
 * Returns 1 if the key satisfies the given criteria or 0 otherwise.
 */
int
xmlSecKeyCheck(xmlSecKeyPtr key, const xmlChar *name, xmlSecKeyValueId id, 
		xmlSecKeyValueType type) {
    xmlSecAssert2(key != NULL, -1);
    
    /* todo:  */
    if(key->value == NULL) {
	return(0);
    }
    
    if((id != xmlSecKeyValueIdUnknown) && (id != key->value->id)) {
	return(0);
    }
    if((type != xmlSecKeyValueTypeAny) && 
       (key->value->type != type) && 
       (key->value->type != xmlSecKeyValueTypePrivate)) {
	 return(0);
    }
    if((name != NULL) && (!xmlStrEqual(key->name, name))) {
	return(0);
    }
    return(1);
}

void
xmlSecKeyDebugDump(xmlSecKeyPtr key, FILE *output) {
    xmlSecAssert(key != NULL);
    xmlSecAssert(output != NULL);

    fprintf(output, "== KEY\n");
    fprintf(output, "=== key name: %s\n", 
	    (key->name != NULL) ? 
	    (char*)(key->name) : "NULL"); 
    if(key->value != NULL) {
	xmlSecKeyValueDebugDump(key->value, output);
    }	    
    fprintf(output, "=== key origin:");
    if(key->origin & xmlSecKeyOriginKeyManager) {
	fprintf(output, " KeyManager");
    }
    if(key->origin & xmlSecKeyOriginKeyName) {
	fprintf(output, " KeyName");
    }
    if(key->origin & xmlSecKeyOriginKeyValue) {
	fprintf(output, " KeyValue");
    }
    if(key->origin & xmlSecKeyOriginRetrievalDocument) {
	fprintf(output, " RetrievalDocument");
    }
    if(key->origin & xmlSecKeyOriginRetrievalRemote) {
	fprintf(output, " RetrievalRemote");
    }
    if(key->origin & xmlSecKeyOriginX509) {
	fprintf(output, " x509");
    }
    if(key->origin & xmlSecKeyOriginEncryptedKey) {
	fprintf(output, " EncKey");
    }
    if(key->origin & xmlSecKeyOriginPGP) {
	fprintf(output, " PGP");
    }
    fprintf(output, "\n");

    /* todo:
    if(key->x509Data != NULL) {
	xmlSecKeyDataDebugDump(key->x509Data, output);
    }
    if(key->pgpData != NULL) {
	xmlSecKeyDataDebugDump(key->pgpData, output);
    }	
    */
}

void
xmlSecKeyDebugXmlDump(xmlSecKeyPtr key, FILE *output) {
    xmlSecAssert(key != NULL);
    xmlSecAssert(output != NULL);
    
    fprintf(output, "<KeyInfo>\n");
    if(key->name != NULL) {
	fprintf(output, "<KeyName>%s</KeyName>\n", 
	        key->name);
    }
    if(key->value != NULL) {
	xmlSecKeyValueDebugXmlDump(key->value, output);
    }	    
    fprintf(output, "<KeyOrigins>\n");
    if(key->origin & xmlSecKeyOriginKeyManager) {
	fprintf(output, "<KeyOrigin>KeyManager</KeyOrigin>\n");
    }
    if(key->origin & xmlSecKeyOriginKeyName) {
	fprintf(output, "<KeyOrigin>KeyName</KeyOrigin>\n");
    }
    if(key->origin & xmlSecKeyOriginKeyValue) {
	fprintf(output, "<KeyOrigin>KeyValue</KeyOrigin>\n");
    }
    if(key->origin & xmlSecKeyOriginRetrievalDocument) {
	fprintf(output, "<KeyOrigin>RetrievalDocument</KeyOrigin>\n");
    }
    if(key->origin & xmlSecKeyOriginRetrievalRemote) {
	fprintf(output, "<KeyOrigin>RetrievalRemote</KeyOrigin>\n");
    }
    if(key->origin & xmlSecKeyOriginX509) {
	fprintf(output, "<KeyOrigin>x509</KeyOrigin>\n");
    }
    if(key->origin & xmlSecKeyOriginEncryptedKey) {
	fprintf(output, "<KeyOrigin>EncKey</KeyOrigin>\n");
    }
    if(key->origin & xmlSecKeyOriginPGP) {
	fprintf(output, "<KeyOrigin>PGP</KeyOrigin>\n");
    }
    fprintf(output, "</KeyOrigins>\n");
    
    /* todo:
    if(key->x509Data != NULL) {
	xmlSecKeyDataDebugXmlDump(key->x509Data, output);
    }
    if(key->pgpData != NULL) {
	xmlSecKeyDataDebugXmlDump(key->pgpData, output);
    }	
    */
    fprintf(output, "</KeyInfo>\n"); 
}

/***************************************************************************
 *
 * xmlSecKeyData
 *
 **************************************************************************/
xmlSecKeyDataPtr
xmlSecKeyDataCreate(xmlSecKeyDataId id) {
    xmlSecKeyDataPtr data;
    
    xmlSecAssert2(id != NULL, NULL);
    xmlSecAssert2(id->create != NULL, NULL);
    
    data = id->create(id);
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "id->create");
	return(NULL);	
    }
    return(data);
}

void
xmlSecKeyDataDestroy(xmlSecKeyDataPtr data) {
    xmlSecAssert(data != NULL);    
    xmlSecAssert(data->id != NULL);    
    xmlSecAssert(data->id->destroy != NULL);    

    if(!xmlSecKeyDataIsValid(data)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    " ");
	return;
    }
    
    data->id->destroy(data);
}

xmlSecKeyDataPtr
xmlSecKeyDataDuplicate(xmlSecKeyDataPtr data) {
    xmlSecKeyDataPtr newData;

    xmlSecAssert2(data != NULL, NULL);
    xmlSecAssert2(data->id != NULL, NULL);
    xmlSecAssert2(data->id->duplicate != NULL, NULL);
    
    if(!xmlSecKeyDataIsValid(data)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    " ");
	return(NULL);	
    }
    
    newData = data->id->duplicate(data);
    if(newData == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "id->duplicate");
	return(NULL);	
    }
    return(newData);
}

















/**
 * xmlSecKeysMngrGetKey:
 * @keyInfoNode: the pointer to <dsig:KeyInfo> node.
 * @mngr: the keys manager.
 * @context: the pointer to application specific data.
 * @keyId: the required key Id (or NULL for "any").
 * @keyType: the required key (may be "any").
 * @keyUsage: the required key usage.
 * 
 * Reads the <dsig:KeyInfo> node @keyInfoNode and extracts the key.
 *
 * Returns the pointer to key or NULL if the key is not found or 
 * an error occurs.
 */
xmlSecKeyPtr 		
xmlSecKeysMngrGetKey(xmlNodePtr keyInfoNode, xmlSecKeysMngrPtr mngr, void *context,
		xmlSecKeyValueId keyId, xmlSecKeyValueType keyType, xmlSecKeyUsage keyUsage,
		time_t certsVerificationTime) {
    xmlSecKeyPtr key = NULL;
        
    xmlSecAssert2(mngr != NULL, NULL);

    if((key == NULL) && (keyInfoNode != NULL)) {
	key = xmlSecKeyInfoNodeRead(keyInfoNode, mngr, context,
			keyId, keyType, keyUsage, certsVerificationTime);
    }
    
    if((key == NULL) && (mngr->allowedOrigins & xmlSecKeyOriginKeyManager) && 
			(mngr->findKey != NULL)) {
	key = mngr->findKey(mngr, context, NULL, keyId, keyType, keyUsage);
    }
    
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_KEY_NOT_FOUND,
		    " ");
	return(NULL);    
    }
    
    return(key);
}


