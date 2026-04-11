# Keys manager

## Overview

Processing some key data objects requires additional information that
is global to the application (or to a particular part of it). For
example, X509 certificate processing requires a common list of trusted
certificates. The XML Security Library keeps all shared information
needed for key data processing in a collection of key data stores
called a "keys manager".

### Figure: The keys manager structure
![The keys manager structure](images/keysmngr.png)

The keys manager has a special "keys store" that lists the keys known
to the application. This "keys store" is used by the XML Security
Library to look up keys by name, type, and crypto algorithm (for
example, during
[dsig:KeyName](http://www.w3.org/TR/xmldsig-core/#sec-KeyName)
processing). The XML Security Library provides a default simple
"flat-list" implementation of a keys store. The application can
replace it with any other keys store (for example, one based on an SQL
database).

The keys manager is the only object in XML Security Library that is
intended to be shared across many operations (potentially performed in
multiple threads). Usually, a keys manager is initialized once during
application startup and is later used by XML Security Library routines
in "read-only" mode. If an application or a crypto function needs to
modify any of the key data stores inside the keys manager, proper
synchronization must be implemented. An application can also create a
new keys manager each time it needs to perform XML signature,
verification, encryption, or decryption.

## Simple keys store

The XML Security Library has a built-in simple keys store implemented
using a key list. You can use it in your application if you have a
small number of keys. However, this might not be the best option from
a performance point of view if you have many keys. In that case, you
should probably implement your own keys store using an SQL database or
some other key storage.

### Example: Initializing keys manager and loading keys from PEM files

```c

/**
 * @brief Creates a keys manager and loads PEM keys from files.
 * @details Creates a simple keys manager and loads the PEM keys from #files into it.
 * The caller is responsible for destroying returned keys manager using
 * #xmlSecKeysMngrDestroy.
 * @param files the list of filenames.
 * @param files_size the number of filenames in #files.
 * @return the pointer to newly created keys manager or NULL if an error
 * occurs.
 */
xmlSecKeysMngrPtr
load_keys(char** files, int files_size) {
    xmlSecKeysMngrPtr mngr;
    xmlSecKeyPtr key;
    int i;

    assert(files);
    assert(files_size > 0);

    /* create and initialize keys manager, we use a simple list based
     * keys manager, implement your own xmlSecKeysStore klass if you need
     * something more sophisticated
     */
    mngr = xmlSecKeysMngrCreate();
    if(mngr == NULL) {
        fprintf(stderr, "Error: failed to create keys manager.\n");
        return(NULL);
    }
    if(xmlSecCryptoAppDefaultKeysMngrInit(mngr) < 0) {
        fprintf(stderr, "Error: failed to initialize keys manager.\n");
        xmlSecKeysMngrDestroy(mngr);
        return(NULL);
    }

    for(i = 0; i < files_size; ++i) {
        assert(files[i]);

        /* load key */
        key = xmlSecCryptoAppKeyLoadEx(files[i], xmlSecKeyDataTypePrivate | xmlSecKeyDataTypePublic, xmlSecKeyDataFormatPem, NULL, NULL, NULL);
        if(key == NULL) {
            fprintf(stderr,"Error: failed to load pem key from \"%s\"\n", files[i]);
            xmlSecKeysMngrDestroy(mngr);
            return(NULL);
        }

        /* set the key name to the file name; this is only an example */
        if(xmlSecKeySetName(key, BAD_CAST files[i]) < 0) {
            fprintf(stderr,"Error: failed to set key name for key from \"%s\"\n", files[i]);
            xmlSecKeyDestroy(key);
            xmlSecKeysMngrDestroy(mngr);
            return(NULL);
        }

        /* add the key to the keys manager; from now on, the keys manager
         * is responsible for destroying it
         */
        if(xmlSecCryptoAppDefaultKeysMngrAdoptKey(mngr, key) < 0) {
            fprintf(stderr,"Error: failed to add key from \"%s\" to keys manager\n", files[i]);
            xmlSecKeyDestroy(key);
            xmlSecKeysMngrDestroy(mngr);
            return(NULL);
        }
    }

    return(mngr);
}
```

[Full program listing](../examples/verify2.md)

## Using keys manager

Instead of specifying a signature or encryption key in the
corresponding context object (`signKey` member of
[xmlSecDSigCtx](../api/xmlsec_core_xmldsig.md#xmlsecdsigctxcreate)
structure or `encKey` member of
[xmlSecEncCtx](../api/xmlsec_core_xmlenc.md#xmlsecencctxcreate)
structure), the application can use keys manager to select the
signature or encryption key. The simplest way to select a key from the
keys manager is by using
[dsig:KeyName](http://www.w3.org/TR/xmldsig-core/#sec-KeyName)
node in the template and, at the same time, adding a key with the same
name to the keys manager. Similarly, when verifying a signature or
decrypting the data,
[dsig:KeyName](http://www.w3.org/TR/xmldsig-core/#sec-KeyName)
node is used by the XML Security Library to look up the key in the keys
manager.


## Implementing a custom keys store

In many cases, the default built-in list-based keys store is not
sufficient. For example, the default XML Security Library keys store
has no synchronization and supports only "read-only" operations after
initialization. The application can implement a custom keys manager
and use it instead of the default one to improve performance,
scalability, or support multithreaded environments more effectively.

### Example: Creating a custom keys manager

```c

/**
 * @brief Creates a files-based keys manager.
 * @details Creates a files based keys manager: we assume that key name is
 * the key file name.
 * @return pointer to newly created keys manager or NULL if an error occurs.
 */
xmlSecKeysMngrPtr
create_files_keys_mngr(void) {
    xmlSecKeyStorePtr keysStore;
    xmlSecKeysMngrPtr mngr;

    /* create a file-based keys store */
    keysStore = xmlSecKeyStoreCreate(files_keys_store_get_klass());
    if(keysStore == NULL) {
        fprintf(stderr, "Error: failed to create keys store.\n");
        return(NULL);
    }

    /* create keys manager */
    mngr = xmlSecKeysMngrCreate();
    if(mngr == NULL) {
        fprintf(stderr, "Error: failed to create keys manager.\n");
        xmlSecKeyStoreDestroy(keysStore);
        return(NULL);
    }

    /* add store to keys manager, from now on keys manager destroys the store if needed */
    if(xmlSecKeysMngrAdoptKeysStore(mngr, keysStore) < 0) {
        fprintf(stderr, "Error: failed to add keys store to keys manager.\n");
        xmlSecKeyStoreDestroy(keysStore);
        xmlSecKeysMngrDestroy(mngr);
        return(NULL);
    }

    /* initialize crypto library specific data in keys manager */
    if(xmlSecCryptoKeysMngrInit(mngr) < 0) {
        fprintf(stderr, "Error: failed to initialize crypto data in keys manager.\n");
        xmlSecKeysMngrDestroy(mngr);
        return(NULL);
    }

    /* set the get key callback */
    mngr->getKey = xmlSecKeysMngrGetKey;
    return(mngr);
}

/******************************************************************************
 *
 * Files Keys Store: we assume that key's name (content of the
 * <dsig:KeyName/> element is a name of the file with a key (in the
 * current folder).
 * Attention: this probably not a good solution for high traffic systems.
 *
  *****************************************************************************/
static xmlSecKeyPtr             files_keys_store_find_key       (xmlSecKeyStorePtr store,
                                                                 const xmlChar* name,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
static xmlSecKeyStoreKlass files_keys_store_klass = {
    sizeof(xmlSecKeyStoreKlass),
    sizeof(xmlSecKeyStore),
    BAD_CAST "files-based-keys-store",  /* const xmlChar* name; */
    NULL,                               /* xmlSecKeyStoreInitializeMethod initialize; */
    NULL,                               /* xmlSecKeyStoreFinalizeMethod finalize; */
    files_keys_store_find_key,          /* xmlSecKeyStoreFindKeyMethod findKey; */
    NULL,                               /* xmlSecKeyStoreFindKeyFromX509DataMethod findKeyFromX509Data; */

    /* reserved for the future */
    NULL,                               /* void* reserved0; */
};

/**
 * @brief Gets the files-based keys store klass.
 * @details Returns the file-based keys store klass; it assumes that the key
 * name is the key file name.
 * @return the file-based keys store klass.
 */
xmlSecKeyStoreId
files_keys_store_get_klass(void) {
    return(&files_keys_store_klass);
}

/**
 * @brief Finds a key in the files-based keys store.
 * @details Looks up a key in #store. The caller is responsible for destroying
 * the returned key with #xmlSecKeyDestroy.
 * @param store the pointer to simple keys store.
 * @param name the desired key name.
 * @param keyInfoCtx the pointer to <dsig:KeyInfo/> node processing context.
 * @return pointer to key or NULL if key not found or an error occurs.
 */
static xmlSecKeyPtr
files_keys_store_find_key(xmlSecKeyStorePtr store, const xmlChar* name, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyPtr key;
    const xmlChar* p;

    assert(store);
    assert(keyInfoCtx);

    /* it is possible that the key name or desired key type is missing,
     * and there is nothing we can do in that case */
    if((name == NULL) || (keyInfoCtx->keyReq.keyId == xmlSecKeyDataIdUnknown)){
        return(NULL);
    }

    /* we do not want to open files outside the current folder;
     * to prevent that, limit the characters in the key name to letters, digits,
     * '.', '-' or '_'.
     */
    for(p = name; (*p) != '\0'; ++p) {
        if(!isalnum((*p)) && ((*p) != '.') && ((*p) != '-') && ((*p) != '_')) {
            return(NULL);
        }
    }

    if((keyInfoCtx->keyReq.keyId == xmlSecKeyDataDsaId) || (keyInfoCtx->keyReq.keyId == xmlSecKeyDataRsaId)) {
        /* load key from a pem file, if key is not found then it's an error (is it?) */
        key = xmlSecCryptoAppKeyLoadEx((const char*)name, xmlSecKeyDataTypePrivate, xmlSecKeyDataFormatPem, NULL, NULL, NULL);
        if(key == NULL) {
            fprintf(stderr,"Error: failed to load public pem key from \"%s\"\n", name);
            return(NULL);
        }
    } else {
        /* otherwise it's a binary key, if key is not found then it's an error (is it?) */
        key = xmlSecKeyReadBinaryFile(keyInfoCtx->keyReq.keyId, (const char*)name);
        if(key == NULL) {
            fprintf(stderr,"Error: failed to load key from binary file \"%s\"\n", name);
            return(NULL);
        }
    }

    /* set key name */
    if(xmlSecKeySetName(key, name) < 0) {
        fprintf(stderr,"Error: failed to set key name for key from \"%s\"\n", (const char*)name);
        xmlSecKeyDestroy(key);
        return(NULL);
    }

    return(key);
}

```
[Full program listing](../examples/decrypt3.md)

