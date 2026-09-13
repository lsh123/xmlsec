/**
 * @file bcrypt.h
 * @brief Stub bcrypt.h for doxygen documentation generation on non-Windows platforms.
 */
#ifndef XMLSEC_DOXYGEN_BCRYPT_H
#define XMLSEC_DOXYGEN_BCRYPT_H

/* BCRYPT_ALG_HANDLE and BCRYPT_KEY_HANDLE are provided by the windows.h stub. */

typedef void*           BCRYPT_HASH_HANDLE;
typedef void*           BCRYPT_SECRET_HANDLE;

typedef struct _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
    unsigned long       cbSize;
    unsigned long       dwInfoVersion;
    unsigned char*      pbNonce;
    unsigned long       cbNonce;
    unsigned char*      pbAuthData;
    unsigned long       cbAuthData;
    unsigned char*      pbTag;
    unsigned long       cbTag;
    unsigned char*      pbMacContext;
    unsigned long       cbMacContext;
    unsigned long       cbAAD;
    unsigned long long  cbData;
    unsigned long       dwFlags;
} BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO;

typedef struct _BCRYPT_AUTH_TAG_LENGTHS_STRUCT {
    unsigned long   dwMinLength;
    unsigned long   dwMaxLength;
    unsigned long   dwIncrement;
} BCRYPT_AUTH_TAG_LENGTHS_STRUCT;

typedef struct _BCRYPT_KEY_LENGTHS_STRUCT {
    unsigned long   dwMinLength;
    unsigned long   dwMaxLength;
    unsigned long   dwIncrement;
} BCRYPT_KEY_LENGTHS_STRUCT;

typedef struct _BCRYPT_DH_KEY_BLOB {
    unsigned long   dwMagic;
    unsigned long   cbKey;
} BCRYPT_DH_KEY_BLOB;

typedef struct _BCRYPT_DH_PRIVATE_BLOB {
    unsigned long   dwMagic;
    unsigned long   cbKey;
} BCRYPT_DH_PRIVATE_BLOB;

typedef struct _BCRYPT_DH_PUBLIC_BLOB {
    unsigned long   dwMagic;
    unsigned long   cbKey;
} BCRYPT_DH_PUBLIC_BLOB;

typedef struct _BCRYPT_DSA_KEY_BLOB {
    unsigned long   dwMagic;
    unsigned long   cbKey;
} BCRYPT_DSA_KEY_BLOB;

typedef struct _BCRYPT_DSA_PUBLIC_BLOB {
    unsigned long   dwMagic;
    unsigned long   cbKey;
} BCRYPT_DSA_PUBLIC_BLOB;

typedef struct _BCRYPT_ECCKEY_BLOB {
    unsigned long   dwMagic;
    unsigned long   cbKey;
} BCRYPT_ECCKEY_BLOB;

typedef struct _BCRYPT_ECCPRIVATE_BLOB {
    unsigned long   dwMagic;
    unsigned long   cbKey;
} BCRYPT_ECCPRIVATE_BLOB;

typedef struct _BCRYPT_ECCPUBLIC_BLOB {
    unsigned long   dwMagic;
    unsigned long   cbKey;
} BCRYPT_ECCPUBLIC_BLOB;

typedef struct _BCRYPT_RSAKEY_BLOB {
    unsigned long   Magic;
    unsigned long   BitLength;
    unsigned long   cbPublicExp;
    unsigned long   cbModulus;
    unsigned long   cbPrime1;
    unsigned long   cbPrime2;
} BCRYPT_RSAKEY_BLOB;

typedef struct _BCRYPT_RSAPUBLIC_BLOB {
    unsigned long   dwMagic;
    unsigned long   cbKey;
} BCRYPT_RSAPUBLIC_BLOB;

typedef struct _BCRYPT_KEY_DATA_BLOB_HEADER {
    unsigned long   dwMagic;
    unsigned long   dwVersion;
    unsigned long   cbKeyData;
} BCRYPT_KEY_DATA_BLOB_HEADER;

typedef struct _BCRYPT_KEY_DATA_BLOB {
    BCRYPT_KEY_DATA_BLOB_HEADER   header;
} BCRYPT_KEY_DATA_BLOB;

typedef struct _BCRYPT_PKCS1_PADDING_INFO {
    LPCWSTR         pszAlgId;
} BCRYPT_PKCS1_PADDING_INFO;

typedef struct _BCRYPT_PSS_PADDING_INFO {
    LPCWSTR         pszAlgId;
    unsigned long   cbSalt;
} BCRYPT_PSS_PADDING_INFO;

typedef struct _BCRYPT_OAEP_PADDING_INFO {
    LPCWSTR         pszAlgId;
    unsigned char*  pbLabel;
    unsigned long   cbLabel;
} BCRYPT_OAEP_PADDING_INFO;

#endif /* XMLSEC_DOXYGEN_BCRYPT_H */