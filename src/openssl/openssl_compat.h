#ifndef __XMLSEC_OPENSSL_OPENSSL_COMPAT_H__
#define __XMLSEC_OPENSSL_OPENSSL_COMPAT_H__
/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This file provides a compatibility layer for pre-OpenSSL 1.1.0 versions.
 *
 * The functions here provide accessors for structs which were made opaque in
 * 1.0.0 and 1.1.0 so they an be accessed in earlier versions of the library
 * using the same syntax. This file won't be required once OpenSSL 1.1.0 is
 * the minimum supported version. Note that LibreSSL "forked" at OpenSSL 1.0.0.
 */

/******************************************************************************
 *
 * OpenSSL 1.1.0 compatibility
 *
 *****************************************************************************/
#if !defined(XMLSEC_OPENSSL_API_110)

/* EVP_PKEY stuff */
#define EVP_PKEY_up_ref(pKey)              CRYPTO_add(&((pKey)->references), 1, CRYPTO_LOCK_EVP_PKEY)
#define EVP_PKEY_get0_DSA(pKey)            (((pKey) != NULL) ? ((pKey)->pkey.dsa) : (DSA*)NULL)
#define EVP_PKEY_get0_RSA(pKey)            (((pKey) != NULL) ? ((pKey)->pkey.rsa) : (RSA*)NULL)
#define EVP_PKEY_get0_EC_KEY(pKey)         (((pKey) != NULL) ? ((pKey)->pkey.ec)  : (EC_KEY*)NULL)

/* EVP_MD stuff */
#define EVP_MD_CTX_new()                   EVP_MD_CTX_create()
#define EVP_MD_CTX_free(x)                 EVP_MD_CTX_destroy((x))
#define EVP_MD_CTX_md_data(x)              ((x)->md_data)

/* EVP_CIPHER_CTX stuff */
#define EVP_CIPHER_CTX_encrypting(x)       ((x)->encrypt)

/* HMAC_CTX stuff */
#define HMAC_CTX_new()                     ((HMAC_CTX*)calloc(1, sizeof(HMAC_CTX)))
#define HMAC_CTX_free(x)                   { HMAC_CTX_cleanup((x)); free((x)); }

/* X509 stuff */
#define ASN1_STRING_get0_data(data)        ASN1_STRING_data((data))
#define X509_CRL_get0_nextUpdate(crl)      X509_CRL_get_nextUpdate((crl))
#define X509_get0_notBefore(x509)          X509_get_notBefore((x509))
#define X509_get0_notAfter(x509)           X509_get_notAfter((x509))
#define X509_STORE_CTX_get_by_subject      X509_STORE_get_by_subject
#define X509_REVOKED_get0_serialNumber(r)  (((r) != NULL) ? ((r)->serialNumber) : (ASN1_INTEGER *)NULL)
#define X509_OBJECT_new()                  (calloc(1, sizeof(X509_OBJECT)))
#define X509_OBJECT_free(x)                { X509_OBJECT_free_contents(x); free(x); }
#define X509_OBJECT_get0_X509(x)           (((x) != NULL) ? ((x)->data.x509) : (X509 *)NULL)

#endif /* !defined(XMLSEC_OPENSSL_API_110) */

/******************************************************************************
 *
 * boringssl compatibility
 *
 *****************************************************************************/
#ifdef OPENSSL_IS_BORINGSSL

#define ENGINE_cleanup(...)                 {}
#define CONF_modules_unload(...)            {}
#define RAND_write_file(file)               (0)

#define EVP_PKEY_base_id(pkey)             EVP_PKEY_id(pkey)
#define EVP_CipherFinal(ctx, out, out_len) EVP_CipherFinal_ex(ctx, out, out_len)
#define EVP_read_pw_string(...)             (-1)

#define X509_STORE_CTX_get_by_subject      X509_STORE_get_by_subject
#define X509_OBJECT_new()                  (calloc(1, sizeof(X509_OBJECT)))
#define X509_OBJECT_free(x)                { X509_OBJECT_free_contents(x); free(x); }

#endif /* OPENSSL_IS_BORINGSSL */

/******************************************************************************
 *
 * LibreSSL 2.7 compatibility (implements most of OpenSSL 1.1 API)
 *
 *****************************************************************************/
#if defined(LIBRESSL_VERSION_NUMBER) && defined(XMLSEC_OPENSSL_API_110)
/* EVP_CIPHER_CTX stuff */
#define EVP_CIPHER_CTX_encrypting(x)       ((x)->encrypt)

/* X509 stuff */
#define X509_STORE_CTX_get_by_subject      X509_STORE_get_by_subject
#define X509_OBJECT_new()                  (calloc(1, sizeof(X509_OBJECT)))
#define X509_OBJECT_free(x)                { X509_OBJECT_free_contents(x); free(x); }
#endif /* defined(LIBRESSL_VERSION_NUMBER) && defined(XMLSEC_OPENSSL_API_110) */

#endif /* __XMLSEC_OPENSSL_OPENSSL_COMPAT_H__ */
