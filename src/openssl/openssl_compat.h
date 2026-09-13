/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @brief Compatibility layer for various OpenSSL versions.
 */

#ifndef XMLSEC_OPENSSL_COMPAT_H
#define XMLSEC_OPENSSL_COMPAT_H

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <xmlsec/xmlsec.h>

#include "../cast_helpers.h"

/* internal helpers */
int             xmlSecOpenSSLGenerateRandomBytes             (xmlSecByte* data, xmlSecSize size);


/******************************************************************************
 *
 * boringssl and aws-lc compatibility
 *
  *****************************************************************************/
#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)

/* Not implemented by BoringSSL/AWS-LC (yet?) */
#define XMLSEC_OPENSSL_NO_ASN1_TIME_TO_TM   1
#define XMLSEC_OPENSSL_NO_STORE             1
#define XMLSEC_OPENSSL_NO_DEEP_COPY         1

#ifndef ENGINE_cleanup
#define ENGINE_cleanup()                    {}
#endif

#ifndef RAND_priv_bytes
#define RAND_priv_bytes(buf,len)            RAND_bytes((buf), (len))
#endif
#ifndef RAND_write_file
#define RAND_write_file(file)               (1)
#endif

#ifndef EVP_PKEY_base_id
#define EVP_PKEY_base_id(pkey)              EVP_PKEY_id(pkey)
#endif
#ifndef EVP_CipherFinal
#define EVP_CipherFinal(ctx, out, out_len)  EVP_CipherFinal_ex((ctx), (out), (out_len))
#endif
#ifndef EVP_read_pw_string
#define EVP_read_pw_string(buf, len, prompt, verify)     (-1)
#endif

/* simply return success */
#ifndef sk_X509_reserve
#define sk_X509_reserve(crts, num)          (1)
#endif
#ifndef sk_X509_CRL_reserve
#define sk_X509_CRL_reserve(crls, num)      (1)
#endif

#endif /* defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC) */

/* BoringSSL redefines int->size_t or int->unsigned */
#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)

/* when BoringSSL replaced int with unsigned */
typedef unsigned xmlSecOpenSSLUInt;

#define XMLSEC_OPENSSL_SAFE_CAST_UINT_TO_SIZE(srcVal, dstVal, errorAction, errorObject) \
       XMLSEC_SAFE_CAST_UINT_TO_SIZE((srcVal), (dstVal), errorAction, (errorObject))

#define XMLSEC_OPENSSL_SAFE_CAST_SIZE_TO_UINT(srcVal, dstVal, errorAction, errorObject) \
       XMLSEC_SAFE_CAST_SIZE_TO_UINT((srcVal), (dstVal), errorAction, (errorObject))

#define XMLSEC_OPENSSL_SAFE_CAST_UINT_TO_BYTE(srcVal, dstVal, errorAction, errorObject) \
       XMLSEC_SAFE_CAST_UINT_TO_BYTE((srcVal), (dstVal), errorAction, (errorObject))

/* when BoringSSL replaced int with size_t */
typedef size_t xmlSecOpenSSLSizeT;

#define XMLSEC_OPENSSL_SAFE_CAST_SIZE_T_TO_SIZE(srcVal, dstVal, errorAction, errorObject) \
       (dstVal) = (srcVal)

#define XMLSEC_OPENSSL_SAFE_CAST_SIZE_TO_SIZE_T(srcVal, dstVal, errorAction, errorObject) \
       (dstVal) = (srcVal)

#define XMLSEC_OPENSSL_SAFE_CAST_SIZE_T_TO_UINT(srcVal, dstVal, errorAction, errorObject) \
       XMLSEC_SAFE_CAST_SIZE_T_TO_UINT((srcVal), (dstVal), errorAction, (errorObject))

#define XMLSEC_OPENSSL_SAFE_CAST_SIZE_T_TO_INT(srcVal, dstVal, errorAction, errorObject) \
       XMLSEC_SAFE_CAST_SIZE_T_TO_INT((srcVal), (dstVal), errorAction, (errorObject))

#else /* defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC) */

/* plain int type (no BoringSSL/AWS-LC redefinition) */
typedef int xmlSecOpenSSLUInt;

#define XMLSEC_OPENSSL_SAFE_CAST_UINT_TO_SIZE(srcVal, dstVal, errorAction, errorObject) \
       XMLSEC_SAFE_CAST_INT_TO_SIZE((srcVal), (dstVal), errorAction, (errorObject))

#define XMLSEC_OPENSSL_SAFE_CAST_SIZE_TO_UINT(srcVal, dstVal, errorAction, errorObject) \
       XMLSEC_SAFE_CAST_SIZE_TO_INT((srcVal), (dstVal), errorAction, (errorObject))

#define XMLSEC_OPENSSL_SAFE_CAST_UINT_TO_BYTE(srcVal, dstVal, errorAction, errorObject) \
       XMLSEC_SAFE_CAST_INT_TO_BYTE((srcVal), (dstVal), errorAction, (errorObject))

/* plain int type (no BoringSSL/AWS-LC redefinition) */
typedef int xmlSecOpenSSLSizeT;

#define XMLSEC_OPENSSL_SAFE_CAST_SIZE_T_TO_SIZE(srcVal, dstVal, errorAction, errorObject) \
       XMLSEC_SAFE_CAST_INT_TO_SIZE((srcVal), (dstVal), errorAction, (errorObject))

#define XMLSEC_OPENSSL_SAFE_CAST_SIZE_TO_SIZE_T(srcVal, dstVal, errorAction, errorObject) \
       XMLSEC_SAFE_CAST_SIZE_TO_INT((srcVal), (dstVal), errorAction, (errorObject))

#define XMLSEC_OPENSSL_SAFE_CAST_SIZE_T_TO_UINT(srcVal, dstVal, errorAction, errorObject) \
       XMLSEC_SAFE_CAST_INT_TO_UINT((srcVal), (dstVal), errorAction, (errorObject))

#define XMLSEC_OPENSSL_SAFE_CAST_SIZE_T_TO_INT(srcVal, dstVal, errorAction, errorObject) \
        (dstVal) = (srcVal)

#endif /* defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC) */


/******************************************************************************
 *
 * LibreSSL compatibility (implements most of OpenSSL 1.1 API)
 *
  *****************************************************************************/
#if defined(LIBRESSL_VERSION_NUMBER)

/* Not implemented by LibreSSL (yet?) */
#define XMLSEC_OPENSSL_NO_ASN1_TIME_TO_TM   1
#define XMLSEC_OPENSSL_NO_STORE             1
#define XMLSEC_OPENSSL_NO_PWD_CALLBACK      1
#define XMLSEC_OPENSSL_NO_DEEP_COPY         1

#ifndef RAND_priv_bytes
#define RAND_priv_bytes(buf,len)            RAND_bytes((buf), (len))
#endif

/* simply return success */
#ifndef sk_X509_reserve
#define sk_X509_reserve(crts, num)          (1)
#endif
#ifndef sk_X509_CRL_reserve
#define sk_X509_CRL_reserve(crls, num)      (1)
#endif

#endif /* defined(LIBRESSL_VERSION_NUMBER) */

/******************************************************************************
 *
 * OpenSSL 4.0.0 compatibility
 *
  *****************************************************************************/
#if !defined(XMLSEC_OPENSSL_API_400)
#define XMLSEC_OPENSSL400_CONST
#else   /* !defined(XMLSEC_OPENSSL_API_400) */
/* OpenSSL 4.0.0 or newer adds "const" in a few places */
#define XMLSEC_OPENSSL400_CONST  const
#endif /* !defined(XMLSEC_OPENSSL_API_400) */

/******************************************************************************
 *
 * OpenSSL 3.0.0 compatibility
 *
  *****************************************************************************/
#if !defined(XMLSEC_OPENSSL_API_300)

#define BIO_new_ex(libctx,type)                                     BIO_new((type))
#define PEM_read_bio_PrivateKey_ex(bp,x,cb,u,libctx,propq)          PEM_read_bio_PrivateKey((bp),(x),(cb),(u))
#define PEM_read_bio_PUBKEY_ex(bp,x,cb,u,libctx,propq)              PEM_read_bio_PUBKEY((bp),(x),(cb),(u))
#define d2i_PrivateKey_ex_bio(bp,a,libctx,propq)                    d2i_PrivateKey_bio((bp),(a))

#define EVP_SignFinal_ex(ctx,md,s,pkey,libctx,propq)                EVP_SignFinal((ctx),(md),(s),(pkey))
#define EVP_VerifyFinal_ex(ctx,sigbuf,siglen,pkey,libctx,propq)     EVP_VerifyFinal((ctx),(sigbuf),(siglen),(pkey))

#define X509_new_ex(libctx,propq)                                   X509_new()
#define X509_CRL_new_ex(libctx,propq)                               X509_CRL_new()
#define X509_STORE_CTX_new_ex(libctx,propq)                         X509_STORE_CTX_new()
#define X509_STORE_set_default_paths_ex(ctx,libctx,propq)           X509_STORE_set_default_paths((ctx))
#define X509_NAME_hash_ex(x,libctx,propq,ok)                        X509_NAME_hash((x))

#endif /* !defined(XMLSEC_OPENSSL_API_300) */


/******************************************************************************
 *
 * Common constants that aren't defined anywhere.
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_GOST
#define XMLSEC_OPENSSL_DIGEST_NAME_GOST94       "md_gost94"
#endif /* XMLSEC_NO_GOST */

#ifndef XMLSEC_NO_GOST2012
#define XMLSEC_OPENSSL_DIGEST_NAME_GOST12_256   "md_gost12_256"
#define XMLSEC_OPENSSL_DIGEST_NAME_GOST12_512   "md_gost12_512"
#endif /* XMLSEC_NO_GOST2012 */


#ifdef XMLSEC_OPENSSL_API_300

/* Cipher names, hopefully OpenSSL defines them one day */
#define XMLSEC_OPENSSL_CIPHER_NAME_DES3_EDE         "DES3"
#define XMLSEC_OPENSSL_CIPHER_NAME_AES128_CBC       "AES-128-CBC"
#define XMLSEC_OPENSSL_CIPHER_NAME_AES192_CBC       "AES-192-CBC"
#define XMLSEC_OPENSSL_CIPHER_NAME_AES256_CBC       "AES-256-CBC"
#define XMLSEC_OPENSSL_CIPHER_NAME_AES128_GCM       "AES-128-GCM"
#define XMLSEC_OPENSSL_CIPHER_NAME_AES192_GCM       "AES-192-GCM"
#define XMLSEC_OPENSSL_CIPHER_NAME_AES256_GCM       "AES-256-GCM"


#endif /* XMLSEC_OPENSSL_API_300 */


#endif /* XMLSEC_OPENSSL_COMPAT_H */
