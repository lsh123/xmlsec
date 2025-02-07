/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This file provides a compatibility layer for various OpenSSL versions.
 */

#ifndef __XMLSEC_OPENSSL_OPENSSL_COMPAT_H__
#define __XMLSEC_OPENSSL_OPENSSL_COMPAT_H__

#include <openssl/rand.h>

#include "../cast_helpers.h"


/******************************************************************************
 *
 * boringssl compatibility
 *
 *****************************************************************************/
#ifdef OPENSSL_IS_BORINGSSL

/* Not implemented by LibreSSL (yet?) */
#define XMLSEC_OPENSSL_NO_ASN1_TIME_TO_TM   1
#define XMLSEC_OPENSSL_NO_STORE             1
#define XMLSEC_OPENSSL_NO_DEEP_COPY         1
#define XMLSEC_OPENSSL_NO_CRL_VERIFICATION  1
#define XMLSEC_NO_RSA_OAEP                  1
#define XMLSEC_NO_DH                        1
#define XMLSEC_NO_DSA                       1
#define XMLSEC_NO_SHA3                      1


#define EVP_CIPHER_key_length   (int)EVP_CIPHER_key_length
#define EVP_CIPHER_iv_length    (int)EVP_CIPHER_iv_length
#define EVP_CIPHER_block_size   (int)EVP_CIPHER_block_size

#define ECDSA_do_verify(digest, digest_len, sig, key) \
    ECDSA_do_verify(digest, (size_t)(digest_len), sig, key)
#define ECDSA_do_sign(digest, digest_len, key) \
    ECDSA_do_sign(digest, (size_t)(digest_len), key)

#define HMAC_Init_ex(ctx, key, key_len, md, impl) \
       HMAC_Init_ex(ctx, key, (size_t)(key_len), md, impl)
#define AES_set_encrypt_key(user_key, bits, aes_key) \
       AES_set_encrypt_key(user_key, (unsigned)(bits), aes_key)
#define AES_set_decrypt_key(user_key, bits, aes_key) \
       AES_set_decrypt_key(user_key, (unsigned)(bits), aes_key)

#define RSA_public_encrypt(flen, from, to, rsa, padding) \
       RSA_public_encrypt((size_t)(flen), from, to, rsa, padding)
#define RSA_private_decrypt(flen, from, to, rsa, padding) \
       RSA_private_decrypt((size_t)(flen), from, to, rsa, padding)


#define EVP_MD_size (int)EVP_MD_size
#define RSA_size    (int)RSA_size

#define BN_num_bytes (int)BN_num_bytes
#define BN_num_bits  (int)BN_num_bits
#define BN_bn2bin    (int)BN_bn2bin
#define BN_bin2bn(in, len, ret) BN_bin2bn(in, (size_t)(len), ret)

#define sk_X509_insert   (int)sk_X509_insert
#define sk_X509_push     (int)sk_X509_push
#define sk_X509_num      (int)sk_X509_num
#define sk_X509_CRL_num  (int)sk_X509_CRL_num
#define sk_X509_CRL_push (int)sk_X509_CRL_push
#define sk_X509_CRL_value(sk, idx)        sk_X509_CRL_value(sk, (size_t)(idx))
#define sk_X509_value(sk, idx)            sk_X509_value(sk, (size_t)(idx))
#define sk_X509_NAME_ENTRY_value(sk, idx) sk_X509_NAME_ENTRY_value(sk, (size_t)(idx))
#define sk_X509_REVOKED_value(sk, idx)    sk_X509_REVOKED_value(sk, (size_t)(idx))

#define BIO_pending      (int)BIO_pending

#define sk_X509_NAME_ENTRY_num (int)sk_X509_NAME_ENTRY_num
#define sk_X509_NAME_ENTRY_push (int)sk_X509_NAME_ENTRY_push

#define ENGINE_cleanup(...)                 {}
#define CONF_modules_unload(...)            {}

#define RAND_priv_bytes(buf,len)            RAND_bytes((buf), (size_t)(len))
#define RAND_write_file(file)               (0)

#define EVP_PKEY_base_id(pkey)              EVP_PKEY_id(pkey)
#define EVP_CipherFinal(ctx, out, out_len)  EVP_CipherFinal_ex(ctx, out, out_len)
#define EVP_read_pw_string(...)             (-1)

#define X509_get0_pubkey(cert)              X509_get_pubkey((cert))
#define X509_STORE_CTX_get_by_subject       X509_STORE_get_by_subject

/* simply return success */
#define sk_X509_reserve(crts, num)          (1)
#define sk_X509_CRL_reserve(crls, num)      (1)

#endif /* OPENSSL_IS_BORINGSSL */

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
#define XMLSEC_NO_DH                        1

#define RAND_priv_bytes(buf,len)            RAND_bytes((buf), (len))

/* simply return success */
#define sk_X509_reserve(crts, num)          (1)
#define sk_X509_CRL_reserve(crls, num)      (1)

#if (LIBRESSL_VERSION_NUMBER < 0x3080000fL)
#define XMLSEC_NO_SHA3                      1
#endif /* (LIBRESSL_VERSION_NUMBER < 0x3080000fL) */

#if (LIBRESSL_VERSION_NUMBER < 0x3070200fL)
#define UI_null()                           NULL
#endif /* (LIBRESSL_VERSION_NUMBER < 0x3070200fL) */

#endif /* defined(LIBRESSL_VERSION_NUMBER) */


/******************************************************************************
 *
 * OpenSSL 3.0.0 compatibility
 *
 *****************************************************************************/
#if !defined(XMLSEC_OPENSSL_API_300)

/* ConcatKDF (SSKDF) key derivation algorithm is only available on OpenSSL 3.0.0 or above
 * (https://www.openssl.org/docs/man3.0/man7/EVP_KDF-SS.html)
 */
#define XMLSEC_NO_CONCATKDF     1

/* PBKDF2 key derivation algorithm is only available on OpenSSL 3.0.0 or above
 * (https://www.openssl.org/docs/man3.0/man7/EVP_KDF-PBKDF2.html)
 */
#define XMLSEC_NO_PBKDF2        1

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

#define RAND_priv_bytes_ex(ctx,buf,num,strength)                    xmlSecOpenSSLCompatRand((buf),(num))
static inline int xmlSecOpenSSLCompatRand(unsigned char *buf, xmlSecSize size) {
    int num;
    XMLSEC_SAFE_CAST_SIZE_TO_INT(size, num, return(0), NULL);
    return(RAND_priv_bytes(buf, num));
}

#endif /* !defined(XMLSEC_OPENSSL_API_300) */


/******************************************************************************
 *
 * Common constants that aren't defined anywhere.
 *
 *****************************************************************************/
#ifndef XMLSEC_NO_GOST
#define XMLSEC_OPENSSL_DIGEST_NAME_GOST94       "md_gost94"
#endif /* XMLSEC_NO_GOST*/

#ifndef XMLSEC_NO_GOST2012
#define XMLSEC_OPENSSL_DIGEST_NAME_GOST12_256   "md_gost12_256"
#define XMLSEC_OPENSSL_DIGEST_NAME_GOST12_512   "md_gost12_512"
#endif /* XMLSEC_NO_GOST2012 */


#ifdef XMLSEC_OPENSSL_API_300
#define XMLSEEC_OPENSSL_RAND_BYTES_STRENGTH     0

/* Cipher names, hopefully OpenSSL defines them one day */
#define XMLSEEC_OPENSSL_CIPHER_NAME_DES3_EDE    "DES3"
#define XMLSEEC_OPENSSL_CIPHER_NAME_AES128_CBC  "AES-128-CBC"
#define XMLSEEC_OPENSSL_CIPHER_NAME_AES192_CBC  "AES-192-CBC"
#define XMLSEEC_OPENSSL_CIPHER_NAME_AES256_CBC  "AES-256-CBC"
#define XMLSEEC_OPENSSL_CIPHER_NAME_AES128_GCM  "AES-128-GCM"
#define XMLSEEC_OPENSSL_CIPHER_NAME_AES192_GCM  "AES-192-GCM"
#define XMLSEEC_OPENSSL_CIPHER_NAME_AES256_GCM  "AES-256-GCM"

#endif /* XMLSEC_OPENSSL_API_300 */


#endif /* __XMLSEC_OPENSSL_OPENSSL_COMPAT_H__ */
