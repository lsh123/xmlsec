/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_GCRYPT_CRYPTO_H__
#define __XMLSEC_GCRYPT_CRYPTO_H__

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/dl.h>

#include <gcrypt.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

XMLSEC_CRYPTO_EXPORT xmlSecCryptoDLFunctionsPtr xmlSecCryptoGetFunctions_gcrypt(void);

/********************************************************************
 *
 * Init shutdown
 *
 ********************************************************************/
XMLSEC_CRYPTO_EXPORT int                xmlSecGCryptInit                (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGCryptShutdown            (void);

XMLSEC_CRYPTO_EXPORT int                xmlSecGCryptKeysMngrInit        (xmlSecKeysMngrPtr mngr);
XMLSEC_CRYPTO_EXPORT int                xmlSecGCryptGenerateRandom      (xmlSecBufferPtr buffer,
                                                                         xmlSecSize size);


/********************************************************************
 *
 * AES transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_AES
/**
 * xmlSecGCryptKeyDataAesId:
 *
 * The AES key data klass.
 */
#define xmlSecGCryptKeyDataAesId \
        xmlSecGCryptKeyDataAesGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGCryptKeyDataAesGetKlass  (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGCryptKeyDataAesSet       (xmlSecKeyDataPtr data,
                                                                         const xmlSecByte* buf,
                                                                         xmlSecSize bufSize);
/**
 * xmlSecGCryptTransformAes128CbcId:
 *
 * The AES128 CBC cipher transform klass.
 */
#define xmlSecGCryptTransformAes128CbcId \
        xmlSecGCryptTransformAes128CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGCryptTransformAes128CbcGetKlass(void);

/**
 * xmlSecGCryptTransformAes192CbcId:
 *
 * The AES192 CBC cipher transform klass.
 */
#define xmlSecGCryptTransformAes192CbcId \
        xmlSecGCryptTransformAes192CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGCryptTransformAes192CbcGetKlass(void);

/**
 * xmlSecGCryptTransformAes256CbcId:
 *
 * The AES256 CBC cipher transform klass.
 */
#define xmlSecGCryptTransformAes256CbcId \
        xmlSecGCryptTransformAes256CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGCryptTransformAes256CbcGetKlass(void);

/**
 * xmlSecGCryptTransformKWAes128Id:
 *
 * The AES 128 key wrap transform klass.
 */
#define xmlSecGCryptTransformKWAes128Id \
        xmlSecGCryptTransformKWAes128GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGCryptTransformKWAes128GetKlass(void);

/**
 * xmlSecGCryptTransformKWAes192Id:
 *
 * The AES 192 key wrap transform klass.
 */
#define xmlSecGCryptTransformKWAes192Id \
        xmlSecGCryptTransformKWAes192GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGCryptTransformKWAes192GetKlass(void);

/**
 * xmlSecGCryptTransformKWAes256Id:
 *
 * The AES 256 key wrap transform klass.
 */
#define xmlSecGCryptTransformKWAes256Id \
        xmlSecGCryptTransformKWAes256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGCryptTransformKWAes256GetKlass(void);


#endif /* XMLSEC_NO_AES */

/********************************************************************
 *
 * DES transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_DES
/**
 * xmlSecGCryptKeyDataDesId:
 *
 * The DES key data klass.
 */
#define xmlSecGCryptKeyDataDesId \
        xmlSecGCryptKeyDataDesGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGCryptKeyDataDesGetKlass  (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGCryptKeyDataDesSet       (xmlSecKeyDataPtr data,
                                                                         const xmlSecByte* buf,
                                                                         xmlSecSize bufSize);

/**
 * xmlSecGCryptTransformDes3CbcId:
 *
 * The DES3 CBC cipher transform klass.
 */
#define xmlSecGCryptTransformDes3CbcId \
        xmlSecGCryptTransformDes3CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformDes3CbcGetKlass(void);

/**
 * xmlSecGCryptTransformKWDes3Id:
 *
 * The DES3 KW transform klass.
 */
#define xmlSecGCryptTransformKWDes3Id \
        xmlSecGCryptTransformKWDes3GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformKWDes3GetKlass(void);

#endif /* XMLSEC_NO_DES */

/********************************************************************
 *
 * DSA key and transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_DSA

/**
 * xmlSecGCryptKeyDataDsaId:
 *
 * The DSA key klass.
 */
#define xmlSecGCryptKeyDataDsaId \
        xmlSecGCryptKeyDataDsaGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGCryptKeyDataDsaGetKlass          (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGCryptKeyDataDsaAdoptKey          (xmlSecKeyDataPtr data,
                                                                                 gcry_sexp_t dsa_key);
XMLSEC_CRYPTO_EXPORT int                xmlSecGCryptKeyDataDsaAdoptKeyPair      (xmlSecKeyDataPtr data,
                                                                                 gcry_sexp_t pub_key,
                                                                                 gcry_sexp_t priv_key);
XMLSEC_CRYPTO_EXPORT gcry_sexp_t        xmlSecGCryptKeyDataDsaGetPublicKey      (xmlSecKeyDataPtr data);
XMLSEC_CRYPTO_EXPORT gcry_sexp_t        xmlSecGCryptKeyDataDsaGetPrivateKey     (xmlSecKeyDataPtr data);

#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecGCryptTransformDsaSha1Id:
 *
 * The DSA SHA1 signature transform klass.
 */
#define xmlSecGCryptTransformDsaSha1Id \
        xmlSecGCryptTransformDsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformDsaSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#endif /* XMLSEC_NO_DSA */


/********************************************************************
 *
 * EC key and transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_EC

/**
 * xmlSecGCryptKeyDataEcId:
 *
 * The EC key klass.
 */
#define xmlSecGCryptKeyDataEcId         xmlSecGCryptkeyDataEcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGCryptkeyDataEcGetKlass           (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGCryptKeyDataEcAdoptKey           (xmlSecKeyDataPtr data,
                                                                                 gcry_sexp_t ec_key);
XMLSEC_CRYPTO_EXPORT int                xmlSecGCryptKeyDataEcAdoptKeyPair       (xmlSecKeyDataPtr data,
                                                                                 gcry_sexp_t pub_key,
                                                                                 gcry_sexp_t priv_key);
XMLSEC_CRYPTO_EXPORT gcry_sexp_t        xmlSecGCryptKeyDataEcGetPublicKey       (xmlSecKeyDataPtr data);
XMLSEC_CRYPTO_EXPORT gcry_sexp_t        xmlSecGCryptKeyDataEcGetPrivateKey      (xmlSecKeyDataPtr data);


#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecGCryptTransformEcdsaSha1Id:
 *
 * The ECDSA-SHA1 signature transform klass.
 */
#define xmlSecGCryptTransformEcdsaSha1Id \
        xmlSecGCryptTransformEcdsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformEcdsaSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecGCryptTransformEcdsaSha256Id:
 *
 * The ECDSA-SHA2-256 signature transform klass.
 */
#define xmlSecGCryptTransformEcdsaSha256Id       \
        xmlSecGCryptTransformEcdsaSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformEcdsaSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecGCryptTransformEcdsaSha384Id:
 *
 * The ECDSA-SHA2-384 signature transform klass.
 */
#define xmlSecGCryptTransformEcdsaSha384Id       \
        xmlSecGCryptTransformEcdsaSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformEcdsaSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecGCryptTransformEcdsaSha512Id:
 *
 * The ECDSA-SHA2-512 signature transform klass.
 */
#define xmlSecGCryptTransformEcdsaSha512Id       \
        xmlSecGCryptTransformEcdsaSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformEcdsaSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */


#ifndef XMLSEC_NO_SHA3
/**
 * xmlSecGCryptTransformEcdsaSha3_256Id:
 *
 * The ECDSA-SHA3-256 signature transform klass.
 */
#define xmlSecGCryptTransformEcdsaSha3_256Id       \
        xmlSecGCryptTransformEcdsaSha3_256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformEcdsaSha3_256GetKlass(void);

/**
 * xmlSecGCryptTransformEcdsaSha3_384Id:
 *
 * The ECDSA-SHA3-384 signature transform klass.
 */
#define xmlSecGCryptTransformEcdsaSha3_384Id       \
        xmlSecGCryptTransformEcdsaSha3_384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformEcdsaSha3_384GetKlass(void);

/**
 * xmlSecGCryptTransformEcdsaSha3_512Id:
 *
 * The ECDSA-SHA3-512 signature transform klass.
 */
#define xmlSecGCryptTransformEcdsaSha3_512Id       \
        xmlSecGCryptTransformEcdsaSha3_512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformEcdsaSha3_512GetKlass(void);
#endif /* XMLSEC_NO_SHA3 */

#endif /* XMLSEC_NO_EC */

/********************************************************************
 *
 * HMAC transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_HMAC

/**
 * xmlSecGCryptKeyDataHmacId:
 *
 * The HMAC key klass.
 */
#define xmlSecGCryptKeyDataHmacId \
        xmlSecGCryptKeyDataHmacGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGCryptKeyDataHmacGetKlass (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGCryptKeyDataHmacSet      (xmlSecKeyDataPtr data,
                                                                         const xmlSecByte* buf,
                                                                         xmlSecSize bufSize);

#ifndef XMLSEC_NO_MD5
/**
 * xmlSecGCryptTransformHmacMd5Id:
 *
 * The HMAC with MD5 signature transform klass.
 */
#define xmlSecGCryptTransformHmacMd5Id \
        xmlSecGCryptTransformHmacMd5GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformHmacMd5GetKlass(void);

#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_RIPEMD160
/**
 * xmlSecGCryptTransformHmacRipemd160Id:
 *
 * The HMAC with RipeMD160 signature transform klass.
 */
#define xmlSecGCryptTransformHmacRipemd160Id \
        xmlSecGCryptTransformHmacRipemd160GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformHmacRipemd160GetKlass(void);
#endif /* XMLSEC_NO_RIPEMD160 */

#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecGCryptTransformHmacSha1Id:
 *
 * The HMAC with SHA1 signature transform klass.
 */
#define xmlSecGCryptTransformHmacSha1Id \
        xmlSecGCryptTransformHmacSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformHmacSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecGCryptTransformHmacSha256Id:
 *
 * The HMAC with SHA2-256 signature transform klass.
 */
#define xmlSecGCryptTransformHmacSha256Id \
        xmlSecGCryptTransformHmacSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformHmacSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecGCryptTransformHmacSha384Id:
 *
 * The HMAC with SHA2-384 signature transform klass.
 */
#define xmlSecGCryptTransformHmacSha384Id \
        xmlSecGCryptTransformHmacSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformHmacSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecGCryptTransformHmacSha512Id:
 *
 * The HMAC with SHA2-512 signature transform klass.
 */
#define xmlSecGCryptTransformHmacSha512Id \
        xmlSecGCryptTransformHmacSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformHmacSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_HMAC */

/********************************************************************
 *
 * RSA key and transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_RSA

/**
 * xmlSecGCryptKeyDataRsaId:
 *
 * The RSA key klass.
 */
#define xmlSecGCryptKeyDataRsaId \
        xmlSecGCryptKeyDataRsaGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGCryptKeyDataRsaGetKlass (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGCryptKeyDataRsaAdoptKey          (xmlSecKeyDataPtr data,
                                                                                 gcry_sexp_t rsa_key);
XMLSEC_CRYPTO_EXPORT int                xmlSecGCryptKeyDataRsaAdoptKeyPair      (xmlSecKeyDataPtr data,
                                                                                 gcry_sexp_t pub_key,
                                                                                 gcry_sexp_t priv_key);
XMLSEC_CRYPTO_EXPORT gcry_sexp_t        xmlSecGCryptKeyDataRsaGetPublicKey      (xmlSecKeyDataPtr data);
XMLSEC_CRYPTO_EXPORT gcry_sexp_t        xmlSecGCryptKeyDataRsaGetPrivateKey     (xmlSecKeyDataPtr data);

#ifndef XMLSEC_NO_MD5
/**
 * xmlSecGCryptTransformRsaMd5Id:
 *
 * The RSA-MD5 signature transform klass.
 */
#define xmlSecGCryptTransformRsaMd5Id  \
        xmlSecGCryptTransformRsaMd5GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformRsaMd5GetKlass(void);
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_RIPEMD160
/**
 * xmlSecGCryptTransformRsaRipemd160Id:
 *
 * The RSA-RIPEMD160 signature transform klass.
 */
#define xmlSecGCryptTransformRsaRipemd160Id    \
        xmlSecGCryptTransformRsaRipemd160GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformRsaRipemd160GetKlass(void);
#endif /* XMLSEC_NO_RIPEMD160 */

#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecGCryptTransformRsaSha1Id:
 *
 * The RSA-SHA1 signature transform klass.
 */
#define xmlSecGCryptTransformRsaSha1Id \
        xmlSecGCryptTransformRsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformRsaSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecGCryptTransformRsaSha256Id:
 *
 * The RSA-SHA2-256 signature transform klass.
 */
#define xmlSecGCryptTransformRsaSha256Id       \
        xmlSecGCryptTransformRsaSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformRsaSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecGCryptTransformRsaSha384Id:
 *
 * The RSA-SHA2-384 signature transform klass.
 */
#define xmlSecGCryptTransformRsaSha384Id       \
        xmlSecGCryptTransformRsaSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformRsaSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecGCryptTransformRsaSha512Id:
 *
 * The RSA-SHA2-512 signature transform klass.
 */
#define xmlSecGCryptTransformRsaSha512Id       \
        xmlSecGCryptTransformRsaSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformRsaSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */


#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecGCryptTransformRsaPssSha1Id:
 *
 * The RSA-PSS-SHA1 signature transform klass.
 */
#define xmlSecGCryptTransformRsaPssSha1Id \
        xmlSecGCryptTransformRsaPssSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformRsaPssSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecGCryptTransformRsaPssSha256Id:
 *
 * The RSA-PSS-SHA2-256 signature transform klass.
 */
#define xmlSecGCryptTransformRsaPssSha256Id       \
        xmlSecGCryptTransformRsaPssSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformRsaPssSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecGCryptTransformRsaPssSha384Id:
 *
 * The RSA-PSS-SHA2-384 signature transform klass.
 */
#define xmlSecGCryptTransformRsaPssSha384Id       \
        xmlSecGCryptTransformRsaPssSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformRsaPssSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecGCryptTransformRsaPssSha512Id:
 *
 * The RSA-PSS-SHA2-512 signature transform klass.
 */
#define xmlSecGCryptTransformRsaPssSha512Id       \
        xmlSecGCryptTransformRsaPssSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformRsaPssSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */


#ifndef XMLSEC_NO_SHA3
/**
 * xmlSecGCryptTransformRsaPssSha3_256Id:
 *
 * The RSA-PSS-SHA3-256 signature transform klass.
 */
#define xmlSecGCryptTransformRsaPssSha3_256Id       \
        xmlSecGCryptTransformRsaPssSha3_256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformRsaPssSha3_256GetKlass(void);

/**
 * xmlSecGCryptTransformRsaPssSha3_384Id:
 *
 * The RSA-PSS-SHA3-384 signature transform klass.
 */
#define xmlSecGCryptTransformRsaPssSha3_384Id       \
        xmlSecGCryptTransformRsaPssSha3_384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformRsaPssSha3_384GetKlass(void);

/**
 * xmlSecGCryptTransformRsaPssSha3_512Id:
 *
 * The RSA-PSS-SHA3-512 signature transform klass.
 */
#define xmlSecGCryptTransformRsaPssSha3_512Id       \
        xmlSecGCryptTransformRsaPssSha3_512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformRsaPssSha3_512GetKlass(void);
#endif /* XMLSEC_NO_SHA3 */

/**
 * xmlSecGCryptTransformRsaPkcs1Id:
 *
 * The RSA PKCS1 key transport transform klass.
 */
#define xmlSecGCryptTransformRsaPkcs1Id \
        xmlSecGCryptTransformRsaPkcs1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformRsaPkcs1GetKlass(void);

/**
 * xmlSecGCryptTransformRsaOaepId:
 *
 * The RSA OAEP key transport transform klass (XMLEnc 1.0).
 */
#define xmlSecGCryptTransformRsaOaepId \
        xmlSecGCryptTransformRsaOaepGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformRsaOaepGetKlass(void);

/**
 * xmlSecGCryptTransformRsaOaepEnc11Id:
 *
 * The RSA OAEP key transport transform klass (XMLEnc 1.1).
 */
#define xmlSecGCryptTransformRsaOaepEnc11Id \
        xmlSecGCryptTransformRsaOaepEnc11GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformRsaOaepEnc11GetKlass(void);


#endif /* XMLSEC_NO_RSA */


/********************************************************************
 *
 * SHA transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecGCryptTransformSha1Id:
 *
 * The HMAC with SHA1 signature transform klass.
 */
#define xmlSecGCryptTransformSha1Id \
        xmlSecGCryptTransformSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecGCryptTransformSha256Id:
 *
 * The HMAC with SHA2-256 signature transform klass.
 */
#define xmlSecGCryptTransformSha256Id \
        xmlSecGCryptTransformSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecGCryptTransformSha384Id:
 *
 * The HMAC with SHA2-384 signature transform klass.
 */
#define xmlSecGCryptTransformSha384Id \
        xmlSecGCryptTransformSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecGCryptTransformSha512Id:
 *
 * The HMAC with SHA2-512 signature transform klass.
 */
#define xmlSecGCryptTransformSha512Id \
        xmlSecGCryptTransformSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */


#ifndef XMLSEC_NO_SHA3
/**
 * xmlSecGCryptTransformSha3_256Id:
 *
 * The HMAC with SHA3-256 signature transform klass.
 */
#define xmlSecGCryptTransformSha3_256Id \
        xmlSecGCryptTransformSha3_256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformSha3_256GetKlass(void);

/**
 * xmlSecGCryptTransformSha3_384Id:
 *
 * The HMAC with SHA3-384 signature transform klass.
 */
#define xmlSecGCryptTransformSha3_384Id \
        xmlSecGCryptTransformSha3_384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformSha3_384GetKlass(void);

/**
 * xmlSecGCryptTransformSha3_512Id:
 *
 * The HMAC with SHA3-512 signature transform klass.
 */
#define xmlSecGCryptTransformSha3_512Id \
        xmlSecGCryptTransformSha3_512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformSha3_512GetKlass(void);
#endif /* XMLSEC_NO_SHA3 */


/********************************************************************
 *
 * Md5 transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_MD5
/**
 * xmlSecGCryptTransformMd5Id:
 *
 * The MD5 digest transform klass.
 */
#define xmlSecGCryptTransformMd5Id \
        xmlSecGCryptTransformMd5GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformMd5GetKlass(void);
#endif /* XMLSEC_NO_MD5 */


/********************************************************************
 *
 * RipeMD160 transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_RIPEMD160
/**
 * xmlSecGCryptTransformRipemd160Id:
 *
 * The RIPEMD160 digest transform klass.
 */
#define xmlSecGCryptTransformRipemd160Id \
        xmlSecGCryptTransformRipemd160GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGCryptTransformRipemd160GetKlass(void);
#endif /* XMLSEC_NO_RIPEMD160 */


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_GCRYPT_CRYPTO_H__ */

#define __XMLSEC_GCRYPT_CRYPTO_H__
