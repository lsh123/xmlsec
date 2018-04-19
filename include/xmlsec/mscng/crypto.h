/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2018 Miklos Vajna <vmiklos@vmiklos.hu>. All Rights Reserved.
 */
#ifndef __XMLSEC_MSCNG_CRYPTO_H__
#define __XMLSEC_MSCNG_CRYPTO_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <windows.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/dl.h>

XMLSEC_CRYPTO_EXPORT xmlSecCryptoDLFunctionsPtr xmlSecCryptoGetFunctions_mscng(void);
XMLSEC_CRYPTO_EXPORT LPWSTR xmlSecMSCngMultiByteToWideChar(const char* multiByte);
XMLSEC_CRYPTO_EXPORT LPTSTR xmlSecMSCngConvertUtf8ToTstr(const xmlChar* str);
XMLSEC_CRYPTO_EXPORT LPWSTR xmlSecMSCngConvertUtf8ToUnicode(const xmlChar* str);
XMLSEC_CRYPTO_EXPORT xmlChar* xmlSecMSCngConvertTstrToUtf8(LPCTSTR str);
XMLSEC_CRYPTO_EXPORT xmlChar* xmlSecMSCngConvertUnicodeToUtf8(LPCWSTR str);
XMLSEC_CRYPTO_EXPORT int xmlSecMSCngGenerateRandom(xmlSecBufferPtr buffer, size_t size);

/********************************************************************
 *
 * Init shutdown
 *
 ********************************************************************/
XMLSEC_CRYPTO_EXPORT int                xmlSecMSCngInit              (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecMSCngShutdown          (void);

XMLSEC_CRYPTO_EXPORT int                xmlSecMSCngKeysMngrInit      (xmlSecKeysMngrPtr mngr);

/********************************************************************
 *
 * DSA transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_DSA

/**
 * xmlSecMSCngKeyDataDsaId:
 *
 * The DSA key klass.
 */
#define xmlSecMSCngKeyDataDsaId \
        xmlSecMSCngKeyDataDsaGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId xmlSecMSCngKeyDataDsaGetKlass(void);

#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecMSCngTransformDsaSha1Id:
 *
 * The DSA-SHA1 signature transform klass.
 */
#define xmlSecMSCngTransformDsaSha1Id     \
       xmlSecMSCngTransformDsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformDsaSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#endif /* XMLSEC_NO_DSA */

/********************************************************************
 *
 * RSA transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_RSA

/**
 * xmlSecMSCngKeyDataRsaId:
 *
 * The RSA key klass.
 */
#define xmlSecMSCngKeyDataRsaId \
        xmlSecMSCngKeyDataRsaGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId xmlSecMSCngKeyDataRsaGetKlass(void);

#ifndef XMLSEC_NO_MD5
/**
 * xmlSecMSCngTransformRsaMd5Id:
 *
 * The RSA-MD5 signature transform klass.
 */
#define xmlSecMSCngTransformRsaMd5Id     \
       xmlSecMSCngTransformRsaMd5GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaMd5GetKlass(void);
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecMSCngTransformRsaSha1Id:
 *
 * The RSA-SHA1 signature transform klass.
 */
#define xmlSecMSCngTransformRsaSha1Id     \
       xmlSecMSCngTransformRsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecMSCngTransformRsaSha256Id:
 *
 * The RSA-SHA256 signature transform klass.
 */
#define xmlSecMSCngTransformRsaSha256Id     \
       xmlSecMSCngTransformRsaSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecMSCngTransformRsaSha384Id:
 *
 * The RSA-SHA384 signature transform klass.
 */
#define xmlSecMSCngTransformRsaSha384Id     \
       xmlSecMSCngTransformRsaSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecMSCngTransformRsaSha512Id:
 *
 * The RSA-SHA512 signature transform klass.
 */
#define xmlSecMSCngTransformRsaSha512Id     \
       xmlSecMSCngTransformRsaSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */

/**
 * xmlSecMSCngTransformRsaPkcs1Id:
 *
 * The RSA PKCS1 key transport transform klass.
 */
#define xmlSecMSCngTransformRsaPkcs1Id \
        xmlSecMSCngTransformRsaPkcs1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaPkcs1GetKlass(void);


#endif /* XMLSEC_NO_RSA */

/********************************************************************
 *
 * ECDSA transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_ECDSA

/**
 * xmlSecMSCngKeyDataEcdsaId:
 *
 * The ECDSA key klass.
 */
#define xmlSecMSCngKeyDataEcdsaId \
        xmlSecMSCngKeyDataEcdsaGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId xmlSecMSCngKeyDataEcdsaGetKlass(void);

#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecMSCngTransformEcdsaSha1Id:
 *
 * The ECDSA-SHA1 signature transform klass.
 */
#define xmlSecMSCngTransformEcdsaSha1Id     \
       xmlSecMSCngTransformEcdsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformEcdsaSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecMSCngTransformEcdsaSha256Id:
 *
 * The ECDSA-SHA256 signature transform klass.
 */
#define xmlSecMSCngTransformEcdsaSha256Id     \
       xmlSecMSCngTransformEcdsaSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformEcdsaSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecMSCngTransformEcdsaSha512Id:
 *
 * The ECDSA-SHA512 signature transform klass.
 */
#define xmlSecMSCngTransformEcdsaSha512Id     \
       xmlSecMSCngTransformEcdsaSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformEcdsaSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_ECDSA */

/********************************************************************
 *
 * HMAC transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_HMAC

/**
 * xmlSecMSCngKeyDataHmacId:
 *
 * The HMAC key klass.
 */
#define xmlSecMSCngKeyDataHmacId \
        xmlSecMSCngKeyDataHmacGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId xmlSecMSCngKeyDataHmacGetKlass(void);

#ifndef XMLSEC_NO_MD5
/**
 * xmlSecMSCngTransformHmacMd5Id:
 *
 * The HMAC-MD5 signature transform klass.
 */
#define xmlSecMSCngTransformHmacMd5Id     \
       xmlSecMSCngTransformHmacMd5GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformHmacMd5GetKlass(void);
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecMSCngTransformHmacSha1Id:
 *
 * The HMAC-SHA1 signature transform klass.
 */
#define xmlSecMSCngTransformHmacSha1Id     \
       xmlSecMSCngTransformHmacSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformHmacSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecMSCngTransformHmacSha256Id:
 *
 * The HMAC-SHA256 signature transform klass.
 */
#define xmlSecMSCngTransformHmacSha256Id     \
       xmlSecMSCngTransformHmacSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformHmacSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecMSCngTransformHmacSha384Id:
 *
 * The HMAC-SHA384 signature transform klass.
 */
#define xmlSecMSCngTransformHmacSha384Id     \
       xmlSecMSCngTransformHmacSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformHmacSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecMSCngTransformHmacSha512Id:
 *
 * The HMAC-SHA512 signature transform klass.
 */
#define xmlSecMSCngTransformHmacSha512Id     \
       xmlSecMSCngTransformHmacSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformHmacSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_HMAC */

/********************************************************************
 *
 * MD5 transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_MD5
/**
 * xmlSecMSCngTransformMd5Id:
 *
 * The MD5 digest transform klass.
 */
#define xmlSecMSCngTransformMd5Id \
       xmlSecMSCngTransformMd5GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformMd5GetKlass(void);
#endif /* XMLSEC_NO_MD5 */

/********************************************************************
 *
 * SHA1 transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecMSCngTransformSha1Id:
 *
 * The SHA1 digest transform klass.
 */
#define xmlSecMSCngTransformSha1Id \
       xmlSecMSCngTransformSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

/********************************************************************
 *
 * SHA256 transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecMSCngTransformSha256Id:
 *
 * The SHA256 digest transform klass.
 */
#define xmlSecMSCngTransformSha256Id \
       xmlSecMSCngTransformSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

/********************************************************************
 *
 * SHA384 transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecMSCngTransformSha384Id:
 *
 * The SHA384 digest transform klass.
 */
#define xmlSecMSCngTransformSha384Id \
       xmlSecMSCngTransformSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

/********************************************************************
 *
 * SHA512 transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecMSCngTransformSha512Id:
 *
 * The SHA512 digest transform klass.
 */
#define xmlSecMSCngTransformSha512Id \
       xmlSecMSCngTransformSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */

/********************************************************************
 *
 * AES transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_AES
/**
 * xmlSecMSCngKeyDataAesId:
 *
 * The AES key data klass.
 */
#define xmlSecMSCngKeyDataAesId \
        xmlSecMSCngKeyDataAesGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecMSCngKeyDataAesGetKlass(void);

/**
 * xmlSecMSCngTransformAes128CbcId:
 *
 * The AES128 CBC cipher transform klass.
 */
#define xmlSecMSCngTransformAes128CbcId \
        xmlSecMSCngTransformAes128CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecMSCngTransformAes128CbcGetKlass(void);

/**
 * xmlSecMSCngTransformAes192CbcId:
 *
 * The AES192 CBC cipher transform klass.
 */
#define xmlSecMSCngTransformAes192CbcId \
        xmlSecMSCngTransformAes192CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecMSCngTransformAes192CbcGetKlass(void);

/**
 * xmlSecMSCngTransformAes256CbcId:
 *
 * The AES256 CBC cipher transform klass.
 */
#define xmlSecMSCngTransformAes256CbcId \
        xmlSecMSCngTransformAes256CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecMSCngTransformAes256CbcGetKlass(void);
#endif /* XMLSEC_NO_AES */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_MSCNG_CRYPTO_H__ */
