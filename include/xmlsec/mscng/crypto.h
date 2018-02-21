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

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_MSCNG_CRYPTO_H__ */
