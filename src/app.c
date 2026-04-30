/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_core_app
 * @brief Crypto-engine independent application support functions.
 */
#include "globals.h"

#ifndef XMLSEC_NO_CRYPTO_DYNAMIC_LOADING

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/app.h>
#include <xmlsec/list.h>
#include <xmlsec/keysdata.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/transforms.h>
#include <xmlsec/private.h>
#include <xmlsec/errors.h>


static const char missingMethodError[] = "Method is missing in the dynamically loaded library: %s";

/******************************************************************************
 *
 * Crypto Init/shutdown
 *
  *****************************************************************************/
/**
 * @brief Initializes the XMLSec crypto engine.
 * @details XMLSec library specific crypto engine initialization.
 *
 * Note: The application SHOULD NOT initialize the XML Security Library
 * more than once per process.
 *
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecCryptoInit(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoInit == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "cryptoInit");
        return(-1);
    }

    return(xmlSecCryptoDLGetFunctions()->cryptoInit());
}

/**
 * @brief XMLSec library specific crypto engine shutdown.
 * @details XMLSec library specific crypto engine shutdown.
 *
 * Note: Once this function has been called it might be
 * impossible to reinitialise the library correctly.
 *
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecCryptoShutdown(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoShutdown == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "cryptoShutdown");
        return(-1);
    }

    return(xmlSecCryptoDLGetFunctions()->cryptoShutdown());
}

/**
 * @brief Adds crypto key data stores to the keys manager.
 * @details Adds crypto specific key data stores in keys manager.
 * @param mngr the pointer to keys manager.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecCryptoKeysMngrInit(xmlSecKeysMngrPtr mngr) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoKeysMngrInit == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "cryptoKeysMngrInit");
        return(-1);
    }

    return(xmlSecCryptoDLGetFunctions()->cryptoKeysMngrInit(mngr));
}

/******************************************************************************
 *
 * Key data ids
 *
  *****************************************************************************/
/**
 * @brief The AES key data klass.
 * @return AES key data klass or NULL if an error occurs
 * (xmlsec-crypto library is not loaded or the AES key data
 * klass is not implemented).
 */
xmlSecKeyDataId
xmlSecKeyDataAesGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->keyDataAesGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "keyDataAesGetKlass");
        return(xmlSecKeyDataIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->keyDataAesGetKlass());
}

/**
 * @brief The ConcatKDF key data klass.
 * @return ConcatKDF key data klass or NULL if an error occurs
 * (xmlsec-crypto library is not loaded or the HMAC key data
 * klass is not implemented).
 */
xmlSecKeyDataId
xmlSecKeyDataConcatKdfGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->keyDataConcatKdfGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "keyDataConcatKdfGetKlass");
        return(xmlSecKeyDataIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->keyDataConcatKdfGetKlass());
}

/**
 * @brief The DES key data klass.
 * @return DES key data klass or NULL if an error occurs
 * (xmlsec-crypto library is not loaded or the DES key data
 * klass is not implemented).
 */
xmlSecKeyDataId
xmlSecKeyDataDesGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->keyDataDesGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "keyDataDesId");
        return(xmlSecKeyDataIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->keyDataDesGetKlass());
}

/**
 * @brief The DH key data klass.
 * @return DH key data klass or NULL if an error occurs
 * (xmlsec-crypto library is not loaded or the DH key data
 * klass is not implemented).
 */
xmlSecKeyDataId
xmlSecKeyDataDhGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->keyDataDhGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "keyDataDhGetKlass");
        return(xmlSecKeyDataIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->keyDataDhGetKlass());
}

/**
 * @brief The DSA key data klass.
 * @return DSA key data klass or NULL if an error occurs
 * (xmlsec-crypto library is not loaded or the DSA key data
 * klass is not implemented).
 */
xmlSecKeyDataId
xmlSecKeyDataDsaGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->keyDataDsaGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "keyDataDsaGetKlass");
        return(xmlSecKeyDataIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->keyDataDsaGetKlass());
}

/**
 * @brief The EC key data klass.
 * @return EC key data klass or NULL if an error occurs
 * (xmlsec-crypto library is not loaded or the EC key data
 * klass is not implemented).
 */
xmlSecKeyDataId
xmlSecKeyDataEcGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->keyDataEcGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "keyDataEcGetKlass");
        return(xmlSecKeyDataIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->keyDataEcGetKlass());
}

/**
 * @brief The GOST2001 key data klass.
 * @return GOST2001 key data klass or NULL if an error occurs
 * (xmlsec-crypto library is not loaded or the GOST2001 key data
 * klass is not implemented).
 */
xmlSecKeyDataId
xmlSecKeyDataGost2001GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->keyDataGost2001GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "keyDataGost2001GetKlass");
        return(xmlSecKeyDataIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->keyDataGost2001GetKlass());
}

/**
 * @brief The GOST R 34.10-2012 256 bit key data klass.
 * @return GOST R 34.10-2012 256 bit key data klass or NULL if an error occurs
 * (xmlsec-crypto library is not loaded or the GOST R 34.10-2012 key data
 * klass is not implemented).
 */
xmlSecKeyDataId
xmlSecKeyDataGostR3410_2012_256GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->keyDataGostR3410_2012_256GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "keyDataGostR3410_2012_256GetKlass");
        return(xmlSecKeyDataIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->keyDataGostR3410_2012_256GetKlass());
}

/**
 * @brief The GOST R 34.10-2012 512 bit key data klass.
 * @return GOST R 34.10-2012 512 bit key data klass or NULL if an error occurs
 * (xmlsec-crypto library is not loaded or the GOST R 34.10-2012 key data
 * klass is not implemented).
 */
xmlSecKeyDataId
xmlSecKeyDataGostR3410_2012_512GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->keyDataGostR3410_2012_512GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "keyDataGostR3410_2012_512GetKlass");
        return(xmlSecKeyDataIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->keyDataGostR3410_2012_512GetKlass());
}

/**
 * @brief The HMAC key data klass.
 * @return HMAC key data klass or NULL if an error occurs
 * (xmlsec-crypto library is not loaded or the HMAC key data
 * klass is not implemented).
 */
xmlSecKeyDataId
xmlSecKeyDataHmacGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->keyDataHmacGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "keyDataHmacGetKlass");
        return(xmlSecKeyDataIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->keyDataHmacGetKlass());
}

/**
 * @brief The HKDF key data klass.
 * @return HKDF key data klass or NULL if an error occurs
 * (xmlsec-crypto library is not loaded or the HKDF key data
 * klass is not implemented).
 */
xmlSecKeyDataId
xmlSecKeyDataHkdfGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->keyDataHkdfGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "keyDataHkdfGetKlass");
        return(xmlSecKeyDataIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->keyDataHkdfGetKlass());
}

/**
 * @brief The PBKDF2 key data klass.
 * @return PBKDF2 key data klass or NULL if an error occurs
 * (xmlsec-crypto library is not loaded or the HMAC key data
 * klass is not implemented).
 */
xmlSecKeyDataId
xmlSecKeyDataPbkdf2GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->keyDataPbkdf2GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "keyDataPbkdf2GetKlass");
        return(xmlSecKeyDataIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->keyDataPbkdf2GetKlass());
}
/**
 * @brief The RSA key data klass.
 * @return RSA key data klass or NULL if an error occurs
 * (xmlsec-crypto library is not loaded or the RSA key data
 * klass is not implemented).
 */
xmlSecKeyDataId
xmlSecKeyDataRsaGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->keyDataRsaGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "keyDataRsaGetKlass");
        return(xmlSecKeyDataIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->keyDataRsaGetKlass());
}
/**
 * @brief The ML-DSA key data klass.
 * @return ML-DSA key data klass or NULL if an error occurs
 * (xmlsec-crypto library is not loaded or the ML-DSA key data
 * klass is not implemented).
 */
xmlSecKeyDataId
xmlSecKeyDataMLDSAGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->keyDataMLDSAGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "keyDataMLDSAGetKlass");
        return(xmlSecKeyDataIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->keyDataMLDSAGetKlass());
}
/**
 * @brief The ML-KEM key data klass.
 * @return ML-KEM key data klass or NULL if an error occurs
 * (xmlsec-crypto library is not loaded or the ML-KEM key data
 * klass is not implemented).
 */
xmlSecKeyDataId
xmlSecKeyDataMLKEMGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->keyDataMLKEMGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "keyDataMLKEMGetKlass");
        return(xmlSecKeyDataIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->keyDataMLKEMGetKlass());
}
/**
 * @brief The SLH-DSA key data klass.
 * @return SLH-DSA key data klass or NULL if an error occurs
 * (xmlsec-crypto library is not loaded or the SLH-DSA key data
 * klass is not implemented).
 */
xmlSecKeyDataId
xmlSecKeyDataSLHDSAGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->keyDataSLHDSAGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "keyDataSLHDSAGetKlass");
        return(xmlSecKeyDataIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->keyDataSLHDSAGetKlass());
}

/**
 * @brief The EdDSA key data klass.
 * @return EdDSA key data klass or NULL if an error occurs
 * (xmlsec-crypto library is not loaded or the EdDSA key data
 * klass is not implemented).
 */
xmlSecKeyDataId
xmlSecKeyDataEdDSAGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->keyDataEdDSAGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "keyDataEdDSAGetKlass");
        return(xmlSecKeyDataIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->keyDataEdDSAGetKlass());
}

/**
 * @brief The XDH key data klass.
 * @return XDH key data klass or NULL if an error occurs
 * (xmlsec-crypto library is not loaded or the XDH key data
 * klass is not implemented).
 */
xmlSecKeyDataId
xmlSecKeyDataXdhGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->keyDataXdhGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "keyDataXdhGetKlass");
        return(xmlSecKeyDataIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->keyDataXdhGetKlass());
}

/**
 * @brief The X509 key data klass.
 * @return X509 key data klass or NULL if an error occurs
 * (xmlsec-crypto library is not loaded or the X509 key data
 * klass is not implemented).
 */
xmlSecKeyDataId
xmlSecKeyDataX509GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->keyDataX509GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "keyDataX509GetKlass");
        return(xmlSecKeyDataIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->keyDataX509GetKlass());
}

/**
 * @brief The raw X509 cert key data klass.
 * @return raw x509 cert key data klass or NULL if an error occurs
 * (xmlsec-crypto library is not loaded or the raw X509 cert key data
 * klass is not implemented).
 */
xmlSecKeyDataId
xmlSecKeyDataRawX509CertGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->keyDataRawX509CertGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "keyDataRawX509CertGetKlass");
        return(xmlSecKeyDataIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->keyDataRawX509CertGetKlass());
}


/**
 * @brief The DEREncodedKeyValue key data klass.
 * @return X5DEREncodedKeyValue09 key data klass or NULL if an error occurs
 * (xmlsec-crypto library is not loaded or the DEREncodedKeyValue key data
 * klass is not implemented).
 */
xmlSecKeyDataId
xmlSecKeyDataDEREncodedKeyValueGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->keyDataDEREncodedKeyValueGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "keyDataDEREncodedKeyValueGetKlass");
        return(xmlSecKeyDataIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->keyDataDEREncodedKeyValueGetKlass());
}
/******************************************************************************
 *
 * Key data store ids
 *
  *****************************************************************************/
/**
 * @brief The X509 certificates key data store klass.
 * @return pointer to X509 certificates key data store klass or NULL if
 * an error occurs (xmlsec-crypto library is not loaded or the raw X509
 * cert key data klass is not implemented).
 */
xmlSecKeyDataStoreId
xmlSecX509StoreGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->x509StoreGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "x509StoreGetKlass");
        return(xmlSecKeyStoreIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->x509StoreGetKlass());
}

/******************************************************************************
 *
 * Crypto transforms ids
 *
  *****************************************************************************/
/**
 * @brief AES 128 CBC encryption transform klass.
 * @return pointer to AES 128 CBC encryption transform or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformAes128CbcGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformAes128CbcGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformAes128CbcGetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformAes128CbcGetKlass());
}

/**
 * @brief AES 192 CBC encryption transform klass.
 * @return pointer to AES 192 CBC encryption transform or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformAes192CbcGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformAes192CbcGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformAes192CbcGetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformAes192CbcGetKlass());
}

/**
 * @brief AES 256 CBC encryption transform klass.
 * @return pointer to AES 256 CBC encryption transform or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformAes256CbcGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformAes256CbcGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformAes256CbcGetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformAes256CbcGetKlass());
}

/**
 * @brief AES 128 GCM encryption transform klass.
 * @return pointer to AES 128 GCM encryption transform or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformAes128GcmGetKlass(void)
{
    if ((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformAes128GcmGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformAes128GcmGetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformAes128GcmGetKlass());
}

/**
 * @brief AES 192 GCM encryption transform klass.
 * @return pointer to AES 192 GCM encryption transform or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformAes192GcmGetKlass(void)
{
    if ((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformAes192GcmGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformAes192GcmGetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformAes192GcmGetKlass());
}

/**
 * @brief AES 256 GCM encryption transform klass.
 * @return pointer to AES 256 GCM encryption transform or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformAes256GcmGetKlass(void)
{
    if ((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformAes256GcmGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformAes256GcmGetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformAes256GcmGetKlass());
}

/**
 * @brief ConcatKDF key derivaton transform klass.
 * @return pointer to ConcatKDF key derivaton transform or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformConcatKdfGetKlass(void)
{
    if ((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformConcatKdfGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformConcatKdfGetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformConcatKdfGetKlass());
}

/**
 * @brief The AES-128 key wrapper transform klass.
 * @return AES-128 kew wrapper transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformKWAes128GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformKWAes128GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformKWAes128GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformKWAes128GetKlass());
}

/**
 * @brief The AES-192 key wrapper transform klass.
 * @return AES-192 kew wrapper transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformKWAes192GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformKWAes192GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformKWAes192GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformKWAes192GetKlass());
}

/**
 * @brief The AES-256 key wrapper transform klass.
 * @return AES-256 kew wrapper transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformKWAes256GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformKWAes256GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformKWAes256GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformKWAes256GetKlass());
}

/**
 * @brief Triple DES CBC encryption transform klass.
 * @return pointer to Triple DES encryption transform or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformDes3CbcGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformDes3CbcGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformDes3CbcGetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformDes3CbcGetKlass());
}

/**
 * @brief The Triple DES key wrapper transform klass.
 * @return Triple DES key wrapper transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformKWDes3GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformKWDes3GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformKWDes3GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformKWDes3GetKlass());
}

/**
 * @brief DH-ES key agreement transform klass.
 * @return pointer to DH-ES key agreement transform or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformDhEsGetKlass(void)
{
    if ((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformDhEsGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformDhEsGetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformDhEsGetKlass());
}

/**
 * @brief The DSA-SHA1 signature transform klass.
 * @return DSA-SHA1 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformDsaSha1GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformDsaSha1GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformDsaSha1GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformDsaSha1GetKlass());
}

/**
 * @brief HKDF key derivation transform klass.
 * @return pointer to HKDF key derivation transform or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformHkdfGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformHkdfGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformHkdfGetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformHkdfGetKlass());
}

/**
 * @brief The DSA-SHA2-256 signature transform klass.
 * @return DSA-SHA2-256 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformDsaSha256GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformDsaSha256GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformDsaSha256GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformDsaSha256GetKlass());
}

/**
 * @brief ECDH key agreement transform klass.
 * @return pointer to ECDH key agreement transform or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformEcdhGetKlass(void)
{
    if ((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformEcdhGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformEcdhGetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformEcdhGetKlass());
}

/**
 * @brief X25519 key agreement transform klass.
 * @return pointer to X25519 key agreement transform or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformX25519GetKlass(void)
{
    if ((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformX25519GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformX25519GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformX25519GetKlass());
}

/**
 * @brief X448 key agreement transform klass.
 * @return pointer to X448 key agreement transform or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformX448GetKlass(void)
{
    if ((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformX448GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformX448GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformX448GetKlass());
}

/**
 * @brief The ECDSA-RIPEMD160 signature transform klass.
 * @return ECDSA-RIPEMD160 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformEcdsaRipemd160GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformEcdsaRipemd160GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformEcdsaRipemd160GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformEcdsaRipemd160GetKlass());
}

/**
 * @brief The ECDSA-SHA1 signature transform klass.
 * @return ECDSA-SHA1 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformEcdsaSha1GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformEcdsaSha1GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformEcdsaSha1GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformEcdsaSha1GetKlass());
}

/**
 * @brief The ECDSA-SHA2-224 signature transform klass.
 * @return ECDSA-SHA2-224 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformEcdsaSha224GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformEcdsaSha224GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformEcdsaSha224GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformEcdsaSha224GetKlass());
}

/**
 * @brief The ECDSA-SHA2-256 signature transform klass.
 * @return ECDSA-SHA2-256 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformEcdsaSha256GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformEcdsaSha256GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformEcdsaSha256GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformEcdsaSha256GetKlass());
}

/**
 * @brief The ECDSA-SHA2-384 signature transform klass.
 * @return ECDSA-SHA2-384 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformEcdsaSha384GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformEcdsaSha384GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformEcdsaSha384GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformEcdsaSha384GetKlass());
}

/**
 * @brief The ECDSA-SHA2-512 signature transform klass.
 * @return ECDSA-SHA2-512 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformEcdsaSha512GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformEcdsaSha512GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformEcdsaSha512GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformEcdsaSha512GetKlass());
}


/**
 * @brief The ECDSA-SHA3-224 signature transform klass.
 * @return ECDSA-SHA3-224 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformEcdsaSha3_224GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformEcdsaSha3_224GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformEcdsaSha3_224GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformEcdsaSha3_224GetKlass());
}

/**
 * @brief The ECDSA-SHA3-256 signature transform klass.
 * @return ECDSA-SHA3-256 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformEcdsaSha3_256GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformEcdsaSha3_256GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformEcdsaSha3_256GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformEcdsaSha3_256GetKlass());
}

/**
 * @brief The ECDSA-SHA3-384 signature transform klass.
 * @return ECDSA-SHA3-384 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformEcdsaSha3_384GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformEcdsaSha3_384GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformEcdsaSha3_384GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformEcdsaSha3_384GetKlass());
}

/**
 * @brief The ECDSA-SHA3-512 signature transform klass.
 * @return ECDSA-SHA3-512 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformEcdsaSha3_512GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformEcdsaSha3_512GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformEcdsaSha3_512GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformEcdsaSha3_512GetKlass());
}

/**
 * @brief Gets the GOST2001-GOSTR3411_94 signature transform klass.
 * @details The GOST2001-GOSTR3411_94 signature transform klass.
 * @return GOST2001-GOSTR3411_94 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformGost2001GostR3411_94GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformGost2001GostR3411_94GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformGost2001GostR3411_94GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformGost2001GostR3411_94GetKlass());
}

/**
 * @brief Gets GOST R 34.10-2012/R 34.11-2012 256-bit signature klass.
 * @details The GOST R 34.10-2012 - GOST R 34.11-2012 256 bit signature transform klass.
 * @return GOST R 34.10-2012 - GOST R 34.11-2012 256 bit signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformGostR3410_2012GostR3411_2012_256GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformGostR3410_2012GostR3411_2012_256GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformGostR3410_2012GostR3411_2012_256GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformGostR3410_2012GostR3411_2012_256GetKlass());
}

/**
 * @brief Gets GOST R 34.10-2012/R 34.11-2012 512-bit signature klass.
 * @details The GOST R 34.10-2012 - GOST R 34.11-2012 512 bit signature transform klass.
 * @return GOST R 34.10-2012 - GOST R 34.11-2012 512 bit signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformGostR3410_2012GostR3411_2012_512GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformGostR3410_2012GostR3411_2012_512GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformGostR3410_2012GostR3411_2012_512GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformGostR3410_2012GostR3411_2012_512GetKlass());
}


/**
 * @brief Gets the RSA-OAEP transform klass (XMLEnc 1.1).
 * @details The RSA-OAEP key transport transform klass (XMLEnc 1.1).
 * @return RSA-OAEP key transport transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformRsaOaepEnc11GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformRsaOaepEnc11GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformRsaOaepEnc11GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformRsaOaepEnc11GetKlass());
}


/**
 * @brief GOSTR3411_94 digest transform klass.
 * @return pointer to GOSTR3411_94 digest transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformGostR3411_94GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformGostR3411_94GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformGostR3411_94GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformGostR3411_94GetKlass());
}

/**
 * @brief GOST R 34.11-2012 256 bit digest transform klass.
 * @return pointer to GOST R 34.11-2012 256 bit digest transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */

xmlSecTransformId
xmlSecTransformGostR3411_2012_256GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformGostR3411_2012_256GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformGostR3411_2012_256GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformGostR3411_2012_256GetKlass());
}

/**
 * @brief The HMAC-MD5 transform klass.
 * @return the HMAC-MD5 transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformHmacMd5GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformHmacMd5GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformHmacMd5GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformHmacMd5GetKlass());
}

/**
 * @brief The HMAC-RIPEMD160 transform klass.
 * @return the HMAC-RIPEMD160 transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformHmacRipemd160GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformHmacRipemd160GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformHmacRipemd160GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformHmacRipemd160GetKlass());
}

/**
 * @brief The HMAC-SHA1 transform klass.
 * @return the HMAC-SHA1 transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformHmacSha1GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformHmacSha1GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformHmacSha1GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformHmacSha1GetKlass());
}

/**
 * @brief The HMAC-SHA224 transform klass.
 * @return the HMAC-SHA224 transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformHmacSha224GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformHmacSha224GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformHmacSha224GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformHmacSha224GetKlass());
}

/**
 * @brief The HMAC-SHA256 transform klass.
 * @return the HMAC-SHA256 transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformHmacSha256GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformHmacSha256GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformHmacSha256GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformHmacSha256GetKlass());
}

/**
 * @brief The HMAC-SHA384 transform klass.
 * @return the HMAC-SHA384 transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformHmacSha384GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformHmacSha384GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformHmacSha384GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformHmacSha384GetKlass());
}

/**
 * @brief The HMAC-SHA512 transform klass.
 * @return the HMAC-SHA512 transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformHmacSha512GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformHmacSha512GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformHmacSha512GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformHmacSha512GetKlass());
}

/**
 * @brief MD5 digest transform klass.
 * @return pointer to MD5 digest transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformMd5GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformMd5GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformMd5GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformMd5GetKlass());
}

/**
 * @brief The ML-DSA-44 signature transform klass.
 * @return ML-DSA-44 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformMLDSA44GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformMLDSA44GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformMLDSA44GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformMLDSA44GetKlass());
}

/**
 * @brief The ML-DSA-65 signature transform klass.
 * @return ML-DSA-65 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformMLDSA65GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformMLDSA65GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformMLDSA65GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformMLDSA65GetKlass());
}

/**
 * @brief The ML-DSA-87 signature transform klass.
 * @return ML-DSA-87 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformMLDSA87GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformMLDSA87GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformMLDSA87GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformMLDSA87GetKlass());
}
/**
 * @brief The ML-KEM-512 key transport transform klass.
 * @return ML-KEM-512 key transport transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformMLKEM512GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformMLKEM512GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformMLKEM512GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformMLKEM512GetKlass());
}

/**
 * @brief The ML-KEM-768 key transport transform klass.
 * @return ML-KEM-768 key transport transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformMLKEM768GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformMLKEM768GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformMLKEM768GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformMLKEM768GetKlass());
}

/**
 * @brief The ML-KEM-1024 key transport transform klass.
 * @return ML-KEM-1024 key transport transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformMLKEM1024GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformMLKEM1024GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformMLKEM1024GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformMLKEM1024GetKlass());
}
/**
 * @brief PBKDF2 key derivaton transform klass.
 * @return pointer to PBKDF2 key derivaton transform or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformPbkdf2GetKlass(void)
{
    if ((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformPbkdf2GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformPbkdf2GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformPbkdf2GetKlass());
}


/**
 * @brief RIPEMD-160 digest transform klass.
 * @return pointer to RIPEMD-160 digest transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformRipemd160GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformRipemd160GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformRipemd160GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformRipemd160GetKlass());
}

/**
 * @brief The RSA-MD5 signature transform klass.
 * @return RSA-MD5 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformRsaMd5GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformRsaMd5GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformRsaMd5GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformRsaMd5GetKlass());
}

/**
 * @brief The RSA-RIPEMD160 signature transform klass.
 * @return RSA-RIPEMD160 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformRsaRipemd160GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformRsaRipemd160GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformRsaRipemd160GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformRsaRipemd160GetKlass());
}

/**
 * @brief The RSA-SHA1 signature transform klass.
 * @return RSA-SHA1 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformRsaSha1GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformRsaSha1GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformRsaSha1GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformRsaSha1GetKlass());
}

/**
 * @brief The RSA-SHA2-224 signature transform klass.
 * @return RSA-SHA2-224 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformRsaSha224GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformRsaSha224GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformRsaSha224GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformRsaSha224GetKlass());
}

/**
 * @brief The RSA-SHA2-256 signature transform klass.
 * @return RSA-SHA2-256 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformRsaSha256GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformRsaSha256GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformRsaSha256GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformRsaSha256GetKlass());
}

/**
 * @brief The RSA-SHA2-384 signature transform klass.
 * @return RSA-SHA2-384 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformRsaSha384GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformRsaSha384GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformRsaSha384GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformRsaSha384GetKlass());
}

/**
 * @brief The RSA-SHA2-512 signature transform klass.
 * @return RSA-SHA2-512 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformRsaSha512GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformRsaSha512GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformRsaSha512GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformRsaSha512GetKlass());
}


/**
 * @brief The RSA-PSS-SHA1 signature transform klass.
 * @return RSA-PSS-SHA1 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformRsaPssSha1GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformRsaPssSha1GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformRsaPssSha1GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformRsaPssSha1GetKlass());
}

/**
 * @brief The RSA-PSS-SHA2-224 signature transform klass.
 * @return RSA-PSS-SHA2-224 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformRsaPssSha224GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformRsaPssSha224GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformRsaPssSha224GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformRsaPssSha224GetKlass());
}

/**
 * @brief The RSA-PSS-SHA2-256 signature transform klass.
 * @return RSA-PSS-SHA2-256 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformRsaPssSha256GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformRsaPssSha256GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformRsaPssSha256GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformRsaPssSha256GetKlass());
}

/**
 * @brief The RSA-PSS-SHA2-384 signature transform klass.
 * @return RSA-PSS-SHA2-384 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformRsaPssSha384GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformRsaPssSha384GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformRsaPssSha384GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformRsaPssSha384GetKlass());
}

/**
 * @brief The RSA-PSS-SHA2-512 signature transform klass.
 * @return RSA-PSS-SHA2-512 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformRsaPssSha512GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformRsaPssSha512GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformRsaPssSha512GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformRsaPssSha512GetKlass());
}


/**
 * @brief The RSA-PSS-SHA2-224 signature transform klass.
 * @return RSA-PSS-SHA3-224 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformRsaPssSha3_224GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformRsaPssSha3_224GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformRsaPssSha3_224GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformRsaPssSha3_224GetKlass());
}

/**
 * @brief The RSA-PSS-SHA2-256 signature transform klass.
 * @return RSA-PSS-SHA3-256 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformRsaPssSha3_256GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformRsaPssSha3_256GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformRsaPssSha3_256GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformRsaPssSha3_256GetKlass());
}

/**
 * @brief The RSA-PSS-SHA2-384 signature transform klass.
 * @return RSA-PSS-SHA3-384 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformRsaPssSha3_384GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformRsaPssSha3_384GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformRsaPssSha3_384GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformRsaPssSha3_384GetKlass());
}

/**
 * @brief The RSA-PSS-SHA2-512 signature transform klass.
 * @return RSA-PSS-SHA3-512 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformRsaPssSha3_512GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformRsaPssSha3_512GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformRsaPssSha3_512GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformRsaPssSha3_512GetKlass());
}


/**
 * @brief The RSA-PKCS1 key transport transform klass.
 * @return RSA-PKCS1 key transport transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformRsaPkcs1GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformRsaPkcs1GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformRsaPkcs1GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformRsaPkcs1GetKlass());
}

/**
 * @brief Gets the RSA-OAEP key transport transform klass (XMLEnc 1.0).
 * @details The RSA-OAEP key transport transform klass (XMLEnc 1.0).
 * @return RSA-OAEP key transport (XMLEnc 1.0) transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformRsaOaepGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformRsaOaepGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformRsaOaepGetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformRsaOaepGetKlass());
}

/**
 * @brief The SLH-DSA-SHA2-128f signature transform klass.
 * @return SLH-DSA-SHA2-128f signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformSLHDSA_SHA2_128fGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformSLHDSA_SHA2_128fGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformSLHDSA_SHA2_128fGetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformSLHDSA_SHA2_128fGetKlass());
}

/**
 * @brief The SLH-DSA-SHA2-128s signature transform klass.
 * @return SLH-DSA-SHA2-128s signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformSLHDSA_SHA2_128sGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformSLHDSA_SHA2_128sGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformSLHDSA_SHA2_128sGetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformSLHDSA_SHA2_128sGetKlass());
}

/**
 * @brief The SLH-DSA-SHA2-192f signature transform klass.
 * @return SLH-DSA-SHA2-192f signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformSLHDSA_SHA2_192fGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformSLHDSA_SHA2_192fGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformSLHDSA_SHA2_192fGetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformSLHDSA_SHA2_192fGetKlass());
}

/**
 * @brief The SLH-DSA-SHA2-192s signature transform klass.
 * @return SLH-DSA-SHA2-192s signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformSLHDSA_SHA2_192sGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformSLHDSA_SHA2_192sGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformSLHDSA_SHA2_192sGetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformSLHDSA_SHA2_192sGetKlass());
}

/**
 * @brief The SLH-DSA-SHA2-256f signature transform klass.
 * @return SLH-DSA-SHA2-256f signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformSLHDSA_SHA2_256fGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformSLHDSA_SHA2_256fGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformSLHDSA_SHA2_256fGetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformSLHDSA_SHA2_256fGetKlass());
}

/**
 * @brief The SLH-DSA-SHA2-256s signature transform klass.
 * @return SLH-DSA-SHA2-256s signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformSLHDSA_SHA2_256sGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformSLHDSA_SHA2_256sGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformSLHDSA_SHA2_256sGetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformSLHDSA_SHA2_256sGetKlass());
}


/**
 * @brief The EdDSA-Ed25519 signature transform klass.
 * @return EdDSA-Ed25519 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformEdDSAEd25519GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformEdDSAEd25519GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformEdDSAEd25519GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformEdDSAEd25519GetKlass());
}

/**
 * @brief The EdDSA-Ed25519ctx signature transform klass.
 * @return EdDSA-Ed25519ctx signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformEdDSAEd25519ctxGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformEdDSAEd25519ctxGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformEdDSAEd25519ctxGetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformEdDSAEd25519ctxGetKlass());
}

/**
 * @brief The EdDSA-Ed25519ph signature transform klass.
 * @return EdDSA-Ed25519ph signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformEdDSAEd25519phGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformEdDSAEd25519phGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformEdDSAEd25519phGetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformEdDSAEd25519phGetKlass());
}

/**
 * @brief The EdDSA-Ed448 signature transform klass.
 * @return EdDSA-Ed448 signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformEdDSAEd448GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformEdDSAEd448GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformEdDSAEd448GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformEdDSAEd448GetKlass());
}

/**
 * @brief The EdDSA-Ed448ph signature transform klass.
 * @return EdDSA-Ed448ph signature transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformEdDSAEd448phGetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformEdDSAEd448phGetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformEdDSAEd448phGetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformEdDSAEd448phGetKlass());
}


/**
 * @brief GOST R 34.11-2012 512 bit digest transform klass.
 * @return pointer to GOST R 34.11-2012 512 bit digest transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformGostR3411_2012_512GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformGostR3411_2012_512GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformGostR3411_2012_512GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformGostR3411_2012_512GetKlass());
}
/**
 * @brief SHA-1 digest transform klass.
 * @return pointer to SHA-1 digest transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformSha1GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformSha1GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformSha1GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformSha1GetKlass());
}

/**
 * @brief SHA2-224 digest transform klass.
 * @return pointer to SHA2-224 digest transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformSha224GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformSha224GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformSha224GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformSha224GetKlass());
}

/**
 * @brief SHA2-256 digest transform klass.
 * @return pointer to SHA2-256 digest transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformSha256GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformSha256GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformSha256GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformSha256GetKlass());
}

/**
 * @brief SHA2-384 digest transform klass.
 * @return pointer to SHA2-384 digest transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformSha384GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformSha384GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformSha384GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformSha384GetKlass());
}

/**
 * @brief SHA2-512 digest transform klass.
 * @return pointer to SHA2-512 digest transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformSha512GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformSha512GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformSha512GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformSha512GetKlass());
}


/**
 * @brief SHA3-224 digest transform klass.
 * @return pointer to SHA3-224 digest transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformSha3_224GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformSha3_224GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformSha3_224GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformSha3_224GetKlass());
}

/**
 * @brief SHA3-256 digest transform klass.
 * @return pointer to SHA3-256 digest transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformSha3_256GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformSha3_256GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformSha3_256GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformSha3_256GetKlass());
}

/**
 * @brief SHA3-384 digest transform klass.
 * @return pointer to SHA3-384 digest transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformSha3_384GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformSha3_384GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformSha3_384GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformSha3_384GetKlass());
}

/**
 * @brief SHA3-512 digest transform klass.
 * @return pointer to SHA3-512 digest transform klass or NULL if an error
 * occurs (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
xmlSecTransformId
xmlSecTransformSha3_512GetKlass(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->transformSha3_512GetKlass == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "transformSha3_512GetKlass");
        return(xmlSecTransformIdUnknown);
    }

    return(xmlSecCryptoDLGetFunctions()->transformSha3_512GetKlass());
}


/******************************************************************************
 *
 * High-level routines for the xmlsec command-line utility
 *
  *****************************************************************************/
/**
 * @brief Initializes the crypto engine for the command-line utility.
 * @details General crypto engine initialization. This function is used
 * by the XMLSec command-line utility and is called before the
 * #xmlSecInit function.
 *
 * Note: The application SHOULD NOT initialize the XML Security Library
 * more than once per process.
 *
 * @param config the path to crypto library configuration.
 *
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecCryptoAppInit(const char* config) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoAppInit == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "cryptoAppInit");
        return(-1);
    }

    return(xmlSecCryptoDLGetFunctions()->cryptoAppInit(config));
}


/**
 * @brief Shuts down the crypto engine for the command-line utility.
 * @details General crypto engine shutdown. This function is used
 * by the XMLSec command-line utility and is called after the
 * #xmlSecShutdown function.
 *
 * Note: Once this function has been called it might be
 * impossible to reinitialise the library correctly.
 *
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecCryptoAppShutdown(void) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoAppShutdown == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "cryptoAppShutdown");
        return(-1);
    }

    return(xmlSecCryptoDLGetFunctions()->cryptoAppShutdown());
}

/**
 * @brief Initializes the keys manager with default stores.
 * @details Initializes @p mngr with simple keys store #xmlSecSimpleKeysStoreId
 * and a default crypto key data stores.
 * @param mngr the pointer to keys manager.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecCryptoAppDefaultKeysMngrInit(xmlSecKeysMngrPtr mngr) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoAppDefaultKeysMngrInit == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "cryptoAppDefaultKeysMngrInit");
        return(-1);
    }

    return(xmlSecCryptoDLGetFunctions()->cryptoAppDefaultKeysMngrInit(mngr));
}

/**
 * @brief Adds a key to the keys manager.
 * @details Adds @p key to the keys manager @p mngr created with #xmlSecCryptoAppDefaultKeysMngrInit
 * function.
 * @param mngr the pointer to keys manager.
 * @param key the pointer to key.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecCryptoAppDefaultKeysMngrAdoptKey(xmlSecKeysMngrPtr mngr, xmlSecKeyPtr key) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoAppDefaultKeysMngrAdoptKey == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "cryptoAppDefaultKeysMngrAdoptKey");
        return(-1);
    }

    return(xmlSecCryptoDLGetFunctions()->cryptoAppDefaultKeysMngrAdoptKey(mngr, key));
}


/**
 * @brief Verifies a key using the keys manager.
 * @details Verifies @p key with the keys manager @p mngr created with #xmlSecCryptoAppDefaultKeysMngrInit
 * function:
 * - Checks that key certificate is present
 * - Checks that key certificate is valid
 *
 * Adds @p key to the keys manager @p mngr created with #xmlSecCryptoAppDefaultKeysMngrInit
 * function.
 * @param mngr the pointer to keys manager.
 * @param key the pointer to key.
 * @param keyInfoCtx the key info context for verification.
 * @return 1 if key is verified, 0 otherwise, or a negative value if an error occurs.
 */
int
xmlSecCryptoAppDefaultKeysMngrVerifyKey(xmlSecKeysMngrPtr mngr, xmlSecKeyPtr key, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoAppDefaultKeysMngrVerifyKey == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "cryptoAppDefaultKeysMngrVerifyKey");
        return(-1);
    }

    return(xmlSecCryptoDLGetFunctions()->cryptoAppDefaultKeysMngrVerifyKey(mngr, key, keyInfoCtx));
}

/**
 * @brief Loads a keys file into the keys manager.
 * @details Loads XML keys file from @p uri to the keys manager @p mngr created
 * with #xmlSecCryptoAppDefaultKeysMngrInit function.
 * @param mngr the pointer to keys manager.
 * @param uri the uri.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecCryptoAppDefaultKeysMngrLoad(xmlSecKeysMngrPtr mngr, const char* uri) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoAppDefaultKeysMngrLoad == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "cryptoAppDefaultKeysMngrLoad");
        return(-1);
    }

    return(xmlSecCryptoDLGetFunctions()->cryptoAppDefaultKeysMngrLoad(mngr, uri));
}

/**
 * @brief Saves keys from @p mngr to  XML keys file.
 * @param mngr the pointer to keys manager.
 * @param filename the destination filename.
 * @param type the type of keys to save (public/private/symmetric).
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecCryptoAppDefaultKeysMngrSave(xmlSecKeysMngrPtr mngr, const char* filename,
                                   xmlSecKeyDataType type) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoAppDefaultKeysMngrSave == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "cryptoAppDefaultKeysMngrSave");
        return(-1);
    }

    return(xmlSecCryptoDLGetFunctions()->cryptoAppDefaultKeysMngrSave(mngr, filename, type));
}

/**
 * @brief Loads a certificate into the keys manager.
 * @details Reads cert from @p filename and adds to the list of trusted or known
 * untrusted certs in @p store.
 * @param mngr the keys manager.
 * @param filename the certificate file.
 * @param format the certificate file format.
 * @param type the flag that indicates is the certificate in @p filename
 *                      trusted or not.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecCryptoAppKeysMngrCertLoad(xmlSecKeysMngrPtr mngr, const char *filename,
                                xmlSecKeyDataFormat format, xmlSecKeyDataType type) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoAppKeysMngrCertLoad == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "cryptoAppKeysMngrCertLoad");
        return(-1);
    }

    return(xmlSecCryptoDLGetFunctions()->cryptoAppKeysMngrCertLoad(mngr, filename, format, type));
}

/**
 * @brief Loads a certificate from memory into the keys manager.
 * @details Reads cert from binary buffer @p data and adds to the list of trusted or known
 * untrusted certs in @p store.
 * @param mngr the keys manager.
 * @param data the certificate binary data.
 * @param dataSize the certificate binary data size.
 * @param format the certificate data format.
 * @param type the flag that indicates is the certificate trusted or not.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecCryptoAppKeysMngrCertLoadMemory(xmlSecKeysMngrPtr mngr, const xmlSecByte* data,
                                    xmlSecSize dataSize, xmlSecKeyDataFormat format,
                                    xmlSecKeyDataType type) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoAppKeysMngrCertLoadMemory == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "cryptoAppKeysMngrCertLoadMemory");
        return(-1);
    }

    return(xmlSecCryptoDLGetFunctions()->cryptoAppKeysMngrCertLoadMemory(mngr, data, dataSize, format, type));
}

/**
 * @brief Loads CRLs from a file into the keys manager.
 * @details Reads crls from @p filename and adds to the list of crls in @p store.
 * @param mngr the keys manager.
 * @param filename the CRL file.
 * @param format the CRL file format.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecCryptoAppKeysMngrCrlLoad(xmlSecKeysMngrPtr mngr, const char *filename, xmlSecKeyDataFormat format) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoAppKeysMngrCrlLoad == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "cryptoAppKeysMngrCrlLoad");
        return(-1);
    }

    return(xmlSecCryptoDLGetFunctions()->cryptoAppKeysMngrCrlLoad(mngr, filename, format));
}


/**
 * @brief Loads and verifies a CRL into the keys manager.
 * @details Reads and verifies the CRL from @p filename.  If verification is successful, the CRL is added to
 * the keys manager @p store.
 * @param mngr the keys manager.
 * @param filename the CRL file.
 * @param format the CRL file format.
 * @param keyInfoCtx the key info context for verification parameters.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecCryptoAppKeysMngrCrlLoadAndVerify(xmlSecKeysMngrPtr mngr, const char *filename,
    xmlSecKeyDataFormat format, xmlSecKeyInfoCtxPtr keyInfoCtx
) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoAppKeysMngrCrlLoadAndVerify == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "cryptoAppKeysMngrCrlLoadAndVerify");
        return(-1);
    }

    return(xmlSecCryptoDLGetFunctions()->cryptoAppKeysMngrCrlLoadAndVerify(mngr, filename, format, keyInfoCtx));
}

/**
 * @brief Loads CRLs from memory into the keys manager.
 * @details Reads crl from binary buffer @p data and adds to the list of crls in @p store.
 * @param mngr the keys manager.
 * @param data the CRL binary data.
 * @param dataSize the CRL binary data size.
 * @param format the CRL data format.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecCryptoAppKeysMngrCrlLoadMemory(xmlSecKeysMngrPtr mngr, const xmlSecByte* data, xmlSecSize dataSize,
    xmlSecKeyDataFormat format
) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoAppKeysMngrCrlLoadMemory == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "cryptoAppKeysMngrCrlLoadMemory");
        return(-1);
    }

    return(xmlSecCryptoDLGetFunctions()->cryptoAppKeysMngrCrlLoadMemory(mngr, data, dataSize, format));
}


/**
 * @brief Reads a key from a file.
 * @param filename the key filename.
 * @param type the key type (public / private).
 * @param format the key file format.
 * @param pwd the key file password.
 * @param pwdCallback the key password callback.
 * @param pwdCallbackCtx the user context for password callback.
 * @return pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecCryptoAppKeyLoadEx(const char *filename, xmlSecKeyDataType type, xmlSecKeyDataFormat format,
                       const char *pwd, void* pwdCallback, void* pwdCallbackCtx) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoAppKeyLoadEx == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "cryptoAppKeyLoadEx");
        return(NULL);
    }

    return(xmlSecCryptoDLGetFunctions()->cryptoAppKeyLoadEx(filename, type, format, pwd, pwdCallback, pwdCallbackCtx));
}

/**
 * @brief Reads a key from the memory buffer.
 * @param data the binary key data.
 * @param dataSize the size of binary key.
 * @param format the key file format.
 * @param pwd the key file password.
 * @param pwdCallback the key password callback.
 * @param pwdCallbackCtx the user context for password callback.
 * @return pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecCryptoAppKeyLoadMemory(const xmlSecByte* data, xmlSecSize dataSize, xmlSecKeyDataFormat format,
                       const char *pwd, void* pwdCallback, void* pwdCallbackCtx) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoAppKeyLoadMemory == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "cryptoAppKeyLoadMemory");
        return(NULL);
    }

    return(xmlSecCryptoDLGetFunctions()->cryptoAppKeyLoadMemory(data, dataSize, format, pwd, pwdCallback, pwdCallbackCtx));
}

/**
 * @brief Reads a key and certificates from a PKCS12 file.
 * @details Reads a key and all associated certificates from the PKCS12 file.
 * For uniformity, call xmlSecCryptoAppKeyLoadEx instead of this function. Pass
 * in format=xmlSecKeyDataFormatPkcs12.
 * @param filename the PKCS12 key filename.
 * @param pwd the PKCS12 file password.
 * @param pwdCallback the password callback.
 * @param pwdCallbackCtx the user context for password callback.
 * @return pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecCryptoAppPkcs12Load(const char* filename, const char* pwd, void* pwdCallback,
                          void* pwdCallbackCtx) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoAppPkcs12Load == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "cryptoAppPkcs12Load");
        return(NULL);
    }

    return(xmlSecCryptoDLGetFunctions()->cryptoAppPkcs12Load(filename, pwd, pwdCallback, pwdCallbackCtx));
}

/**
 * @brief Reads a key and certificates from PKCS12 memory buffer.
 * @details Reads a key and all associated certificates from the PKCS12 data in the memory buffer.
 * For uniformity, call xmlSecCryptoAppKeyLoadMemory instead of this function. Pass
 * in format=xmlSecKeyDataFormatPkcs12.
 * @param data the PKCS12 binary data.
 * @param dataSize the PKCS12 binary data size.
 * @param pwd the PKCS12 file password.
 * @param pwdCallback the password callback.
 * @param pwdCallbackCtx the user context for password callback.
 * @return pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecCryptoAppPkcs12LoadMemory(const xmlSecByte* data, xmlSecSize dataSize,
                           const char *pwd, void* pwdCallback,
                           void* pwdCallbackCtx) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoAppPkcs12LoadMemory == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "cryptoAppPkcs12LoadMemory");
        return(NULL);
    }

    return(xmlSecCryptoDLGetFunctions()->cryptoAppPkcs12LoadMemory(data, dataSize, pwd, pwdCallback, pwdCallbackCtx));
}

/**
 * @brief Loads a certificate and adds it to a key.
 * @details Reads the certificate from $@p filename and adds it to key.
 * @param key the pointer to key.
 * @param filename the certificate filename.
 * @param format the certificate file format.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecCryptoAppKeyCertLoad(xmlSecKeyPtr key, const char* filename, xmlSecKeyDataFormat format) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoAppKeyCertLoad == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "cryptoAppKeyCertLoad");
        return(-1);
    }

    return(xmlSecCryptoDLGetFunctions()->cryptoAppKeyCertLoad(key, filename, format));
}

/**
 * @brief Loads a certificate from memory and adds it to a key.
 * @details Reads the certificate from memory buffer and adds it to key.
 * @param key the pointer to key.
 * @param data the certificate binary data.
 * @param dataSize the certificate binary data size.
 * @param format the certificate file format.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecCryptoAppKeyCertLoadMemory(xmlSecKeyPtr key, const xmlSecByte* data, xmlSecSize dataSize,
                                xmlSecKeyDataFormat format) {
    if((xmlSecCryptoDLGetFunctions() == NULL) || (xmlSecCryptoDLGetFunctions()->cryptoAppKeyCertLoadMemory == NULL)) {
        xmlSecNotImplementedError2(missingMethodError, "cryptoAppKeyCertLoadMemory");
        return(-1);
    }

    return(xmlSecCryptoDLGetFunctions()->cryptoAppKeyCertLoadMemory(key, data, dataSize, format));
}

/**
 * @brief Gets default password callback.
 * @return default password callback.
 */
void*
xmlSecCryptoAppGetDefaultPwdCallback(void) {
    if(xmlSecCryptoDLGetFunctions() == NULL) {
        xmlSecNotImplementedError2(missingMethodError, "cryptoAppDefaultPwdCallback");
        return(NULL);
    }

    return(xmlSecCryptoDLGetFunctions()->cryptoAppDefaultPwdCallback);
}

#endif /* XMLSEC_NO_CRYPTO_DYNAMIC_LOADING */
