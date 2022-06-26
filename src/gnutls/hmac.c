/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:hmac
 * @Short_description: HMAC transforms implementation for GnuTLS.
 * @Stability: Private
 *
 */

#ifndef XMLSEC_NO_HMAC
#include "globals.h"

#include <string.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>
#include <xmlsec/keys.h>
#include <xmlsec/private.h>
#include <xmlsec/transforms.h>

#include <xmlsec/gnutls/app.h>
#include <xmlsec/gnutls/crypto.h>

#include "../cast_helpers.h"
#include "../transform_helpers.h"


/**************************************************************************
 *
 * We use xmlsec-gcrypt for all the basic crypto ops
 *
 *****************************************************************************/
#include <xmlsec/gcrypt/crypto.h>

/**
 * xmlSecGnuTLSHmacGetMinOutputLength:
 *
 * DEPRECATED (use @xmlSecTransformHmacGetMinOutputBitsSize instead).
 * Gets the value of min HMAC length.
 *
 * Returns: the min HMAC output length
 */
int xmlSecGnuTLSHmacGetMinOutputLength(void)
{
    xmlSecSize val = xmlSecTransformHmacGetMinOutputBitsSize();
    int res;

    XMLSEC_SAFE_CAST_SIZE_TO_INT(val, res, return(-1), NULL);
    return res;
}

/**
 * xmlSecGnuTLSHmacSetMinOutputLength:
 * @min_length: the new min length
 *
 * DEPRECATED (use @xmlSecTransformHmacSetMinOutputBitsSize instead).
 * Sets the min HMAC output length
 */
void xmlSecGnuTLSHmacSetMinOutputLength(int min_length)
{
    xmlSecSize val;
    XMLSEC_SAFE_CAST_INT_TO_SIZE(min_length, val, return, NULL);
    xmlSecTransformHmacSetMinOutputBitsSize(val);
}



#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecGnuTLSTransformHmacSha1GetKlass:
 *
 * The HMAC-SHA1 transform klass.
 *
 * Returns: the HMAC-SHA1 transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformHmacSha1GetKlass(void) {
    return (xmlSecGCryptTransformHmacSha1GetKlass());
}
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecGnuTLSTransformHmacSha256GetKlass:
 *
 * The HMAC-SHA256 transform klass.
 *
 * Returns: the HMAC-SHA256 transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformHmacSha256GetKlass(void) {
    return (xmlSecGCryptTransformHmacSha256GetKlass());
}
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecGnuTLSTransformHmacSha384GetKlass:
 *
 * The HMAC-SHA384 transform klass.
 *
 * Returns: the HMAC-SHA384 transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformHmacSha384GetKlass(void) {
      return (xmlSecGCryptTransformHmacSha384GetKlass());
}
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecGnuTLSTransformHmacSha512GetKlass:
 *
 * The HMAC-SHA512 transform klass.
 *
 * Returns: the HMAC-SHA512 transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformHmacSha512GetKlass(void) {
        return (xmlSecGCryptTransformHmacSha512GetKlass());
}
#endif /* XMLSEC_NO_SHA512 */


#ifndef XMLSEC_NO_RIPEMD160
/**
 * xmlSecGnuTLSTransformHmacRipemd160GetKlass:
 *
 * The HMAC-RIPEMD160 transform klass.
 *
 * Returns: the HMAC-RIPEMD160 transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformHmacRipemd160GetKlass(void) {
       return (xmlSecGCryptTransformHmacRipemd160GetKlass());
}
#endif /* XMLSEC_NO_RIPEMD160 */

#ifndef XMLSEC_NO_MD5
/**
 * xmlSecGnuTLSTransformHmacMd5GetKlass:
 *
 * The HMAC-MD5 transform klass.
 *
 * Returns: the HMAC-MD5 transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformHmacMd5GetKlass(void) {
    return (xmlSecGCryptTransformHmacMd5GetKlass());
}
#endif /* XMLSEC_NO_MD5 */


#endif /* XMLSEC_NO_HMAC */
