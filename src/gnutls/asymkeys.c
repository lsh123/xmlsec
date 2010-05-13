/**
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2010 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/base64.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/gnutls/crypto.h>

/**************************************************************************
 *
 * We use xmlsec-gcrypt for all the basic crypto ops
 *
 *****************************************************************************/
#include <xmlsec/gcrypt/crypto.h>
#include <gcrypt.h>

#ifndef XMLSEC_NO_DSA

/**
 * xmlSecGnuTLSKeyDataDsaGetKlass:
 *
 * The DSA key data klass.
 *
 * Returns: pointer to DSA key data klass.
 */
xmlSecKeyDataId
xmlSecGnuTLSKeyDataDsaGetKlass(void) {
    return (xmlSecGCryptKeyDataDsaGetKlass());
}

/**
 * xmlSecGnuTLSKeyDataDsaAdoptPrivateKey:
 * @data:               the pointer to DSA key data.
 * @dsa_key:            the pointer to GnuTLS DSA private key.
 *
 * Sets the value of DSA key data.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSKeyDataDsaAdoptPrivateKey(xmlSecKeyDataPtr data, gnutls_x509_privkey_t dsa_key) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataDsaId), -1);
    xmlSecAssert2(dsa_key != NULL, -1);

    /* ALEKSEY_TODO */
    return(0);
}


/**
 * xmlSecGnuTLSKeyDataDsaAdoptPublicKey:
 * @data:               the pointer to DSA key data.
 * @p:                  the pointer to p component of the DSA public key
 * @q:                  the pointer to q component of the DSA public key
 * @g:                  the pointer to g component of the DSA public key
 * @y:                  the pointer to y component of the DSA public key
 *
 * Sets the value of DSA key data.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSKeyDataDsaAdoptPublicKey(xmlSecKeyDataPtr data,
                                     gnutls_datum_t * p, gnutls_datum_t * q,
                                     gnutls_datum_t * g, gnutls_datum_t * y) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataDsaId), -1);
    xmlSecAssert2(p != NULL, -1);
    xmlSecAssert2(q != NULL, -1);
    xmlSecAssert2(g != NULL, -1);
    xmlSecAssert2(y != NULL, -1);

    /* ALEKSEY_TODO */
    return(0);
}

#endif /* XMLSEC_NO_DSA */


#ifndef XMLSEC_NO_RSA

/**
 * xmlSecGnuTLSKeyDataRsaGetKlass:
 *
 * The GnuTLS RSA key data klass.
 *
 * Returns: pointer to GnuTLS RSA key data klass.
 */
xmlSecKeyDataId
xmlSecGnuTLSKeyDataRsaGetKlass(void) {
    return (xmlSecGCryptKeyDataRsaGetKlass());
}

/**
 * xmlSecGnuTLSKeyDataRsaAdoptPrivateKey:
 * @data:               the pointer to RSA key data.
 * @rsa_key:            the pointer to GnuTLS RSA private key.
 *
 * Sets the value of RSA key data.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSKeyDataRsaAdoptPrivateKey(xmlSecKeyDataPtr data, gnutls_x509_privkey_t rsa_key) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataRsaId), -1);
    xmlSecAssert2(rsa_key != NULL, -1);

    /* ALEKSEY_TODO */
    return(0);
}


/**
 * xmlSecGnuTLSKeyDataRsaAdoptPublicKey:
 * @data:               the pointer to RSA key data.
 * @m:                  the pointer to m component of the RSA public key
 * @e:                  the pointer to e component of the RSA public key
 *
 * Sets the value of RSA key data.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSKeyDataRsaAdoptPublicKey(xmlSecKeyDataPtr data,
                                     gnutls_datum_t * m, gnutls_datum_t * e) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataRsaId), -1);
    xmlSecAssert2(m != NULL, -1);
    xmlSecAssert2(e != NULL, -1);

    /* ALEKSEY_TODO */
    return(0);
}
#endif /* XMLSEC_NO_RSA */
