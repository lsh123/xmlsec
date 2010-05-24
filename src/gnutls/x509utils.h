/*
 * XML Security Library
 *
 * THIS IS A PRIVATE XMLSEC HEADER FILE
 * DON'T USE IT IN YOUR APPLICATION
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2010 Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_GNUTLS_X509UTILS_H__
#define __XMLSEC_GNUTLS_X509UTILS_H__

#ifndef XMLSEC_PRIVATE
#error "gnutls/x509utils.h file contains private xmlsec definitions and should not be used outside xmlsec or xmlsec-<crypto> libraries"
#endif /* XMLSEC_PRIVATE */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifndef XMLSEC_NO_X509

/**************************************************************************
 *
 * X509 certs list
 *
 *****************************************************************************/
#define xmlSecGnuTLSX509CrtListId   \
        xmlSecGnuTLSX509CrtListGetKlass()
xmlSecPtrListId         xmlSecGnuTLSX509CrtListGetKlass         (void);


/*************************************************************************
 *
 * Utils/helpers
 *
 ************************************************************************/
gnutls_x509_crt_t       xmlSecGnuTLSX509CertDup                 (gnutls_x509_crt_t src);
xmlChar *               xmlSecGnuTLSX509CertGetSubjectDN        (gnutls_x509_crt_t cert);
xmlChar *               xmlSecGnuTLSX509CertGetIssuerDN         (gnutls_x509_crt_t cert);
xmlChar *               xmlSecGnuTLSX509CertGetIssuerSerial     (gnutls_x509_crt_t cert);
xmlChar *               xmlSecGnuTLSX509CertGetSKI              (gnutls_x509_crt_t cert);
gnutls_x509_crt_t       xmlSecGnuTLSX509CertDerRead             (const xmlSecByte* buf,
                                                                 xmlSecSize size);
gnutls_x509_crt_t       xmlSecGnuTLSX509CertBase64DerRead       (xmlChar* buf);
xmlChar*                xmlSecGnuTLSX509CertBase64DerWrite      (gnutls_x509_crt_t cert,
                                                                 int base64LineWrap);
void                    xmlSecGnuTLSX509CertDebugDump           (gnutls_x509_crt_t cert,
                                                                 FILE* output);
void                    xmlSecGnuTLSX509CertDebugXmlDump        (gnutls_x509_crt_t cert,
                                                                 FILE* output);
xmlChar*                xmlSecGnuTLSASN1IntegerWrite            (const unsigned char * data, 
                                                                 size_t len);


#endif /* XMLSEC_NO_X509 */

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* ! __XMLSEC_GNUTLS_X509UTILS_H__ */
