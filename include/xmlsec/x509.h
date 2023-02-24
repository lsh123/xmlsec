/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_X509_H__
#define __XMLSEC_X509_H__

/**
 * xmlSecKeyX509DataValue:
 * @cert:              the certificate from <dsig:X509Certificate/> node.
 * @crl:               the crl from <dsig:X509CRL/> node.
 * @ski:               the ski from <dsig:X509SKI/> node.
 * @subject:           the subject name from <dsig:X509SubjectName /> node.
 * @issuerName:        the ski from <dsig:X509IssuerSerial/> node.
 * @issuerSerial:      the ski from <dsig:X509IssuerSerial/> node.
 * @digestAlgorithm:   the @digest algorithm from <dsig11:X509Digest/> node.
 * @digest:            the digest from <dsig11:X509Digest/> node.
 *
 * The content of a child of <X509Data/> node. Not all values will be set!
 */
struct _xmlSecKeyX509DataValue {
    xmlSecBuffer cert;
    xmlSecBuffer crl;

    xmlSecBuffer ski;

    xmlChar* subject;

    xmlChar* issuerName;
    xmlChar* issuerSerial;

    xmlChar* digestAlgorithm;
    xmlSecBuffer digest;
};

#endif /* __XMLSEC_X509_H__ */
