/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @brief Internal XML Encryption helpers.
 */
#ifndef XMLSEC_XMLENC_HELPERS_H
#define XMLSEC_XMLENC_HELPERS_H

#ifndef XMLSEC_PRIVATE
#error "xmlenc_helpers.h file contains private xmlsec definitions and should not be used outside xmlsec or xmlsec-crypto libraries"
#endif /* XMLSEC_PRIVATE */

#ifndef XMLSEC_NO_XMLENC

#include <xmlsec/keyinfo.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

xmlSecTransformOperation        xmlSecEncCtxMapOperation                    (xmlSecTransformOperation operation);

int                             xmlSecEncCtxEncryptedKeyXmlRead             (xmlSecEncCtxPtr encCtx,
                                                                             xmlNodePtr node,
                                                                             xmlSecKeyPtr key,
                                                                             xmlSecKeyInfoCtxPtr keyInfoCtx);

int                             xmlSecEncCtxEncryptedKeyXmlWrite            (xmlSecEncCtxPtr encCtx,
                                                                             xmlNodePtr node,
                                                                             xmlSecKeyPtr key,
                                                                             xmlSecKeyInfoCtxPtr keyInfoCtx);

xmlSecKeyPtr                    xmlSecEncCtxDerivedKeyGenerate              (xmlSecEncCtxPtr encCtx,
                                                                             xmlSecKeyDataId keyId,
                                                                             xmlNodePtr node,
                                                                             xmlSecKeyInfoCtxPtr keyInfoCtx);

xmlSecKeyPtr                    xmlSecEncCtxAgreementMethodGenerate         (xmlSecEncCtxPtr encCtx,
                                                                             xmlSecKeyDataId keyId,
                                                                             xmlNodePtr node,
                                                                             xmlSecKeyInfoCtxPtr keyInfoCtx);
int                             xmlSecEncCtxAgreementMethodXmlWrite         (xmlSecEncCtxPtr encCtx,
                                                                             xmlNodePtr node,
                                                                             xmlSecKeyInfoCtxPtr keyInfoCtx);



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* XMLSEC_NO_XMLENC */

#endif /* XMLSEC_XMLENC_HELPERS_H */
