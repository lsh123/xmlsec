/** 
 * XMLSec library
 *
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_H__
#define __XMLSEC_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>

#include <xmlsec/version.h>

/* XMLDSig namespace */
extern const xmlChar xmlSecDSigNs[];

/* XMLEnc namespace */
extern const xmlChar xmlSecEncNs[];


void 		xmlSecInit			(void);
void 		xmlSecShutdown			(void);


#define xmlSecIsHex(c) \
    (( (('0' <= (c)) && ((c) <= '9')) || \
       (('a' <= (c)) && ((c) <= 'f')) || \
       (('A' <= (c)) && ((c) <= 'F')) ) ? 1 : 0)

#define xmlSecGetHex(c) \
    ( (('0' <= (c)) && ((c) <= '9')) ? (c) - '0' : \
    ( (('a' <= (c)) && ((c) <= 'f')) ? (c) - 'a' + 10 :  \
    ( (('A' <= (c)) && ((c) <= 'F')) ? (c) - 'A' + 10 : 0 )))




/**
 * "Hide" warnings about 
 *     static const char func[] = "XXX";
 *  when debug messages are disabled
 */
#if defined(__GNUC__)
#define _UNUSED_VARIABLE_ 	__attribute__((unused))
#else /* __GCC__ */
#define _UNUSED_VARIABLE_ 
#endif /* __GCC__ */ 


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_H__ */

