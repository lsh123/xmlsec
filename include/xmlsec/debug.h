/** 
 * XMLSec library
 *
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_DEBUG_H__
#define __XMLSEC_DEBUG_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 


XMLSEC_EXPORT void	xmlSecTimerInit				(void);
XMLSEC_EXPORT void	xmlSecTimerStart			(void);
XMLSEC_EXPORT void	xmlSecTimerEnd				(void);
XMLSEC_EXPORT double 	xmlSecTimerGet				(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_DEBUG_H__ */

