/** 
 * XMLSec library
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <string.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>
#include <xmlsec/crypto.h>
#include <xmlsec/nss/errors.h>

/**
 * xmlSecCryptoInit:
 * 
 * XMLSec library specific crypto engine initialization. 
 * This is an internal function called by @xmlSecInit function.
 * The application must call @xmlSecAppCryptoInit before
 * calling @xmlSecInit function or do general crypto engine
 * initialization by itself.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int	
xmlSecCryptoInit(void) {
    return(0);
}

/**
 * xmlSecCryptoShutdown:
 * 
 * XMLSec library specific crypto engine shutdown. 
 * This is an internal function called by @xmlSecShutdown function.
 * The application must call @xmlSecShutdown function
 * before calling @xmlSecAppCryptoInit or doing general 
 * crypto engine shutdown by itself.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecCryptoShutdown(void) {
    return(0);
}

/**
 * xmlSecAppCryptoInit:
 * 
 * General crypto engine initialization. This function is used
 * by XMLSec command line utility and called before 
 * @xmlSecInit function.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecAppCryptoInit(void) {
    return(0);
}

/**
 * xmlSecAppCryptoShutdown:
 * 
 * General crypto engine shutdown. This function is used
 * by XMLSec command line utility and called after 
 * @xmlSecShutdown function.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecAppCryptoShutdown(void) {
    return(0);
}

