/** 
 * XML Security standards test: XMLDSig
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_MSC_VER)
#define snprintf _snprintf
#endif

#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#ifndef XMLSEC_NO_XSLT
#include <libxslt/xslt.h>
#include <libxslt/extensions.h> 
#include <libxslt/xsltInternals.h>
#include <libxslt/xsltutils.h>
#include <libexslt/exslt.h>
#endif /* XMLSEC_NO_XSLT */

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/transforms.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/xmlenc.h>
#include <xmlsec/debug.h>
#include <xmlsec/errors.h>

#include "crypto.h"

static const char copyright[] =
    "Written by Aleksey Sanin <aleksey@aleksey.com>.\n"
    "Copyright (C) 2002 Aleksey Sanin.\n"
    "This is free software: see the source for copying information.\n";

static const char bugs[] = 
    "To report bugs or get some help check XML Security Library home page:\n"
    "  http://www.aleksey.com/xmlsec\n";

static const char usage[] = 
    "Usage: xmlsec %s [<options>] <file> [<file> [ ... ]]\n";

static const char helpCommands[] =     
    "XMLSec commands are:\n"
    "  help                  display this help information and exit\n"
    "  help-<command>        display help information for <command> and exit\n"
    "  version               print version information and exit\n"
    "  keys                  keys XML file manipulation\n"
#ifndef XMLSEC_NO_XMLDSIG
    "  sign                  sign data and output XML document\n"
    "  verify                verify signed document\n"
#endif /* XMLSEC_NO_XMLDSIG */
#ifndef XMLSEC_NO_XMLENC
    "  encrypt               encrypt data and output XML document\n"
    "  decrypt               decrypt data from XML document\n"
#endif /* XMLSEC_NO_XMLENC */
    "\n";

static const char helpVersion[] = 
    "Usage: xmlsec version\n"
    "\n"
    "Prints version information and exits.\n"
    "\n";    

static const char helpKeys[] = 
    "Keys XML file manipulation. The result keys set is written to the file.\n"
    "\n"
    "Keys generation options:\n"
    "  --gen-<keyKlass>-<keySize> <name>\n"
    "                        generate new <keyKlass> key of <keySize> bits size,\n"
    "                        set the key name to <name> and add the result to keys manager\n"
    "                        (for example, \"--gen-rsa-1024 mykey\" generates a new 1024 bits\n"
    "                         RSA key and sets it's name to \"mykey\")\n"
    "\n";

static const char helpKeySelect[] = 
    "Key selection options:\n"
    "  --sesssion-<keyKlass>-<keySize>\n"
    "                        generate new session <keyKlass> key of <keySize> bits size\n"
    "                        (for example, \"--session-des-192\" generates a new 192 bits\n"
    "                         DES key for DES3 encryption)\n"
    "\n";



static const char helpSign[] = 
    "Signs data in the file and outputs document in \"XML Signature\" format.\n"
    "\n"
#ifndef XMLSEC_NO_XMLDSIG    
    "Signature options:\n"
    "  --output <filename>   write signed document to file <filename>\n"
    "  --ignore-manifests    do not process <Manifest> elements\n"
    "  --fake-signatures     disable actual signature calc for perf tests\n"
#else  /* XMLSEC_NO_XMLDSIG */
    "XML Digital Signatures support was disabled during compilation\n"
#endif /* XMLSEC_NO_XMLDSIG */    
    "\n";

static const char helpVerify[] = 
    "Verifies signed XML document in the file.\n"
    "\n"
#ifndef XMLSEC_NO_XMLDSIG    
    "Verification options:\n"
    "  --ignore-manifests    do not process <Manifest> elements\n"
    "  --print-result        print the result information\n"
    "  --print-references    store and print the pre-digested\n"
    "                        signature references\n"
    "  --print-manifests     store and print the pre-digested\n"
    "                        manifests references\n"
    "  --print-signature     store and print the pre-signated\n"
    "                        data (<SignedInfo> element)\n"
    "  --print-all           combination of the all \"--print-*\" options\n"
    "  --print-xml           print the result information in XML format\n"
    "  --print-to-file <file> print the result to file <file>\n"
    "  --fake-signatures     disable actual signature calc for perf tests\n"
#else  /* XMLSEC_NO_XMLDSIG */
    "XML Digital Signatures support was disabled during compilation\n"
#endif /* XMLSEC_NO_XMLDSIG */    
    "\n";

static const char helpEncrypt[] = 
    "Encrypts data and outputs document in \"XML Encryption\" format.\n"    
    "\n"
#ifndef XMLSEC_NO_XMLENC
    "Encryption options:\n"
    "  --output <filename>   write encrypted document to file <filename>\n"
    "  --binary <binary>     binary file to encrypt\n"
    "  --xml <file>          XML file to encrypt\n"
#else /* XMLSEC_NO_XMLENC */
    "XML Encryption support was disabled during compilation\n"
#endif /* XMLSEC_NO_XMLENC */    
    "\n";

static const char helpDecrypt[] =
    "Decrypts data from document in \"XML Encryption\" format.\n"
#ifndef XMLSEC_NO_XMLENC
    "  --output <filename>   write decrypted document to file <filename>\n"
#else /* XMLSEC_NO_XMLENC */
    "\n"
    "XML Encryption support was disabled during compilation\n"
#endif /* XMLSEC_NO_XMLENC */    
    "\n";

static const char helpNodeSelection[] = 
    "Start node selection options:\n"
    "  --node-id <id>        set the operation start point to the node \n"
    "                        with given <id>\n"
    "  --node-name [<namespace-uri>:]<name>\n"
    "                        set the operation start point to the first node \n"
    "                        with given <name> and <namespace> URI\n"
    "  --node-xpath <expr>   set the operation start point to the first node \n"
    "                        selected by the specified XPath expression\n"
    "  --dtdfile <file>      Load the specified file as the DTD\n"
    "\n";
    
static const char helpKeysMngmt[] = 
    "Keys management options:\n"
    "  --keys <file>         load keys from XML file\n"
    "  --privkey[:<name>] <file>[,<cafile>[,<cafile>[...]]]\n"
    "                        load private key from PEM file and certificates\n"
    "                        that verify this key\n"
    "  --pubkey[:<name>] <file>\n"
    "                        load public key from PEM file\n"
#ifndef XMLSEC_NO_X509
    "  --pkcs12[:<name>] <file>\n"
    "                        load private key from pkcs12 file\n"
#endif /* XMLSEC_NO_X509 */    
#ifndef XMLSEC_NO_HMAC    
    "  --hmackey[:<name>] <file>\n"
    "                        load hmac key from binary file\n"
#endif  /* XMLSEC_NO_HMAC */    
    "  --allowed <list>      specify the set of the allowed key origins\n"
    "                        for signature verification or decryption;\n"
    "                        <list> is a comma separated collection of\n"
    "                        the following values:\n"
    "                          \"keymanager\", \"keyname\", \"keyvalue\",\n"
    "                          \"retrieval-doc\", \"retrieval-remote\",\n"
    "                          \"enc-key\", \"x509\", \"pgp\"\n"
    "                        by default, all key origins are allowed\n"
    "  --pwd <password>      the password to use for reading keys and certs\n"
    "\n";
    
static const char helpX509[] =
#ifndef XMLSEC_NO_X509    
    "X509 certificates options:\n"
    "  --trusted <file>      load trusted (root) certificate from PEM file\n"
    "  --untrusted <file>    load un-trusted certificate from PEM file\n"
    "  --pwd <password>      the password to use for reading keys and certs\n"
    "  --verification-time <time> the local time in \"YYYY-MM-DD HH:MM:SS\"\n"
    "                       format used certificates verification\n"
    "  --depth <number>      maximum chain depth\n"
#else /* XMLSEC_NO_X509 */
    "x509 certificates support was disabled during compilation\n"
#endif /* XMLSEC_NO_X509 */        
    "\n";
    
static const char helpMisc[] = 
    "Misc. options:\n"
    "  --repeat <number>     repeat the operation <number> times\n"
    "  --disable-error-msgs  do not print xmlsec error messages\n"
#ifdef XMLSEC_CRYPTO_OPENSSL
    "  --print-openssl-errors print openssl errors stack at the end\n"
#endif /* XMLSEC_CRYPTO_OPENSSL */    
    "\n";

typedef enum _xmlsecCommand {
    xmlsecCommandNone = 0,
    xmlsecCommandKeys,
    xmlsecCommandSign,
    xmlsecCommandVerify,
    xmlsecCommandEncrypt,
    xmlsecCommandDecrypt
} xmlsecCommand;

typedef struct _xmlSecDSigStatus {
    size_t			signaturesOk;
    size_t			signaturesFail;
    size_t			signRefOk;
    size_t			signRefFail;
    size_t			manifestRefOk;
    size_t			manifestRefFail;
} xmlSecDSigStatus, *xmlSecDSigStatusPtr;

typedef struct _xmlSecAppCtx		xmlSecAppCtx, *xmlSecAppCtxPtr;
struct _xmlSecAppCtx {
    xmlSecKeysMngrPtr 	keysMngr; 
    xmlSecKeyPtr 	sessionKey;
    
#ifndef XMLSEC_NO_XMLDSIG
    xmlSecDSigCtxPtr 	dsigCtx;
#endif /* XMLSEC_NO_XMLDSIG */
#ifndef XMLSEC_NO_XMLENC
    xmlSecEncCtxPtr 	encCtx;
#endif /* XMLSEC_NO_XMLENC */
    
};

static xmlSecAppCtx	gXmlSecAppCtx;

/**
 * Init/Shutdown
 */
static int		xmlSecAppInit			(xmlSecAppCtxPtr ctx);
static int		xmlSecAppShutdown		(xmlSecAppCtxPtr ctx);

/** 
 * Parsing command line
 */
static int		xmlSecAppOptionsParse		(xmlSecAppCtxPtr ctx, 
							 int argc, 
							 char** argv, 
							 int pos);

int findIDNodes(xmlDtdPtr dtd, xmlDocPtr doc);
xmlNodePtr findStartNode(xmlDocPtr doc, const xmlChar* defNodeName, const xmlChar* defNodeNs);

/**
 * Read command line options
 */
int  readKeyOrigins(char *keyOrigins);
int  readNumber(const char *str, int *number);
int  readTime(const char* str, time_t* t);

/**
 * Print help
 */
void printUsage(const char *command);
void printVersion(void);


/**
 * XML Signature
 */
#ifndef XMLSEC_NO_XMLDSIG
void getDSigResult(xmlSecDSigResultPtr result, xmlSecDSigStatusPtr status);
int  generateDSig(xmlDocPtr doc);
int  validateDSig(xmlDocPtr doc);
#endif /* XMLSEC_NO_XMLDSIG */

/**
 * XML Encryption
 */
#ifndef XMLSEC_NO_XMLENC
char *dataFile = NULL;
int binary = 0;

int encrypt(xmlDocPtr tmpl);
int decrypt(xmlDocPtr doc);
#endif /* XMLSEC_NO_XMLENC */

/**
 * Global data
 */

char *output = NULL; 
char *nodeId = NULL;
char *nodeName = NULL;
char *nodeNs = NULL;
char* nodeXPath = NULL;
int repeats = 1;
int printResult = 0;
int printXml = 0;
FILE* printFile = NULL;
clock_t total_time = 0;
char *global_pwd = NULL;
int print_openssl_errors = 0;
xmlDtdPtr idsDtd = NULL;

int main(int argc, char **argv) {
    int res = 1;
    xmlsecCommand command = xmlsecCommandNone;
    xmlDocPtr doc = NULL;
    int i;
    int pos;
    int ret;
    int templateRequired = 0;
            
    /**
     * Read the command
     */
    if((argc < 2) || (strcmp(argv[1], "help") == 0) || (strcmp(argv[1], "--help") == 0)) {
	printUsage(NULL);
	return(0);
    } else if(strncmp(argv[1], "help-", 5) == 0) { 
	printUsage(argv[1] + 5);
	return(0);
    } else if((strcmp(argv[1], "version") == 0) || (strcmp(argv[1], "--version") == 0)) {
	printVersion();
	return(0);
    } else if(strcmp(argv[1], "keys") == 0) {
	command = xmlsecCommandKeys;
#ifndef XMLSEC_NO_XMLDSIG
    } else if(strcmp(argv[1], "sign") == 0) {
	command = xmlsecCommandSign;
	templateRequired = 1;
    } else if(strcmp(argv[1], "verify") == 0) {
	command = xmlsecCommandVerify;
	templateRequired = 1;
#endif /* XMLSEC_NO_XMLDSIG */
#ifndef XMLSEC_NO_XMLENC
    } else if(strcmp(argv[1], "encrypt") == 0) {
	command = xmlsecCommandEncrypt;
	templateRequired = 1;
    } else if(strcmp(argv[1], "decrypt") == 0) {
	command = xmlsecCommandDecrypt;
	templateRequired = 1;
#endif /* XMLSEC_NO_XMLENC */
    } else if(strcmp(argv[1], "keys") == 0) {
	command = xmlsecCommandKeys;
    } else {
	fprintf(stdout, "Error: unknown command \"%s\"\n", argv[1]);
	printUsage(NULL);
	return(0);
    }

    if(xmlSecAppInit(&gXmlSecAppCtx) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAppInit");
	goto done;
    }

    xmlSecTimerInit();
        
    pos = xmlSecAppOptionsParse(&gXmlSecAppCtx, argc, argv, 2);
    if(pos < 0) {
	printUsage(NULL);
	goto done;	    
    }
    
    /**
     * Now process files one after another
     */
    ret = 0; 
    while((pos < argc) && (ret >= 0)) {
	templateRequired = 0;
	for(i = 0; (i < repeats); ++i) {
	    if(command == xmlsecCommandKeys) {
		/* simply save keys */
		ret = xmlSecAppCryptoSimpleKeysMngrSave(gXmlSecAppCtx.keysMngr,  argv[pos], xmlSecKeyDataTypeAny);
	    } else {
		doc = xmlSecParseFile(argv[pos]);
	        if(doc == NULL) {
		    fprintf(stderr, "Error: failed to read XML file \"%s\"\n", argv[pos]);
		    printUsage(NULL);
	    	    goto done;
		}
                if (idsDtd) {
                    findIDNodes(idsDtd, doc);
		}
			
    		switch(command) {	    
#ifndef XMLSEC_NO_XMLDSIG	    
    		case xmlsecCommandSign:
		    ret = generateDSig(doc);
		    break;
		case xmlsecCommandVerify:
		    ret = validateDSig(doc);
	    	    break;
#endif /* XMLSEC_NO_XMLDSIG */
		
#ifndef XMLSEC_NO_XMLENC
		case xmlsecCommandEncrypt:
		    ret = encrypt(doc);
		    break;
		case xmlsecCommandDecrypt:
		    ret = decrypt(doc);
		    break;
#endif /* XMLSEC_NO_XMLENC */

		default:
		    fprintf(stderr, "Error: unknown command\n");
	    	    printUsage(NULL);
		    goto done;	    
		}
	    }
	    if((ret < 0) && (repeats <= 1)) {				
		fprintf(stderr, "Error: operation failed\n");
 		goto done;	    	    
	    }
	    xmlFreeDoc(doc); doc = NULL;
	}
	++pos;
    }
    if(templateRequired != 0) {
	fprintf(stderr, "Error: no templates specified\n");
 	goto done;	    	    
    }
    
    if(repeats > 1) {
        fprintf(stderr, "Executed %d tests in %ld msec\n", repeats, total_time / (CLOCKS_PER_SEC / 1000));    
	if(xmlSecTimerGet() > 0.0001) {
	    fprintf(stderr, "The debug timer is %f\n", xmlSecTimerGet());    
	}
    }

    /* success */
    res = 0;
    
done:    
    if(print_openssl_errors) {
#ifdef XMLSEC_CRYPTO_OPENSSL
	ERR_print_errors_fp(stderr);
#endif /* XMLSEC_CRYPTO_OPENSSL */    
    }
    if(doc != NULL) {
	xmlFreeDoc(doc); 
    }
    if(idsDtd != NULL) {
	xmlFreeDtd(idsDtd);
    }

    if(xmlSecAppShutdown(&gXmlSecAppCtx) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAppShutdown");
	/* could do nothing with that */
    }
    return(res);
}






void printUsage(const char *command) {
    if(command == NULL) {
	fprintf(stderr, usage, "<command>");
	fprintf(stderr, "\n");
	fprintf(stderr, "%s", helpCommands);
    } else if(strcmp(command, "version") == 0) {
	fprintf(stderr, "%s", helpVersion);
    } else if(strcmp(command, "keys") == 0) {
	fprintf(stderr, usage, command);
	fprintf(stderr, "\n");
	fprintf(stderr, "%s", helpKeys);
	fprintf(stderr, "%s", helpKeysMngmt);
	fprintf(stderr, "%s", helpMisc);
    } else if(strcmp(command, "sign") == 0) {
	fprintf(stderr, usage, command);
	fprintf(stderr, "\n");
	fprintf(stderr, "%s", helpSign);
	fprintf(stderr, "%s", helpNodeSelection);
	fprintf(stderr, "%s", helpKeysMngmt);
	fprintf(stderr, "%s", helpKeySelect);
	fprintf(stderr, "%s", helpMisc);
    } else if(strcmp(command, "verify") == 0) {
	fprintf(stderr, usage, command);
	fprintf(stderr, "\n");
	fprintf(stderr, "%s", helpVerify);
	fprintf(stderr, "%s", helpNodeSelection);
	fprintf(stderr, "%s", helpKeysMngmt);
	fprintf(stderr, "%s", helpKeySelect);
	fprintf(stderr, "%s", helpX509);
	fprintf(stderr, "%s", helpMisc);
    } else if(strcmp(command, "encrypt") == 0) {
	fprintf(stderr, usage, command);
	fprintf(stderr, "\n");
	fprintf(stderr, "%s", helpEncrypt);
	fprintf(stderr, "%s", helpNodeSelection);
	fprintf(stderr, "%s", helpKeysMngmt);
	fprintf(stderr, "%s", helpKeySelect);
	fprintf(stderr, "%s", helpMisc);
    } else if(strcmp(command, "decrypt") == 0) {
	fprintf(stderr, usage, command);
	fprintf(stderr, "\n");
	fprintf(stderr, "%s", helpDecrypt);
	fprintf(stderr, "%s", helpNodeSelection);
	fprintf(stderr, "%s", helpKeysMngmt);
	fprintf(stderr, "%s", helpKeySelect);
	fprintf(stderr, "%s", helpX509);
	fprintf(stderr, "%s", helpMisc);
    } else {
	fprintf(stderr, "Error: unknown command \"%s\"\n", command);
	fprintf(stderr, usage, "<command>");
	fprintf(stderr, "\n");
	fprintf(stderr, "%s", helpCommands);
    }
    fprintf(stderr, "%s\n", bugs);
    fprintf(stderr, "%s\n", copyright);
}

void printVersion(void) {
    fprintf(stdout, "xmlsec %s\n", XMLSEC_VERSION);
    fprintf(stderr, "\n");
    fprintf(stderr, "%s\n", bugs);
    fprintf(stderr, "%s\n", copyright);    
}



/**
 * Command line options
 */
int  readNumber(const char *str, int *number) {
    if(sscanf(str, "%d", number) <= 0) {
	fprintf(stderr, "Error: the number is expected instead of \"%s\"\n", str);
	return(-1);
    }
    return(0);
}

int  readTime(const char* str, time_t* t) {
    struct tm tm;
    int n;
    
    if((str == NULL) || (t == NULL)) {
	return(-1);
    }
    memset(&tm, 0, sizeof(tm));
    tm.tm_isdst = -1;
    
    n = sscanf(str, "%4d-%2d-%2d%*c%2d:%2d:%2d", 
			    &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
			    &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
    if((n != 6) || (tm.tm_year < 1900) 
		|| (tm.tm_mon  < 1) || (tm.tm_mon  > 12) 
		|| (tm.tm_mday < 1) || (tm.tm_mday > 31)
		|| (tm.tm_hour < 0) || (tm.tm_hour > 23)
		|| (tm.tm_min  < 0) || (tm.tm_min  > 59)
		|| (tm.tm_sec  < 0) || (tm.tm_sec  > 61)) {
	return(-1);	    
    }

    tm.tm_year -= 1900; /* tm relative format year */
    tm.tm_mon  -= 1; /* tm relative format month */

    (*t) = mktime(&tm);
    return(0);    
}


int  readKeyOrigins(char *keyOrigins) {
    xmlSecKeyOrigin res = xmlSecKeyOriginDefault;
    char *p;
    
    p = strtok(keyOrigins, ",");
    while(p != NULL) {
	if(strcmp(p, "keymanager") == 0) {
	    res |= xmlSecKeyOriginKeyManager;
	} else if(strcmp(p, "keyname") == 0) {
	    res |= xmlSecKeyOriginKeyName;
	} else if(strcmp(p, "keyvalue") == 0) {
	    res |= xmlSecKeyOriginKeyValue;
	} else if(strcmp(p, "retrieval-doc") == 0) {
	    res |= xmlSecKeyOriginRetrievalDocument;
	} else if(strcmp(p, "retrieval-remote") == 0) {
	    res |= xmlSecKeyOriginRetrievalRemote;
	} else if(strcmp(p, "x509") == 0) {
	    res |= xmlSecKeyOriginX509;
	} else if(strcmp(p, "pgp") == 0) {
	    res |= xmlSecKeyOriginPGP;
	} else if(strcmp(p, "enc-key") == 0) {
	    res |= xmlSecKeyOriginEncryptedKey;
	} else {
	    fprintf(stderr, "Error: unknown key origin: \"%s\" (ignored)\n", p);
	    return(-1);
	}
	p = strtok(NULL, ",");
    }    
    
    gXmlSecAppCtx.keysMngr->allowedOrigins = res;
    return(0);
}

xmlNodePtr findStartNode(xmlDocPtr doc, const xmlChar* defNodeName, const xmlChar* defNodeNs) {
    xmlNodePtr cur = NULL;
    
    if(doc == NULL) {
	fprintf(stderr, "Error: document is null\n");
	return(NULL);
    }
    
    if(nodeId != NULL) {
	xmlAttrPtr attr;
	    
	attr = xmlGetID(doc, BAD_CAST nodeId);
	cur = (attr != NULL) ? attr->parent : NULL;
    } else if(nodeName != NULL) {
	cur = xmlSecFindNode(xmlDocGetRootElement(doc), BAD_CAST nodeName, BAD_CAST nodeNs);
    } else if(nodeXPath != NULL) {
	xmlXPathContextPtr ctx = NULL;
	xmlXPathObjectPtr obj = NULL;
	
	ctx = xmlXPathNewContext(doc);
	obj = xmlXPathEval(BAD_CAST nodeXPath, ctx);

	if ((obj != NULL) && (obj->nodesetval != NULL) && (obj->nodesetval->nodeNr > 0)) {
	    cur = obj->nodesetval->nodeTab[0];
	}
	
	xmlXPathFreeContext(ctx);
	xmlXPathFreeObject(obj);
    } else if(defNodeName != NULL) {
	cur = xmlSecFindNode(xmlDocGetRootElement(doc), defNodeName, defNodeNs);
    } else {
	cur = xmlDocGetRootElement(doc);
    }
    return(cur);
}

/**
 * XML Digital Signature
 */ 
#ifndef XMLSEC_NO_XMLDSIG
 
void getDSigResult(xmlSecDSigResultPtr result, xmlSecDSigStatusPtr status) {
    xmlSecReferenceResultPtr ref;
    
    if((result == NULL) || (status == NULL)) {
	fprintf(stderr, "Error: result or result is null\n");
	return;
    }
    
    if(result->result == xmlSecTransformStatusOk) {
	++(status->signaturesOk);
    } else {
	++(status->signaturesFail);
    }
    
    ref = result->firstSignRef;
    while(ref != NULL) {
	if(ref->result == xmlSecTransformStatusOk) {
	    ++(status->signRefOk);
	} else {
	    ++(status->signRefFail);
	}
	ref = ref->next;
    }

    ref = result->firstManifestRef;
    while(ref != NULL) {
	if(ref->result == xmlSecTransformStatusOk) {
	    ++(status->manifestRefOk);
	} else {
	    ++(status->manifestRefFail);
	}
	ref = ref->next;
    }
}

int generateDSig(xmlDocPtr doc) {    
    xmlSecDSigResultPtr result = NULL;
    xmlNodePtr signNode;
    xmlChar *string = NULL;	
    int len;
    int ret;
    int res = -1;
    clock_t start_time;

    signNode = findStartNode(doc, BAD_CAST "Signature", xmlSecDSigNs);
    if(signNode == NULL) {
        fprintf(stderr,"Error: failed to find Signature node\n");
	return(-1);
    }    

    start_time = clock();
    ret = xmlSecDSigGenerate(gXmlSecAppCtx.dsigCtx, NULL, gXmlSecAppCtx.sessionKey, signNode, &result);
    total_time += clock() - start_time;    
    if(ret < 0) {
        fprintf(stderr,"Error: xmlSecDSigGenerate() failed \n");
	goto done;    
    }
    
    if(repeats <= 1) { 
        /*
	 * Print document out in default UTF-8 encoding
         */
	xmlDocDumpMemoryEnc(doc, &string, &len, NULL);
        if(string == NULL) {
	    fprintf(stderr,"Error: failed to dump document to memory\n");
	    goto done;
        }
	
	if(output) {
	    FILE* f = fopen(output, "w");
	    if(f == NULL) {
		fprintf(stderr,"Error: failed to open output file \"%s\"\n", output);
		goto done;
	    }
	    fwrite(string, len, 1, f);
	    fclose(f);
	} else {	    
	    fwrite(string, len, 1, stdout);
	}
    }
    res = 0;
    
done:    
    if(printFile != NULL) {
	fclose(printFile);
    }
    if(string != NULL) {
	xmlFree(string);        
    }
    if(result != NULL) {
	xmlSecDSigResultDestroy(result);
    }
    return(res);
}

int validateDSig(xmlDocPtr doc) {    
    xmlSecDSigResultPtr result = NULL;
    xmlSecDSigStatus status;
    xmlNodePtr signNode;
    clock_t start_time;
    int ret;
    	    
    signNode = findStartNode(doc, BAD_CAST "Signature", xmlSecDSigNs);
    if(signNode == NULL) {
        fprintf(stderr,"Error: failed to find Signature node\n");
	return(-1);
    }    

    start_time = clock();        
    ret = xmlSecDSigValidate(gXmlSecAppCtx.dsigCtx, NULL, gXmlSecAppCtx.sessionKey, signNode, &result);
    total_time += clock() - start_time;    
    if((ret < 0) || (result == NULL)){
	fprintf(stdout,"ERROR\n");
	if(result != NULL) { 
	    xmlSecDSigResultDestroy(result); 
	}
	return(-1);
    } 
	    
    if(printResult) {
	if(printXml) {	
    	    xmlSecDSigResultDebugXmlDump(result, 
		    (printFile != NULL) ? printFile : stderr);
	} else {
    	    xmlSecDSigResultDebugDump(result, 
		    (printFile != NULL) ? printFile : stderr);
	}	
    }	
	    
    /** 
     * we will simply walk thru and calculate the number of 
     * ok/fails
     */
    memset(&status, 0, sizeof(status));
    getDSigResult(result, &status);
    
    if(repeats <= 1){ 
        
	fprintf(stderr, "= Status:\n");
	fprintf(stderr, "== Signatures ok: %d\n", status.signaturesOk);
        fprintf(stderr, "== Signatures fail: %d\n", status.signaturesFail);
	fprintf(stderr, "== SignedInfo Ref ok: %d\n", status.signRefOk);
        fprintf(stderr, "== SignedInfo Ref fail: %d\n", status.signRefFail);
	fprintf(stderr, "== Manifest Ref ok: %d\n", status.manifestRefOk);
        fprintf(stderr, "== Manifest Ref fail: %d\n", status.manifestRefFail);
    }
    	    	
    if(result != NULL) {
	xmlSecDSigResultDestroy(result);
    }

    if(status.signaturesFail == 0) {
	fprintf(stdout, "OK\n");  
	return(0);    
    }
    
    fprintf(stdout, "FAIL\n");
    return(-1);
}
#endif /* XMLSEC_NO_XMLDSIG */


/**
 * XML Encryption
 */
#ifndef XMLSEC_NO_XMLENC
int encrypt(xmlDocPtr tmpl) {    
    xmlSecEncResultPtr encResult = NULL;
    xmlChar *result = NULL;	
    xmlDocPtr doc = NULL;
    clock_t start_time;
    int len;
    int ret;
    int res = -1;

    if(binary && (dataFile != NULL)) {
        start_time = clock();        
	ret = xmlSecEncryptUri(gXmlSecAppCtx.encCtx, NULL, gXmlSecAppCtx.sessionKey,
				xmlDocGetRootElement(tmpl), dataFile, 
				&encResult);
        total_time += clock() - start_time;    
	if(ret < 0) {
    	    fprintf(stderr,"Error: xmlSecEncryptUri() failed \n");
	    goto done;    
	} 

    } else if(!binary && (dataFile != NULL)) { 
	xmlNodePtr cur;
	
	/** 
	 * Load doc
	 */
	doc = xmlParseFile(dataFile);
	if (doc == NULL) {
	    fprintf(stderr, "Error: unable to parse file \"%s\"\n", dataFile);
	    goto done;    
	}

	/**
	 * What do we want to replace?
	 */    
	cur = findStartNode(doc, NULL, NULL);
	if(cur == NULL) {
    	    fprintf(stderr,"Error: empty document for file \"%s\" or unable to find node\n", dataFile);
	    goto done;    
	}

        start_time = clock();        	
	ret = xmlSecEncryptXmlNode(gXmlSecAppCtx.encCtx, NULL, gXmlSecAppCtx.sessionKey,
				xmlDocGetRootElement(tmpl), 
				cur, &encResult);	
        total_time += clock() - start_time;    
	if(ret < 0) {
    	    fprintf(stderr,"Error: xmlSecEncryptXmlNode() failed \n");
	    goto done;    
	} 
    } else {
        fprintf(stderr,"Error: unknown type or bad type parameters\n");
	goto done;    
    }
    
    if(repeats <= 1) {	
        /*
	 * Print document out in default UTF-8 encoding
         */     
	if((encResult != NULL) && (encResult->replaced) && (doc != NULL)) {
	    xmlDocDumpMemoryEnc(doc, &result, &len, NULL);  
        } else {
    	    xmlDocDumpMemoryEnc(tmpl, &result, &len, NULL);
        }
	if(result == NULL) {
    	    fprintf(stderr,"Error: failed to dump document to memory\n");
    	    goto done;
        }
	if(output) {
	    FILE* f = fopen(output, "w");
	    if(f == NULL) {
		fprintf(stderr,"Error: failed to open output file \"%s\"\n", output);
		goto done;
	    }
	    fwrite(result, len, 1, f);
	    fclose(f);
	} else {	    
	    fwrite(result, len, 1, stdout);
	}
    }
    res = 0;

    if(printResult) {
    	xmlSecEncResultDebugDump(encResult, stderr);
    }	
        
done:    
    if(doc != NULL) {
	xmlFreeDoc(doc);
    }
    if(result != NULL) {
	xmlFree(result);        
    }
    if(encResult != NULL) {
	xmlSecEncResultDestroy(encResult);
    }
    return(res);
}

int decrypt(xmlDocPtr doc) {    
    xmlSecEncResultPtr encResult = NULL;
    xmlNodePtr cur;
    clock_t start_time;
    int ret;
    int res = -1;

    cur = findStartNode(doc, BAD_CAST "EncryptedData", xmlSecEncNs);
    if(cur == NULL) {
        fprintf(stderr,"Error: unable to find EncryptedData node\n");
	goto done;    
    }

    start_time = clock();            
    ret = xmlSecDecrypt(gXmlSecAppCtx.encCtx, NULL, gXmlSecAppCtx.sessionKey, cur, &encResult);
    total_time += clock() - start_time;    
    if(ret < 0) {
        fprintf(stderr,"Error: xmlSecDecrypt() failed \n");
	goto done;    
    } 

    if(repeats <= 1) {
	FILE* f = stdout;
	if(output) {
	    f = fopen(output, "w");
	    if(f == NULL) {
		fprintf(stderr,"Error: failed to open output file \"%s\"\n", output);
		goto done;
	    }
	}

	if((encResult != NULL) && encResult->replaced && (encResult->buffer != NULL)) {
	    ret = xmlDocDump(f, doc);    
        } else if((encResult != NULL) && !encResult->replaced) {
    	    ret = fwrite(xmlSecBufferGetData(encResult->buffer), 
	    		 xmlSecBufferGetSize(encResult->buffer),
	        	 1, f);		       
	} else {
	    if(f != stdout) {
		fclose(f);
	    }
    	    fprintf(stderr,"Error: bad results \n");
	    goto done;    
	}
	if(f != stdout) {
	    fclose(f);
	}
        if(ret < 0) {
	    fprintf(stderr,"Error: failed to print out the result \n");
	    goto done;    
	}
    
	if(printResult) {
    	    xmlSecEncResultDebugDump(encResult, stderr);
	}
    }	
        
    res = 0;
    
done:    
    if(encResult != NULL) {
	xmlSecEncResultDestroy(encResult);
    }
    return(res);
}
#endif /* XMLSEC_NO_XMLENC */

int findIDNodes(xmlDtdPtr dtd, xmlDocPtr doc) {
    xmlValidCtxt c;

    memset(&c, 0, sizeof(c));    
    xmlValidateDtd(&c, doc, dtd);
    return 0;
}


/**************************************************************************
 *
 *
 *
 *************************************************************************/
static int
xmlSecAppInit(xmlSecAppCtxPtr ctx) {
    xmlSecAssert2(ctx != NULL, -1);
    
    /* init ctx */
    memset(ctx, 0, sizeof(xmlSecAppCtx));
    
    /* Init libxml */     
    xmlInitParser();
    LIBXML_TEST_VERSION
    xmlTreeIndentString = "\t";
#ifndef XMLSEC_NO_XSLT
    xmlIndentTreeOutput = 1; 
#endif /* XMLSEC_NO_XSLT */
    
    	
    /* Init xmlsec */
    if(xmlSecInit() < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecInit");
	return(-1);
    }

    /* Init Crypto */
    if(xmlSecAppCryptoInit() < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAppCryptoInit");
	return(-1);
    }

    /* Create keys manager */
    gXmlSecAppCtx.keysMngr = xmlSecKeysMngrCreate();
    if(gXmlSecAppCtx.keysMngr == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeysMngrCreate");
	return(-1);
    }
    if(xmlSecAppCryptoSimpleKeysMngrInit(gXmlSecAppCtx.keysMngr) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAppCryptoSimpleKeysMngrInit");
	return(-1);
    }    
    
    /* init DSig Ctx */
#ifndef XMLSEC_NO_XMLDSIG    
    ctx->dsigCtx = xmlSecDSigCtxCreate(gXmlSecAppCtx.keysMngr);
    if(ctx->dsigCtx == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecDSigCtxCreate");
	return(-1);
    }
    /**
     * Set default values to process manifests and store nothing
     * Overwrite this options thru command line if needed!
     */
    ctx->dsigCtx->processManifests = 1;
    ctx->dsigCtx->storeSignatures  = 0;
    ctx->dsigCtx->storeReferences  = 0;
    ctx->dsigCtx->storeManifests   = 0;
#endif /* XMLSEC_NO_XMLDSIG */

    /* init XML Enc context */
#ifndef XMLSEC_NO_XMLENC
    ctx->encCtx = xmlSecEncCtxCreate(gXmlSecAppCtx.keysMngr);
    if(ctx->encCtx == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecEncCtxCreate");
	return(-1);
    }
#endif /* XMLSEC_NO_XMLENC */
    
    return(0);
}

static int 
xmlSecAppShutdown(xmlSecAppCtxPtr ctx) {
    xmlSecAssert2(ctx != NULL, -1);
    
    /* cleanup context */
    if(ctx->sessionKey != NULL) {
	xmlSecKeyDestroy(ctx->sessionKey);
    }
#ifndef XMLSEC_NO_XMLENC
    if(ctx->encCtx != NULL) {
	xmlSecEncCtxDestroy(ctx->encCtx);
    }
#endif /* XMLSEC_NO_XMLENC */
#ifndef XMLSEC_NO_XMLDSIG
    if(ctx->dsigCtx != NULL) {
	xmlSecDSigCtxDestroy(ctx->dsigCtx);
    }
#endif /* XMLSEC_NO_XMLDSIG */
    if(gXmlSecAppCtx.keysMngr != NULL) {
	xmlSecKeysMngrDestroy(gXmlSecAppCtx.keysMngr);
    }
    memset(ctx, 0, sizeof(xmlSecAppCtx));


    /* Shutdown Crypto */
    if(xmlSecAppCryptoShutdown() < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAppCryptoShutdown");
	return(-1);
    }
    
    /* Shutdown xmlsec */
    if(xmlSecShutdown() < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecShutdown");
	return(-1);
    }
    
    /* Shutdown libxslt/libxml */
#ifndef XMLSEC_NO_XSLT
    xsltCleanupGlobals();            
#endif /* XMLSEC_NO_XSLT */
    xmlCleanupParser();
    
    return(0);
}



/**************************************************************************
 *
 *
 *
 *************************************************************************/
static int		xmlSecAppKeysOptionsParse	(xmlSecAppCtxPtr ctx, 
							 int argc, 
							 char** argv, 
							 int pos);
static int		xmlSecAppX509OptionsParse	(xmlSecAppCtxPtr ctx, 
							 int argc, 
							 char** argv, 
							 int pos);
static int		xmlSecAppDSigOptionsParse	(xmlSecAppCtxPtr ctx, 
							 int argc, 
							 char** argv, 
							 int pos);
static int		xmlSecAppEncOptionsParse	(xmlSecAppCtxPtr ctx, 
							 int argc, 
							 char** argv, 
							 int pos);
static int		xmlSecAppStartNodeOptionsParse	(xmlSecAppCtxPtr ctx, 
							 int argc, 
							 char** argv, 
							 int pos);
static int		xmlSecAppMiscOptionsParse	(xmlSecAppCtxPtr ctx, 
							 int argc, 
							 char** argv, 
							 int pos);
/**
 * options
 */	
static int
xmlSecAppOptionsParse(xmlSecAppCtxPtr ctx, int argc, char** argv, int pos) {
    int ret;
    
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(argv != NULL, -1);
    xmlSecAssert2(pos >= 0, -1);
    xmlSecAssert2(pos < argc, -1);

    while((pos < argc) && (argv[pos][0] == '-')) {
	/* Keys and keys mngr options */ 
	ret = xmlSecAppKeysOptionsParse(&gXmlSecAppCtx, argc, argv, pos);
	if(ret < 0) {
	    return(-1);
	} else if (ret > pos) {
	    pos = ret;
	    continue;
	}

	/* x509 options */ 
	ret = xmlSecAppX509OptionsParse(&gXmlSecAppCtx, argc, argv, pos);
	if(ret < 0) {
	    return(-1);
	} else if (ret > pos) {
	    pos = ret;
	    continue;
	}

	/* dsig options */ 
	ret = xmlSecAppDSigOptionsParse(&gXmlSecAppCtx, argc, argv, pos);
	if(ret < 0) {
	    return(-1);
	} else if (ret > pos) {
	    pos = ret;
	    continue;
	}

	/* enc options */ 
	ret = xmlSecAppEncOptionsParse(&gXmlSecAppCtx, argc, argv, pos);
	if(ret < 0) {
	    return(-1);
	} else if (ret > pos) {
	    pos = ret;
	    continue;
	}

	/* Node selection options */
	ret = xmlSecAppStartNodeOptionsParse(&gXmlSecAppCtx, argc, argv, pos);
	if(ret < 0) {
	    return(-1);
	} else if (ret > pos) {
	    pos = ret;
	    continue;
	}

	/* misc options */ 
	ret = xmlSecAppMiscOptionsParse(&gXmlSecAppCtx, argc, argv, pos);
	if(ret < 0) {
	    return(-1);
	} else if (ret > pos) {
	    pos = ret;
	    continue;
	}

	/* if we are here then option is unknown */
	fprintf(stderr, "Error: option \"%s\" is unknown\n", argv[pos]);
	return(-1);
    }

    return(pos);
}

/**
 * Key selection options
 */	
static int
xmlSecAppKeysOptionsParse(xmlSecAppCtxPtr ctx, int argc, char** argv, int pos) {
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(argv != NULL, -1);
    xmlSecAssert2(pos >= 0, -1);
    xmlSecAssert2(pos < argc, -1);

    /**
     * Allowed key origins
     */
    if((strcmp(argv[pos], "--allowed") == 0) && (pos + 1 < argc)) {
	if(readKeyOrigins(argv[++pos]) < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "readKeyOrigins");
	    return(-1);
	}
    } else 
    
    /**
     * Loading keys in the keys manager
     */
    if((strcmp(argv[pos], "--keys") == 0) && (pos + 1 < argc)) {
	if(xmlSecAppCryptoSimpleKeysMngrLoad(ctx->keysMngr, argv[++pos]) < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecAppCryptoSimpleKeysMngrLoad");
	    return(-1);
	}
    } else if((strncmp(argv[pos], "--privkey", 9) == 0) && (pos + 1 < argc)) {
	char *name;
	    
	name = strchr(argv[pos], ':');
	if(name != NULL) ++name;
	if(xmlSecAppCryptoSimpleKeysMngrPemKeyAndCertsLoad(ctx->keysMngr, argv[++pos], global_pwd, name, 1) < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecAppCryptoSimpleKeysMngrPemKeyAndCertsLoad");
	    return(-1);
	}
    } else if((strncmp(argv[pos], "--pubkey", 8) == 0) && (pos + 1 < argc)) {
	char *name;
	    
	name = strchr(argv[pos], ':');
	if(name != NULL) ++name;
	if(xmlSecAppCryptoSimpleKeysMngrPemKeyAndCertsLoad(ctx->keysMngr, argv[++pos], global_pwd, name, 0) < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecAppCryptoSimpleKeysMngrPemKeyAndCertsLoad");
	    return(-1);
	}
    } else if((strncmp(argv[pos], "--pkcs12", 8) == 0) && (pos + 1 < argc)) {
	char *name;
	    
	name = strchr(argv[pos], ':');
	if(name != NULL) ++name;	    
	if(xmlSecAppCryptoSimpleKeysMngrPkcs12KeyLoad(ctx->keysMngr, argv[++pos], global_pwd, name) < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecAppCryptoSimpleKeysMngrPkcs12KeyLoad");
	    return(-1);
	}
    } else if((strncmp(argv[pos], "--hmackey", 9) == 0) && (pos + 1 < argc)) {
	char *name;
	    
	name = strchr(argv[pos], ':');
	if(name != NULL) ++name;	    
	if(xmlSecAppCryptoSimpleKeysMngrBinaryKeyLoad(ctx->keysMngr, "hmac", argv[++pos], name) < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecAppCryptoSimpleKeysMngrBinaryKeyLoad(hmac)");
	    return(-1);
	}
    } else 
    
    /** 
     * Session key options
     */
    if(strncmp(argv[pos], "--session-", 10) == 0) {
	char* klassAndSize = argv[pos] + 10;
	
	if(ctx->sessionKey != NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    "xmlSecAppCryptoShutdown");
	    return(-1);
	}
	
	ctx->sessionKey = xmlSecAppCryptoKeyGenerate(klassAndSize, NULL);
	if(ctx->sessionKey == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecAppCryptoKeyGenerate(klassAndSize)");
	    return(-1);
	}
    } else 
    
    /**
     * Keys generation options
     */
    if((strncmp(argv[pos], "--gen-", 6) == 0) && (pos + 1 < argc)) {
	char* klassAndSize = argv[pos] + 6;
	
	if(xmlSecAppCryptoSimpleKeysMngrKeyGenerate(ctx->keysMngr, klassAndSize, argv[++pos]) < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecAppCryptoSimpleKeysMngrKeyGenerate(klassAndSize)");
	    return(-1);
	}
    } else {
	/* the option is unknown */
	return(pos);
    }
    
    return(++pos); 
}


/** 
 * Node selection options 
 */
static int
xmlSecAppStartNodeOptionsParse(xmlSecAppCtxPtr ctx, int argc, char** argv, int pos) {
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(argv != NULL, -1);
    xmlSecAssert2(pos >= 0, -1);
    xmlSecAssert2(pos < argc, -1);
	
    if((strcmp(argv[pos], "--node-id") == 0) && (pos + 1 < argc)) {    
	if((nodeName != NULL) || (nodeId != NULL) || (nodeXPath != NULL)){
	    fprintf(stderr, "Error: another node selection option present\n");
	    return(-1);
	} else {
	    nodeId = argv[++pos];
	}
    } else if((strcmp(argv[pos], "--node-name") == 0) && (pos + 1 < argc)) {    
	if((nodeName != NULL) || (nodeId != NULL) || (nodeXPath != NULL)){
	    fprintf(stderr, "Error: another node selection option present\n");
	    return(-1);
	} else {
	    nodeName = strrchr(argv[++pos], ':');
	    if(nodeName != NULL) {
		*(nodeName++) = '\0';
		nodeNs = argv[pos];
	    } else {
	        nodeName = argv[pos];
		nodeNs = NULL;
	    }
	}
    } else if((strcmp(argv[pos], "--node-xpath") == 0) && (pos + 1 < argc)) {    
	if((nodeName != NULL) || (nodeId != NULL) || (nodeXPath != NULL)){
	    fprintf(stderr, "Error: another node selection option present\n");
	    return(-1);
	} else {
	    nodeXPath = argv[++pos];
	}
    } else if((strcmp(argv[pos], "--dtdfile") == 0) && (pos + 1 < argc)) {
        if(idsDtd != NULL){
            fprintf(stderr, "Error: DTD already specified\n");
            return(-1);
        } else {
            idsDtd = xmlParseDTD(NULL, (const xmlChar*)argv[++pos]);
            if(idsDtd == NULL) {
                fprintf(stderr, "Could not parse DTD\n");
                return(-1);
            }
        }
    } else {
	/* the option is unknown */
	return(pos);
    }
    
    return(++pos); 
}

static int
xmlSecAppX509OptionsParse(xmlSecAppCtxPtr ctx, int argc, char** argv, int pos) {
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(argv != NULL, -1);
    xmlSecAssert2(pos >= 0, -1);
    xmlSecAssert2(pos < argc, -1);
	
    if((strcmp(argv[pos], "--trusted") == 0) && (pos + 1 < argc)) {
	if(xmlSecAppCryptoSimpleKeysMngrPemCertLoad(ctx->keysMngr, argv[++pos], 1) < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecAppCryptoSimpleKeysMngrPemCertLoad(%s)", argv[pos]);
	    return(-1);
	}
    } else if((strcmp(argv[pos], "--untrusted") == 0) && (pos + 1 < argc)) {	
	if(xmlSecAppCryptoSimpleKeysMngrPemCertLoad(ctx->keysMngr, argv[++pos], 0) < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecAppCryptoSimpleKeysMngrPemCertLoad(%s)", argv[pos]);
	    return(-1);
	}
    } else if((strcmp(argv[pos], "--verification-time") == 0) && (pos + 1 < argc)) {
	time_t t = 0;
	     
	if(readTime(argv[++pos], &t) < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"readTime");
	    return(-1);
	}
	
#ifndef XMLSEC_NO_XMLDSIG
	xmlSecAssert2(ctx->dsigCtx != NULL, -1);	    
	ctx->dsigCtx->keyInfoCtx.certsVerificationTime = t;		        
#endif /* XMLSEC_NO_XMLDSIG */
#ifndef XMLSEC_NO_XMLENC
	xmlSecAssert2(ctx->encCtx != NULL, -1);
	ctx->encCtx->keyInfoCtx.certsVerificationTime = t;		        
#endif /* XMLSEC_NO_XMLENC */
    } else if((strncmp(argv[pos], "--depth", 7) == 0) && (pos + 1 < argc)) {
	int depth;
	
	depth = atoi(argv[++pos]);
#ifndef XMLSEC_NO_XMLDSIG
	xmlSecAssert2(ctx->dsigCtx != NULL, -1);
	    
	ctx->dsigCtx->keyInfoCtx.certsVerificationDepth = depth;  
#endif /* XMLSEC_NO_XMLDSIG */
#ifndef XMLSEC_NO_XMLENC
	xmlSecAssert2(ctx->encCtx != NULL, -1);
	    
	ctx->encCtx->keyInfoCtx.certsVerificationDepth = depth;
#endif /* XMLSEC_NO_XMLENC */
    } else {
	/* the option is unknown */
	return(pos);
    }
    
    return(++pos); 
}

static int
xmlSecAppMiscOptionsParse(xmlSecAppCtxPtr ctx, int argc, char** argv, int pos) {
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(argv != NULL, -1);
    xmlSecAssert2(pos >= 0, -1);
    xmlSecAssert2(pos < argc, -1);

    if((strcmp(argv[pos], "--repeat") == 0) && (pos + 1 < argc)) {
	if(readNumber(argv[++pos], &repeats) < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"readNumber");
	    return(-1);
	}	
    } else if((strcmp(argv[pos], "--pwd") == 0) && (pos + 1 < argc)) {
	global_pwd = argv[++pos];
    } else if((strcmp(argv[pos], "--output") == 0) && (pos + 1 < argc)) {
	output = argv[++pos];
    } else if((strcmp(argv[pos], "--disable-error-msgs") == 0)) {
	xmlSecPrintErrorMessages = 0;
    } else if((strcmp(argv[pos], "--print-openssl-errors") == 0)) {
	print_openssl_errors = 1;
    } else {
	/* the option is unknown */
	return(pos);
    }
    
    return(++pos); 
}

static int
xmlSecAppDSigOptionsParse(xmlSecAppCtxPtr ctx, int argc, char** argv, int pos) {
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(argv != NULL, -1);
    xmlSecAssert2(pos >= 0, -1);
    xmlSecAssert2(pos < argc, -1);
	
#ifndef XMLSEC_NO_XMLDSIG	
    xmlSecAssert2(ctx->dsigCtx != NULL, -1);
    
    if(strcmp(argv[pos], "--ignore-manifests") == 0) {
	ctx->dsigCtx->processManifests = 0; 
    } else if(strcmp(argv[pos], "--fake-signatures") == 0) {
	ctx->dsigCtx->fakeSignatures = 1; 
    } else if(strcmp(argv[pos], "--print-result") == 0)  {
	printResult = 1;
    } else if(strcmp(argv[pos], "--print-references") == 0) {
	ctx->dsigCtx->storeReferences = 1; 
	printResult = 1;	    
    } else if(strcmp(argv[pos], "--print-manifests") == 0) { 
	ctx->dsigCtx->storeManifests = 1; 
	printResult = 1;
    } else if(strcmp(argv[pos], "--print-signature") == 0) { 
	ctx->dsigCtx->storeSignatures = 1; 
	printResult = 1;
    } else if(strcmp(argv[pos], "--print-all") == 0) { 	    
	ctx->dsigCtx->storeReferences = 1; 
	ctx->dsigCtx->storeManifests = 1; 
	ctx->dsigCtx->storeSignatures = 1; 	    
	printResult = 1;
    } else if(strcmp(argv[pos], "--print-xml") == 0) {
	printXml = 1;
	printResult = 1;
    } else if((strcmp(argv[pos], "--print-to-file") == 0) && (pos + 1 < argc) && (printFile == NULL)) {
	printFile = fopen(argv[++pos], "w");
	if(printFile == NULL) {
	    fprintf(stderr, "Error: failed to open result file \"%s\"\n", argv[pos]);
	    return(-1);
	}
    } else {
	/* the option is unknown */
	return(pos);
    }
    return(++pos); 
#else /* XMLSEC_NO_XMLDSIG */
    return(pos);
#endif /* XMLSEC_NO_XMLDSIG */
}

static int
xmlSecAppEncOptionsParse(xmlSecAppCtxPtr ctx, int argc, char** argv, int pos) {
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(argv != NULL, -1);
    xmlSecAssert2(pos >= 0, -1);
    xmlSecAssert2(pos < argc, -1);
	
#ifndef XMLSEC_NO_XMLEMC
    xmlSecAssert2(ctx->encCtx != NULL, -1);

    if((strcmp(argv[pos], "--binary") == 0) && (pos + 1 < argc)) {
	if(dataFile != NULL){
	    fprintf(stderr, "Error: data file was already specified\n");
	    return(-1);
	} else {
	    dataFile = argv[++pos];
	    binary = 1;
	}
    } else if((strcmp(argv[pos], "--xml") == 0) && (pos + 1 < argc)) {
	if(dataFile != NULL){
	    fprintf(stderr, "Error: dataFile file was already specified\n");
	    return(-1);
	} else {
	    dataFile = argv[++pos];
	    binary = 0;
	}
    } else {
	/* the option is unknown */
	return(pos);
    }
    
    return(++pos); 
#else /* XMLSEC_NO_XMLENC */
    return(pos);
#endif /* XMLSEC_NO_XMLENC */
}


