## Process this file with automake to produce Makefile.in

SUBDIRS = $(XMLSEC_CRYPTO_LIST)

xmlsecincdir = $(includedir)/xmlsec

xmlsecinc_HEADERS = \
base64.h \
buffer.h \
debug.h \
errors.h \
io.h \
keyinfo.h \
keysdata.h \
keys.h \
keysmngr.h \
list.h \
membuf.h \
nodeset.h \
parser.h \
strings.h \
templates.h \
transforms.h \
transforms-old.h \
version.h \
xmldsig.h \
xmlenc.h \
xmlsec.h \
xmltree.h

install-exec-hook:
	$(mkinstalldirs) $(DESTDIR)$(xmlsecincdir)

