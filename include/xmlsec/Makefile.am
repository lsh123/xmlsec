## Process this file with automake to produce Makefile.in

SUBDIRS = openssl

xmlsecincdir = $(includedir)/xmlsec

xmlsecinc_HEADERS = \
base64.h \
buffered.h \
ciphers.h \
digests.h \
debug.h \
errors.h \
io.h \
keyinfo.h \
keys.h \
keysmngr.h \
list.h \
membuf.h \
nodeset.h \
strings.h \
templates.h \
transforms.h \
transformsInternal.h \
version.h \
xmldsig.h \
xmlenc.h \
xmlsec.h \
xmltree.h

install-exec-hook:
	$(mkinstalldirs) $(DESTDIR)$(xmlsecincdir)

