NULL =

SUBDIRS = include src apps tests man

bin_SCRIPTS = xmlsec-config

EXTRA_DIST = \
	win32 \
	globals.h \
	docs \
	debian \
	NEWS \
	ChangeLog \
	Copyright \
	xmlsec.spec \
	xmlsec.spec.in \
	xmlsec-config.in \
	xmlsecConf.sh \
	xmlsec.pc \
	xmlsec.pc.in \
	$(NULL)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = xmlsec.pc

api-doc:
	@cd docs/api;make

api-doc-clean:
	@cd docs/api;make clean

memcheck:
	@export DEBUG_MEMORY=1;make check
