NULL =

SUBDIRS = include src apps tests man

bin_SCRIPTS = xmlsec-config

EXTRA_DIST = \
	win32 \
	globals.h \
	docs \
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

check-km:
	@cd tests;make check-km

check-dsig:
	@cd tests;make check-dsig

check-enc:
	@cd tests;make check-enc

memcheck:
	@export DEBUG_MEMORY=1;make check

perfcheck:
	@export PERF_TEST=10;make check
