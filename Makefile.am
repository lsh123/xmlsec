NULL =

SUBDIRS = include src apps tests man
TEST_APP = apps/xmlsec
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

check-km: $(TEST_APP)
	@cd tests;make check-km

check-dsig: $(TEST_APP)
	@cd tests;make check-dsig

check-enc: $(TEST_APP)
	@cd tests;make check-enc

memcheck: $(TEST_APP)
	@export DEBUG_MEMORY=1;make check

perfcheck: $(TEST_APP)
	@export PERF_TEST=10;make check
