NULL =

SUBDIRS = include src apps tests man 
TEST_APP = apps/xmlsec
bin_SCRIPTS = xmlsec-config

EXTRA_DIST = \
	win32 \
	docs/*.html \
	docs/api/*.html \
	docs/api/xmlsec.sgml \
	docs/api/images \
	docs/images \
	examples \
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

docs: api-docs docs-format

docs-clean: api-docs-clean

api-docs: api-docs-create
	

api-docs-create:
	@cd docs/api; \
	make;\
	echo "Cleaning up result files"; \
	perl ../../scripts/remove-gtkdoclink.pl `find . -name "*.html" -print`

api-docs-clean:
	@cd docs/api;make clean

docs-format:
	@(echo "Formatting html documents"; \
	for i in `find docs -name "*.html" -print`; \
	do \
	    echo "Processing $$i"; \
	    top_folder=`echo $$i | sed 's#/[^/]*$$#/#' | \
			sed 's#/[^/]*/#/../#g' | sed 's#docs/##'`; \
	    xsltproc --html --stringparam topfolder "$$top_folder" \
		     --output $$i.tmp scripts/xmlsec.xsl $$i; \
	    if [ $$? != 0 ]; \
	    then \
		echo "ERROR: processing file $$i"; \
		exit 1; \
	    fi; \
	    mv $$i.tmp $$i; \
	done)

check-km: $(TEST_APP)
	@cd tests;make check-km

check-dsig: $(TEST_APP)
	@cd tests;make check-dsig

check-enc: $(TEST_APP)
	@cd tests;make check-enc

memcheck-res:
	@cd tests;make memcheck-res

memcheck: $(TEST_APP)
	@export DEBUG_MEMORY=1;make check;make memcheck-res

perfcheck: $(TEST_APP)
	@export PERF_TEST=10;make check

