NULL =

SUBDIRS 	= include src apps man docs
TEST_APP 	= apps/xmlsec1

bin_SCRIPTS 	= xmlsec1-config
pkgconfig_DATA 	= xmlsec1.pc
pkgconfigdir 	= $(libdir)/pkgconfig
confexecdir	= $(libdir)
confexec_DATA 	= xmlsec1Conf.sh

MAINTAINERCLEANFILES = \
	xmlsec1Conf.sh \
	xmlsec1.pc \
	xmlsec1-config \
	xmlsec1.spec \
	$NULL

EXTRA_DIST = \
	examples \
	scripts \
	tests \
	win32 \
	NEWS \
	ChangeLog \
	Copyright \
	xmlsec.pc.in \
	xmlsec-config.in \
	xmlsecConf.sh.in \
	xmlsec.spec.in \
	$(NULL)

EXTRA_CLEAN = \
	examples \
	$(NULL)

docs: docs-man
	@(cd docs; $(MAKE) docs)

docs-clean: 
	@(cd docs; $(MAKE) clean)

docs-man: 
	@(cd man;$(MAKE) man)

check: check-info check-km check-dsig check-enc

check-info:
	@echo "-------------------------- ATTENTION -----------------------------------"
	@echo "--- 1) Some of the following tests use resources located on external ---"
	@echo "--- HTTP servers. If you have no Internet connection or the external ---"
	@echo "--- resource is not responding then the test will fail.              ---"
	@echo "--- 2) The test fails if corresponding feature(s) is disabled.       ---"
	@echo "--- Please, don't be surprised that many XML Encryption tests fails  ---"
	@echo "--- when you use OpenSSL 0.9.6 (see the FAQ for details)             ---"
	@echo "-------------------------- ATTENTION -----------------------------------"

check-km: $(TEST_APP)
	@$(SHELL) $(top_srcdir)/tests/testKeys.sh $(top_srcdir)/tests $(top_builddir)/$(TEST_APP)

check-dsig: $(TEST_APP)
	@$(SHELL) $(top_srcdir)/tests/testDSig.sh $(top_srcdir)/tests $(top_builddir)/$(TEST_APP)

check-enc: $(TEST_APP)
	@$(SHELL) $(top_srcdir)/tests/testEnc.sh $(top_srcdir)/tests $(top_builddir)/$(TEST_APP)

memcheck-res:
	@grep -i lost /tmp/*.log | sed 's/==.*== *//' | sort -u
	@grep -i leak /tmp/*.log | sed 's/==.*== *//' | sort -u

memcheck: $(TEST_APP)
	@(export DEBUG_MEMORY=1;$(MAKE) check;$(MAKE) memcheck-res)

perfcheck: $(TEST_APP)
	@(export PERF_TEST=10;$(MAKE) check)

dist-hook:
	@(rm -rf `find $(distdir) -name CVS`)

cleantar:
	@(rm -f xmlsec*.tar.gz COPYING.LIB)

rpm: cleantar
	@(unset CDPATH ; $(MAKE) dist && rpmbuild -ta $(distdir).tar.gz)

