NULL =

DEPS = $(top_builddir)/apps/xmlsec

EXTRA_DIST = \
	testDSig.sh \
	testEnc.sh \
	testKeys.sh \
	keys \
	01-phaos-xmlenc-3 \
	aleksey-xmldsig-01 \
	aleksey-xmlenc-01 \
	merlin-exc-c14n-one \
	merlin-xmldsig-twenty-three \
	merlin-xmlenc-five \
	01-geuerp-xfilter2 \
	$(NULL)

check: $(DEPS)
	@echo "-------------------------- ATTENTION -----------------------------------"
	@echo "--- 1) Some of the following tests use resources located on external ---"
	@echo "--- HTTP servers. If you have no Internet connection or the external ---"
	@echo "--- resource is not responding then the test will fail.              ---"
	@echo "--- 2) The test fails if corresponding feature(s) is disabled.       ---"
	@echo "--- Please, don't be surprised that many XML Encryption tests fails  ---"
	@echo "--- when you use OpenSSL 0.9.6 (see the FAQ for details)             ---"
	@echo "-------------------------- ATTENTION -----------------------------------"
if XMLSEC_WITH_SKM_TEST
	@./testKeys.sh
	@echo
endif 	
if XMLSEC_WITH_XMLDSIG_TEST	
	@./testDSig.sh
	@echo
endif	
if XMLSEC_WITH_XMLENC_TEST
	@./testEnc.sh
	@echo
endif

