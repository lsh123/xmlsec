TOP=../..
MODULE=xmlsec
SOURCE_DIR=$(TOP)/src
INCLUDE_DIR=$(TOP)/include
SGML_CATALOG_FILES=/usr/share/sgml/docbook/sgml-dtd-3.0-1.0-8/catalog:/usr/share/sgml/openjade-1.3.1/catalog:/usr/share/sgml/docbook/dsssl-stylesheets/catalog

#
# We need to pre-process original source files
# because gtkdoc does not understand some C features
#
DOC_SOURCE_DIR=./code
DOC_SOURCE_FILES=$(shell find $(SOURCE_DIR) -name '*.c' -print )  \
	$(shell find $(INCLUDE_DIR) -name '*.h' -print )

all: sgml html

html: sgml xmlsec.sgml
	gtkdoc-mkhtml xmlsec xmlsec.sgml
	
sgml: templates
	@gtkdoc-mkdb --module=xmlsec --main-sgml-file xmlsec.sgml \
		    --source-dir=$(DOC_SOURCE_DIR)/src/base \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/base
	@gtkdoc-mkdb --module=xmlsec-openssl --main-sgml-file xmlsec-openssl.sgml \
		    --tmpl-dir=tmpl/openssl --output-dir=sgml/openssl \
		    --source-dir=$(DOC_SOURCE_DIR)/src/openssl \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/openssl
	@gtkdoc-mkdb --module=xmlsec-gnutls --main-sgml-file xmlsec-gnutls.sgml \
		    --tmpl-dir=tmpl/gnutls --output-dir=sgml/gnutls \
		    --source-dir=$(DOC_SOURCE_DIR)/src/gnutls \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/gnutls
	@gtkdoc-mkdb --module=xmlsec-nss --main-sgml-file xmlsec-nss.sgml \
		    --tmpl-dir=tmpl/nss --output-dir=sgml/nss \
		    --source-dir=$(DOC_SOURCE_DIR)/src/nss \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/nss
templates: scan
	@gtkdoc-mktmpl --module=xmlsec 
	
scan: doc_sources
	@gtkdoc-scan --module=xmlsec \
		    --source-dir=$(DOC_SOURCE_DIR)/src/base \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/base
	@gtkdoc-scan --module=xmlsec-openssl \
		    --source-dir=$(DOC_SOURCE_DIR)/src/base \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/openssl
	@gtkdoc-scan --module=xmlsec-gnutls \
		    --source-dir=$(DOC_SOURCE_DIR)/src/base \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/gnutls
	@gtkdoc-scan --module=xmlsec-nss \
		    --source-dir=$(DOC_SOURCE_DIR)/src/base \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/nss
		
doc_sources: $(DOC_SOURCE_FILES)
	@(for i in $(DOC_SOURCE_FILES) ; do \
	    folder_name=`echo $$i | sed 's#$(TOP)/##' | sed 's#/[^/]*$$##'`; \
	    file_name=`echo $$i | sed 's#.*/##'`; \
	    test -d $(DOC_SOURCE_DIR)/$$folder_name || mkdir -p $(DOC_SOURCE_DIR)/$$folder_name; \
	    cat $$i | \
		sed 's/#if.*//' | \
		sed 's/#el.*//' | \
		sed 's/#end.*//' | \
		sed 's/XMLSEC_CRYPTO_EXPORT//' | \
		sed 's/XMLSEC_EXPORT_VAR//' | \
		sed 's/XMLSEC_EXPORT//' | \
		sed 's/XMLSEC_ERRORS_PRINTF_ATTRIBUTE//' > \
		$(DOC_SOURCE_DIR)/$$folder_name/$$file_name; \
	done);
	@mkdir -p $(DOC_SOURCE_DIR)/src/base
	@mv -f $(DOC_SOURCE_DIR)/src/*.c $(DOC_SOURCE_DIR)/src/base
	@mkdir -p $(DOC_SOURCE_DIR)/include/xmlsec/base
	@mv -f $(DOC_SOURCE_DIR)/include/xmlsec/*.h $(DOC_SOURCE_DIR)/include/xmlsec/base

clean:
	@rm -rf $(DOC_SOURCE_DIR)
	@rm -f sgml/*~ sgml/*.bak  
	@rm -f tmpl/*~ tmpl/*.bak  
	@rm -f *~ *.bak *.hierarchy *.signals *-unused.txt *.stamp

clean-local:
	@rm -f *~ *.bak *.hierarchy *.signals *-unused.txt

maintainer-clean-local: clean
	@rm -rf *.html *.txt \
	    sgml/*.sgml sgml/openssl/*.sgml \
	    sgml/gnutls/*.sgml sgml/nss/*.sgml
	