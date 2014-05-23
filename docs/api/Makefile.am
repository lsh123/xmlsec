#
#
#
NULL=
TOP=../..
MODULE=xmlsec
SOURCE_DIR=$(TOP)/src
INCLUDE_DIR=$(TOP)/include
SGML_CATALOG_FILES=/usr/share/sgml/docbook/sgml-dtd-3.0-1.0-8/catalog:/usr/share/sgml/openjade-1.3.1/catalog:/usr/share/sgml/docbook/dsssl-stylesheets/catalog

EXTRA_DIST = \
	chapters \
	images \
	$(NULL)

#
# We need to pre-process original source files
# because gtkdoc does not understand some C features
#
DOC_SOURCE_DIR=./code
DOC_SOURCE_FILES=\
	$(shell find $(SOURCE_DIR) -name '*.c' -a ! -name "xkms*" -print )  \
	$(shell find $(INCLUDE_DIR) -name '*.h' -a ! -name "symbols.h" -a ! -name "xkms*" -print )

EXAMPLES_SOURCE_DIR=../../examples
EXAMPLES_SOURCE_FILES=\
	$(shell find $(EXAMPLES_SOURCE_DIR) -name '*.c' -print) \
	$(shell find $(EXAMPLES_SOURCE_DIR) -name '*.xml' -print) 

# do nothing for all
all:

docs: sgml html clean-sources

# need to cleanup "bad" chars
html: sgml xmlsec.sgml xmlsec-index
	gtkdoc-mkhtml xmlsec xmlsec.sgml

#
# Prepeare sgml files from sources for each library. We are also
# doing some "magic" here by automatically adding links to XML DSig and 
# XML Enc specification, we also remove "Ptr" from the end of the link
# targets to make more references
#
sgml: templates
	gtkdoc-mkdb --module=xmlsec \
		    --main-sgml-file=xmlsec.sgml \
		    --source-dir=$(DOC_SOURCE_DIR)/src/base \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/base
	gtkdoc-mkdb --module=xmlsec-openssl \
		    --main-sgml-file=xmlsec-openssl.sgml \
		    --tmpl-dir=tmpl/openssl \
		    --output-dir=sgml/openssl \
		    --source-dir=$(DOC_SOURCE_DIR)/src/openssl \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/openssl
	gtkdoc-mkdb --module=xmlsec-gnutls \
		    --main-sgml-file=xmlsec-gnutls.sgml \
		    --tmpl-dir=tmpl/gnutls \
		    --output-dir=sgml/gnutls \
		    --source-dir=$(DOC_SOURCE_DIR)/src/gnutls \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/gnutls
	gtkdoc-mkdb --module=xmlsec-gcrypt \
		    --main-sgml-file=xmlsec-gcrypt.sgml \
		    --tmpl-dir=tmpl/gcrypt \
		    --output-dir=sgml/gcrypt \
		    --source-dir=$(DOC_SOURCE_DIR)/src/gcrypt \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/gcrypt
	gtkdoc-mkdb --module=xmlsec-nss \
		    --main-sgml-file=xmlsec-nss.sgml \
		    --tmpl-dir=tmpl/nss \
		    --output-dir=sgml/nss \
		    --source-dir=$(DOC_SOURCE_DIR)/src/nss \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/nss
	gtkdoc-mkdb --module=xmlsec-mscrypto \
		    --main-sgml-file=xmlsec-mscrypto.sgml \
		    --tmpl-dir=tmpl/mscrypto \
		    --output-dir=sgml/mscrypto \
		    --source-dir=$(DOC_SOURCE_DIR)/src/mscrypto \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/mscrypto
	(for i in `find sgml -name "*.sgml" -print` ; do \
	    cat $$i | \
		sed 's!\(&lt;dsig:\)\([^/]*\)\(\/&gt;\)!<ulink URL=\"http://www.w3.org/TR/xmldsig-core/#sec-\2\">\1\2\3</ulink>!g' | \
		sed 's!\(&lt;enc:\)\([^/]*\)\(\/&gt;\)!<ulink URL=\"http://www.w3.org/TR/xmlenc-core/#sec-\2\">\1\2\3</ulink>!g' | \
		sed 's!linkend=\"\(.*\)Ptr\"!linkend=\"\1\"!g' > \
		$$i.tmp; \
		mv -f $$i.tmp $$i; \
	done);

templates: scan
	gtkdoc-mktmpl --module=xmlsec
	gtkdoc-mktmpl --module=xmlsec-openssl \
		    --output-dir=tmpl/openssl
	gtkdoc-mktmpl --module=xmlsec-gnutls \
		    --output-dir=tmpl/gnutls
	gtkdoc-mktmpl --module=xmlsec-gcrypt \
		    --output-dir=tmpl/gcrypt
	gtkdoc-mktmpl --module=xmlsec-nss \
		    --output-dir=tmpl/nss
	gtkdoc-mktmpl --module=xmlsec-mscrypto \
		    --output-dir=tmpl/mscrypto

scan: doc_sources example_sources
	gtkdoc-scan --module=xmlsec \
		    --rebuild-sections \
		    --source-dir=$(DOC_SOURCE_DIR)/src/base \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/base
	gtkdoc-scan --module=xmlsec-openssl \
		    --rebuild-sections \
		    --source-dir=$(DOC_SOURCE_DIR)/src/openssl \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/openssl
	gtkdoc-scan --module=xmlsec-gnutls \
		    --rebuild-sections \
		    --source-dir=$(DOC_SOURCE_DIR)/src/gnutls \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/gnutls
	gtkdoc-scan --module=xmlsec-gcrypt \
		    --rebuild-sections \
		    --source-dir=$(DOC_SOURCE_DIR)/src/gcrypt \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/gcrypt
	gtkdoc-scan --module=xmlsec-nss \
		    --rebuild-sections \
		    --source-dir=$(DOC_SOURCE_DIR)/src/nss \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/nss
	gtkdoc-scan --module=xmlsec-mscrypto \
		    --rebuild-sections \
		    --source-dir=$(DOC_SOURCE_DIR)/src/mscrypto \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/mscrypto

#
# Prepare source files by coping them to "code" folder and 
# removing XMLSEC_EXPORT_* stuff that makes gtkdoc crazy
#
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
	-@mkdir -p $(DOC_SOURCE_DIR)/src/base
	-@mv -f $(DOC_SOURCE_DIR)/src/*.c $(DOC_SOURCE_DIR)/src/base
	-@mkdir -p $(DOC_SOURCE_DIR)/include/xmlsec/base
	-@mv -f $(DOC_SOURCE_DIR)/include/xmlsec/*.h $(DOC_SOURCE_DIR)/include/xmlsec/base
	-@rm -f $(DOC_SOURCE_DIR)/include/xmlsec/*/symbols.h

#
# Create index for all functions. For macros and defines need to add -CAPS suffix
#
xmlsec-index: scan
	@grep -h '<NAME>.*</NAME>' xmlsec-*decl.txt | \
		grep -v '<NAME>extern</NAME>' | \
		sort -u | \
		sed 's#_#-#g' | \
		sed 's#<NAME>\([^-]*\)-\([^<]*\)</NAME>#<listitem><para><link linkend=\"\1-\2-CAPS\">\1-\2</link></para></listitem>#g' | \
		sed 's#<NAME>\([^<]*\)</NAME>#<listitem><para><link linkend=\"\1\">\1</link></para></listitem>#g' > \
		xmlsec-index.sgml

#
# The following code converts C example file to sgml RefEntry files.
# We get file title from a string "XML Security Library example: ..."
# which is usually placed at the top of the file. Also all "unsafe" xml 
# characters (<, >, &) are escaped. 
#
example_sources:
	@mkdir -p examples
	@(for i in $(EXAMPLES_SOURCE_FILES) ; do \
	    file_name=`echo $$i | sed 's#.*/##' | sed 's#\..*$$##'`; \
	    file_ext=`echo $$i | sed 's#.*/##' | sed 's#.*\.##'`; \
	    echo Converting $$file_name.$$file_ext to $$file_name.sgml ...; \
	    file_title=`cat $$i | grep 'XML Security Library example: ' | sed 's#^.*: *##'`; \
	    echo "<sect2 id=\"xmlsec-example-$$file_name\" >" > \
		examples/$$file_name.sgml; \
	    echo "<title>$$file_name.$$file_ext</title><para><informalexample><programlisting>" >> \
		examples/$$file_name.sgml; \
	    cat $$i | \
		sed "s#&#\&amp;#g" | \
		sed "s#<#\&lt;#g" | \
		sed "s#>#\&gt;#g" >> \
		examples/$$file_name.sgml; \
	    echo "</programlisting></informalexample></para></sect2>" >> \
		examples/$$file_name.sgml; \
	done);

dist-hook:
	@cp -p $(srcdir)/*.html $(srcdir)/*.png $(srcdir)/*.sgml $(distdir)

clean: clean-sources
	-@rm -rf $(DOC_SOURCE_DIR)
	-@rm -rf sgml/*~ sgml/*.bak  
	-@rm -rf tmpl/*~ tmpl/*.bak  
	-@rm -rf *~ *.bak *.hierarchy *.signals *-unused.txt *.stamp

clean-sources:
	-@rm -rf code examples

clean-local:
	-@rm -rf *~ *.bak *.hierarchy *.signals *-unused.txt

maintainer-clean-local: clean
	-@rm *.html *.txt
	-@rm -rf `find sgml -name "*.sgml" -print`

