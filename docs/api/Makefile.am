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
	@(export SGML_CATALOG_FILES=$(SGML_CATALOG_FILES); \
	gtkdoc-mkhtml $(MODULE) xmlsec.sgml)
	
sgml: templates
	@gtkdoc-mkdb --module=$(MODULE)  --source-dir=$(DOC_SOURCE_DIR) 

templates: scan
	@gtkdoc-mktmpl --module=$(MODULE)
	
scan: doc_sources
	@gtkdoc-scan --module=$(MODULE)  --source-dir=$(DOC_SOURCE_DIR)
		
doc_sources: $(DOC_SOURCE_FILES)
	@(for i in $(DOC_SOURCE_FILES) ; do \
	    folder_name=`echo $$i | sed 's#$(TOP)/##' | sed 's#/[^/]*$$##'`; \
	    file_name=`echo $$i | sed 's#.*/##'`; \
	    test -d $(DOC_SOURCE_DIR)/$$folder_name || mkdir -p $(DOC_SOURCE_DIR)/$$folder_name; \
	    cat $$i | sed 's/XMLSEC_EXPORT//' > $(DOC_SOURCE_DIR)/$$folder_name/$$file_name; \
	done)

clean:
	@rm -rf $(DOC_SOURCE_DIR)
	@rm -f sgml/*~ sgml/*.bak  
	@rm -f tmpl/*~ tmpl/*.bak  
	@rm -f *~ *.bak *.hierarchy *.signals *-unused.txt *.stamp

