NULL =

EXTRA_DIST = \
	globals.h \
	$(NULL)

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/include \
	$(XMLSEC_DEFINES) \
	$(XMLSEC_SKELETON_DEFINES) \
	$(SKELETON_CFLAGS) \
	$(LIBXSLT_CFLAGS) \
	$(LIBXML_CFLAGS) \
	-Wall -ansi \
	$(NULL)

lib_LTLIBRARIES = \
	libxmlsec1-skeleton.la \
	$(NULL)

libxmlsec1_skeleton_la_SOURCES =\
	app.c \
	crypto.c \
	$(NULL)

libxmlsec1_skeleton_la_LIBADD = \
	$(SKELETON_LIBS) \
	$(LIBXSLT_LIBS) \
	$(LIBXML_LIBS) \
	$(NULL)
        
libxmlsec1_skeleton_la_LDFLAGS = \
	-version-info @XMLSEC_VERSION_INFO@ \
	$(NULL)
