#
#
#
PROGRAMS	 = \
	dsig1 dsig2 dsig3 dsig4 \
	enc1 enc2 enc3 enc4 enc5 enc6

cc	 	 = gcc
CC	 	 = gcc
LD	 	 = gcc

CFLAGS		+= -g $(shell xmlsec-config --cflags)
LDFLAGS		+= -g
LIBS 		+= $(shell xmlsec-config --libs) 

all: $(PROGRAMS)

%: %.c 
	$(cc) $< $(LDFLAGS) $(CFLAGS) -o $@ $(PROGRAM) $(LIBRARY) $(LIBS)

clean:
	@rm -rf $(PROGRAMS)

check: $(PROGRAMS)
	./dsig1 dsig1-tmpl.xml rsakey.pem
	./dsig2 dsig2-doc.xml  rsakey.pem
	./dsig3 dsig1-res.xml  rsapub.pem
	./dsig3 dsig2-res.xml  rsapub.pem
	./dsig4 dsig1-res.xml  rsapub.pem
	./dsig4 dsig2-res.xml  rsapub.pem
	./enc1  enc1-tmpl.xml  deskey.bin
	./enc2  enc2-doc.xml   deskey.bin 
	./enc3	enc3-doc.xml   rsakey.pem
	./enc4  enc1-res.xml   deskey.bin
	./enc4  enc2-res.xml   deskey.bin
	./enc5  enc1-res.xml   deskey.bin
	./enc5  enc2-res.xml   deskey.bin
	./enc6  enc1-res.xml
	./enc6  enc2-res.xml
	./enc6  enc3-res.xml
