#
#
#
PROGRAMS	 = \
	sign1 sign2 \
	verify1 verify2 \
	encrypt1 encrypt2 encrypt3 \
	decrypt1 decrypt2 decrypt3

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
	./sign1    sign1-tmpl.xml    rsakey.pem
	./sign2    sign2-doc.xml     rsakey.pem
	./verify1  sign1-res.xml     rsapub.pem
	./verify1  sign2-res.xml     rsapub.pem
	./verify2  sign1-res.xml     rsapub.pem
	./verify2  sign2-res.xml     rsapub.pem
	./encrypt1 encrypt1-tmpl.xml deskey.bin
	./encrypt2 encrypt2-doc.xml  deskey.bin 
	./encrypt3 encrypt3-doc.xml  rsakey.pem
	./decrypt1 encrypt1-res.xml  deskey.bin
	./decrypt1 encrypt2-res.xml  deskey.bin
	./decrypt2 encrypt1-res.xml  deskey.bin
	./decrypt2 encrypt2-res.xml  deskey.bin
	./decrypt3 encrypt1-res.xml
	./decrypt3 encrypt2-res.xml
	./decrypt3 encrypt3-res.xml
