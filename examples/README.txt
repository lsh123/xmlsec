This folder contains XML Security Library examples. 

1. Files List
-------------------------

    README.txt			This file.
    Makefile			Makefile for building all the examples
    rsakey.pem			Private PEM key file
    rsapub.pem			Public PEM key file
    deskey.bin			A DES keys
    sign1.c			Signing with a template file
    sign1-tmpl.xml		An example template file for sign1 example
    sign1-res.xml		The result of processing sign1_tmpl.xml by sign1.c
    sign2.c			Signing a file with a dynamicaly created template
    sign2-doc.xml		An example XML file for signing by sign2.c
    sign2-res.xml		The result of signing sign2-doc.xml by sign2.c
    verify1.c			Verifying a signed document with a single key
    verify2.c			Verifying a signed document using keys manager
    encrypt1.c			Encrypting binary data with a template file
    encrypt1-res.xml		An example template file for encrypt1.c
    encrypt1-tmpl.xml		The result of processing encrypt1_tmpl.xml by encrypt1.c
    encrypt2.c			Encrypting XML file using a dynamicaly created template
    encrypt2-doc.xml		An example XML file for encryption by encrypt2.c
    encrypt2-res.xml		The result of encryptin encrypt2-doc.xml by encrypt2.c
    encrypt2.c			Encrypting XML file using a session DES key
    encrypt2-doc.xml		An example XML file for encryption by encrypt3.c
    encrypt2-res.xml		The result of encryptin encrypt3-doc.xml by encrypt3.c
    decrypt1.c			Decrypting binary data using a signle key
    decrypt2.c			Decrypting binary data using keys manager
    decrypt3.c			Decrypting binary file using custom keys manager


2. Building Examples 
-------------------------

Unixes:  
    Just type 'make' (assuming that xmlsec, libxml and all other required 
    libraries are already installed). This will build all the examples.

Windows:
    There is no easy solution for you. Check the README file in the top level 
    "win32" folder and have fun :)
    
Other platforms:
    If none of the above works for you and you've managed to compile xmlsec
    library by yourself then you probably know what to do.



3. Runnning Examples.
-------------------------

The following are just examples and you can use the programs from this
folder with any other input files:
    
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
    
