This folder contains XML Security Library examples. 

1. Files List
-------------------------

    README.txt			This file.
    Makefile			Makefile for building all the examples
    rsakey.pem			Private PEM key file
    rsapub.pem			Public PEM key file
    deskey.bin			A DES keys
    dsig1.c			Signing with a template file
    dsig1-tmpl.xml		An example template file for dsig1 example
    dsig1-res.xml		The result of processing dsig1_tmpl.xml by dsig1.c
    dsig2.c			Signing a file with a dynamicaly created template
    dsig2-doc.xml		An example XML file for signing by dsig2.c
    dsig2-res.xml		The result of signing dsig2-doc.xml by dsig2.c
    dsig3.c			Verifying a signed document with a single key
    dsig4.c			Verifying a signed document using keys manager
    enc1.c			Encrypting binary data with a template file
    enc1-res.xml		An example template file for enc1.c
    enc1-tmpl.xml		The result of processing enc1_tmpl.xml by enc1.c
    enc2.c			Encrypting XML file using a dynamicaly created template
    enc2-doc.xml		An example XML file for encryption by enc2.c
    enc2-res.xml		The result of encryptin enc2-doc.xml by enc2.c
    enc3.c			Decrypting binary data using a signle key
    enc4.c			Decrypting binary data using keys manager
    enc5.c			Decrypting binary file using custom keys manager


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
    
    $ ./dsig1 dsig1-tmpl.xml rsakey.pem
    $ ./dsig2 dsig2-doc.xml  rsakey.pem
    $ ./dsig3 dsig1-res.xml  rsapub.pem
    $ ./dsig3 dsig2-res.xml  rsapub.pem
    $ ./dsig4 dsig1-res.xml  rsapub.pem
    $ ./dsig4 dsig2-res.xml  rsapub.pem
    $ ./enc1  enc1-tmpl.xml  deskey.bin
    $ ./enc2  enc2-doc.xml   deskey.bin 
    $ ./enc4  enc1-res.xml   deskey.bin
    $ ./enc4  enc2-res.xml   deskey.bin
    $ ./enc5  enc1-res.xml   deskey.bin
    $ ./enc5  enc2-res.xml   deskey.bin
    $ ./enc6  enc1-res.xml
    $ ./enc6  enc2-res.xml
    
