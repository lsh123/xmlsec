Tests
    locate-example-1.xml 	- LocateRequest example 4.1.1 from XKMS 2.0 spec
    locate-example-2.xml 	- LocateRequest example 4.1.2 from XKMS 2.0 spec 
				with certificate from cert3.pem 
    validate-example-1.xml	- ValidateRequest example 4.2.1 from XKMS 2.0 spec 
				with certificates from cert2.pem and cert3.pem 
    compaund-example-1.xml	- CompaundRequest example 2.8.1 from XKMS 2.0 spec 
				with certificate from cert3.pem 
    
Keys and certificates
    cakey.pem			- root certificate RSA 1024 key encrypted with 
				password "secret"
    cacert.pem			- root certificate for cakey.pem
    key2.pem			- second level RSA 1024 key 
    cert2.pem			- certificate for key2.pem signed with cakey.pem (cacert.pem)
    key3.pem			- third level RSA 1024 key 
    cert3.pem			- certificate for key3.pem signed with key2.pem (cert2.pem)

How keys and certificates were created
    0) Install openssl
    1) Create root key and certificate
	> CA.pl -newca
	> cp ./demoCA/cacert.pem .
	> cp ./demoCA/private/cakey.pem .

    View resulting certificate:
	> openssl x509 -text -in cacert.pem
	
    2) Generate RSA key and second level certificate
	> openssl genrsa -out key2.pem
	> openssl req -new -key key2.pem -out req2.pem
	> openssl ca -cert cacert.pem -keyfile cakey.pem -out cert2.pem -infiles req2.pem

    Test resulting certificate:
	> openssl verify -CAfile cacert.pem cert2.pem
	
    3) Generate another RSA key and third level certificate 
	> openssl genrsa -out key3.pem
	> openssl req -new -key key3.pem -out req3.pem
	> openssl ca -cert cert2.pem -keyfile key2.pem -out cert3.pem -infiles req3.pem

    Test resulting certificate:
	> openssl verify -CAfile cacert.pem -untrusted cert2.pem cert3.pem

    4) Cleanup:
	> rm -rf demoCA/ req*.pem 