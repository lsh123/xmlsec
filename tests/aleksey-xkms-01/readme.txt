XKMS Featrues
    <xkms:StatusRequest>
    <xkms:LocateRequest>
    <xkms:ValidateRequest>
    <xkms:CompundRequest>
    Pending requests
    <xkms:MessageExtension>
    <xkms:OpaqueClientData>
    <xkms:KeyUsage>
    <xkms:UseKeyWith>
    <xkms:TieInstant> and <xkms:ValidityInterval> 
    
    

Tests
    locate-example-1.xml 		- LocateRequest example 4.1.1 from XKMS 2.0 spec
    locate-example-1-no-match.xml	- "NoMatch" LocateResponse for locate-example-1.xml
    locate-example-2.xml 		- LocateRequest example 4.1.2 from XKMS 2.0 spec 
					with certificate from cert3.pem 
    locate-example-2-no-match.xml	- "NoMatch" LocateResponse for locate-example-2.xml
    validate-example-1.xml		- ValidateRequest example 4.2.1 from XKMS 2.0 spec 
					with certificates from cert2.pem and cert3.pem 
    compaund-example-1.xml		- CompaundRequest example 2.8.1 from XKMS 2.0 spec 
					with certificate from cert3.pem 
    locate-opaque-client-data.xml	- LocateRequest with xkms:MessageExtension and 
					xkms:OpaqueClientData nodes
    locate-opaque-client-data-no-match.xml	
					- "NoMatch" LocateResponse for locate-opaque-client-data.xml
    

Keys and certificates (private keys are encrypted with "empty" or no password)
    cakey.pem				- root certificate RSA 1024 key in PEM format
    cakey.der				- cakey.pem key in DER format
    cakey-pk8.der			- cakey.pem key in PKCS8 DER format 
    cakey.p12				- cakey.pem key and cacert.pem in PKCS12 format
    cacert.pem				- root certificate for cakey.pem
    cacert.der				- cacert.pem certificate in DER format
    key2.pem				- second level RSA 1024 key 
    key2.der				- key2.pem key in DER format
    key2.p12				- key2.pem key and cert2.pem in PKCS12 format
    key2-pk8.der			- key2.pem key in PKCS8 DER format 
    cert2.pem				- certificate for key2.pem signed with cakey.pem (cacert.pem)
    cert2.der				- cert2.pem certificate in DER format
    key3.pem				- third level RSA 1024 key 
    key3.der				- key3.pem key in DER format
    key3.p12				- key3.pem key and cert3.pem in PKCS12 format
    key3-pk8.der			- key3.pem key in PKCS8 DER format 
    cert3.pem				- certificate for key3.pem signed with key2.pem (cert2.pem)
    cert3.der				- cert3.pem certificate in DER format

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
    
    4) Convert all private keys to der, pkcs8/der and pkcs12 format
	> openssl rsa -inform PEM -outform DER -in cakey.pem -out cakey.der
	> openssl rsa -inform PEM -outform DER -in key2.pem -out key2.der
	> openssl rsa -inform PEM -outform DER -in key3.pem -out key3.der

	> openssl pkcs8 -in cakey.pem -inform pem -out cakey-pk8.der -outform der -topk8
	> openssl pkcs8 -in key2.pem -inform pem -out key2-pk8.der -outform der -topk8
	> openssl pkcs8 -in key3.pem -inform pem -out key3-pk8.der -outform der -topk8
	    
       > openssl pkcs12 -export -in cacert.pem -inkey cakey.pem -name cakey -out cakey.p12
       > openssl pkcs12 -export -in cert2.pem -inkey key2.pem -name key2 -out key2.p12
       > openssl pkcs12 -export -in cert3.pem -inkey key3.pem -name key3 -out key3.p12
	
    5) Convert all certificates to der format
	> openssl x509 -outform DER -in cacert.pem -out cacert.der 
	> openssl x509 -outform DER -in cert2.pem -out cert2.der 
	> openssl x509 -outform DER -in cert3.pem -out cert3.der 

    6) Cleanup:
	> rm -rf demoCA/ req*.pem 
	
	
	