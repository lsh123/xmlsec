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
  validate-example-1.xml	- ValidateRequest example 4.2.1 from XKMS 2.0 spec 
				with certificates from cert2.pem and cert3.pem 
  compaund-example-1.xml	- CompaundRequest example 2.8.1 from XKMS 2.0 spec 
				with certificate from cert3.pem 
  locate-opaque-client-data.xml	- LocateRequest with xkms:MessageExtension and 
  				xkms:OpaqueClientData nodes
  locate-opaque-client-data-no-match.xml	
				- "NoMatch" LocateResponse for locate-opaque-client-data.xml
    

Keys and certificates (private keys are encrypted with password "secret")
  keys/create-keys.sh		- shell script to create the keys and certificates chain
  keys/openssl.cnf		- config file for create-keys.sh script
  keys/key1.pem			- root certificate RSA 1024 key in PEM format
  keys/key1.der			- key1.pem key in DER format
  keys/key1-pk8.der		- key1.pem key in PKCS8 DER format 
  keys/key1.p12			- key1.pem key and cert1.pem in PKCS12 format
  keys/cert1.pem		- root certificate for key1.pem
  keys/cert1.der		- cert1.pem certificate in DER format
  keys/key2.pem			- second level CA RSA 1024 key 
  keys/key2.der			- key2.pem key in DER format
  keys/key2.p12			- key2.pem key and cert2.pem in PKCS12 format
  keys/key2-pk8.der		- key2.pem key in PKCS8 DER format 
  keys/cert2.pem		- certificate for key2.pem signed with key1.pem (cert1.pem)
  keys/cert2.der		- cert2.pem certificate in DER format
  keys/key3.pem			- signature/encryption RSA 1024 key 
  keys/key3.der			- key3.pem key in DER format
  keys/key3.p12			- key3.pem key and cert3.pem in PKCS12 format
  keys/key3-pk8.der		- key3.pem key in PKCS8 DER format 
  keys/cert3.pem		- certificate for key3.pem signed with key2.pem (cert2.pem)
  keys/cert3.der		- cert3.pem certificate in DER format

	