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
    

Expected service is http://www.example.com/xkms

1) Tests
1.1) locate-example-1 (LocateRequest example 4.1.1 from XKMS 2.0 spec).

    * locate-example-1.xml		- LocateRequest file.
    * locate-example-1-no-match.xml	- LocateResult: "NoMatch" error 
					  (key not found).
    * locate-example-1-bad-service.xml	- LocateResult: bad "Service".
    
1.2) locate-example-2 (LocateRequest example 4.1.2 from XKMS 2.0 spec 
with certificate from cert2.pem file). 

    * locate-example-2.xml		- LocateRequest file.
    * locate-example-2-no-match.xml	- LocateResult: "NoMatch" error 
					  (key not found).

1.3) validate-example-1 (ValidateRequest example 4.2.1 from XKMS 2.0 spec 
with certificates from cert2.pem and cert3.pem file).

    * validate-example-1.xml		- ValidateRequest file.
    * validate-example-1-no-match.xml	- ValidateResult: "NoMatch" error 
					  (key not found).
   
1.4) compaund-example-1 (CompaundRequest example 2.8.1 from XKMS 2.0 spec 
with certificate from cert3.pem file).

    * compaund-example-1.xml		- CompaundRequest file.
    * compound-example-1-no-match.xml	- CompoundResult: "NoMatch" error 
					  (key not found).

1.5) locate-opaque-client-data (LocateRequest with xkms:MessageExtension and 
xkms:OpaqueClientData nodes).
    
    * locate-opaque-client-data.xml	- LocateRequest file.
    * locate-opaque-client-data-no-match.xml	
					- LocateResult: "NoMatch" error 
					(key not found).

1.6) status-request (simple StatusRequest)

    * status-request.xml		- StatusRequest file.
    * status-request-success.xml	- StatusResult: success.

1.7) soap12-locate-example-1 (SOAP 1.2 LocateRequest example 3.1.1 
from XKMS 2.0 spec 
    
    * soap12-locate-example-1.xml	- SOAP 1.2 LocateRequest file.
    * soap12-locate-example-1-no-match.xml	
					- SOAP 1.2 LocateResult: "NoMatch" 
					error (key not found).
    * soap12-locate-example-1-unsupported.xml	
					- Processing SOAP 1.2 request with 
					SOAP 1.1: "Unsupported SOAP Version": 
            
1.8) soap11-locate-example-1 (SOAP 1.1 LocateRequest example 3.1.2 
from XKMS 2.0 spec 

    * soap11-locate-example-1.xml	- SOAP 1.1 LocateRequest file.
    * soap11-locate-example-1-no-match.xml	
					- SOAP 1.1 LocateResult: "NoMatch" 
					error (key not found).
    * soap11-locate-example-1-unsupported.xml	
					- Processing SOAP 1.1 request with 
					SOAP 1.2: "Unsupported SOAP Version": 

1.9) bad-request-name (A request with invalid node name).
  bad-request-name.xml			- Invalid request file.    
  bad-request-name-not-supported.xml	- Result: MessageNotSupported error.

1.10) soap12-bad-request-name (SOAP 1.2 request with invalid node name).
  soap12-bad-request-name.xml		- SOAP 1.2 Invalid request file.    
  soap12-bad-request-name-not-supported.xml 	
					- SOAP 1.2 Result: MessageNotSupported error.

1.11) soap11-bad-request-name (SOAP 1.1 request with invalid node name).
  soap11-bad-request-name.xml		- SOAP 1.1 Invalid request file.    
  soap11-bad-request-name-not-supported.xml 	
					- SOAP 1.1 Result: MessageNotSupported error.


2) Keys and certificates (private keys are encrypted with password "secret")
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

	