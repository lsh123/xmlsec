<xkms:LocateRequest Id Service Nonce? OriginalRequestId? ResponseLimit? >
	<dsig:Signature/>?
	<xkms:MessageExtension/>*
	<xkms:OpaqueClientData/>?
	<xkms:ResponseMechanism/>*
	<xkms:RespondWith/>*
	<xkms:PendingNotification Mechanism Identifier />?
	<xkms:QueryKeyBinding Id? >
		<dsig:KeyInfo/>?
		<xkms:KeyUsage/>*
		<xkms:UseKeyWith Application Identifier />*
		<xkms:TimeInstant Time />?
	</xkms:QueryKeyBinding>
</xkms:LocateRequest>


<xkms:LocateResult Id Service Nonce? ResultMajor ResultMinor? RequestId? >
	<dsig:Signature/>?
	<xkms:MessageExtension/>*
	<xkms:OpaqueClientData/>?
	<xkms:RequestSignatureValue/>?
	(<xkms:UnverifiedKeyBinding Id? >
		<dsig:KeyInfo/>?
		<xkms:KeyUsage/>*
		<xkms:UseKeyWith Application Identifier />*
		<xkms:ValidityInterval NotBefore? NotOnOrAfter? />?
	</xkms:UnverifiedKeyBinding>)*
</xkms:LocateResult>


Tests:

./apps/xmlsec1 xkms-locate --untrusted ./tests/keys/ca2cert.pem --trusted  ./tests/keys/cacert.pem 
                           ./tests/aleksey-xkms-01/locate-keyvalue-from-x509.xml

Issues:

1) In the schema for <xkms:ValidityInreval/> element "NotBefore" and "NotAfter" 
attributes do not have "use=\"optional\"" specified.
2) The "maxOccurs=\"3\"" for <xkms:KeyUsage/> element may prevent schema extension
in the future, I would suggest to change this to "maxOccurs=\"unbound\"".
3) No key type (RSA/DSA/etc.) specified.
