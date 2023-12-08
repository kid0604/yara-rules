import "pe"

rule INDICATOR_KB_CERT_19beff8a6c129663e5e8c18953dc1f67
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "ad3deacd821fee3bb158665bd7fa491e39aab2e6"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CULNADY LTD LTD" and pe.signatures[i].serial=="19:be:ff:8a:6c:12:96:63:e5:e8:c1:89:53:dc:1f:67")
}
