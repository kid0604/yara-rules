import "pe"

rule INDICATOR_KB_CERT_0c5396dcb2949c70fac48ab08a07338e
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "b6b24aea9e983ed6bda9586a145a7ddd7e220196"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Mozilla Corporation" and pe.signatures[i].serial=="0c:53:96:dc:b2:94:9c:70:fa:c4:8a:b0:8a:07:33:8e")
}
