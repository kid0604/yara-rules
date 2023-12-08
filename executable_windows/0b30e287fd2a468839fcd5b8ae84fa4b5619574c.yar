import "pe"

rule INDICATOR_KB_CERT_00fc7065abf8303fb472b8af85918f5c24
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "b61a6607154d27d64de35e7529cb853dcb47f51f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DIG IN VISION SP Z O O" and pe.signatures[i].serial=="00:fc:70:65:ab:f8:30:3f:b4:72:b8:af:85:91:8f:5c:24")
}
