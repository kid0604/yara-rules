import "pe"

rule INDICATOR_KB_CERT_047801d5b55c800b48411fd8c320ca5b
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "00c49b8d6fd7d2aa26faad8e5a31f93a15d66d09"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LICHFIELD STUDIO GLASS LIMITED" and pe.signatures[i].serial=="04:78:01:d5:b5:5c:80:0b:48:41:1f:d8:c3:20:ca:5b")
}
