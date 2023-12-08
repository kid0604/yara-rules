import "pe"

rule INDICATOR_KB_CERT_07f9d80b85ceff7ee3f58dc594fe66b6
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "bf9254919794c1075ea027889c5d304f1121c653"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Kaspersky Lab" and pe.signatures[i].serial=="07:f9:d8:0b:85:ce:ff:7e:e3:f5:8d:c5:94:fe:66:b6")
}
