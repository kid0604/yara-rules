import "pe"

rule INDICATOR_KB_CERT_00taffias
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "88d563dccb2ffc9c5f6d6a3721ad17203768735a"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TAFFIAS" and pe.signatures[i].serial=="00")
}
