import "pe"

rule INDICATOR_KB_CERT_283518f1940a11caf187646d8063d61d
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "aaeb19203b71e26c857613a5a2ba298c79910f5d"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Eeeeeeba" and pe.signatures[i].serial=="28:35:18:f1:94:0a:11:ca:f1:87:64:6d:80:63:d6:1d")
}
