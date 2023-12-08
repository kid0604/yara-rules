import "pe"

rule INDICATOR_KB_CERT_038fc745523b41b40d653b83aa381b80
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "05124a4a385b4b2d7a9b58d1c3ad7f2a84e7b0af"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Optima" and pe.signatures[i].serial=="03:8f:c7:45:52:3b:41:b4:0d:65:3b:83:aa:38:1b:80")
}
