import "pe"

rule INDICATOR_KB_CERT_65cd323c2483668b90a44a711d2a6b98
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "188810cf106a5f38fe8aa0d494cbd027da9edf97"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Giperion" and pe.signatures[i].serial=="65:cd:32:3c:24:83:66:8b:90:a4:4a:71:1d:2a:6b:98")
}
