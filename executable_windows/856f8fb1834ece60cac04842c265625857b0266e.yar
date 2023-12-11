import "pe"

rule INDICATOR_KB_CERT_4743e140c05b33f0449023946bd05acb
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "7b32c8cc35b86608c522a38c4fe38ebaa57f27675504cba32e0ab6babbf5094a"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "STROI RENOV SARL" and pe.signatures[i].serial=="47:43:e1:40:c0:5b:33:f0:44:90:23:94:6b:d0:5a:cb")
}
