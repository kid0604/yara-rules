import "pe"

rule INDICATOR_KB_CERT_13794371c052ec0559e9b492abb25c26
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "dd3ab539932e81db45cf262d44868e1f0f88a7b0baf682fb89d1a3fcfba3980b"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Carmel group LLC" and pe.signatures[i].serial=="13:79:43:71:c0:52:ec:05:59:e9:b4:92:ab:b2:5c:26")
}
