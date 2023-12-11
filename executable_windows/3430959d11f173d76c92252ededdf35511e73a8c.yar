import "pe"

rule INDICATOR_KB_CERT_3cee26c125b8c188f316c3fa78d9c2f1
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "9efcf68a289d9186ec17e334205cb644c2b6a147"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bitubit LLC" and pe.signatures[i].serial=="3c:ee:26:c1:25:b8:c1:88:f3:16:c3:fa:78:d9:c2:f1")
}
