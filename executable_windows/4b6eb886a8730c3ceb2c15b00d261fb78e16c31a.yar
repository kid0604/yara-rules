import "pe"

rule INDICATOR_KB_CERT_00d9e834182dec62c654e775e809ac1d1b
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "5bb983693823dbefa292c86d93b92a49ec6f9b26"
		hash = "645dbb6df97018fafb4285dc18ea374c721c86349cb75494c7d63d6a6afc27e6"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FoodLehto Oy" and pe.signatures[i].serial=="00:d9:e8:34:18:2d:ec:62:c6:54:e7:75:e8:09:ac:1d:1b")
}
