import "pe"

rule INDICATOR_KB_CERT_7ed801843fa001b8add52d3a97b25931
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "4ee1539c1455f0070d8d04820fb814f8794f84df"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AM El-Teknik ApS" and pe.signatures[i].serial=="7e:d8:01:84:3f:a0:01:b8:ad:d5:2d:3a:97:b2:59:31")
}
