import "pe"

rule INDICATOR_KB_CERT_7d36cbb64bc9add17ba71737d3ecceca
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "a7287460dcf02e38484937b121ce8548191d4e64"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LTD SERVICES LIMITED" and pe.signatures[i].serial=="7d:36:cb:b6:4b:c9:ad:d1:7b:a7:17:37:d3:ec:ce:ca")
}
