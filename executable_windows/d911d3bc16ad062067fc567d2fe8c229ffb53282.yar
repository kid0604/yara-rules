import "pe"

rule INDICATOR_KB_CERT_4d78e90e0950fc630000000055657e1a
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "fd010fdee2314f5d87045d1d7bf0da01b984b0fe"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Telus Health Solutions Inc." and pe.signatures[i].serial=="4d:78:e9:0e:09:50:fc:63:00:00:00:00:55:65:7e:1a")
}
