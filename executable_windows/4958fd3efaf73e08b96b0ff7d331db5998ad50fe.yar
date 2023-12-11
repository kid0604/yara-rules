import "pe"

rule INDICATOR_KB_CERT_05abac07f8d0ce567f7d75ee047efee2
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "68b32eac87652af4172e40e3764477437e5a5ce9"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ultrareach Internet Corp." and pe.signatures[i].serial=="05:ab:ac:07:f8:d0:ce:56:7f:7d:75:ee:04:7e:fe:e2")
}
