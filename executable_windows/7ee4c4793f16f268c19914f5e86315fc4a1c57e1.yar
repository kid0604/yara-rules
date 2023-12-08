import "pe"

rule INDICATOR_KB_CERT_3afe693728f8406054a613f6736f89e3
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "89528e9005a635bcee8da5539e71c5fc4f839f50"
		hash1 = "d98bdf3508763fe0df177ef696f5bf8de7ff7c7dc68bb04a14a95ec28528c3f9"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ROB ALDERMAN FITNESS LIMITED" and pe.signatures[i].serial=="3a:fe:69:37:28:f8:40:60:54:a6:13:f6:73:6f:89:e3")
}
