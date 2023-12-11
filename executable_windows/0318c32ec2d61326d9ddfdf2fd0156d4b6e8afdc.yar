import "pe"

rule INDICATOR_KB_CERT_277cd16de5d61b9398b645afe41c09c7
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "11a18b9ba48e2b715202def00c2005a394786b23"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "THE SIGN COMPANY LIMITED" and pe.signatures[i].serial=="27:7c:d1:6d:e5:d6:1b:93:98:b6:45:af:e4:1c:09:c7")
}
