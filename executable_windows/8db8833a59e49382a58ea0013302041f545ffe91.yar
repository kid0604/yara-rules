import "pe"

rule INDICATOR_KB_CERT_1ffc9825644caf5b1f521780c5c7f42c
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "4e7e022c7bb6bd90a75674a67f82e839d54a0a5e"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ACTIVUS LIMITED" and pe.signatures[i].serial=="1f:fc:98:25:64:4c:af:5b:1f:52:17:80:c5:c7:f4:2c")
}
