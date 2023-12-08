import "pe"

rule INDICATOR_KB_CERT_2888cf0f953a4a3640ee4cfc6304d9d4
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "eb5f5ab7294ba39f2b77085f47382bd7e759ff3a"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Lotte Schmidt" and pe.signatures[i].serial=="28:88:cf:0f:95:3a:4a:36:40:ee:4c:fc:63:04:d9:d4")
}
