import "pe"

rule INDICATOR_KB_CERT_3b007314844b114c61bc156a0609a286
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "52ae9fdda7416553ab696388b66f645e07e753cd"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SATURDAY CITY LIMITED" and pe.signatures[i].serial=="3b:00:73:14:84:4b:11:4c:61:bc:15:6a:06:09:a2:86")
}
