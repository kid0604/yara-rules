import "pe"

rule INDICATOR_KB_CERT_3972443af922b751d7d36c10dd313595
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "d89e3bd43d5d909b47a18977aa9d5ce36cee184c"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Sore Loser Games ApS" and pe.signatures[i].serial=="39:72:44:3a:f9:22:b7:51:d7:d3:6c:10:dd:31:35:95")
}
