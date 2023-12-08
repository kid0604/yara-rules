import "pe"

rule INDICATOR_KB_CERT_37f3384b16d4eef0a9b3344b50f1d8a3
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "3fcdcf15c35ef74dc48e1573ad1170b11a623b40"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Sore Loser Games ApS" and pe.signatures[i].serial=="37:f3:38:4b:16:d4:ee:f0:a9:b3:34:4b:50:f1:d8:a3")
}
