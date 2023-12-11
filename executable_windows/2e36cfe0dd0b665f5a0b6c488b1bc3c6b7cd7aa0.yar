import "pe"

rule INDICATOR_KB_CERT_c6d7ad852af211bf48f19cc0242dcd72
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "bddcef09f222ea4270d4a1811c10f4fcf98e4125"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "APDZQKILIIQVIJSCTY" and pe.signatures[i].serial=="c6:d7:ad:85:2a:f2:11:bf:48:f1:9c:c0:24:2d:cd:72")
}
