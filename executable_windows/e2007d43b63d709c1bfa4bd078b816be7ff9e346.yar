import "pe"

rule INDICATOR_KB_CERT_2355895f1759e9e3648026f4
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "f46d457898d436769f0c70127044e2019583ee16"
		hash1 = "f4f4a5953d0c87db611fa05bb51672591295049978a0e9e14eca8224254ecd7a"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Avira Operations GmbH & Co. KG" and pe.signatures[i].serial=="23:55:89:5f:17:59:e9:e3:64:80:26:f4")
}
