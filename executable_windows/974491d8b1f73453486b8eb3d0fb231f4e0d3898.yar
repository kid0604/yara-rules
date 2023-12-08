import "pe"

rule INDICATOR_KB_CERT_00d3356318924c8c42959bf1d1574e6482
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "e21f261f5cf7c2856bd9da5a5ed2c4e2b2ef4c9a"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ADV TOURS d.o.o." and pe.signatures[i].serial=="00:d3:35:63:18:92:4c:8c:42:95:9b:f1:d1:57:4e:64:82")
}
