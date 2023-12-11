import "pe"

rule INDICATOR_KB_CERT_0084888d5a12228e8950683ecdab62fe7a
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "390b23ed9750745e8441e35366b294a2a5c66fcd"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ub30 Limited" and pe.signatures[i].serial=="00:84:88:8d:5a:12:22:8e:89:50:68:3e:cd:ab:62:fe:7a")
}
