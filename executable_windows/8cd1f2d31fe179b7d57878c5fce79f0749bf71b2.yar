import "pe"

rule INDICATOR_KB_CERT_00e161f76da3b5e4623892c8e6fda1ea3d
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "df5fbfbfd47875b580b150603de240ead9c7ad27"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TGN Nedelica d.o.o." and pe.signatures[i].serial=="00:e1:61:f7:6d:a3:b5:e4:62:38:92:c8:e6:fd:a1:ea:3d")
}
