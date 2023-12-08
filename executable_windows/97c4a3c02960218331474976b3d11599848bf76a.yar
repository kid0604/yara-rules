import "pe"

rule INDICATOR_KB_CERT_c650ae531100a91389a7f030228b3095
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "05eebfec568abc5fc4b2fd9e5eca087b02e49f53"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "POKEROWA STRUNA SP Z O O" and pe.signatures[i].serial=="c6:50:ae:53:11:00:a9:13:89:a7:f0:30:22:8b:30:95")
}
