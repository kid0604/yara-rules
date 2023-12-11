import "pe"

rule INDICATOR_KB_CERT_2c90eaf4de3afc03ba924c719435c2a3
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "6b916111ffbd6736afa569d7d940ada544daf3b18213a0da3025b20973a577dc"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AntiFIX s.r.o." and pe.signatures[i].serial=="2c:90:ea:f4:de:3a:fc:03:ba:92:4c:71:94:35:c2:a3")
}
