import "pe"

rule INDICATOR_KB_CERT_670c3494206b9f0c18714fdcffaaa42f
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "59612473a9e23dc770f3a33b1ef83c02e3cfd4b6"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ADRIATIK PORT SERVIS, d.o.o." and pe.signatures[i].serial=="67:0c:34:94:20:6b:9f:0c:18:71:4f:dc:ff:aa:a4:2f")
}
