import "pe"

rule INDICATOR_KB_CERT_4e7545c9fc5938f5198ab9f1749ca31c
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "7a49677c535a13d0a9b6deb539d084ff431a5b54"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "For M d.o.o." and pe.signatures[i].serial=="4e:75:45:c9:fc:59:38:f5:19:8a:b9:f1:74:9c:a3:1c")
}
