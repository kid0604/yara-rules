import "pe"

rule INDICATOR_KB_CERT_09830675eb483e265c3153f0a77c3de9
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "1bb5503a2e1043616b915c4fce156c34304505d6"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "James LTH d.o.o." and pe.signatures[i].serial=="09:83:06:75:eb:48:3e:26:5c:31:53:f0:a7:7c:3d:e9")
}
