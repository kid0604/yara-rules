import "pe"

rule INDICATOR_KB_CERT_0a1dc99e4d5264c45a5090f93242a30a
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "17680b1ebaa74f94272957da11e914a3a545f16f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "K & D KOMPANI d.o.o." and pe.signatures[i].serial=="0a:1d:c9:9e:4d:52:64:c4:5a:50:90:f9:32:42:a3:0a")
}
