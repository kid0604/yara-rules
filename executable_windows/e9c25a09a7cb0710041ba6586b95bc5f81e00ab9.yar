import "pe"

rule INDICATOR_KB_CERT_00f454f2fdc800b3454059d8889bd73d67
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "2b560fabc34e0db81dae1443b1c4929eef820266"
		hash1 = "e58b80e4738dc03f5aa82d3a40a6d2ace0d7c7cfd651f1dd10df76d43d8c0eb3"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BEAUTY CORP SRL" and (pe.signatures[i].serial=="f4:54:f2:fd:c8:00:b3:45:40:59:d8:88:9b:d7:3d:67" or pe.signatures[i].serial=="00:f4:54:f2:fd:c8:00:b3:45:40:59:d8:88:9b:d7:3d:67"))
}
