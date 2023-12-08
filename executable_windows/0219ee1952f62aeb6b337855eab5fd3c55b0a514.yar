import "pe"

rule INDICATOR_KB_CERT_0a23b660e7322e54d7bd0e5acc890966
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "c1e0c6dc2bc8ea07acb0f8bdb09e6a97ae91e57c"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ARTBUD RADOM SP Z O O" and pe.signatures[i].serial=="0a:23:b6:60:e7:32:2e:54:d7:bd:0e:5a:cc:89:09:66")
}
