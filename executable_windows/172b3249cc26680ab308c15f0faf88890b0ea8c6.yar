import "pe"

rule INDICATOR_KB_CERT_0b1926a5e8ae50a0efa504f005f93869
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "2052ed19dcb0e3dfff71d217be27fc5a11c0f0d4"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Nordkod LLC" and pe.signatures[i].serial=="0b:19:26:a5:e8:ae:50:a0:ef:a5:04:f0:05:f9:38:69")
}
