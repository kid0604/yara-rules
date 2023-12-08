import "pe"

rule INDICATOR_KB_CERT_0ed1847a2ae5d71def1e833fddd33d38
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "e611a7d4cd6bb8650e1e670567ac99d0bf24b3e8"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SNAB-RESURS, OOO" and pe.signatures[i].serial=="0e:d1:84:7a:2a:e5:d7:1d:ef:1e:83:3f:dd:d3:3d:38")
}
