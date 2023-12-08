import "pe"

rule INDICATOR_KB_CERT_105440f57e9d04419f5a3e72195110e6
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "e95c7b4f2e5f64b388e968d0763da67014eb3aeb8c04bd44333ca3e151aa78c2"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CRYPTOLAYER SRL" and pe.signatures[i].serial=="10:54:40:f5:7e:9d:04:41:9f:5a:3e:72:19:51:10:e6")
}
