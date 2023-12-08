import "pe"

rule INDICATOR_KB_CERT_26b125e669e77a5e58db378e9816fbc3
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "900aa9e6ff07c6528ecd71400e6404682e812017"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FLOWER DELI LTD" and pe.signatures[i].serial=="26:b1:25:e6:69:e7:7a:5e:58:db:37:8e:98:16:fb:c3")
}
