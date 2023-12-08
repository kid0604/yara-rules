import "pe"

rule INDICATOR_KB_CERT_c01e41ff29078e6626a640c5a19a8d80
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "cca4a461592e6adff4e0a4458ebe29ee4de5f04c638dbd3b7ee30f3519cfd7e5"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BurnAware" and pe.signatures[i].serial=="c0:1e:41:ff:29:07:8e:66:26:a6:40:c5:a1:9a:8d:80")
}
