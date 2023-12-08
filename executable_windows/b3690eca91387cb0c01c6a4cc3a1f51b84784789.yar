import "pe"

rule INDICATOR_KB_CERT_0e1bacb85e77d355ea69ba0b
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "6750c9224540d7606d3c82c7641f49147c1b3fd0"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BULDOK LIMITED" and pe.signatures[i].serial=="0e:1b:ac:b8:5e:77:d3:55:ea:69:ba:0b")
}
