import "pe"

rule INDICATOR_KB_CERT_0ddeb53f957337fbeaf98c4a615b149d
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "91cabea509662626e34326687348caf2dd3b4bba"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Mozilla Corporation" and pe.signatures[i].serial=="0d:de:b5:3f:95:73:37:fb:ea:f9:8c:4a:61:5b:14:9d")
}
