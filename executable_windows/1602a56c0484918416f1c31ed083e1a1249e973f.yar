import "pe"

rule INDICATOR_KB_CERT_6a241ffe96a6349df608d22c02942268
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "f97f4b9953124091a5053712b2c22b845b587cb2655156dcafed202fa7ceeeb1"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "HELP, d.o.o." and pe.signatures[i].serial=="6a:24:1f:fe:96:a6:34:9d:f6:08:d2:2c:02:94:22:68")
}
