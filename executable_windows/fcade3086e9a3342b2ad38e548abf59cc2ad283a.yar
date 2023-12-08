import "pe"

rule INDICATOR_KB_CERT_736dcfd309ea4c3bea23287473ffe071
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "8bfc13bf01e98e5b38f8f648f0f843b63af03f55"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ESTELLA, OOO" and pe.signatures[i].serial=="73:6d:cf:d3:09:ea:4c:3b:ea:23:28:74:73:ff:e0:71")
}
