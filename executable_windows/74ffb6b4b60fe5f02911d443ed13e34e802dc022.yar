import "pe"

rule INDICATOR_KB_CERT_063a7d09107eddd8aa1f733634c6591b
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "a03f9b3f3eb30ac511463b24f2e59e89ee4c6d4a"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Smart Line Logistics" and pe.signatures[i].serial=="06:3a:7d:09:10:7e:dd:d8:aa:1f:73:36:34:c6:59:1b")
}
