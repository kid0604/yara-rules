import "pe"

rule INDICATOR_KB_CERT_0b1f8cd59e64746beae153ecca21066b
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "74b2e146a82f2b71f8eb4b13ebbb6f951757d8c2"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Mozilla Corporation" and pe.signatures[i].serial=="0b:1f:8c:d5:9e:64:74:6b:ea:e1:53:ec:ca:21:06:6b")
}
