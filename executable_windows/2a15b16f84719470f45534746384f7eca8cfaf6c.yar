import "pe"

rule INDICATOR_KB_CERT_0fa13ae98e17ae23fcfe7ae873d0c120
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "be226576c113cd14bcdb67e46aab235d9257cd77b826b0d22a9aa0985bad5f35"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "KLAKSON, LLC" and pe.signatures[i].serial=="0f:a1:3a:e9:8e:17:ae:23:fc:fe:7a:e8:73:d0:c1:20")
}
