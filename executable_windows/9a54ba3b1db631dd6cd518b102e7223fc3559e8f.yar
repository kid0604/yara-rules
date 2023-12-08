import "pe"

rule INDICATOR_KB_CERT_b5f34b7c326c73c392b515eb4c2ec80e
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "9d35805d6311fd2fe6c49427f55f0b4e2836bbc5"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Cdaadbffbaedaabbdedfdbfebf" and pe.signatures[i].serial=="b5:f3:4b:7c:32:6c:73:c3:92:b5:15:eb:4c:2e:c8:0e")
}
