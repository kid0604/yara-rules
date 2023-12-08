import "pe"

rule INDICATOR_KB_CERT_0d261c8470adbb65800ceaf3eac70819
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "307ef8a02a0fc9032591c624624fa3531c235aa1"
		hash1 = "050dbd816c222d3c012ba9f2b1308db8e160e7d891f231272f1eacf19d0a0a06"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bandicam Company Corp." and pe.signatures[i].serial=="0d:26:1c:84:70:ad:bb:65:80:0c:ea:f3:ea:c7:08:19")
}
