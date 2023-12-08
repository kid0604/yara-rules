import "pe"

rule INDICATOR_KB_CERT_4a7f07c5d4ad2e23f9e8e03f0e229dd4
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "b37e7f9040c4adc6d29da6829c7a35a2f6a56fdb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Danalis LLC" and pe.signatures[i].serial=="4a:7f:07:c5:d4:ad:2e:23:f9:e8:e0:3f:0e:22:9d:d4")
}
