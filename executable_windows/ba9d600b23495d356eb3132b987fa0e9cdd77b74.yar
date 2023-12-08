import "pe"

rule INDICATOR_KB_CERT_4f8ebbb263f3cbe558d37118c43f8d58
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "3f27a35fe7af06977138d02ad83ddbf13a67b7c3"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Maxthon Technology Co, Ltd." and pe.signatures[i].serial=="4f:8e:bb:b2:63:f3:cb:e5:58:d3:71:18:c4:3f:8d:58")
}
