import "pe"

rule INDICATOR_KB_CERT_3112c69d460c781fd649c71e61bfec82
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "7ec961d2c69f7686e33f39d497a5e3039e512cf3"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "KREATURHANDLER BJARNE ANDERSEN ApS" and pe.signatures[i].serial=="31:12:c6:9d:46:0c:78:1f:d6:49:c7:1e:61:bf:ec:82")
}
