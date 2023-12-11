import "pe"

rule INDICATOR_KB_CERT_41d05676e0d31908be4dead3486aeae3
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "e6e597527853ee64b45d48897e3ca4331f6cc08a88cc57ff2045923e65461598"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Rov SP Z O O" and pe.signatures[i].serial=="41:d0:56:76:e0:d3:19:08:be:4d:ea:d3:48:6a:ea:e3")
}
