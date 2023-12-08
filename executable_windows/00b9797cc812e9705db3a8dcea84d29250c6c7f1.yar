import "pe"

rule INDICATOR_KB_CERT_75522215406335725687af888dcdc80c
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = ""
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "THEESOLUTIONS LTD" and pe.signatures[i].serial=="75:52:22:15:40:63:35:72:56:87:af:88:8d:cd:c8:0c")
}
