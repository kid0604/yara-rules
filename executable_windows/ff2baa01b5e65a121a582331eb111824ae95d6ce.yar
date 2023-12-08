import "pe"

rule INDICATOR_KB_CERT_0f2b44e398ba76c5f57779c41548607b
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "cef53e9ca954d1383a8ece037925aa4de9268f3f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DIGITAL DR" and pe.signatures[i].serial=="0f:2b:44:e3:98:ba:76:c5:f5:77:79:c4:15:48:60:7b")
}
