import "pe"

rule INDICATOR_KB_CERT_072472f2386f4608a0790da2be8a48f7
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "e2a79e70b7a16a6fc2af7fbdc3d2cbfd3ef66978"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FOXIT SOFTWARE INC." and pe.signatures[i].serial=="07:24:72:f2:38:6f:46:08:a0:79:0d:a2:be:8a:48:f7")
}
