import "pe"

rule INDICATOR_KB_CERT_62205361a758b00572d417cba014f007
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "83e851e8c50f9d7299363181f2275edc194037be8cb6710762d2099e0b3f31c6"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "UNITEKH-S, OOO" and pe.signatures[i].serial=="62:20:53:61:a7:58:b0:05:72:d4:17:cb:a0:14:f0:07")
}
