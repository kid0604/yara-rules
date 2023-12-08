import "pe"

rule INDICATOR_KB_CERT_3d31ed3b22867f425db86fb532eb449f
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "1e708efa130d1e361afb76cc94ba22aca3553590"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Badfcbdbcdbfafcaeebad" and pe.signatures[i].serial=="3d:31:ed:3b:22:86:7f:42:5d:b8:6f:b5:32:eb:44:9f")
}
