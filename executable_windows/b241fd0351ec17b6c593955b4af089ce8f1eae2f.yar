import "pe"

rule INDICATOR_KB_CERT_7d08a74747557d6016aaaf47a679312f
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "d7fdad88c626b8e6d076f3f414bbae353f444618"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Abfacfbdcd" and pe.signatures[i].serial=="7d:08:a7:47:47:55:7d:60:16:aa:af:47:a6:79:31:2f")
}
