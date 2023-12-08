import "pe"

rule INDICATOR_KB_CERT_008d52fb12a2511e86bbb0ba75c517eab0
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "9e918ce337aebb755e23885d928e1a67eca6823934935010e82b561b928df2f9"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VThink Software Consulting Inc." and pe.signatures[i].serial=="00:8d:52:fb:12:a2:51:1e:86:bb:b0:ba:75:c5:17:ea:b0")
}
