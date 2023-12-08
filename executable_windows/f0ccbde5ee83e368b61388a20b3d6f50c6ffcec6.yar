import "pe"

rule INDICATOR_KB_CERT_f2c4b99487ed33396d77029b477494bc
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "f38abffd259919d68969b8b2d265afac503a53dd"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bedaabaefadfdfedcbbbebaaef" and pe.signatures[i].serial=="f2:c4:b9:94:87:ed:33:39:6d:77:02:9b:47:74:94:bc")
}
